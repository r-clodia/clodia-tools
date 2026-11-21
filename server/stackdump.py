"""What every thread of the gateway is executing, on demand and during a
stall (clodia-platform#710).

## Why it exists

21 Nov 2026, 08:54–09:02 UTC: after the host woke up, the gateway ran at 100%
CPU for ~8 minutes and its event loop stalled 30–45 s every ~45 s. Which code
held the CPU could not be established: the container has no profiler, and the
stall line of `inflight.report_if_stalled` lists the requests in flight, not
what the threads are executing. Worse, that line is written by a coroutine ON
the event loop, so it can only run AFTER the stall is over — when the code
that held the loop has already returned.

Three ways to see the stacks, no restart and no new dependency:

- **SIGUSR1** (`install_signal_dump`): `faulthandler` writes the Python stack
  of every thread to `<state dir>/diagnostics/thread-stacks.txt`, so
  `docker kill -s USR1 <gateway container>` dumps them. The handler is C code
  run from the signal: it works even when a thread holds the GIL inside an
  extension, which is the case nothing written in Python can see. The file is
  on the gateway's own state volume (the agent-server does not mount it), and
  it holds code locations only — no locals, no arguments.
- **the stall sampler** (`StallSampler`): a daemon thread watches the
  heartbeat that `inflight.watch` beats on the loop. When the heartbeat is
  older than `CLODIA_STALL_STACKS_S` (default 10 s) it samples
  `sys._current_frames()` WHILE the loop is still blocked, logs one compact,
  redacted line set (the loop thread first, then the threads that are not
  parked), rate-limited, and keeps the last sample for the route below.
- **the route** `GET /internal/diagnostics/stacks` (`stackdump_api`): the full
  dump — threads with name, CPU time and frames, asyncio tasks of the loop,
  the requests in flight, the offload pool, the last stall sample and the tail
  of the SIGUSR1 file — for the agent-server's service role and admin persons
  only, redacted with the `logs.tail` redactor.

Secrets never: frames carry file, line, function and the source line of the
code (open source), never a local variable. Every string still goes through
`logs.redact_line` with the lowest clearance — credentials, query strings,
mail addresses, message text and topic names are masked — because a task name
or a coroutine repr is built at runtime and could carry anything.
"""
from __future__ import annotations

import asyncio
import faulthandler
import linecache
import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path

LOG = logging.getLogger("clodia-tools.stacks")

#: Loop blocked at least this long → the sampler takes and logs the stacks.
_DEFAULT_STALL_STACKS_S = 10.0
#: The same stall line is not repeated more often than this.
_DEFAULT_REPEAT_S = 120.0
#: Frames kept per thread/task in the full dump, and in the compact log line.
MAX_FRAMES = 40
COMPACT_FRAMES = 6
#: Threads shown in the compact sample, besides the loop thread.
COMPACT_THREADS = 5
#: Lines of the SIGUSR1 file returned by the route (its tail).
SIGNAL_TAIL_LINES = 400
_SIGNAL_FILE_MAX = 2_000_000
_STR_MAX = 300

#: Where a thread waits when it has nothing to do: a thread whose innermost
#: frame is one of these is parked, not busy. Names, not identities: the same
#: function is called from many places.
_IDLE = frozenset({
    ("threading.py", "wait"), ("threading.py", "_wait_for_tstate_lock"),
    ("queue.py", "get"), ("selectors.py", "select"),
    ("thread.py", "_worker"), ("socket.py", "accept"),
    ("socket.py", "readinto"), ("ssl.py", "read"), ("ssl.py", "recv_into"),
})


def _env_float(name: str, default: float) -> float:
    try:
        return float((os.environ.get(name) or "").strip() or default)
    except ValueError:
        return default


def _redact(text) -> str:
    """Every string of a dump, through the `logs.tail` redactor with the
    lowest clearance (no topic name survives), capped."""
    from .tools.logs import redact_line
    return redact_line(str(text or ""), None)[:_STR_MAX]


# ── Frames ───────────────────────────────────────────────────────────────────

def _frame_rows(frame, limit: int = MAX_FRAMES) -> list[dict]:
    """The stack of `frame`, outermost first like a traceback, last `limit`
    frames. File, line, function and the source line; never locals."""
    rows = []
    f = frame
    while f is not None and len(rows) < limit:
        code = f.f_code
        rows.append((code.co_filename, f.f_lineno, code.co_name))
        f = f.f_back
    out = []
    for filename, lineno, func in reversed(rows):
        src = linecache.getline(filename, lineno).strip() if lineno else ""
        out.append({"file": _redact(_short_path(filename)), "line": lineno,
                    "func": _redact(func), "code": _redact(src)})
    return out


def _short_path(path: str) -> str:
    """`/usr/local/lib/python3.12/site-packages/httpx/_client.py` →
    `httpx/_client.py`: the package is the information, the prefix is noise
    (and a host path in a dump is information about the host)."""
    p = str(path or "")
    for marker in ("site-packages/", "dist-packages/", "/server/"):
        i = p.rfind(marker)
        if i >= 0:
            rest = p[i + len(marker):]
            return ("server/" + rest) if marker == "/server/" else rest
    if "/lib/python" in p:
        return "stdlib/" + p.rsplit("/", 1)[-1]
    return p.rsplit("/", 2)[-1] if p.count("/") > 2 else p


def _is_idle(frames: list[dict]) -> bool:
    if not frames:
        return True
    top = frames[-1]
    return (top["file"].rsplit("/", 1)[-1], top["func"]) in _IDLE


def _thread_cpu_s(native_id) -> float | None:
    """CPU seconds (user+system) consumed by one thread, from
    `/proc/self/task/<tid>/stat`: the column that names the busy thread. None
    off Linux, or if the thread is gone."""
    if not native_id:
        return None
    try:
        raw = Path(f"/proc/self/task/{native_id}/stat").read_text()
    except OSError:
        return None
    try:
        # The command name (2nd field) is in parentheses and may contain
        # spaces: split after the last ')'.
        fields = raw[raw.rindex(")") + 2:].split()
        ticks = int(fields[11]) + int(fields[12])        # utime + stime
        return round(ticks / (os.sysconf("SC_CLK_TCK") or 100), 2)
    except (ValueError, IndexError, OSError):
        return None


def threads(limit: int = MAX_FRAMES) -> list[dict]:
    """Every thread of the process: name, ids, daemon, CPU seconds, frames.
    The loop thread is marked (`loop: true`) when known."""
    loop_ident = _LOOP_THREAD_IDENT
    by_ident = {t.ident: t for t in threading.enumerate()}
    out = []
    for ident, frame in sys._current_frames().items():
        t = by_ident.get(ident)
        native = getattr(t, "native_id", None) if t else None
        frames = _frame_rows(frame, limit)
        out.append({
            "name": _redact(t.name if t else f"thread-{ident}"),
            "ident": ident, "native_id": native,
            "daemon": bool(t.daemon) if t else None,
            "loop": ident == loop_ident,
            "cpu_s": _thread_cpu_s(native),
            "idle": _is_idle(frames),
            "frames": frames,
        })
    # The loop thread first, then the busy ones, by CPU time.
    out.sort(key=lambda r: (not r["loop"], r["idle"], -(r["cpu_s"] or 0.0)))
    return out


def tasks(loop: asyncio.AbstractEventLoop | None = None,
          limit: int = MAX_FRAMES) -> list[dict]:
    """The asyncio tasks of `loop` (the running one by default): name, the
    coroutine, and where each is suspended. Empty off the loop thread."""
    try:
        loop = loop or asyncio.get_running_loop()
        all_tasks = asyncio.all_tasks(loop)
    except RuntimeError:
        return []
    out = []
    for task in all_tasks:
        coro = task.get_coro()
        try:
            stack = task.get_stack(limit=limit)
        except Exception:  # noqa: BLE001 — a task finishing under us
            stack = []
        frames = []
        for f in stack:
            frames.extend(_frame_rows(f, 1))
        out.append({
            "name": _redact(task.get_name()),
            "coro": _redact(getattr(coro, "__qualname__", type(coro).__name__)),
            "done": task.done(),
            "frames": frames,
        })
    out.sort(key=lambda r: r["name"])
    return out


# ── SIGUSR1 → file ───────────────────────────────────────────────────────────

_SIGNAL_FILE = None          # kept open: faulthandler writes to its fd
_SIGNAL_PATH: Path | None = None


def signal_dump_path() -> Path:
    from .state_paths import state_dir
    return state_dir() / "diagnostics" / "thread-stacks.txt"


def install_signal_dump(path: Path | None = None) -> Path | None:
    """`kill -USR1 <pid>` → the stacks of every thread appended to `path`.

    Idempotent and fail-open: no SIGUSR1 (Windows) or an unwritable volume
    leaves the gateway running without it, with one warning. The file is
    truncated when it outgrows `_SIGNAL_FILE_MAX`: it is a diagnostic, not an
    archive."""
    global _SIGNAL_FILE, _SIGNAL_PATH
    sig = getattr(signal, "SIGUSR1", None)
    if sig is None:
        return None
    try:
        target = Path(path) if path else signal_dump_path()
        if _SIGNAL_FILE is not None and _SIGNAL_PATH == target:
            return target
        target.parent.mkdir(parents=True, exist_ok=True)
        mode = "w" if (target.exists() and target.stat().st_size > _SIGNAL_FILE_MAX) else "a"
        fh = open(target, mode, encoding="utf-8")       # noqa: SIM115 — must stay open
        os.chmod(target, 0o600)
        faulthandler.register(sig, file=fh, all_threads=True, chain=False)
        old = _SIGNAL_FILE
        _SIGNAL_FILE, _SIGNAL_PATH = fh, target
        if old is not None:
            old.close()
        LOG.info("thread stack dump: kill -USR1 %d → %s", os.getpid(), target)
        return target
    except Exception as e:  # noqa: BLE001 — a diagnostic never blocks the boot
        LOG.warning("thread stack dump on SIGUSR1 not installed: %s", type(e).__name__)
        return None


def uninstall_signal_dump() -> None:
    """For tests: unregister the handler and close the file."""
    global _SIGNAL_FILE, _SIGNAL_PATH
    sig = getattr(signal, "SIGUSR1", None)
    if sig is not None:
        try:
            faulthandler.unregister(sig)
        except Exception:  # noqa: BLE001
            pass
    if _SIGNAL_FILE is not None:
        _SIGNAL_FILE.close()
    _SIGNAL_FILE = _SIGNAL_PATH = None


def signal_dump_installed() -> bool:
    return _SIGNAL_PATH is not None


def signal_dump_tail(lines: int = SIGNAL_TAIL_LINES) -> dict:
    """The last `lines` lines of the SIGUSR1 file, redacted."""
    p = _SIGNAL_PATH
    if p is None:
        return {"installed": False, "lines": []}
    try:
        rows = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        rows = []
    return {"installed": True, "file": p.name,
            "lines": [_redact(r) for r in rows[-lines:]] if lines > 0 else []}


# ── The stall sampler ────────────────────────────────────────────────────────

_LOOP_THREAD_IDENT: int | None = None
_BEAT = 0.0
_LAST_STALL: dict | None = None
_LOCK = threading.Lock()


def heartbeat() -> None:
    """Called on the event loop by `inflight.watch` every round: the loop is
    alive now. Also records which thread is the loop's."""
    global _BEAT, _LOOP_THREAD_IDENT
    _BEAT = time.monotonic()
    _LOOP_THREAD_IDENT = threading.get_ident()


def last_stall() -> dict | None:
    with _LOCK:
        return dict(_LAST_STALL) if _LAST_STALL else None


def compact_sample() -> list[dict]:
    """The loop thread plus up to `COMPACT_THREADS` threads that are not
    parked, `COMPACT_FRAMES` innermost frames each."""
    rows = threads(limit=COMPACT_FRAMES)
    keep = [r for r in rows if r["loop"]]
    keep += [r for r in rows if not r["loop"] and not r["idle"]][:COMPACT_THREADS]
    return [{"name": r["name"], "loop": r["loop"], "cpu_s": r["cpu_s"],
             "frames": [f"{f['file']}:{f['line']} {f['func']}" for f in r["frames"]]}
            for r in keep]


def sample_stall(blocked_s: float) -> dict:
    """Take, keep and log the compact sample of a stall in progress."""
    global _LAST_STALL
    sample = {"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "blocked_s": round(blocked_s, 1), "threads": compact_sample()}
    with _LOCK:
        _LAST_STALL = sample
    righe = []
    for t in sample["threads"]:
        label = t["name"] + (" (loop)" if t["loop"] else "")
        if t["cpu_s"] is not None:
            label += f", cpu {t['cpu_s']}s"
        righe.append(f"[{label}] " + " <- ".join(reversed(t["frames"])))
    LOG.warning("event loop blocked for %.1fs — stacks: %s",
                blocked_s, " | ".join(righe) or "no thread")
    return sample


class StallSampler:
    """A daemon thread that samples the stacks while the loop is blocked.

    It is a thread on purpose: a coroutine cannot observe a stall of the loop
    it runs on. If a thread holds the GIL inside C code the sampler waits for
    it too — that case is what SIGUSR1 is for."""

    def __init__(self, threshold_s: float | None = None,
                 repeat_s: float | None = None, poll_s: float = 1.0):
        self.threshold_s = threshold_s if threshold_s is not None else _env_float(
            "CLODIA_STALL_STACKS_S", _DEFAULT_STALL_STACKS_S)
        self.repeat_s = repeat_s if repeat_s is not None else _DEFAULT_REPEAT_S
        self.poll_s = poll_s
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_said = -1e9
        self._sampled_beat = None       # one sample per stall

    def check(self, now: float | None = None) -> dict | None:
        """One round: sample if the loop is blocked past the threshold. Returns
        the sample when it took one."""
        beat = _BEAT
        if not beat or self.threshold_s <= 0:
            return None
        now = time.monotonic() if now is None else now
        blocked = now - beat
        if blocked < self.threshold_s or self._sampled_beat == beat:
            return None
        if now - self._last_said < self.repeat_s:
            return None
        self._sampled_beat, self._last_said = beat, now
        return sample_stall(blocked)

    def _run(self) -> None:
        while not self._stop.wait(self.poll_s):
            try:
                self.check()
            except Exception as e:  # noqa: BLE001 — the measure never breaks the measured
                LOG.debug("stall sampler: %s", type(e).__name__)

    def start(self) -> "StallSampler":
        if self._thread is None and self.threshold_s > 0:
            self._thread = threading.Thread(target=self._run, name="stall-sampler",
                                            daemon=True)
            self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()


def reset() -> None:
    """For tests."""
    global _BEAT, _LAST_STALL, _LOOP_THREAD_IDENT
    _BEAT, _LAST_STALL, _LOOP_THREAD_IDENT = 0.0, None, None


# ── The full dump ────────────────────────────────────────────────────────────

def dump() -> dict:
    """Everything the route returns. Call it on the event loop: the asyncio
    tasks are read from the running loop."""
    from . import inflight
    return {
        "pid": os.getpid(),
        "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "threads": threads(),
        "tasks": tasks(),
        "inflight": [{k: (_redact(v) if isinstance(v, str) else v) for k, v in r.items()}
                     for r in inflight.snapshot()],
        "offload_pool": inflight.pool_stats(),
        "last_stall": last_stall(),
        "signal_dump": signal_dump_tail(),
    }

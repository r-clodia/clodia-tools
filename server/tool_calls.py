"""Per-call timeout and per-verb telemetry of the gateway's tool calls
(clodia-platform#550).

## Why it exists

15 Oct 2026, ~18:32–18:35, SEAL-2/earnext: four `topic.*` calls of
`messaggero` hung on the gateway, the last one 72 s before the turn ran out,
and the 180 s turn budget was gone with nothing in the channel. Nothing on
the gateway's side said which call was slow, how slow, or whether the
gateway was slow or dead: there was no timeout per tool call, so one call
that never answered consumed the whole turn, and no telemetry an operator
could read.

## The timeout

Every call gets a deadline (`timeout_for`): `DEFAULT_TIMEOUT_S` unless
something more specific says otherwise. When it expires the call is
cancelled and the agent receives `ERROR: ToolCallTimeout: …` — a clean,
recognisable answer it can act on, while its turn still has budget.

- **What is cancelled.** The dispatch coroutine. A proxied MCP backend's
  session is an async context: cancelling it closes the HTTP stream or
  terminates the stdio process. Work offloaded with `asyncio.to_thread`
  cannot be killed in Python: the caller stops waiting and the result is
  discarded, but the thread runs to its end (and stays visible in
  `inflight`'s offload pool counters). The agent is answered either way.
- **What is NOT counted.** Time spent waiting for a human consent
  (`main._require_gate_consent`) pauses the deadline (`paused()`): a person
  deciding is not a backend hanging, and the gate has its own expiry. The
  per-agent slow-call queue (`slow_calls`) is before the deadline and keeps
  its own limit. Latencies in the telemetry exclude the paused time too.
- **Configuration**, most specific first:
  1. env `CLODIA_TOOL_CALL_TIMEOUTS` — `pattern=seconds` pairs separated by
     commas, e.g. `github=60,topic.open=20,packs.*=900`;
  2. `tool_call_timeouts:` in the gateway config — `default:` and
     `overrides: {pattern: seconds}`;
  3. `call_timeout_s:` on an `mcp_backends` entry (that backend's verbs);
  4. the built-in budgets below for the families that legitimately take long;
  5. env `CLODIA_TOOL_CALL_TIMEOUT_S`, then config `default`, then 120 s.

  A pattern is an exact verb (`topic.open`), a prefix (`packs.*` or
  `packs.`), or a bare backend / family name (`github` = `github.*`); among
  patterns the exact verb wins, then the longest prefix. `0` disables the
  timeout for what it matches.

## The telemetry

In memory, since the process started: per verb and per backend (the verb's
namespace — the MCP backend for a proxied verb, the family for a native
one), the number of calls, ok / errors / denied / timeouts, and latency
p50 / p95 / max over the last `LATENCY_WINDOW` calls. **Names and numbers
only**: no argument, no result, no agent, no channel. A verb the gateway does
not implement is counted under `(unknown)`, so an agent cannot write
arbitrary strings into the table by calling made-up verbs, and the number of
rows stays bounded by the catalogue (`MAX_VERBS`).

Read by admins and the agent-server's service role only:
`GET /internal/diagnostics/tool-calls` (`tool_calls_api`) and the
`tool_calls` block of `runtime.health` for an admin reader.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import math
import os
import threading
import time
from collections import deque
from contextvars import ContextVar
from dataclasses import dataclass, field

LOG = logging.getLogger("clodia-tools.tool_calls")

DEFAULT_TIMEOUT_S = 120.0

#: Families whose calls legitimately take minutes. Generous on purpose: the
#: timeout is there to stop a call that will never answer, not to rush one
#: that is working.
BUILTIN_TIMEOUTS: dict[str, float] = {
    "packs.*": 900.0,             # install/update builds and pulls images
    "mcp.*": 300.0,               # mounting/testing a backend spawns it
    "agents.*": 300.0,            # spawning an agent waits for its runtime
    "eu_corpus.ingest": 900.0,    # PDF parsing + embeddings
    "rag.*": 600.0,               # ingestion
    "image.*": 300.0,             # image generation
    "web.download": 300.0,
    # These re-enter `call_tool`: the inner call has its own deadline, and an
    # outer one would also cut the inner call's consent wait.
    "copybrain.call": 0.0,
    "channel.deliver": 0.0,
}

UNKNOWN = "(unknown)"
OTHER = "(other)"
#: Distinct verbs kept; past this every new one is counted under `(other)`.
MAX_VERBS = 2000
#: Calls per verb the percentiles are computed on.
LATENCY_WINDOW = 512


class ToolCallTimeout(Exception):
    """A tool call did not answer within its budget."""


# ── Configuration ────────────────────────────────────────────────────────────

def _num(v) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if f >= 0 and math.isfinite(f) else None


_ENV_CACHE: tuple[str, dict[str, float]] = ("", {})


def _env_overrides() -> dict[str, float]:
    global _ENV_CACHE
    raw = os.environ.get("CLODIA_TOOL_CALL_TIMEOUTS") or ""
    if raw == _ENV_CACHE[0]:
        return _ENV_CACHE[1]
    out: dict[str, float] = {}
    for part in raw.split(","):
        pat, sep, val = part.partition("=")
        n = _num(val.strip()) if sep else None
        if pat.strip() and n is not None:
            out[pat.strip()] = n
        elif part.strip():
            LOG.warning("CLODIA_TOOL_CALL_TIMEOUTS: ignored entry %r", part.strip()[:80])
    _ENV_CACHE = (raw, out)
    return out


def _config() -> dict:
    try:
        from .whitelist import CONFIG
        sec = CONFIG.get("tool_call_timeouts") or {}
        return sec if isinstance(sec, dict) else {}
    except Exception:  # noqa: BLE001 — no config: the defaults
        return {}


def _config_overrides() -> dict[str, float]:
    raw = _config().get("overrides") or {}
    if not isinstance(raw, dict):
        return {}
    return {str(k): n for k, v in raw.items() if (n := _num(v)) is not None}


def _backend_timeout(verb: str) -> float | None:
    ns = verb.split(".", 1)[0]
    try:
        from .proxy import _backends
        entry = _backends().get(ns)
    except Exception:  # noqa: BLE001
        return None
    return _num((entry or {}).get("call_timeout_s")) if entry else None


def _match(verb: str, table: dict[str, float]) -> float | None:
    """The exact verb, else the longest prefix pattern that covers it."""
    if verb in table:
        return table[verb]
    best, best_len = None, -1
    for pat, secs in table.items():
        prefix = pat[:-1] if pat.endswith("*") else pat
        if not prefix.endswith("."):
            if "." in prefix:
                continue                  # an exact verb that is not this one
            prefix += "."                 # a bare backend / family name
        if verb.startswith(prefix) and len(prefix) > best_len:
            best, best_len = secs, len(prefix)
    return best


def default_timeout() -> float:
    env = _num(os.environ.get("CLODIA_TOOL_CALL_TIMEOUT_S"))
    if env is not None:
        return env
    cfg = _num(_config().get("default"))
    return cfg if cfg is not None else DEFAULT_TIMEOUT_S


def timeout_for(verb: str) -> float:
    """Seconds `verb` may take; `0` = no limit. See the module docstring."""
    verb = str(verb or "")
    for lookup in (lambda: _match(verb, _env_overrides()),
                   lambda: _match(verb, _config_overrides()),
                   lambda: _backend_timeout(verb),
                   lambda: _match(verb, BUILTIN_TIMEOUTS)):
        v = lookup()
        if v is not None:
            return v
    return default_timeout()


# ── The deadline ─────────────────────────────────────────────────────────────

@dataclass
class _Call:
    verb: str
    budget: float
    cm: object = None                   # asyncio.Timeout, None without a limit
    paused_s: float = 0.0


#: The calls in progress in this task, outermost first (a verb that re-enters
#: `call_tool` nests one call inside another).
_CALLS: ContextVar[tuple] = ContextVar("tool_call_deadlines", default=())


@contextlib.asynccontextmanager
async def deadline(verb: str):
    """Run the body under `verb`'s budget. Yields the `_Call` (for the paused
    time). On expiry the body is cancelled and `ToolCallTimeout` raised."""
    call = _Call(verb=verb, budget=timeout_for(verb))
    tok = _CALLS.set(_CALLS.get() + (call,))
    try:
        if not call.budget:
            yield call
            return
        try:
            async with asyncio.timeout(call.budget) as cm:
                call.cm = cm
                yield call
        except TimeoutError:
            # Only our own deadline becomes ToolCallTimeout: `asyncio.timeout`
            # re-raises a TimeoutError of the body unchanged, with `expired()`
            # false.
            if call.cm is not None and call.cm.expired():
                raise ToolCallTimeout(
                    f"'{verb}' did not answer within {call.budget:g}s: the call "
                    "was cancelled. The gateway or the backend is slow or "
                    "unreachable right now — try again later, or with a smaller "
                    "request; do not repeat it in a loop.") from None
            raise
    finally:
        _CALLS.reset(tok)


@contextlib.contextmanager
def paused():
    """Stop the clock of every call in progress in this task (a human is
    deciding a consent), and restart each with the time it had left."""
    calls = [c for c in _CALLS.get() if c.cm is not None]
    if not calls:
        yield
        return
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    left: list[float | None] = []
    for c in calls:
        when = c.cm.when()
        if when is None or c.cm.expired():
            left.append(None)             # already paused (nested) or expired
            continue
        left.append(max(0.0, when - t0))
        try:
            c.cm.reschedule(None)
        except RuntimeError:
            left[-1] = None
    try:
        yield
    finally:
        now = loop.time()
        for c, rem in zip(calls, left):
            if rem is None:
                continue
            c.paused_s += now - t0
            try:
                c.cm.reschedule(now + rem)
            except RuntimeError:          # the call is already unwinding
                pass


# ── Telemetry ────────────────────────────────────────────────────────────────

@dataclass
class _Stat:
    count: int = 0
    ok: int = 0
    errors: int = 0
    denied: int = 0
    timeouts: int = 0
    max_ms: int = 0
    last_timeout_at: int | None = None
    latencies: deque = field(default_factory=lambda: deque(maxlen=LATENCY_WINDOW))

    def add(self, status: str, ms: int, timed_out: bool) -> None:
        self.count += 1
        if status == "ok":
            self.ok += 1
        elif status == "denied":
            self.denied += 1
        else:
            self.errors += 1            # error, conflict, cancelled, timeout
        if timed_out:
            self.timeouts += 1
            self.last_timeout_at = int(time.time())
        if status != "denied":          # a refusal measures the policy, not the backend
            self.latencies.append(ms)
            self.max_ms = max(self.max_ms, ms)

    def view(self) -> dict:
        lat = sorted(self.latencies)
        out = {"count": self.count, "ok": self.ok, "errors": self.errors,
               "denied": self.denied, "timeouts": self.timeouts,
               "p50_ms": _pct(lat, 50), "p95_ms": _pct(lat, 95),
               "max_ms": self.max_ms if lat else None}
        if self.last_timeout_at:
            out["last_timeout_at"] = self.last_timeout_at
        return out


def _pct(sorted_ms: list[int], p: int) -> int | None:
    if not sorted_ms:
        return None
    k = max(0, math.ceil(p / 100 * len(sorted_ms)) - 1)
    return int(sorted_ms[k])


_LOCK = threading.Lock()
_VERBS: dict[str, _Stat] = {}
_BACKENDS: dict[str, _Stat] = {}
_STARTED = int(time.time())


def backend_of(verb: str) -> str:
    """The verb's namespace: the MCP backend of a proxied verb (`github` for
    `github.list_issues`), the family of a native one (`topic`)."""
    return verb.split(".", 1)[0] if "." in verb else verb


def record(verb: str, status: str, duration_s: float, *,
           known: bool = True, timed_out: bool = False) -> None:
    """Count one call. `status` is the outcome class of `main._outcome_of`
    (`ok` | `denied` | `error` | `conflict`) or `cancelled`. Never raises."""
    try:
        key = str(verb) if known else UNKNOWN
        ms = max(0, int(duration_s * 1000))
        with _LOCK:
            if key not in _VERBS and len(_VERBS) >= MAX_VERBS:
                key = OTHER
            _VERBS.setdefault(key, _Stat()).add(status, ms, timed_out)
            bkey = backend_of(key) if key not in (UNKNOWN, OTHER) else key
            if bkey not in _BACKENDS and len(_BACKENDS) >= MAX_VERBS:
                bkey = OTHER
            _BACKENDS.setdefault(bkey, _Stat()).add(status, ms, timed_out)
    except Exception as e:  # noqa: BLE001 — telemetry never breaks a call
        LOG.debug("tool_calls: record failed (%s)", type(e).__name__)


def snapshot(*, top: int | None = None) -> dict:
    """The telemetry, names and numbers only. `top` keeps the N verbs with
    most calls (backends are all kept)."""
    with _LOCK:
        verbs = {k: v.view() for k, v in _VERBS.items()}
        backends = {k: v.view() for k, v in _BACKENDS.items()}
    order = sorted(verbs, key=lambda k: (-verbs[k]["count"], k))
    if top is not None:
        order = order[:max(0, int(top))]
    return {
        "since": _STARTED,
        "timeouts": {"default_s": default_timeout(),
                     "overrides": {**BUILTIN_TIMEOUTS, **_config_overrides(),
                                   **_env_overrides()}},
        "totals": {"count": sum(v["count"] for v in verbs.values()),
                   "errors": sum(v["errors"] for v in verbs.values()),
                   "timeouts": sum(v["timeouts"] for v in verbs.values())},
        "backends": {k: backends[k] for k in sorted(backends)},
        "verbs": {k: verbs[k] for k in order},
    }


def reset() -> None:
    """Tests only."""
    global _ENV_CACHE
    with _LOCK:
        _VERBS.clear()
        _BACKENDS.clear()
    _ENV_CACHE = ("", {})

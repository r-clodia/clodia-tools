"""egress_proxy_api — what the agents' egress proxy saw, on the audit trail
(clodia-platform#463).

The proxy (clodia-platform `docker/egress/`) is the only route out of the agent
container. HTTPS goes through it as a CONNECT tunnel, so it sees `host:port`
and never a header inside the tunnel: a trace id cannot reach it the way it
reaches the gateway. It reaches it in the proxy CREDENTIALS instead. The
agent-server gives every spawn a proxy URL `http://<spawn>:<tag>@egress-proxy`,
with `tag = HMAC(orchestrator secret, spawn)` (`audit.trace.egress_tag`), and
the clients send them on the CONNECT as `Proxy-Authorization`.

For each request the proxy calls `POST /internal/egress/record` with the spawn
and tag it received. The gateway checks the tag, takes the trace of the spawn's
current turn (announced by `turn.start`, #433) and records `egress.connect`
under that trace, hung under the turn span — the same trace id as every
`tool.call` of the turn. The answer gives the proxy the trace id and the event
id to write in its own log, so the two records name each other.

What the proxy sends is its observation, and the gateway records it as such
(`actor.source = "egress-proxy"`). Attribution is `verified` only when the tag
matches: a request with no credentials, or with a tag that does not match, is
recorded without a spawn, never with the one it claims.

Authentication: `CLODIA_EGRESS_PROXY_SECRET` in `X-Egress-Proxy-Secret` —
deliberately NOT the orchestrator secret, which mints identities and has no
business in the proxy container. Unset = the route refuses (fail-closed).
The tag itself never enters the trail or a log.

Denials are coalesced. A spawn that retries a refused destination in a loop
would otherwise append one signed event per attempt to the chain. The first
denial of a `(source, host, port, method, reason)` in a window of
`CLODIA_EGRESS_DENY_WINDOW_S` seconds (default 60) is recorded as usual; the
repeats in that window are counted, and when the window is over they become
ONE `egress.connect` event with `decision.count` and `decision.coalesced`,
pointing at the first (`decision.first_event_id`). A source — a verified
spawn, or "unattributed" — has at most `CLODIA_EGRESS_DENY_BURST` distinct
denied destinations recorded per window (default 20); beyond that, its
denials are counted into a single `*` summary, so varying the host does not
get around the coalescing either. Windows are closed lazily, on the next
report (the proxy reports every request, so that is soon). Allowed requests
are never coalesced.
"""
from __future__ import annotations

import asyncio
import os
import re
import threading
import time

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import audit
from .audit import trace

#: Matched with `fullmatch`: under `match`, `$` also accepts a trailing "\n".
_HOST = re.compile(r"[A-Za-z0-9._:\[\]-]{1,253}")
_METHODS = frozenset({"CONNECT", "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE",
                      "OPTIONS"})
#: Why the proxy refused, as a class. Free text would be a channel.
_REASONS = frozenset({"filtered", "port", "address", "bad_request", "upstream_error",
                      "busy"})


def _authorized(request: Request) -> bool:
    expected = (os.environ.get("CLODIA_EGRESS_PROXY_SECRET") or "").strip()
    if not expected:
        return False  # fail-closed
    got = (request.headers.get("x-egress-proxy-secret") or "").strip()
    return trace.secret_equal(got, expected)   # never raises on non-ASCII


def _seed(spawn: str) -> str:
    head, _, tail = spawn.rpartition("-")
    return head if head and tail.isdigit() else spawn


def record(body: dict) -> dict:
    """Record one proxy observation; return what the proxy writes in its log."""
    host = str(body.get("host") or "")
    if not _HOST.fullmatch(host):
        raise ValueError("host is not a host name or address")
    try:
        port = int(body.get("port"))
    except (TypeError, ValueError):
        raise ValueError("port must be an integer") from None
    if not 0 < port < 65536:
        raise ValueError("port out of range")
    method = str(body.get("method") or "").upper()
    if method not in _METHODS:
        raise ValueError("unknown method")
    allowed = body.get("allowed") is True
    reason = body.get("reason")
    reason = reason if reason in _REASONS else (None if allowed else "filtered")

    spawn = body.get("spawn")
    spawn = spawn if isinstance(spawn, str) and trace.valid_spawn_label(spawn) else None
    if spawn is None:
        attribution = "none"
    elif trace.verify_egress(spawn, body.get("tag")):
        attribution = "verified"
    else:
        attribution, spawn = "unverified", None
    cur = trace.current(spawn) if spawn else None

    _denials.sweep()               # windows close on ANY report, allowed ones too
    if not allowed:
        key = (spawn, host, port, method, reason)
        repeat, first_id = _denials.admit(key, cur, spawn, attribution)
        if repeat:                 # inside the window: counted, not recorded
            return {"recorded": False, "coalesced": True, "event_id": first_id,
                    "trace_id": cur[0] if cur else None,
                    "span_id": cur[1] if cur else None,
                    "spawn": spawn, "attribution": attribution}

    rec = _emit(host, port, method, allowed, reason, spawn, attribution, cur)
    if not allowed:
        _denials.recorded((spawn, host, port, method, reason), (rec or {}).get("event_id"))
    return {"recorded": bool(rec), "event_id": (rec or {}).get("event_id"),
            "trace_id": cur[0] if cur else None,
            "span_id": cur[1] if cur else None,
            "spawn": spawn, "attribution": attribution}


def _emit(host, port, method, allowed, reason, spawn, attribution, cur,
          extra_decision: dict | None = None) -> dict | None:
    return audit.emit(
        "egress.connect", identity="explicit",
        action="allow" if allowed else "deny", resource=f"{host}:{port}",
        trace_id=cur[0] if cur else None, parent_span_id=cur[1] if cur else None,
        actor={"type": "service", "id": "egress-proxy", "source": "egress-proxy"},
        agent={"seed": _seed(spawn), "spawn": spawn} if spawn else None,
        tool={"name": "egress-proxy", "destination": host, "port": port,
              "method": method},
        decision={"allowed": allowed, "reason": reason, **(extra_decision or {})},
        security={"attribution": attribution})


# ── coalescing of denials ─────────────────────────────────────────────────────
def _window_s() -> float:
    try:
        return max(0.0, float(os.environ.get("CLODIA_EGRESS_DENY_WINDOW_S", "60")))
    except ValueError:
        return 60.0


def _burst() -> int:
    try:
        return max(1, int(os.environ.get("CLODIA_EGRESS_DENY_BURST", "20")))
    except ValueError:
        return 20


_OVERFLOW = ("*", 0, "*", None)   # host, port, method, reason of a source's overflow bucket


class _Denials:
    """Per-window counters of denied requests. `admit` answers whether a
    denial is a repeat (then it is only counted); closed windows with repeats
    are turned into one summary event each."""

    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.lock = threading.Lock()
        #: key -> {"start", "count", "event_id", "cur", "attribution"}
        self.open: dict[tuple, dict] = {}

    def _expired(self, now: float, window: float) -> list[tuple[tuple, dict]]:
        out = [(k, v) for k, v in self.open.items() if now - v["start"] >= window]
        for k, _ in out:
            del self.open[k]
        return out

    def admit(self, key: tuple, cur, spawn, attribution) -> tuple[bool, str | None]:
        """`(False, None)`: record this denial as an event. `(True, id)`: it
        is a repeat — counted — of the event `id` (None for an overflow
        bucket, or while the first one is being written)."""
        now, window = self.clock(), _window_s()
        with self.lock:
            closed = self._expired(now, window)
            ent = self.open.get(key)
            if ent is None and window > 0:
                source = key[0]
                distinct = sum(1 for k in self.open if k[0] == source and k[1:] != _OVERFLOW)
                if distinct >= _burst():
                    key = (source, *_OVERFLOW)
                    ent = self.open.setdefault(key, {"start": now, "count": 0, "event_id": None,
                                                     "cur": cur, "attribution": attribution})
            if ent is not None:
                ent["count"] += 1
                hit = (True, ent["event_id"])
            else:
                hit = (False, None)
                if window > 0:
                    # a placeholder until `recorded` gives the event id
                    self.open[key] = {"start": now, "count": 1, "event_id": None,
                                      "cur": cur, "attribution": attribution}
        self._summarise(closed, window)
        return hit

    def recorded(self, key: tuple, event_id: str | None) -> None:
        with self.lock:
            ent = self.open.get(key)
            if ent is not None and ent["event_id"] is None:
                ent["event_id"] = event_id

    def sweep(self) -> None:
        """Summarise the windows that are over."""
        now, window = self.clock(), _window_s()
        with self.lock:
            closed = self._expired(now, window)
        self._summarise(closed, window)

    def flush(self) -> None:
        """Close every window now (tests, shutdown)."""
        with self.lock:
            closed, self.open = list(self.open.items()), {}
        self._summarise(closed, _window_s())

    def _summarise(self, closed, window: float) -> None:
        for (spawn, host, port, method, reason), ent in closed:
            overflow = (host, port, method, reason) == _OVERFLOW
            repeats = ent["count"] if overflow else ent["count"] - 1
            if repeats <= 0:
                continue
            extra = {"coalesced": True, "count": repeats, "window_s": window}
            if ent["event_id"]:
                extra["first_event_id"] = ent["event_id"]
            _emit(host, port, method, False, "rate_limited" if overflow else reason,
                  spawn, ent["attribution"], ent["cur"], extra)


_denials = _Denials()


async def ingest(request: Request):
    """POST /internal/egress/record {spawn?, tag?, host, port, method, allowed, reason?}"""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "bad_json"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "bad_json"}, status_code=400)
    try:
        out = await asyncio.to_thread(record, body)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    return JSONResponse(out)


routes = [Route("/internal/egress/record", ingest, methods=["POST"])]

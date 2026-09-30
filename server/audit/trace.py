"""Turn-level trace correlation (clodia-platform#433).

A Claude Code session gets its MCP bearer once, at start, so a per-turn
`trace_id` cannot travel inside the token. It travels the other way: the
agent-server tells the gateway when a turn starts and ends for a spawn
(`turn.start` / `turn.end` through `/internal/audit/event`), with a W3C
trace id (32 hex) and the turn's span id (16 hex). Every event the gateway
records for that spawn in between — identified by the SIGNED `execution_id`
claim, not by anything the agent says — carries that trace id, and hangs
under the turn span unless it has a closer parent.

A spawn runs one turn at a time, so the mapping is unambiguous. A turn that
never reports its end expires after `TTL_S`, so a crashed agent-server does not
leave a stale trace glued to the next turn.

W3C `traceparent` (clodia-platform#463). A request may also carry a
`traceparent` header: the agent-server puts the turn's on every internal call,
and a runtime with OTel tracing on (Claude Code) puts its own span's on every
MCP call. It is the caller's word, so it never overrides the trace of a spawn's
announced turn: a matching trace gives the event a closer parent span, a
different one is kept as a span LINK — which is how a runtime's OTel span is
joined to the gateway's event. Only a request with no spawn behind it (an
internal call of the agent-server) takes its trace from the header.

Egress attribution (#463). The egress proxy sees `host:port` of a CONNECT and
nothing inside it, so the join to the turn travels in the proxy credentials:
the agent-server gives every spawn `http://<spawn>:<tag>@egress-proxy:8888`,
where `tag` is an HMAC of the spawn under the orchestrator secret. The proxy
reports each request here; the tag proves which spawn made it (a spawn cannot
compute another spawn's tag without the secret, which never reaches it), and
the spawn's current turn gives the trace id.
"""
from __future__ import annotations

import contextvars
import hashlib
import hmac
import os
import re
import threading
import time

TTL_S = 6 * 3600
_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_HEX16 = re.compile(r"^[0-9a-f]{16}$")

_by_spawn: dict[str, tuple[str, str, float]] = {}
_lock = threading.Lock()


def valid_trace_id(t: str | None) -> bool:
    return bool(t and _HEX32.match(t) and t != "0" * 32)


def valid_span_id(s: str | None) -> bool:
    return bool(s and _HEX16.match(s) and s != "0" * 16)


def start(spawn: str, trace_id: str, span_id: str) -> None:
    if not (spawn and valid_trace_id(trace_id) and valid_span_id(span_id)):
        raise ValueError("turn.start needs a spawn, a W3C trace id and a span id")
    with _lock:
        _by_spawn[spawn] = (trace_id, span_id, time.monotonic())


def end(spawn: str, trace_id: str | None = None) -> None:
    with _lock:
        cur = _by_spawn.get(spawn)
        if cur and (trace_id is None or cur[0] == trace_id):
            _by_spawn.pop(spawn, None)


def current(spawn: str | None) -> tuple[str, str] | None:
    if not spawn:
        return None
    with _lock:
        cur = _by_spawn.get(spawn)
        if not cur:
            return None
        if time.monotonic() - cur[2] > TTL_S:
            _by_spawn.pop(spawn, None)
            return None
        return cur[0], cur[1]


# ── W3C traceparent (#463) ────────────────────────────────────────────────────
_TRACEPARENT = re.compile(r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})(-.*)?$")

_REQUEST_PARENT: "contextvars.ContextVar[tuple[str, str] | None]" = contextvars.ContextVar(
    "audit_request_traceparent", default=None)


def parse_traceparent(value: str | None) -> tuple[str, str] | None:
    """`(trace_id, parent_span_id)` of a W3C `traceparent`, or None if malformed.

    Version `ff` is invalid; version `00` must have exactly four fields; a
    higher version may carry more (W3C Trace Context §3.2.4)."""
    m = _TRACEPARENT.match((value or "").strip().lower())
    if not m:
        return None
    version, trace_id, span_id, _flags, rest = m.groups()
    if version == "ff" or (version == "00" and rest):
        return None
    if not (valid_trace_id(trace_id) and valid_span_id(span_id)):
        return None
    return trace_id, span_id


def format_traceparent(trace_id: str, span_id: str, sampled: bool = True) -> str:
    return f"00-{trace_id}-{span_id}-{'01' if sampled else '00'}"


def set_request_parent(parent: tuple[str, str] | None):
    return _REQUEST_PARENT.set(parent)


def reset_request_parent(token) -> None:
    _REQUEST_PARENT.reset(token)


def request_parent() -> tuple[str, str] | None:
    """The `traceparent` of the request being served, if it had a valid one."""
    return _REQUEST_PARENT.get()


class TraceparentMiddleware:
    """Puts the request's `traceparent` where `audit.emit` can read it."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        value = ""
        for k, v in scope.get("headers") or []:
            if k.decode("latin-1").lower() == "traceparent":
                value = v.decode("latin-1")[:128]
                break
        tok = set_request_parent(parse_traceparent(value))
        try:
            await self.app(scope, receive, send)
        finally:
            reset_request_parent(tok)


# ── egress attribution (#463) ─────────────────────────────────────────────────
#: A spawn label as the agent-server writes it into the proxy URL userinfo.
_SPAWN_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")
_EGRESS_DOMAIN = b"clodia-egress-attribution/v1|"


def valid_spawn_label(spawn: str | None) -> bool:
    return bool(spawn and _SPAWN_LABEL.match(spawn))


def egress_tag(spawn: str, secret: str | None = None) -> str | None:
    """The proxy credential of `spawn`: HMAC-SHA256 under the orchestrator
    secret, 32 hex. None without a secret (dev): nothing can be proved then."""
    key = (secret if secret is not None
           else os.environ.get("CLODIA_ORCHESTRATOR_SECRET") or "").strip()
    if not key or not valid_spawn_label(spawn):
        return None
    mac = hmac.new(key.encode("utf-8"), _EGRESS_DOMAIN + spawn.encode("utf-8"),
                   hashlib.sha256)
    return mac.hexdigest()[:32]


def verify_egress(spawn: str | None, tag: str | None) -> bool:
    want = egress_tag(spawn or "")
    return bool(want and tag) and hmac.compare_digest(want, str(tag).strip().lower())

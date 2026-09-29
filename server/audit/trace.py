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
"""
from __future__ import annotations

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

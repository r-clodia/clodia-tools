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
"""
from __future__ import annotations

import asyncio
import hmac
import os
import re

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import audit
from .audit import trace

_HOST = re.compile(r"^[A-Za-z0-9._:\[\]-]{1,253}$")
_METHODS = frozenset({"CONNECT", "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE",
                      "OPTIONS"})
#: Why the proxy refused, as a class. Free text would be a channel.
_REASONS = frozenset({"filtered", "port", "bad_request", "upstream_error", "busy"})


def _authorized(request: Request) -> bool:
    expected = (os.environ.get("CLODIA_EGRESS_PROXY_SECRET") or "").strip()
    if not expected:
        return False  # fail-closed
    got = (request.headers.get("x-egress-proxy-secret") or "").strip()
    return bool(got) and hmac.compare_digest(got, expected)


def _seed(spawn: str) -> str:
    head, _, tail = spawn.rpartition("-")
    return head if head and tail.isdigit() else spawn


def record(body: dict) -> dict:
    """Record one proxy observation; return what the proxy writes in its log."""
    host = str(body.get("host") or "")
    if not _HOST.match(host):
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

    rec = audit.emit(
        "egress.connect", identity="explicit",
        action="allow" if allowed else "deny", resource=f"{host}:{port}",
        trace_id=cur[0] if cur else None, parent_span_id=cur[1] if cur else None,
        actor={"type": "service", "id": "egress-proxy", "source": "egress-proxy"},
        agent={"seed": _seed(spawn), "spawn": spawn} if spawn else None,
        tool={"name": "egress-proxy", "destination": host, "port": port,
              "method": method},
        decision={"allowed": allowed, "reason": reason},
        security={"attribution": attribution})
    return {"recorded": bool(rec), "event_id": (rec or {}).get("event_id"),
            "trace_id": cur[0] if cur else None,
            "span_id": cur[1] if cur else None,
            "spawn": spawn, "attribution": attribution}


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

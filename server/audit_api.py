"""audit_api — health and checkpoint of the audit trail (clodia-platform#431).

Server-to-server only, authenticated like `egress_api`: the
`CLODIA_ORCHESTRATOR_SECRET` in `X-Orchestrator-Secret`. Not reachable from a
spawn. It returns the STATE of the trail (counts, head, checkpoints,
exporters), never events: reading the trail is its own feature (#447), with
its own access rule and its own audit event.
"""
from __future__ import annotations

import asyncio
import hmac
import os

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import audit


def _authorized(request: Request) -> bool:
    expected = (os.environ.get("CLODIA_ORCHESTRATOR_SECRET") or "").strip()
    if not expected:
        return False  # fail-closed
    got = (request.headers.get("x-orchestrator-secret") or "").strip()
    return bool(got) and hmac.compare_digest(got, expected)


async def status(request: Request):
    """GET /internal/audit/status"""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return JSONResponse(await asyncio.to_thread(audit.status))


async def checkpoint(request: Request):
    """POST /internal/audit/checkpoint — sign and export a checkpoint now."""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    res = await asyncio.to_thread(audit.checkpoint_now)
    if res is None:
        return JSONResponse({"created": False, "reason": "no new events since the last checkpoint"})
    cp = res["checkpoint"]
    return JSONResponse({"created": True, "seq": cp["seq"], "exports": res["exports"]})


routes = [
    Route("/internal/audit/status", status, methods=["GET"]),
    Route("/internal/audit/checkpoint", checkpoint, methods=["POST"]),
]

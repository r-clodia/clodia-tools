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


async def evidence(request: Request):
    """GET /internal/audit/evidence?hash=&tier=&reader=&clearance=

    The content behind a hash of the trail. The caller (clodia-logic) has
    authenticated the human reader and passes their id and clearance; the
    gateway enforces clearance ≥ tier and records the read — reading evidence
    is itself an event (#425 §1.6)."""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from starlette.responses import Response
    from .audit import evidence as ev
    q = request.query_params
    h, tier = q.get("hash", ""), q.get("tier", "")
    reader, clearance = q.get("reader", ""), q.get("clearance", "")
    if not (h and tier and reader and clearance):
        return JSONResponse({"error": "hash, tier, reader and clearance are required"},
                            status_code=400)
    if not ev.valid_clearance(clearance):
        # An unknown clearance is not "the highest": it is no clearance.
        return JSONResponse({"error": "clearance must be a SEAL tier"}, status_code=400)
    outcome = "denied"
    try:
        data = await asyncio.to_thread(ev.fetch, h, tier, clearance)
        outcome = "served"
        return Response(content=data, media_type="application/octet-stream")
    except ev.EvidenceDenied:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    except FileNotFoundError as e:
        outcome = "not_found"
        return JSONResponse({"error": "not_found", "detail": str(e)}, status_code=404)
    finally:
        await asyncio.to_thread(
            audit.emit, "audit.evidence_read", identity="explicit", action=outcome,
            resource=h, actor={"type": "human", "id": reader, "clearance": clearance},
            scope={"tier": ev.norm_tier(tier)})


routes = [
    Route("/internal/audit/evidence", evidence, methods=["GET"]),
    Route("/internal/audit/status", status, methods=["GET"]),
    Route("/internal/audit/checkpoint", checkpoint, methods=["POST"]),
]

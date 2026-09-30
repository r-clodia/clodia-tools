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


async def export(request: Request):
    """POST /internal/audit/export {reader, since?, until?, purpose?}

    A signed bundle of the trail, verifiable offline. The caller (clodia-logic)
    has checked that `reader` may export (admin); the export is recorded."""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from datetime import date
    from starlette.responses import Response
    from .audit import export as _export
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = {}
    reader = str(body.get("reader") or "").strip()
    if not reader:
        return JSONResponse({"error": "reader is required"}, status_code=400)
    try:
        since = date.fromisoformat(body["since"]) if body.get("since") else None
        until = date.fromisoformat(body["until"]) if body.get("until") else None
    except ValueError:
        return JSONResponse({"error": "since/until must be YYYY-MM-DD"}, status_code=400)
    blob = await asyncio.to_thread(_export.build, audit.store(), reader=reader,
                                   since=since, until=until,
                                   purpose=str(body.get("purpose") or ""))
    return Response(blob, media_type="application/gzip", headers={
        "Content-Disposition": 'attachment; filename="clodia-audit-export.tgz"'})


#: Event types the agent-server may deposit: what only it knows (turns,
#: routing, provider and model, interrupts, its own control plane). It may not
#: forge the gateway's own evidence (tool.*, policy.*, gate.*, flow.*, audit.*).
AGENT_SERVER_TYPES = ("turn.", "model.", "route.", "control.", "human.")


async def ingest(request: Request):
    """POST /internal/audit/event — an event reported by the agent-server.

    Recorded with `actor.source = "agent-server"`: it is the orchestrator's
    word, verified by its secret, not the gateway's own observation — the two
    weigh differently for an auditor (#425 §1.5). `turn.start` / `turn.end`
    also open and close the spawn's trace (#433)."""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from .audit import trace
    try:
        b = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "bad_json"}, status_code=400)
    et = str(b.get("type") or "")
    if not et.startswith(AGENT_SERVER_TYPES):
        return JSONResponse({"error": f"type '{et}' is not the agent-server's to report"},
                            status_code=403)
    spawn = (b.get("agent") or {}).get("spawn")
    if et == "turn.start":
        try:
            trace.start(spawn, b.get("trace_id"), b.get("span_id"))
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=400)
    sections = {k: b[k] for k in ("scope", "agent", "model", "input", "decision",
                                  "authorization", "tool", "result", "provenance",
                                  "security") if isinstance(b.get(k), dict)}
    actor = dict(b.get("actor") or {"type": "service", "id": "agent-server"})
    actor["source"] = "agent-server"
    try:
        rec = await asyncio.to_thread(
            audit.emit, et, identity="explicit", action=b.get("action"),
            resource=b.get("resource"), trace_id=b.get("trace_id"),
            span_id=b.get("span_id"), parent_span_id=b.get("parent_span_id"),
            actor=actor, **sections)
    except audit.RecordError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    finally:
        if et == "turn.end":
            trace.end(spawn, b.get("trace_id"))
    return JSONResponse({"recorded": bool(rec), "event_id": (rec or {}).get("event_id")})


routes = [
    Route("/internal/audit/event", ingest, methods=["POST"]),
    Route("/internal/audit/export", export, methods=["POST"]),
    Route("/internal/audit/evidence", evidence, methods=["GET"]),
    Route("/internal/audit/status", status, methods=["GET"]),
    Route("/internal/audit/checkpoint", checkpoint, methods=["POST"]),
]

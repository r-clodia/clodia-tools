"""Endpoint INTERNO per registrare un agent nella whitelist del gateway.

Serve all'auto-provisioning dei responder confinati (clone per-topic dal backend):
quando il backend crea un'identità confinata per un canale, la registra qui così
la sua sessione MCP può aprirsi (l'auth middleware richiede l'agent in config.yaml).
Auth ckt1 ristretta al principal privilegiato (clodia), come gli altri /internal.
"""
from __future__ import annotations

import logging
import os

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import whitelist
from .pki_verify import verify_session_token

LOG = logging.getLogger("clodia-tools.agents_api")

_PRINCIPALS = {
    p.strip() for p in (os.environ.get("CLODIA_PROVIDER_PRINCIPALS") or "clodia").split(",")
    if p.strip()
}


def _authorize(request: Request):
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    try:
        payload = verify_session_token(token)
    except PermissionError as e:
        LOG.warning("agents_api auth fallita: %s", e)
        return None, JSONResponse({"error": "unauthorized"}, status_code=401)
    agent = str(payload.get("agent") or "")
    if agent not in _PRINCIPALS:
        return None, JSONResponse({"error": "forbidden"}, status_code=403)
    return agent, None


async def register(request: Request):
    """POST /internal/agents/whitelist {agent, allowed_tools?} → upsert config.yaml."""
    _agent, err = _authorize(request)
    if err:
        return err
    body = await request.json()
    name = (body.get("agent") or "").strip()
    if not name:
        return JSONResponse({"error": "agent richiesto"}, status_code=400)
    spec = whitelist.upsert_agent(name, allowed_tools=body.get("allowed_tools"))
    whitelist.reload_config()
    return JSONResponse({"ok": True, "agent": name, "allowed_tools": spec.get("allowed_tools")})


routes = [
    Route("/internal/agents/whitelist", register, methods=["POST"]),
]

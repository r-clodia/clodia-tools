"""Endpoint interni M-gate (sostituisce sudo_api).

Il consenso a un verbo *gated* è un artefatto crittografico: una capability
`ccap1` firmata dalla CA (`cap = gate:<verb>`), coniata dal flusso di
approvazione umano di clodia-logic (che verifica la RBAC dell'approvatore sul
verbo). Qui il gateway: elenca le richieste pending, registra il consenso
verificando la firma CA (`gate.grant`), nega/risolve. Auth ckt1 come gli altri
/internal; la RBAC-per-verbo dell'approvatore è applicata a monte (clodia-logic)
e la firma CA è la prova non falsificabile.
"""
import logging

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import gate
from .pki_verify import verify_session_token

LOG = logging.getLogger("clodia-tools.gate_api")


def _authorize(request: Request):
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    try:
        payload = verify_session_token(token)
    except PermissionError as e:
        LOG.warning("gate_api auth fallita: %s", e)
        return None, JSONResponse({"error": "unauthorized"}, status_code=401)
    principal = str(payload.get("principal") or "")
    if not principal:
        return None, JSONResponse({"error": "forbidden"}, status_code=403)
    return principal, None


async def grant(request: Request):
    """POST /internal/gate/grant {agent, instance, verb, token} — registra il
    consenso (capability ccap1 gate:<verb>). fail-closed se la firma non verifica."""
    principal, err = _authorize(request)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "bad_json"}, status_code=400)
    agent = (body.get("agent") or "").strip()
    instance = (body.get("instance") or "-").strip() or "-"
    verb = (body.get("verb") or "").strip()
    token = body.get("token") or ""
    if not (agent and verb and token):
        return JSONResponse({"error": "agent/verb/token richiesti"}, status_code=400)
    try:
        res = gate.grant(agent, instance, verb, token)
    except PermissionError as e:
        LOG.warning("gate grant rifiutato %s@%s:%s — %s", agent, instance, verb, e)
        return JSONResponse({"error": "bad_capability", "detail": str(e)}, status_code=400)
    gate.resolve_request(agent, instance, verb)
    LOG.info("GATE consenso %s@%s:%s da %s (%ss)", agent, instance, verb,
             principal, res.get("expires_in_s"))
    return JSONResponse({"ok": True, **res})


async def deny(request: Request):
    """POST /internal/gate/deny {agent, instance, verb} — nega la richiesta."""
    principal, err = _authorize(request)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "bad_json"}, status_code=400)
    agent = (body.get("agent") or "").strip()
    instance = (body.get("instance") or "-").strip() or "-"
    verb = (body.get("verb") or "").strip()
    removed = gate.resolve_request(agent, instance, verb)
    LOG.info("GATE richiesta NEGATA %s@%s:%s da %s: %s", agent, instance, verb,
             principal, removed)
    return JSONResponse({"ok": True, "denied": removed})


async def pending(request: Request):
    """GET /internal/gate/pending — richieste di gate in attesa (per il popup)."""
    _principal, err = _authorize(request)
    if err:
        return err
    return JSONResponse({"requests": gate.list_requests(), "gated": gate.gated_verbs_spec()})


routes = [
    Route("/internal/gate/grant", grant, methods=["POST"]),
    Route("/internal/gate/deny", deny, methods=["POST"]),
    Route("/internal/gate/pending", pending, methods=["GET"]),
]

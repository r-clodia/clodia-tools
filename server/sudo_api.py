"""Endpoint interni per la gestione dei grant SUDO (M-sudo).

Un APPROVATORE umano (admin) concede sudo a un SUDOER (clodia/ophelia/sysadmin)
per una finestra time-boxed (e, quando arriverà l'id-istanza, instance-boxed).
Gating: il `principal` umano del token ckt1 dev'essere un approvatore
(`sudo.is_approver`). Auth ckt1 come gli altri /internal.

Nota: l'escalation-request lato agente (popup admin) e l'instance-boxing pieno
sono fasi successive; qui c'è il meccanismo di grant/revoke/status che rende
utilizzabili le operazioni già sudo-gated (cross-topic, add_participant).
"""
import logging

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import sudo
from .pki_verify import verify_session_token

LOG = logging.getLogger("clodia-tools.sudo_api")


def _authorize_approver(request: Request):
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    try:
        payload = verify_session_token(token)
    except PermissionError as e:
        LOG.warning("sudo_api auth fallita: %s", e)
        return None, JSONResponse({"error": "unauthorized"}, status_code=401)
    principal = str(payload.get("principal") or "")
    if not sudo.is_approver(principal):
        return None, JSONResponse(
            {"error": "forbidden", "detail": "solo un admin approvatore può concedere sudo"},
            status_code=403)
    return principal, None


async def grant(request: Request):
    """POST /internal/sudo/grant {agent, instance?, minutes?} — concede sudo."""
    approver, err = _authorize_approver(request)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    agent = (body.get("agent") or "").strip()
    if not agent:
        return JSONResponse({"error": "agent richiesto"}, status_code=400)
    if not sudo.is_sudoer(agent):
        return JSONResponse(
            {"error": "not_sudoer", "detail": f"'{agent}' non è nel gruppo sudoer"},
            status_code=400)
    instance = (body.get("instance") or "-").strip() or "-"
    minutes = body.get("minutes", 15)
    res = sudo.grant(agent, instance, minutes, by=approver, scope=body.get("scope"))
    sudo.resolve_request(agent, instance)  # l'approvazione consuma la richiesta pending
    LOG.info("SUDO concesso a %s@%s per %ss da %s", agent, instance,
             res.get("expires_in_s"), approver)
    return JSONResponse({"ok": True, **res})


async def deny(request: Request):
    """POST /internal/sudo/deny {agent, instance?} — nega una richiesta pending."""
    approver, err = _authorize_approver(request)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    agent = (body.get("agent") or "").strip()
    instance = (body.get("instance") or "-").strip() or "-"
    removed = sudo.resolve_request(agent, instance)
    LOG.info("SUDO richiesta NEGATA %s@%s da %s: %s", agent, instance, approver, removed)
    return JSONResponse({"ok": True, "denied": removed})


async def pending(request: Request):
    """GET /internal/sudo/pending — richieste di escalation in attesa (per il popup owner)."""
    approver, err = _authorize_approver(request)
    if err:
        return err
    return JSONResponse({"requests": sudo.list_requests()})


async def revoke(request: Request):
    """POST /internal/sudo/revoke {agent, instance?} — revoca sudo."""
    approver, err = _authorize_approver(request)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    agent = (body.get("agent") or "").strip()
    instance = (body.get("instance") or "-").strip() or "-"
    removed = sudo.revoke(agent, instance)
    LOG.info("SUDO revocato %s@%s da %s: %s", agent, instance, approver, removed)
    return JSONResponse({"ok": True, "revoked": removed})


async def status(request: Request):
    """GET /internal/sudo/status?agent= — grant sudo attivi (per la UI/audit)."""
    approver, err = _authorize_approver(request)
    if err:
        return err
    agent = request.query_params.get("agent")
    return JSONResponse({"grants": sudo.status(agent), "sudoers": sorted(sudo.SUDOERS)})


routes = [
    Route("/internal/sudo/grant", grant, methods=["POST"]),
    Route("/internal/sudo/deny", deny, methods=["POST"]),
    Route("/internal/sudo/revoke", revoke, methods=["POST"]),
    Route("/internal/sudo/status", status, methods=["GET"]),
    Route("/internal/sudo/pending", pending, methods=["GET"]),
]

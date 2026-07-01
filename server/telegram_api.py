"""Endpoint INTERNI Telegram per il channel-runner server-side (clodia-logic).

Come `/internal/providers` e `/internal/topics`: auth ckt1 ristretta a un
principal privilegiato (`clodia`), NON un grant MCP per-agente. Il channel-runner
del backend chiama questi endpoint per drenare/inviare messaggi del binding
chat↔topic senza passare dal modello di lease per-agente (è l'unico consumer di
quei chat). Il token del bot vive nel vault e non transita mai da qui verso il
chiamante.
"""
from __future__ import annotations

import logging
import os

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from .pki_verify import verify_session_token
from .tools import telegram as tg

LOG = logging.getLogger("clodia-tools.telegram_api")

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
        LOG.warning("telegram_api auth fallita: %s", e)
        return None, JSONResponse({"error": "unauthorized"}, status_code=401)
    agent = str(payload.get("agent") or "")
    if agent not in _PRINCIPALS:
        LOG.warning("telegram_api: principal '%s' non autorizzato", agent)
        return None, JSONResponse({"error": "forbidden"}, status_code=403)
    return agent, None


async def updates(request: Request):
    """POST /internal/telegram/updates {chat_id} → drena la coda di quella chat."""
    _agent, err = _authorize(request)
    if err:
        return err
    body = await request.json()
    chat_id = str(body.get("chat_id") or "").strip()
    if not chat_id:
        return JSONResponse({"error": "chat_id richiesto"}, status_code=400)
    try:
        return JSONResponse(tg.drain_internal(chat_id))
    except Exception as e:  # noqa: BLE001
        LOG.warning("telegram updates errore: %s", e)
        return JSONResponse({"error": str(e)[:200]}, status_code=502)


async def send(request: Request):
    """POST /internal/telegram/send {chat_id, text} → invia al gruppo."""
    _agent, err = _authorize(request)
    if err:
        return err
    body = await request.json()
    chat_id = str(body.get("chat_id") or "").strip()
    text = body.get("text") or ""
    if not chat_id:
        return JSONResponse({"error": "chat_id richiesto"}, status_code=400)
    try:
        return JSONResponse(tg.send_internal(chat_id, text))
    except Exception as e:  # noqa: BLE001
        LOG.warning("telegram send errore: %s", e)
        return JSONResponse({"error": str(e)[:200]}, status_code=502)


routes = [
    Route("/internal/telegram/updates", updates, methods=["POST"]),
    Route("/internal/telegram/send", send, methods=["POST"]),
]

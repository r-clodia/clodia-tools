"""Endpoint INTERNI Telegram per il channel-runner server-side (clodia-logic).

Come `/internal/providers` e `/internal/topics`: auth ckt1 ristretta a un
principal privilegiato (`clodia`), NON un grant MCP per-agente. Il channel-runner
del backend chiama questi endpoint per drenare/inviare messaggi del binding
chat↔topic senza passare dal modello di lease per-agente (è l'unico consumer di
quei chat). Il token del bot vive nel vault e non transita mai da qui verso il
chiamante.
"""
from __future__ import annotations

import asyncio
import logging

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import internal_auth
from .tools import telegram as tg

LOG = logging.getLogger("clodia-tools.telegram_api")


def _authorize(request: Request):
    """Regola unica delle rotte interne: `internal_auth.authorize` applica il
    principal privilegiato **e** ciò che qui mancava — revoca, tetto
    `scoped_tools` e rifiuto delle sessioni on-behalf. Questa è la porta di un
    processo (il runner), non di un flusso umano (clodia-platform#261)."""
    payload, err = internal_auth.authorize(request, log=LOG)
    return (str(payload.get("agent")) if payload else None), err


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


async def poll(request: Request):
    """POST /internal/telegram/poll {timeout} → LONG-POLL: blocca fino a che arriva
    un messaggio (o scade timeout) e ritorna i messaggi nuovi di tutte le chat.
    Il relay del backend lo chiama in loop → latenza quasi zero."""
    _agent, err = _authorize(request)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = {}
    timeout = max(1, min(50, int(body.get("timeout", 25))))
    try:
        # getUpdates blocca `timeout`s → in un thread per non congelare l'event loop.
        msgs = await asyncio.to_thread(tg.poll_updates, timeout)
        return JSONResponse({"messages": msgs, "count": len(msgs)})
    except Exception as e:  # noqa: BLE001
        LOG.warning("telegram poll errore: %s", e)
        return JSONResponse({"error": str(e)[:200]}, status_code=502)


async def download(request: Request):
    """POST /internal/telegram/download {file_id} → scarica un file da Telegram e
    ritorna {content_b64, size}. Il relay lo salva nello storage del topic."""
    _agent, err = _authorize(request)
    if err:
        return err
    body = await request.json()
    file_id = str(body.get("file_id") or "").strip()
    if not file_id:
        return JSONResponse({"error": "file_id richiesto"}, status_code=400)
    try:
        return JSONResponse(await asyncio.to_thread(tg.download_file, file_id))
    except Exception as e:  # noqa: BLE001
        LOG.warning("telegram download errore: %s", e)
        return JSONResponse({"error": str(e)[:200]}, status_code=502)


routes = [
    Route("/internal/telegram/updates", updates, methods=["POST"]),
    Route("/internal/telegram/send", send, methods=["POST"]),
    Route("/internal/telegram/poll", poll, methods=["POST"]),
    Route("/internal/telegram/download", download, methods=["POST"]),
]

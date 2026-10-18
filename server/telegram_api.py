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

from . import instance_profile
from . import internal_auth
from . import proxy
from .tools import telegram as tg

LOG = logging.getLogger("clodia-tools.telegram_api")

#: Il connettore di queste rotte. In posizione `pack` l'implementazione sta nel
#: backend MCP omonimo e queste rotte diventano un RINVIO: non un secondo
#: percorso, un unico percorso con due implementazioni dietro.
CONNECTOR = "telegram"


def _nativo() -> bool:
    try:
        return instance_profile.connector_is_native(CONNECTOR)
    except Exception:  # noqa: BLE001 — profilo illeggibile: com'era ieri
        return True


async def _pack(verbo: str, args: dict, *, claims: dict | None = None,
                token: str | None = None) -> dict:
    """Chiama il verbo del backend del pack e ne ritorna il JSON.

    Non passa da `call_tool`: questa è già una porta privilegiata
    (`internal_auth`), e farla rientrare dal PDP per-agente chiederebbe un
    grant a un processo che non è un agente. Soprattutto: `telegram.updates`
    NON è un verbo d'agente — Telegram ammette un solo consumer `getUpdates`
    per bot, e questa rotta è quel consumer.
    """
    import json as _json

    # comms-pack ≥ 2.1.0 runs Telegram as a GATEWAY COMPONENT (#558/#522):
    # the relay's two internal operations are its services, never agent verbs.
    # Before that version, its MCP backend `telegram`.
    from .components import loader as _components
    _svc = _components.service("comms-pack", f"{CONNECTOR}_{verbo}")
    if _svc is not None:
        return await asyncio.to_thread(_svc.handler, dict(args))
    # The relay's other operation, `send` (a reply into the bound group), is
    # the component's agent VERB: called here as the gateway, it is the same
    # code the backend ran for it — never through `call_tool`, as before
    # (this door is `internal_auth`, not an agent's).
    _verb = _components.verb(f"{CONNECTOR}.{verbo}")
    if _verb is not None and _verb.pack == "comms-pack":
        # The handler asks the call's identity (`host.agent()`): it is the
        # authorized internal caller's, set from its verified token as on any
        # internal route — never invented (review of clodia-tools#397).
        def _run():
            from .claims import ClaimsContext
            with ClaimsContext(dict(claims or {}), token or ""):
                return _verb.handler(dict(args))
        return await asyncio.to_thread(_run)

    testo = await proxy.call_proxied(f"{CONNECTOR}.{verbo}", args)
    if str(testo).startswith("ERROR: "):
        raise RuntimeError(str(testo)[len("ERROR: "):][:200])
    try:
        return _json.loads(testo)
    except ValueError:
        raise RuntimeError(f"{CONNECTOR}.{verbo}: risposta non JSON "
                           f"({str(testo)[:120]})") from None


def _intercetta_join(messaggi: list, bot_username) -> list:
    """Consuma i `/start <token>` di un join per link (clodia-platform#549).

    Nel gateway l'intercettazione viveva dentro il ciclo degli update; con
    l'implementazione nel pack quel ciclo è di là, e il join NON si è spostato
    con lui: è control-plane — mette una PROPOSTA in attesa dell'owner, non un
    messaggio da riportare. Quindi si intercetta qui, sull'unica porta da cui
    gli update entrano. Senza, un `/start <token>` arriverebbe nel topic come
    un messaggio qualunque e il bottone del topic non proporrebbe mai il gruppo.
    """
    from .tools import telegram_join as _join

    tenuti = []
    for m in messaggi or []:
        finto = {
            "text": m.get("text") or "",
            "chat": {"id": m.get("chat_id"), "title": m.get("chat_title"),
                     "type": m.get("chat_type")},
            "from": {"username": m.get("from_username"), "id": m.get("from_id")},
        }
        try:
            if _join.intercept(finto, bot_username):
                continue
        except Exception as e:  # noqa: BLE001 — un join rotto non ferma il relay
            LOG.warning("join Telegram non consumato (%s)", e)
        tenuti.append(m)
    return tenuti


def _authorize(request: Request):
    """Regola unica delle rotte interne: `internal_auth.authorize` applica il
    principal privilegiato **e** ciò che qui mancava — revoca, tetto
    `scoped_tools` e rifiuto delle sessioni on-behalf. Questa è la porta di un
    processo (il runner), non di un flusso umano (clodia-platform#261)."""
    payload, err = internal_auth.authorize(request, log=LOG)
    return (str(payload.get("agent")) if payload else None), err


def _verified(request: Request) -> tuple[dict, str]:
    """The (already authorized) caller's claims and token, for a component
    handler that reads the call's identity."""
    payload, _err = internal_auth.authorize(request, log=LOG)
    return dict(payload or {}), internal_auth.bearer(request)


async def updates(request: Request):
    """POST /internal/telegram/updates {chat_id} → drena la coda di quella chat."""
    _agent, err = _authorize(request)
    if err:
        return err
    body = await request.json()
    chat_id = str(body.get("chat_id") or "").strip()
    if not chat_id:
        return JSONResponse({"error": "chat_id richiesto"}, status_code=400)
    if not _nativo():
        # Nessun equivalente nel pack, e nessun chiamante: il relay usa `poll`.
        # Si risponde con il motivo invece di inventare un drenaggio che
        # consumerebbe la coda condivisa di tutte le chat.
        return JSONResponse(
            {"error": "telegram è implementato da un pack su questa istanza: "
                      "il drenaggio per-chat non esiste lì, usa /poll"},
            status_code=501)
    try:
        return JSONResponse(tg.drain_internal(chat_id))
    except Exception as e:  # noqa: BLE001
        LOG.warning("telegram updates errore: %s", e)
        return JSONResponse({"error": str(e)[:200]}, status_code=502)


async def send(request: Request):
    """POST /internal/telegram/send {chat_id, text, thread_id?} → invia al gruppo
    (nel thread del forum, se dato: clodia-platform#548)."""
    _agent, err = _authorize(request)
    if err:
        return err
    body = await request.json()
    chat_id = str(body.get("chat_id") or "").strip()
    text = body.get("text") or ""
    if not chat_id:
        return JSONResponse({"error": "chat_id richiesto"}, status_code=400)
    try:
        if not _nativo():
            args = {"chat_id": chat_id, "text": text}
            if body.get("thread_id") is not None:
                args["thread_id"] = body["thread_id"]
            _claims, _tok = _verified(request)
            return JSONResponse(await _pack("send", args, claims=_claims, token=_tok))
        return JSONResponse(tg.send_internal(chat_id, text, thread_id=body.get("thread_id")))
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
        if not _nativo():
            risposta = await _pack("updates", {"timeout": timeout})
            msgs = _intercetta_join(risposta.get("messages") or [],
                                    risposta.get("bot_username"))
            return JSONResponse({"messages": msgs, "count": len(msgs)})
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
        if not _nativo():
            return JSONResponse(await _pack("download", {"file_id": file_id}))
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

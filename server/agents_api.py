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


async def flow_allow(request: Request):
    """POST /internal/agents/flow-allow → concede le voci di flusso di un pack.

    Un pack può DICHIARARE nel proprio manifest le destinazioni (`egress:`) e le
    fonti (`ingress:`) che considera parte del proprio funzionamento normale. È
    una dichiarazione di **flusso**, non di permessi, e per questo non ha
    equivalenti nei sistemi di plugin: `host_permissions` di un'estensione dice
    «posso toccare questo host»; qui si dice «il contenuto che arriva da qui non
    contamina ciò che potrai fare dopo».

    Per la stessa ragione la dichiarazione **non è fiducia**. I pack arrivano da
    repo di terzi: se `ingress:` diventasse una concessione automatica, l'autore
    del pack deciderebbe cosa non contamina il canale di chi lo installa, e lo
    deciderebbe nella direzione d'errore che non si vede. Quindi due modi:

    - `validate: true` → **non concede nulla**, dice solo cosa sarebbe concesso e
      cosa verrebbe rifiutato. È ciò che l'installazione mostra all'owner.
    - senza → concede, e ogni voce finisce nella lista globale come qualunque
      altra: visibile nelle impostazioni e revocabile una per una.
    """
    _agent, err = _authorize(request)
    if err:
        return err
    body = await request.json()
    validate = bool(body.get("validate"))
    src = str(body.get("source") or "").strip()
    from . import egress
    out: dict = {"validate": validate, "source": src, "granted": [], "refused": []}
    for direction in ("egress", "ingress"):
        for raw in (body.get(direction) or []):
            uri = str(raw).strip()
            try:
                if validate:
                    egress.check_grantable(direction, uri)
                    out["granted"].append({"direction": direction,
                                           "uri": egress.canonical(uri),
                                           "note": egress.admin_note(direction, uri)})
                else:
                    r = egress.allow(direction, uri)
                    r["direction"] = direction
                    out["granted"].append(r)
            except ValueError as e:
                out["refused"].append({"direction": direction, "uri": uri,
                                       "reason": str(e)})
    if not validate and out["granted"]:
        LOG.warning("flusso · %d voci concesse da %s (approvate da un umano)",
                    len(out["granted"]), src or "?")
        whitelist.reload_config()
    return JSONResponse(out)


routes = [
    Route("/internal/agents/whitelist", register, methods=["POST"]),
    Route("/internal/agents/flow-allow", flow_allow, methods=["POST"]),
]

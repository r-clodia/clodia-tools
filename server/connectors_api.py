"""Connettori delegabili (Fase 2) — endpoint interni ckt1 per la webui (owner).

Un connettore = un account email (credenziale `gmail_<account>` nel vault). Un
agent può essere abilitato/disabilitato per-connettore: il grant tocca DUE livelli
- vault-policy.yaml: grant `fetch` sulla credenziale (l'agent può usare quelle creds);
- config.yaml whitelist: il namespace tool `email.*` nella allowed_tools dell'agent.

Così "studio → Dairio sì, Saim no": Dairio ottiene il grant gmail_studio + email.*,
Saim no. I super-agent (clodia/ophelia) bypassano comunque (accesso a tutto).
"""
from __future__ import annotations

import logging
import os

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import vault
from .pki_verify import verify_session_token

LOG = logging.getLogger("clodia-tools.connectors")

_PRINCIPALS = {
    p.strip() for p in (os.environ.get("CLODIA_PROVIDER_PRINCIPALS") or "clodia").split(",")
    if p.strip()
}


def _authorize(request: Request):
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    try:
        payload = verify_session_token(token)
    except PermissionError:
        return None, JSONResponse({"error": "unauthorized"}, status_code=401)
    if str(payload.get("agent") or "") not in _PRINCIPALS:
        return None, JSONResponse({"error": "forbidden"}, status_code=403)
    return payload.get("agent"), None


def _mailboxes() -> list[str]:
    return sorted(n[len("mailbox_"):] for n in vault.store_names() if n.startswith("mailbox_"))


def _cred_for(connector_id: str) -> str | None:
    """Mappa l'id del connettore alla credenziale vault. 'trello' → 'trello';
    un account Gmail → 'gmail_<account>'; una casella → 'mailbox_<account>'."""
    if connector_id == "trello":
        return "trello" if vault.has_credential("trello") else None
    if connector_id in vault.email_connectors():
        return f"gmail_{connector_id}"
    if connector_id in _mailboxes():
        return f"mailbox_{connector_id}"
    return None


def _connectors(agent: str | None) -> list[dict]:
    out = []
    for acct in vault.email_connectors():
        cred = f"gmail_{acct}"
        out.append({
            "id": acct, "type": "email", "credential": cred,
            "granted": bool(agent) and agent in vault.agents_with_grant(cred),
            "agents": vault.agents_with_grant(cred),
        })
    for acct in _mailboxes():
        cred = f"mailbox_{acct}"
        out.append({
            "id": acct, "type": "email", "credential": cred,
            "granted": bool(agent) and agent in vault.agents_with_grant(cred),
            "agents": vault.agents_with_grant(cred),
        })
    if vault.has_credential("trello"):
        out.append({
            "id": "trello", "type": "trello", "credential": "trello",
            "granted": bool(agent) and agent in vault.agents_with_grant("trello"),
            "agents": vault.agents_with_grant("trello"),
        })
    return out


async def list_connectors(request: Request):
    _, err = _authorize(request)
    if err:
        return err
    agent = request.query_params.get("agent") or None
    return JSONResponse({"connectors": _connectors(agent)})


async def grant_connector(request: Request):
    _, err = _authorize(request)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    agent = (body.get("agent") or "").strip()
    account = (body.get("account") or "").strip()
    granted = bool(body.get("granted"))
    if not agent or not account:
        return JSONResponse({"error": "agent e account richiesti"}, status_code=400)
    cred = _cred_for(account)
    if cred is None:
        return JSONResponse({"error": f"connettore '{account}' inesistente"}, status_code=404)
    # Grant SOLO nel vault (montato → persistente). L'accesso ai tool del
    # connettore (email.*, trello.*) è derivato dal grant vault nel gate del
    # gateway (main._connector_allows), così non dipende da config.yaml
    # (baked → effimero al rebuild).
    vault.set_grant(cred, agent, granted)
    return JSONResponse({"agent": agent, "account": account, "granted": granted})


routes = [
    Route("/internal/connectors", list_connectors, methods=["GET"]),
    Route("/internal/connectors/grant", grant_connector, methods=["POST"]),
]

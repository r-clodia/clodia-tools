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

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import internal_auth, vault

LOG = logging.getLogger("clodia-tools.connectors")


def _authorize(request: Request):
    """Regola unica delle rotte interne: `internal_auth.authorize` applica il
    principal privilegiato **e** ciò che qui mancava — revoca, tetto
    `scoped_tools` e rifiuto delle sessioni on-behalf. Questa è la porta di un
    processo (il runner), non di un flusso umano (clodia-platform#261)."""
    payload, err = internal_auth.authorize(request, log=LOG)
    return (payload or {}).get("agent"), err


def _mailboxes() -> list[str]:
    return sorted(n[len("mailbox_"):] for n in vault.store_names() if n.startswith("mailbox_"))


def _google_accounts() -> list[str]:
    """Account Google UNIFICATI (`google_<account>`), che abilitano SIA email.*
    SIA gdrive./gcalendar./gdocs./gsheets. — vedi `_grant_covers` in main.py.

    Perché mancavano. Questa vista enumerava solo `gmail_*` e `mailbox_*`, cioè
    le due forme legacy, mentre il controllo dei permessi riconosce da tempo
    anche `google_*`. Le due metà erano in disaccordo, e il disaccordo aveva un
    costo preciso: su un'istanza con la sola credenziale unificata la sezione
    Integrations risultava VUOTA, quindi un admin non poteva concedere a un
    agente un accesso che il gateway avrebbe accettato. Non un permesso
    mancante: un permesso concedibile e non mostrato."""
    return sorted(n[len("google_"):] for n in vault.store_names()
                  if n.startswith("google_"))


def _cred_for(connector_id: str) -> str | None:
    """Mappa l'id del connettore alla credenziale vault.
    un account Gmail → 'gmail_<account>'; una casella → 'mailbox_<account>'."""
    if connector_id in vault.email_connectors():
        return f"gmail_{connector_id}"
    if connector_id in _google_accounts():
        return f"google_{connector_id}"
    if connector_id in _mailboxes():
        return f"mailbox_{connector_id}"
    return None


def _card(acct: str, cred: str, agent: str | None, **extra) -> dict:
    """La parte comune delle tre viste, scritta una volta.

    `scope` dice **a chi** e **dove** vale ciascun grant (clodia-platform#270):
    senza, la UI mostrerebbe «Dairio: sì» tanto per un accesso all'intera
    istanza quanto per uno ristretto a una persona e a una stanza — due cose
    che una matrice dei permessi esiste apposta per distinguere. Liste vuote =
    nessuna restrizione.
    """
    return {
        "id": acct, "credential": cred,
        "granted": bool(agent) and agent in vault.agents_with_grant(cred),
        "agents": vault.agents_with_grant(cred),
        "scope": vault.grant_scope(cred),
        **extra,
    }


def _connectors(agent: str | None) -> list[dict]:
    out = []
    for acct in _google_accounts():
        # `type: google` e non `email`: la credenziale unificata porta anche
        # Drive/Calendar/Docs, e chiamarla «email» farebbe credere a chi
        # concede di aprire un canale solo, mentre ne apre cinque.
        out.append(_card(acct, f"google_{acct}", agent, type="google",
                         enables=["email", "gdrive", "gcalendar", "gdocs", "gsheets"]))
    for acct in vault.email_connectors():
        out.append(_card(acct, f"gmail_{acct}", agent, type="email"))
    for acct in _mailboxes():
        out.append(_card(acct, f"mailbox_{acct}", agent, type="email"))
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
    # Restringimenti FACOLTATIVI (clodia-platform#270): un body che non li nomina
    # concede come prima, a chiunque e ovunque — la UI di oggi non cambia di una
    # riga. `[]` e assente sono la stessa cosa qui: «nessuna restrizione».
    scope = {}
    for key in vault.SCOPE_KEYS:
        valori = body.get(key)
        if valori is None:
            continue
        if not isinstance(valori, list) or any(not isinstance(v, str) for v in valori):
            return JSONResponse({"error": f"'{key}' dev'essere una lista di stringhe"},
                                status_code=400)
        scope[key] = valori
    if not agent or not account:
        return JSONResponse({"error": "agent e account richiesti"}, status_code=400)
    cred = _cred_for(account)
    if cred is None:
        return JSONResponse({"error": f"connettore '{account}' inesistente"}, status_code=404)
    # Grant SOLO nel vault (montato → persistente). L'accesso ai tool del
    # connettore (email.*, …) è derivato dal grant vault nel gate del
    # gateway (main._connector_allows), così non dipende da config.yaml
    # (baked → effimero al rebuild).
    vault.set_grant(cred, agent, granted, **scope)
    return JSONResponse({"agent": agent, "account": account, "granted": granted,
                         "scope": vault.grant_scope(cred).get(agent, {})})


routes = [
    Route("/internal/connectors", list_connectors, methods=["GET"]),
    Route("/internal/connectors/grant", grant_connector, methods=["POST"]),
]

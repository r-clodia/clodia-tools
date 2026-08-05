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
    # `gated_tools` arriva dal SEED (dichiarazione) e viene custodito qui
    # (autorità): il seed vive sulla datadir insieme al codice degli agenti, e un
    # agente capace di riscriverlo cancellerebbe i propri gate. Assente nel corpo
    # → non si tocca ciò che è già registrato: un chiamante vecchio non deve
    # poter azzerare i gate per omissione.
    spec = whitelist.upsert_agent(name, allowed_tools=body.get("allowed_tools"),
                                  gated_tools=body.get("gated_tools"))
    whitelist.reload_config()
    return JSONResponse({"ok": True, "agent": name,
                         "allowed_tools": spec.get("allowed_tools"),
                         "gated_tools": spec.get("gated_tools") or []})


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


async def verbs(request: Request):
    """GET /internal/agents/{name}/verbs → verbi EFFETTIVI con il flag gated.

    Serve alla scheda del seed. Espande i wildcard, ma **solo dove serve**: un
    `ns.*` che non contiene nessun verbo gated resta compatto. La regola è di
    Davide e ha una buona ragione — si espande dove c'è qualcosa da vedere,
    altrimenti `clodia` con `*` diventa un muro di duecento righe in cui il
    lucchetto che conta non si nota.

    Sta nel gateway perché è l'unico posto che conosce tutte e quattro le cose
    insieme: l'elenco dei verbi nativi, la lista gated GLOBALE, i `gated_tools`
    per-agente e i `denied_tools`. Il backend ne ha solo la dichiarazione del
    seed, e una risposta costruita là sarebbe una seconda verità.
    """
    _agent, err = _authorize(request)
    if err:
        return err
    name = (request.path_params.get("name") or "").strip()
    if not name:
        return JSONResponse({"error": "agent richiesto"}, status_code=400)
    from . import gate as _gate, main as _main
    # Si legge la config DIRETTAMENTE: `agent_config()` risolve l'agente della
    # richiesta corrente, che qui è il principal privilegiato, non il soggetto.
    spec = (whitelist.CONFIG.get("agents") or {}).get(name) or {}
    allowed = [str(x) for x in (spec.get("allowed_tools") or [])]
    denied = {str(x) for x in (spec.get("denied_tools") or [])}
    per_agent = {str(x) for x in (spec.get("gated_tools") or [])}
    catalogue = sorted(_main.all_native_verb_names())

    def _row(v: str, via: str) -> dict:
        g_global = _gate.is_gated(v)
        g_agent = v in per_agent
        return {"verb": v, "gated": bool(g_global or g_agent),
                "gated_by": ("global" if g_global else ("agent" if g_agent else None)),
                "via": via}

    out: list[dict] = []
    groups: list[dict] = []
    for grant in allowed:
        if grant == "*" or grant.endswith(".*"):
            ns = None if grant == "*" else grant[:-2]
            covered = [v for v in catalogue
                       if v not in denied and (ns is None or v.split(".", 1)[0] == ns)]
            gated_inside = [v for v in covered if _gate.is_gated(v) or v in per_agent]
            if gated_inside:
                groups.append({"grant": grant, "expanded": True,
                               "verbs": [_row(v, grant) for v in covered]})
            else:
                # Nessun lucchetto dentro: niente da espandere. Si dice QUANTI
                # verbi copre, perché «compatto» non deve leggersi come «pochi».
                groups.append({"grant": grant, "expanded": False,
                               "count": len(covered), "verbs": []})
        else:
            if grant in denied:
                continue
            out.append(_row(grant, grant))
    return JSONResponse({"agent": name, "verbs": out, "groups": groups,
                         "denied": sorted(denied),
                         "gated_agent": sorted(per_agent),
                         "gated_global_spec": _gate.gated_verbs_spec()})


routes = [
    Route("/internal/agents/whitelist", register, methods=["POST"]),
    Route("/internal/agents/flow-allow", flow_allow, methods=["POST"]),
    Route("/internal/agents/{name}/verbs", verbs, methods=["GET"]),
]

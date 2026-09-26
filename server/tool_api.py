"""Facade REST sui tool MCP del gateway — **PDP unico** per agenti e umani.

La webui non deve più autorizzare da sé le azioni di piattaforma (era Broken
Access Control): l'agent-server INOLTRA qui, con l'umano come principal + ruolo
firmato, e il gateway applica la STESSA RBAC di `call_tool` (whitelist per-agent
o, per le chiamate on-behalf, ruolo umano via `_human_tool_allowed`). Così esiste
un solo meccanismo di autorizzazione valido per agenti e umani.

Due endpoint:
- `POST /internal/tool {tool, arguments}` → autorizza + ESEGUE il tool, ritorna il
  risultato. Per le azioni già implementate come tool gateway (packs.*, providers.*,
  mcp.*, agents.*, settings.*) è il path unico (esecuzione qui).
- `POST /internal/authorize {tool}` → SOLO decisione (dry-run), nessuna esecuzione.
  Per le azioni che restano implementate nell'agent-server (create_agent,
  jobs…): l'agent-server chiede QUI se è consentito, poi esegue localmente.

Auth: token ckt1 come `/mcp`. I claim `on_behalf`/`human_role`/`principal` sono
firmati dall'agent-server (trusted) → non forgiabili dal modello.
"""
from __future__ import annotations

import json
import logging

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from .claims import ClaimsContext
from . import internal_auth, whitelist
from .pki_verify import verify_session_token

LOG = logging.getLogger("clodia-tools.tool_api")


def _auth(request: Request):
    """Verifica il token ckt1 e ritorna il payload, o (None, risposta 401).

    Qui NON si applica il resto di `internal_auth`: questa è la facciata del PDP
    e il suo lavoro è proprio autorizzare per ruolo umano (`on_behalf` è la
    norma, non l'eccezione) mentre il tetto `scoped_tools` lo applica `call_tool`
    a valle, sul verbo vero. Manca(va) però la revoca, che su `/mcp` c'è: senza,
    un token revocato continuava a far eseguire tool da questa porta fino alla
    scadenza naturale (clodia-platform#261).
    """
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    try:
        payload = verify_session_token(token)
    except PermissionError as e:
        return None, "", JSONResponse({"error": "unauthorized", "detail": str(e)},
                                      status_code=401)
    err = internal_auth.refuse_if_revoked(payload, log=LOG)
    if err:
        return None, "", err
    return payload, token, None


#: La tabella dei claim vive in `claims.py`, condivisa con il middleware di
#: `/mcp` (clodia-platform#398). Il nome resta per i chiamanti e i test.
_Ctx = ClaimsContext


async def call(request: Request):
    """POST /internal/tool {tool, arguments} — autorizza ed esegue il tool."""
    payload, token, err = _auth(request)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    tool = (body.get("tool") or "").strip()
    args = body.get("arguments") or {}
    if not tool:
        return JSONResponse({"error": "tool richiesto"}, status_code=400)
    from . import main  # lazy: evita import circolare a load-time
    with _Ctx(payload, token):
        who = whitelist.current_principal() or payload.get("agent")
        try:
            res = await main.call_tool(tool, args)  # riusa authz + dispatch MCP
        except PermissionError as e:
            LOG.info("DENY tool '%s' a '%s': %s", tool, who, e)
            return JSONResponse({"error": "forbidden", "detail": str(e)}, status_code=403)
        except Exception as e:  # noqa: BLE001
            LOG.warning("tool '%s' errore per '%s': %s", tool, who, e)
            return JSONResponse({"error": "tool_error", "detail": str(e)}, status_code=400)
    text = res[0].text if res and getattr(res[0], "text", None) is not None else "null"
    try:
        data = json.loads(text)
    except Exception:
        data = text
    LOG.info("OK tool '%s' per '%s'", tool, who)
    return JSONResponse({"ok": True, "result": data})


def _agent_allowed(tool: str) -> bool:
    """La decisione per un AGENTE: la STESSA di `call_tool`.

    Era `_is_super(agent)`, cioè «solo un super-agent». Da quando
    `_SUPER_AGENTS` è vuoto (#104) quella riga risponde False a QUALUNQUE
    agente, con qualunque grant: la matrice del principal — seed, ancestry,
    archseed, più gli scoped e i connettori — non veniva consultata proprio
    dall'endpoint che esiste per consultarla. `sysadmin`, che ha `packs.*`,
    chiamava `packs.setup_done` e riceveva un 403 indistinguibile da un
    permesso mancante (clodia-platform#297).

    Le due metà sono quelle di `call_tool`: `_agent_tool_reachable` concede,
    `agent_denies` sottrae (una sottrazione da `*`: vale anche per i super, che
    è il punto della lista).
    """
    from . import main
    try:
        ag = whitelist.agent_name()
    except PermissionError as e:
        # Un'identità non dichiarata è una DECISIONE (negato), non un guasto:
        # lasciarla propagare darebbe 500, e il chiamante traduce ogni non-200
        # in «negato» — un guasto travestito da rifiuto, che è il modo più
        # efficace di nascondere un guasto.
        LOG.info("authorize: identità agente non valida (%s)", e)
        return False
    if not (main._is_super(ag) or main._agent_tool_reachable(tool, ag)):
        return False
    return not whitelist.agent_denies(tool, ag)


async def authorize(request: Request):
    """POST /internal/authorize {tool} — SOLO decisione (per le azioni eseguite
    localmente dall'agent-server). Ritorna {allowed: bool}."""
    payload, token, err = _auth(request)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    tool = (body.get("tool") or "").strip()
    if not tool:
        return JSONResponse({"error": "tool richiesto"}, status_code=400)
    from . import main
    with _Ctx(payload, token):
        if whitelist.is_on_behalf():
            # Il tetto `scoped_tools` vale anche qui: `/internal/tool` lo fa
            # applicare da `call_tool` a valle, ma questo endpoint non esegue
            # nulla — non aveva nessun «a valle» che lo applicasse, e rispondeva
            # «consentito» per verbi fuori dal token che li chiedeva.
            allowed = main._human_tool_allowed(tool) and main._scoped_ceiling_ok(tool)
        else:
            allowed = _agent_allowed(tool)
    return JSONResponse({"allowed": bool(allowed),
                         "principal": payload.get("principal"),
                         "human_role": payload.get("human_role")})


routes = [
    Route("/internal/tool", call, methods=["POST"]),
    Route("/internal/authorize", authorize, methods=["POST"]),
]

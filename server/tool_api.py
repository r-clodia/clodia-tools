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
  workflows…): l'agent-server chiede QUI se è consentito, poi esegue localmente.

Auth: token ckt1 come `/mcp`. I claim `on_behalf`/`human_role`/`principal` sono
firmati dall'agent-server (trusted) → non forgiabili dal modello.
"""
from __future__ import annotations

import json
import logging

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import whitelist
from .pki_verify import verify_session_token

LOG = logging.getLogger("clodia-tools.tool_api")


def _auth(request: Request):
    """Verifica il token ckt1 e ritorna il payload, o (None, risposta 401)."""
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    try:
        return verify_session_token(token), token, None
    except PermissionError as e:
        return None, "", JSONResponse({"error": "unauthorized", "detail": str(e)},
                                      status_code=401)


class _Ctx:
    """Imposta i contextvar della richiesta dai claim del token e li resetta.
    Necessario perché questi endpoint sono FUORI dal mount `/mcp` (che ha il suo
    middleware) → qui li settiamo a mano, identici a `_AuthMiddleware`."""

    # I token si tengono per NOME, non per posizione.
    #
    # Erano una lista rilasciata per indice, e il 5 ago 2026 l'aggiunta di
    # `origin` per la catena di delega ha spostato tutto di uno: `__exit__`
    # passava il token di `origin` al reset di `scoped_tools` — che solleva
    # `ValueError: was created by a different ContextVar` — e `origin` non veniva
    # rilasciato affatto.
    #
    # L'effetto visibile era irriconoscibile dalla causa: `/internal/authorize`
    # DECIDEVA correttamente e poi esplodeva in uscita, rispondendo 500. Il
    # chiamante traduce ogni non-200 in «negato», e all'utente arrivava
    # «azione riservata agli admin» — mandando a cercare un problema di permessi
    # per tre giri. Un difetto di teardown travestito da rifiuto di autorizzazione.
    #
    # Con un dizionario di (setter, resetter) aggiungere una variabile non può
    # più disallineare nulla: non c'è più un ordine da tenere a mente.
    _VARS = (
        ("agent", "set_current_agent", "reset_current_agent",
         lambda p, t: str(p.get("agent") or "")),
        # Lo SPAWN, non il seed: `execution_id` esisteva nel token e nessuno lo
        # riempiva. Aggiungere una riga qui è sicuro perché la tabella ha
        # (nome, setter, resetter): è la struttura nata dal difetto opposto.
        ("spawn", "set_current_spawn", "reset_current_spawn",
         lambda p, t: p.get("execution_id") or None),
        ("principal", "set_current_principal", "reset_current_principal",
         lambda p, t: p.get("principal") or None),
        ("token", "set_current_token", "reset_current_token",
         lambda p, t: t or None),
        ("clearance", "set_current_clearance", "reset_current_clearance",
         lambda p, t: p.get("clearance") or None),
        ("on_behalf", "set_current_on_behalf", "reset_current_on_behalf",
         lambda p, t: bool(p.get("on_behalf"))),
        ("human_role", "set_current_human_role", "reset_current_human_role",
         lambda p, t: p.get("human_role") or None),
        ("chat", "set_current_chat", "reset_current_chat",
         lambda p, t: p.get("chat") or None),
        ("origin", "set_current_origin", "reset_current_origin",
         lambda p, t: p.get("origin") or None),
        ("scoped_tools", "set_current_scoped_tools", "reset_current_scoped_tools",
         lambda p, t: p.get("scoped_tools") or None),
    )

    def __init__(self, payload: dict, token: str):
        self.payload, self.token, self._toks = payload, token, {}

    def __enter__(self):
        p = self.payload
        for nome, setter, _res, val in self._VARS:
            self._toks[nome] = getattr(whitelist, setter)(val(p, self.token))
        return self

    def __exit__(self, *exc):
        # In ordine inverso, e ogni reset protetto: un rilascio che solleva non
        # deve impedire i successivi, altrimenti un contextvar resta impostato
        # per la richiesta seguente sullo stesso task.
        for nome, _set, resetter, _val in reversed(self._VARS):
            tok = self._toks.get(nome)
            if tok is None:
                continue
            try:
                getattr(whitelist, resetter)(tok)
            except Exception:  # noqa: BLE001
                LOG.warning("ctx: reset di '%s' fallito", nome, exc_info=True)
        self._toks.clear()
        return False


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
            allowed = main._human_tool_allowed(tool)
        else:
            allowed = main._is_super(whitelist.agent_name())
    return JSONResponse({"allowed": bool(allowed),
                         "principal": payload.get("principal"),
                         "human_role": payload.get("human_role")})


routes = [
    Route("/internal/tool", call, methods=["POST"]),
    Route("/internal/authorize", authorize, methods=["POST"]),
]

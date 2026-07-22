"""Transport HTTP del gateway clodia-tools (microservizio MCP).

Avvolge il server MCP low-level esistente (``main.app``, con i 18 tool) in uno
StreamableHTTP, dietro un middleware di auth a chiave pubblica: ogni richiesta
deve portare ``Authorization: Bearer ckt1.*``; il token viene verificato coi
certificati PUBBLICI (pki_verify) e l'agente risolto viene impostato nel
contextvar della whitelist (enforcement per-richiesta in main.call_tool).

Avvio: ``python cli.py --http [--host 0.0.0.0] [--port 7849]``.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.routing import Mount

from . import whitelist
from .main import app as mcp_server
from .pki_verify import verify_session_token

LOG = logging.getLogger("clodia-tools.http")

# stateless: ogni richiesta è indipendente (nessuno stato di sessione MCP
# server-side da mantenere tra le chiamate dei diversi agenti).
_sm = StreamableHTTPSessionManager(app=mcp_server, stateless=True, json_response=True)


async def _send_401(send, reason: str) -> None:
    await send({"type": "http.response.start", "status": 401,
                "headers": [(b"content-type", b"application/json")]})
    await send({"type": "http.response.body",
                "body": b'{"error":"unauthorized"}'})


class _AuthMiddleware:
    """Verifica il Bearer ckt1 e imposta l'agente nel contextvar whitelist."""

    def __init__(self, handler):
        self.handler = handler

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.handler(scope, receive, send)
            return
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        auth = headers.get("authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        try:
            payload = verify_session_token(token)
        except PermissionError as e:
            LOG.warning("auth fallita: %s", e)
            await _send_401(send, str(e))
            return
        tok = whitelist.set_current_agent(str(payload.get("agent") or ""))
        # claim `principal` (utente umano della chat) → contextvar per runtime.current_user
        ptok = whitelist.set_current_principal(payload.get("principal") or None)
        # token grezzo verificato → inoltrabile al backend (agents.* → caps)
        ttok = whitelist.set_current_token(token or None)
        # clearance firmata → enforcement clearance≥tier sui topic
        ctok = whitelist.set_current_clearance(payload.get("clearance") or None)
        # RBAC umana (PDP unico): claim firmati dall'agent-server per le chiamate
        # ON-BEHALF di un umano → autorizzazione per ruolo, non per carrier-agent.
        obtok = whitelist.set_current_on_behalf(bool(payload.get("on_behalf")))
        hrtok = whitelist.set_current_human_role(payload.get("human_role") or None)
        chtok = whitelist.set_current_chat(payload.get("chat") or None)
        try:
            await self.handler(scope, receive, send)
        finally:
            whitelist.reset_current_chat(chtok)
            whitelist.reset_current_human_role(hrtok)
            whitelist.reset_current_on_behalf(obtok)
            whitelist.reset_current_clearance(ctok)
            whitelist.reset_current_token(ttok)
            whitelist.reset_current_principal(ptok)
            whitelist.reset_current_agent(tok)


@asynccontextmanager
async def _lifespan(_app):
    async with _sm.run():
        LOG.info("clodia-tools MCP HTTP: session manager attivo")
        # M3++: in modalità runtime-keyless (CLODIA_ORCHESTRATOR_SECRET set) il
        # gateway è il trust-anchor → bootstrap PKI qui (CA + identità native),
        # idempotente. L'entrypoint di agent-server la salta in questa modalità.
        import os as _os
        if (_os.environ.get("CLODIA_ORCHESTRATOR_SECRET") or "").strip():
            try:
                from . import pki_mint
                res = pki_mint.bootstrap()
                LOG.info("PKI bootstrap (trust-anchor): CA=%s, identità=%s",
                         res.get("ca"), res.get("issued"))
            except Exception as e:  # noqa: BLE001 — mai bloccare il boot
                LOG.warning("PKI bootstrap gateway fallito: %s", e)
        # Profilo topics:single → assicura il topic-workspace unico al boot
        # (TopicService.new è idempotente: se esiste, no-op).
        try:
            from . import instance_profile
            if instance_profile.topics_mode() == "single":
                conf = instance_profile.topics_single_conf()
                from .topics_api import _service
                _service().new(conf.get("tier") or "SEAL-1",
                               conf.get("name") or "workspace", {})
                LOG.info("profilo topics:single — workspace '%s' pronto",
                         conf.get("name") or "workspace")
        except Exception as e:  # noqa: BLE001 — mai bloccare il boot
            LOG.warning("auto-create workspace (topics:single) fallito: %s", e)
        yield


def build_app() -> Starlette:
    handler = _AuthMiddleware(_sm.handle_request)
    # Backend UI (acquisizione credenziali tool) — auth bearer separata dal
    # ckt1 degli agenti; vedi server/tools_api.py.
    from .tools_api import routes as tools_routes
    # Backend interno credenziali provider (Fase 4) — auth ckt1 ristretta al
    # trusted-core, chiamato dal runner di clodia-logic (mai da un modello).
    from .providers_api import routes as providers_routes
    # Generazione immagini (PFP): endpoint interno ckt1 per i flussi owner.
    from .imagegen_api import routes as imagegen_routes
    # Topic v2 (lettura per la webui): endpoint interni ckt1.
    from .topics_api import routes as topics_routes
    # Connettori delegabili (email per-account) — grant per-agent.
    from .connectors_api import routes as connectors_routes
    from .profile_api import routes as profile_routes
    # Telegram channel-runner (server-side): endpoint interni ckt1 per drenare/inviare.
    from .telegram_api import routes as telegram_routes
    # Registrazione whitelist agent (auto-provisioning responder confinati).
    from .agents_api import routes as agents_routes
    # Lettura credenziali git (PAT) dal vault per i workflow del backend.
    from .vault_api import routes as vault_routes
    # Grant SUDO (M-sudo): un admin approvatore eleva un sudoer time-boxed.
    from .sudo_api import routes as sudo_routes
    # Facade tool (M-authz): PDP unico agenti+umani — la webui inoltra qui.
    from .tool_api import routes as tool_routes
    # Minting (trust-anchor): il gateway conia i token; l'orchestrator li chiede
    # via /internal/mint (auth secret di bootstrap). Le chiavi private stanno solo qui.
    from .mint_api import routes as mint_routes
    # M-gate: consenso umano sui verbi gated (sostituisce sudo_api).
    from .gate_api import routes as gate_routes
    return Starlette(
        routes=[Mount("/mcp", app=handler), *tools_routes, *providers_routes,
                *imagegen_routes, *topics_routes, *connectors_routes, *profile_routes,
                *telegram_routes, *agents_routes, *vault_routes, *sudo_routes,
                *tool_routes, *mint_routes, *gate_routes],
        lifespan=_lifespan)


def run_http(host: str = "0.0.0.0", port: int = 7849) -> None:
    import uvicorn
    logging.basicConfig(level=logging.INFO)
    LOG.info("clodia-tools MCP HTTP in ascolto su %s:%s/mcp", host, port)
    uvicorn.run(build_app(), host=host, port=port, log_level="info")

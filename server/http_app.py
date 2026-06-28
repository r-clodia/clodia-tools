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
        try:
            await self.handler(scope, receive, send)
        finally:
            whitelist.reset_current_principal(ptok)
            whitelist.reset_current_agent(tok)


@asynccontextmanager
async def _lifespan(_app):
    async with _sm.run():
        LOG.info("clodia-tools MCP HTTP: session manager attivo")
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
    return Starlette(
        routes=[Mount("/mcp", app=handler), *tools_routes, *providers_routes,
                *imagegen_routes, *topics_routes, *connectors_routes, *profile_routes],
        lifespan=_lifespan)


def run_http(host: str = "0.0.0.0", port: int = 7849) -> None:
    import uvicorn
    logging.basicConfig(level=logging.INFO)
    LOG.info("clodia-tools MCP HTTP in ascolto su %s:%s/mcp", host, port)
    uvicorn.run(build_app(), host=host, port=port, log_level="info")

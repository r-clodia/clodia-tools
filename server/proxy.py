"""C1 — Proxy MCP: il gateway fa da CLIENT verso backend MCP di terzi.

Il gateway resta un MCP server verso gli agenti (con auth ckt1 + whitelist), e
in più monta backend MCP esterni dichiarati nel registry (C2, sezione
``mcp_backends`` di config.yaml). I tool di un backend ``X`` sono esposti agli
agenti con namespace ``X.<tool>`` e instradati al backend giusto. La front door
(auth + whitelist) non cambia: la whitelist per-agente elenca i nomi namespaced.

v1: connessione **per-chiamata** (semplice e corretta; niente sessioni long-lived
da gestire dentro l'handler HTTP). La lista tool è invece **cache-ata** per
backend (list_tools è chiamato a ogni init di sessione agente: non vogliamo
spawnare tutti i backend ogni volta). Un restart del gateway rinfresca la cache.

Vincolo: i nomi dei backend NON devono collidere coi prefissi nativi
(``trello``/``fs``/``email``/``agent``).
"""
from __future__ import annotations

import os
import re
from contextlib import asynccontextmanager

from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.client.streamable_http import streamablehttp_client
from mcp.types import Tool

from . import vault
from .whitelist import CONFIG

NS_SEP = "."
_NATIVE_PREFIXES = {"trello", "fs", "email", "agent"}

# Placeholder per i secret dei backend: ${VAULT:<credential>} risolto a runtime
# dalla vault (read_internal) → il valore reale NON sta mai nel config.yaml.
_VAULT_RE = re.compile(r"\$\{VAULT:([A-Za-z0-9_.-]+)\}")

# cache {backend_name: [Tool, ...]} popolata lazy
_TOOL_CACHE: dict[str, list[Tool]] = {}


def clear_cache() -> None:
    """Svuota la cache dei tool proxied (dopo register/unregister di un backend)."""
    _TOOL_CACHE.clear()


def _resolve_secrets(val):
    """Sostituisce ricorsivamente ${VAULT:cred} nelle stringhe col segreto dal
    vault (bundle['value']). Invariato se la credenziale non è risolvibile."""
    if isinstance(val, str):
        def _sub(m):
            try:
                b = vault.read_internal(m.group(1))
            except Exception:
                return m.group(0)
            return str(b.get("value", "")) if isinstance(b, dict) else str(b)
        return _VAULT_RE.sub(_sub, val)
    if isinstance(val, dict):
        return {k: _resolve_secrets(v) for k, v in val.items()}
    if isinstance(val, list):
        return [_resolve_secrets(v) for v in val]
    return val


def _backends() -> dict[str, dict]:
    out: dict[str, dict] = {}
    for b in (CONFIG.get("mcp_backends") or []):
        name = b.get("name")
        if not name:
            continue
        if name in _NATIVE_PREFIXES:
            # un backend non può rubare un prefisso nativo
            continue
        out[name] = b
    return out


@asynccontextmanager
async def _session(b: dict):
    """Apre una ClientSession verso il backend (stdio o http). I secret
    ${VAULT:cred} in env/headers/url/args sono risolti dal vault qui, al volo."""
    b = _resolve_secrets(b)
    transport = b.get("transport", "stdio")
    if transport == "stdio":
        params = StdioServerParameters(
            command=b["command"],
            args=b.get("args", []),
            env={**os.environ, **(b.get("env") or {})},
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as s:
                await s.initialize()
                yield s
    elif transport == "http":
        async with streamablehttp_client(b["url"], headers=b.get("headers")) as (read, write, _):
            async with ClientSession(read, write) as s:
                await s.initialize()
                yield s
    else:
        raise ValueError(f"transport MCP non supportato: {transport!r}")


def is_proxied(name: str) -> bool:
    """True se ``name`` appartiene a un backend montato (namespace)."""
    if NS_SEP not in name:
        return False
    return name.split(NS_SEP, 1)[0] in _backends()


async def list_proxied_tools() -> list[Tool]:
    """Tutti i tool dei backend, namespaced. Cache per backend; un backend
    irraggiungibile viene saltato senza far cadere l'intera lista."""
    tools: list[Tool] = []
    for name, b in _backends().items():
        if name not in _TOOL_CACHE:
            try:
                async with _session(b) as s:
                    res = await s.list_tools()
                    _TOOL_CACHE[name] = [
                        Tool(
                            name=f"{name}{NS_SEP}{t.name}",
                            description=f"[{name}] {t.description or ''}".strip(),
                            inputSchema=t.inputSchema,
                        )
                        for t in res.tools
                    ]
            except Exception:
                _TOOL_CACHE[name] = []  # backend down: cache vuota (riprovabile a restart)
        tools.extend(_TOOL_CACHE[name])
    return tools


async def call_proxied(name: str, arguments: dict) -> str:
    """Instrada la call al backend giusto e ritorna il testo concatenato."""
    backend_name, tool_name = name.split(NS_SEP, 1)
    b = _backends().get(backend_name)
    if not b:
        raise ValueError(f"backend MCP sconosciuto: {backend_name!r}")
    async with _session(b) as s:
        res = await s.call_tool(tool_name, arguments)
        parts = [c.text for c in res.content if getattr(c, "type", None) == "text"]
        return "\n".join(parts) if parts else "(nessun contenuto testuale)"

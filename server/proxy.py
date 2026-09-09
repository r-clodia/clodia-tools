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
(``fs``/``email``/``agent``).
"""
from __future__ import annotations

import os
import re
from contextlib import asynccontextmanager

from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters
try:  # mcp <2
    from mcp.client.streamable_http import streamablehttp_client
except ImportError:  # mcp >=2 ha rinominato il simbolo
    from mcp.client.streamable_http import (
        streamable_http_client as streamablehttp_client,
    )
from mcp.types import Tool

from . import docmd as _docmd
from . import vault
from .whitelist import CONFIG

NS_SEP = "."
_NATIVE_PREFIXES = {"fs", "email", "agent", "web"}

#: Byte di testo che la risposta di un backend MCP può portare nel contesto.
#: Stesso numero di `web.fetch` (`DEFAULT_RESPONSE_BYTES`) e dei tre verbi di
#: lettura del gateway (`_READ_FILE_WINDOW`), e per la stessa ragione: il
#: risultato non si paga una volta, si paga a ogni azione successiva del turno.
#: Qui però il taglio è DEFINITIVO — vedi `_cappa`.
MAX_RESULT_BYTES = 64 * 1024

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


def _response_text(content: list) -> str:
    """Flatten textual MCP content, including embedded text resources."""
    parts: list[str] = []
    for item in content:
        if getattr(item, "type", None) == "text":
            parts.append(item.text)
            continue
        if getattr(item, "type", None) == "resource":
            text = getattr(getattr(item, "resource", None), "text", None)
            if text is not None:
                parts.append(text)
    return "\n".join(parts) if parts else "(nessun contenuto testuale)"


def _cappa(text: str, name: str) -> str:
    """Il testo del backend entro `MAX_RESULT_BYTES`, con una nota se tagliato.

    A differenza dei verbi di lettura del gateway, qui NON c'è paginazione di
    recupero: la connessione è per-chiamata (v1, vedi il docstring del modulo),
    il protocollo non dà un cursore sul risultato di una `call_tool` e i tool di
    un backend di terzi hanno ognuno i propri parametri — non esiste un
    `offset` che questo strato possa offrire. Quindi il taglio è definitivo, e
    la nota deve dirlo: una nota che invitasse a «richiamare per il resto»
    manderebbe a spendere un secondo turno per riottenere gli stessi 64 KB.

    Tre cose non deducibili dal testo tagliato, e per questo scritte:
      - un JSON troncato NON è JSON. Senza avviso finisce in un parser e
        l'errore viene letto come un guasto del backend, non come un taglio
        fatto qui;
      - la strada che consegna il contenuto intero — `github.clone` e i file
        nella propria scratch — dove il contenuto è un repository;
      - per un verbo di ricerca o di elenco (non un file) la via d'uscita è
        diversa: non c'è uno "scarica tutto", si stringe la query (filtri,
        path, `perPage`) e si richiama, invece di riprovare la stessa.
    """
    grezzo = (text or "").encode("utf-8")
    if len(grezzo) <= MAX_RESULT_BYTES:
        return text
    # Il taglio cade su un capo a riga (o almeno su un confine UTF-8): una
    # finestra indecodificabile trasformerebbe una risposta valida in un errore
    # che dipende da dove capita l'accento.
    w = _docmd.finestra_byte(grezzo, 0, MAX_RESULT_BYTES)
    return w["data"].decode("utf-8") + (
        f"\n\n[gateway: la risposta di `{name}` era {w['size']} byte, "
        f"consegnati i primi {w['window']} (tetto {MAX_RESULT_BYTES}). "
        f"Il resto NON si recupera richiamando: questo strato non pagina. "
        f"Se sopra c'è un JSON, è troncato e non è JSON valido: non parsarlo. "
        f"Per il contenuto intero di un repository usa `github.clone` e leggi i "
        f"file nella tua scratch; per un documento del topic usa "
        f"`topic.read_file` con offset/max_bytes; per un verbo di ricerca o "
        f"di elenco stringi la query (filtri, path, `perPage`) invece di "
        f"riprovare la stessa.]")


async def call_proxied(name: str, arguments: dict) -> str:
    """Instrada la call al backend giusto e ritorna il testo concatenato."""
    backend_name, tool_name = name.split(NS_SEP, 1)
    b = _backends().get(backend_name)
    if not b:
        raise ValueError(f"backend MCP sconosciuto: {backend_name!r}")
    async with _session(b) as s:
        res = await s.call_tool(tool_name, arguments)
        return _cappa(_response_text(res.content), name)

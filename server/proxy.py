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

import asyncio
import logging
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
from . import mcp_oauth
from . import vault
from .tools import pack_runtime
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

LOG = logging.getLogger("clodia-tools.proxy")

# cache {backend_name: [Tool, ...]} popolata lazy
_TOOL_CACHE: dict[str, list[Tool]] = {}


def clear_cache() -> None:
    """Svuota la cache dei tool proxied (dopo register/unregister di un backend)."""
    _TOOL_CACHE.clear()


def _resolve_secrets(val):
    """Sostituisce ricorsivamente `${VAULT:cred}` nelle stringhe col segreto dal
    vault. Invariato se la credenziale non è risolvibile.

    Due forme, e la seconda è nata con clodia-platform#522:

        ${VAULT:cred}         il campo `value` del bundle
        ${VAULT:cred.campo}   quel campo del bundle

    Un bundle non è sempre `{"value": …}`. `telegram_bot_token` è
    `{"token", "bot_username", "bot_id"}` — lo scrive `tools_api.telegram_connect`
    dopo aver validato con `getMe` — e con la sola prima forma il server MCP del
    pack che quella credenziale deve usarla partiva con il token **stringa
    vuota**: Telegram rispondeva 401 e il sintomo era «il token del bot è
    sbagliato», cioè il posto giusto dove non guardare. Il selettore di campo è
    già ammesso dalla grammatica del placeholder (il `.` sta in `_VAULT_RE`):
    quello che mancava era implementarlo.

    **Un campo che non c'è lascia il placeholder com'è**, e lo dice nei log.
    Prima `bundle.get("value", "")` produceva silenziosamente `""`: un segreto
    vuoto è indistinguibile da un segreto sbagliato, mentre un
    `${VAULT:…}` letterale arrivato fino alla API di un vendor è un errore che
    nomina sé stesso. Stessa direzione del ramo che già esisteva per la
    credenziale assente.
    """
    if isinstance(val, str):
        def _sub(m):
            name, _, field = m.group(1).partition(".")
            try:
                b = vault.read_internal(name)
            except Exception:
                return m.group(0)
            if not isinstance(b, dict):
                return str(b)
            key = field or "value"
            if key not in b:
                LOG.warning(
                    "backend MCP: il bundle '%s' non ha il campo '%s', "
                    "placeholder lasciato intatto (campi: %s)",
                    name, key, ", ".join(sorted(b)) or "nessuno")
                return m.group(0)
            return str(b[key])
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
async def session(b: dict, *, oauth_handlers: tuple | None = None):
    """Apre una ClientSession verso il backend (stdio o http). I secret
    ${VAULT:cred} in env/headers/url/args sono risolti dal vault qui, al volo.

    Un backend http con `auth: {type: oauth}` non porta nessun segreto nel
    config: l'header lo compone `mcp_oauth`, dai token nella vault, con refresh
    automatico (clodia-platform#532). `oauth_handlers` lo passa SOLO il consenso
    guidato dalla card — in una chiamata di tool resta None, e un backend non
    ancora autorizzato fallisce invece di aprire un consenso che nessuno può dare.
    """
    b = _resolve_secrets(b)
    transport = b.get("transport", "stdio")
    if transport == "stdio":
        # `runtime_env` e non `os.environ`: i backend stdio sono i server MCP dei
        # pack, e le loro dipendenze stanno nel venv/prefix npm persistenti che
        # `packs.install_pip`/`install_npm` popolano. Senza questo PATH/PYTHONPATH
        # erano installate sul volume ma invisibili al processo che doveva
        # usarle, e il pack funzionava solo finché la stessa libreria era anche
        # nell'immagine del gateway — che ogni rebuild azzera
        # (clodia-platform#451). L'`env` del backend resta l'ultima parola.
        params = StdioServerParameters(
            command=b["command"],
            args=b.get("args", []),
            env={**pack_runtime.runtime_env(), **(b.get("env") or {})},
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as s:
                await s.initialize()
                yield s
    elif transport == "http":
        auth = mcp_oauth.provider_for(b, handlers=oauth_handlers)
        async with streamablehttp_client(b["url"], headers=b.get("headers"),
                                         auth=auth) as (read, write, _):
            async with ClientSession(read, write) as s:
                await s.initialize()
                yield s
    else:
        raise ValueError(f"transport MCP non supportato: {transport!r}")


#: Nome storico, usato dal resto del modulo.
_session = session


def riautorizzazione(e: BaseException) -> mcp_oauth.ReauthorizationRequired | None:
    """Cerca un «serve un consenso OAuth» dentro un guasto, anche annidato.

    Il transport http gira dentro un task group di anyio: l'errore che risale
    è un `ExceptionGroup`, il cui `str()` è «unhandled errors in a TaskGroup».
    Senza questo srotolamento l'unica cosa che il proprietario leggerebbe —
    nella card e nel risultato della chiamata — è quella frase, che non dice
    niente di ciò che deve fare.
    """
    if isinstance(e, mcp_oauth.ReauthorizationRequired):
        return e
    for sub in getattr(e, "exceptions", ()) or ():
        found = riautorizzazione(sub)
        if found is not None:
            return found
    cause = e.__cause__ or e.__context__
    return riautorizzazione(cause) if cause is not None else None


def is_proxied(name: str) -> bool:
    """True se ``name`` appartiene a un backend montato (namespace)."""
    if NS_SEP not in name:
        return False
    return name.split(NS_SEP, 1)[0] in _backends()


#: Quanto aspettare un backend MCP prima di dichiararlo irraggiungibile.
#: Stesso ordine di grandezza dei test HTTP dei connettori nativi in
#: tools_api.py (15s): un backend di terzi lento non deve bloccare la UI.
TEST_TIMEOUT_S = 15


async def test_backend(name: str) -> dict:
    """Verifica REALE di un backend MCP montato: apre una sessione (i secret
    ${VAULT:cred} sono risolti qui, come per ogni chiamata proxied) e lista i
    tool esposti. Mai il segreto nel risultato — solo ok/detail."""
    b = _backends().get(name)
    if b is None:
        return {"ok": None, "detail": "backend non montato"}
    try:
        async def _probe():
            async with _session(b) as s:
                return await s.list_tools()
        res = await asyncio.wait_for(_probe(), timeout=TEST_TIMEOUT_S)
        return {"ok": True, "detail": f"{len(res.tools)} tool esposti"}
    except TimeoutError:
        return {"ok": False, "detail": f"nessuna risposta entro {TEST_TIMEOUT_S}s"}
    except Exception as e:  # noqa: BLE001 — qualunque guasto del backend è un esito, non un crash della API
        return {"ok": False, "detail": str(riautorizzazione(e) or e)[:200]}


async def list_proxied_tools() -> list[Tool]:
    """Tutti i tool dei backend, namespaced. Cache per backend; un backend
    irraggiungibile viene saltato senza far cadere l'intera lista."""
    tools: list[Tool] = []
    for name, b in _backends().items():
        if _is_transport(name):
            # A provider transport (#523) is a socket of the gateway, not a
            # verb: never listed, whoever asks — see `main._check_not_transport`.
            continue
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


def _is_transport(backend: str) -> bool:
    from .connectors import resolved
    return resolved.is_transport_backend(backend)


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
    try:
        async with _session(b) as s:
            res = await s.call_tool(tool_name, arguments)
            return _cappa(_response_text(res.content), name)
    except Exception as e:
        # Un backend OAuth non ancora autorizzato non è un guasto misterioso:
        # è una cosa che una persona deve fare nella card. Dillo con quelle
        # parole, invece di lasciare risalire il gruppo di eccezioni di anyio.
        reauth = riautorizzazione(e)
        if reauth is None:
            raise
        raise reauth from None


#: Margin over the caller's own timeout for opening the session: a stdio
#: backend is spawned per call (v1), and the transport's `timeout` is the
#: budget of the OPERATION, not of the process start.
TRANSPORT_SESSION_MARGIN_S = 30


class BackendToolError(RuntimeError):
    """A backend tool answered with `isError`, or could not be reached."""


def _backend_named(name: str) -> dict | None:
    """The mounted backend called `name`, compared the way ownership is
    (`resolved.norm_name`: slugs use `-`, namespaces `_`)."""
    from .connectors.resolved import norm_name
    found = _backends().get(name)
    if found is not None:
        return found
    want = norm_name(name)
    return next((b for n, b in _backends().items() if norm_name(n) == want), None)


def call_backend_tool_sync(backend: str, tool: str, arguments: dict,
                           timeout: float) -> str:
    """Call ONE tool of a mounted backend for the gateway itself; the text.

    The provider transport of #523: the gateway, not an agent, is the caller,
    so none of `call_proxied`'s agent-facing shaping applies. In particular no
    `_cappa`: that cap protects a model's context, while here the answer is a
    mail with its attachments, read by the gateway and filtered by it before
    anything reaches an agent. Truncated, it would be a broken JSON — i.e. a
    transport failure manufactured by the gateway.

    Synchronous on purpose: the mail verbs are synchronous code that runs off
    the event loop (`asyncio.to_thread` in the dispatch, #553), so the call
    gets a loop of its own. Called from a thread that already runs a loop it
    cannot nest one, and it moves to a worker thread instead of failing: the
    owner switching the transport must not turn a caller that used to work
    (a blocking subprocess) into a `RuntimeError`.

    Raises `BackendToolError` on a tool error (`isError`) and when the backend
    is not mounted: the caller fails closed, there is no fallback to the
    in-process client — that would be the switch undoing itself silently.
    """
    b = _backend_named(backend)
    if b is None:
        raise BackendToolError(f"backend MCP '{backend}' non montato")
    budget = float(timeout) + TRANSPORT_SESSION_MARGIN_S

    async def _go() -> str:
        async def _call():
            async with _session(b) as s:
                return await s.call_tool(tool, arguments)
        try:
            res = await asyncio.wait_for(_call(), timeout=budget)
        except TimeoutError:
            raise BackendToolError(
                f"{backend}.{tool}: nessuna risposta entro {int(budget)}s") from None
        text = _response_text(res.content)
        if getattr(res, "isError", False):
            raise BackendToolError(f"{backend}.{tool}: {text[:500]}")
        return text

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_go())
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: asyncio.run(_go())).result()

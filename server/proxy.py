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

import httpx

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
from . import mcp_credentials
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
    """Svuota la cache dei tool proxied (dopo register/unregister di un backend).
    Con la cache vanno le annotazioni MCP dei tool (#634): un backend rimontato
    o riconfigurato le ridichiara alla prossima lista."""
    _TOOL_CACHE.clear()
    from . import tool_hints
    tool_hints.clear()


def _resolve_secrets(val):
    """Sostituisce ricorsivamente `${VAULT:cred}` nelle stringhe col segreto dal
    vault. Invariato se la credenziale non è risolvibile.

    Due forme, e la seconda è nata con clodia-platform#522:

        ${VAULT:cred}         il campo `value` del bundle
        ${VAULT:cred.campo}   quel campo del bundle

    Un bundle non è sempre `{"value": …}`. `telegram_bot_token` è
    `{"token", "bot_username", "bot_id"}` — lo scriveva `tools_api.telegram_connect` (rimosso, #522)
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


# ── Pack MCPs bound to a datastore instance (clodia-platform#686) ────────────
#
# The MCP of a pack that declares datastore STRUCTURES works on the instance
# imported in the caller's scope, never on a file of its own: the gateway
# resolves the instance per call from the signed claim's scope and hands its
# file to the process in `CLODIA_DATASTORE_<STRUCTURE>`. One import → that
# one; several → the call names it (`instance`, stripped before forwarding);
# none → refused. A process never serves two instances: a stdio backend is
# spawned per call (v1, see the module docstring), each with the environment
# of its own instance.

#: The argument a call uses to name the instance, never forwarded.
INSTANCE_ARG = "instance"


def bound_structures(backend: str) -> list[dict]:
    """The datastore structures (declared with a `schema`, #684) of the
    installed plugin whose manifest declares the MCP server `backend`. Empty
    for any other backend: nothing changes for them."""
    from . import datastores
    from .connectors.resolved import norm_name
    want = norm_name(backend)
    plugins = set()
    for pack, _root, meta in datastores._manifests():
        servers = meta.get("mcp_servers")
        if isinstance(servers, dict) and any(norm_name(str(n)) == want for n in servers):
            plugins.add(pack)
    if not plugins:
        return []
    return [st for st in datastores.structures().values()
            if st["pack"] in plugins and not st["legacy"]]


def _pick_requested(requested, st: dict) -> str | None:
    """The instance the call names for structure `st`: a full id of THAT
    structure, or a bare name (applies to every bound structure)."""
    from . import datastores
    items = requested if isinstance(requested, list) else [requested]
    for r in items:
        r = str(r or "").strip()
        if not r:
            continue
        parts = datastores.split_instance(r)
        if parts is None:
            return r
        if f"{parts[0]}/{parts[1]}" == st["id"]:
            return r
    return None


def bind_instances(backend: str, b: dict, arguments: dict) -> tuple[dict, dict]:
    """`(backend entry with the instances' env, arguments without
    `instance`)` for a call in the current scope; `(b, arguments)` unchanged
    for a backend bound to no structure. Raises PermissionError / ValueError
    with the reason (no instance, several and none named, access refused)."""
    structs = bound_structures(backend)
    if not structs:
        return b, arguments
    if (b.get("transport") or "stdio") != "stdio":
        # The instance travels in the process environment, which an http
        # backend never sees: it would serve every scope from one database.
        raise PermissionError(
            f"il backend MCP '{backend}' lavora su istanze di datastore "
            f"({', '.join(st['id'] for st in structs)}) ma non è stdio: l'istanza dello "
            "scope non gli arriverebbe. Rifiutato: va montato come processo stdio")
    from . import datastore_instances, topic_data
    from .whitelist import agent_name, current_clearance
    args = dict(arguments or {})
    requested = args.pop(INSTANCE_ARG, None)
    env = dict(b.get("env") or {})
    scope = topic_data.scope_of_call()
    for st in structs:
        entry = datastore_instances.resolve(
            st["id"], scope=scope, agent=agent_name(), clearance=current_clearance(),
            instance=_pick_requested(requested, st) if requested else None, write=True)
        env[datastore_instances.env_name(st["name"])] = entry["abs_path"]
    return {**b, "env": env}, args


@asynccontextmanager
async def _listing_env(backend: str, b: dict):
    """The backend entry for listing its tools (no call, no scope): a bound
    backend gets throwaway databases built from its structures' schemas, so
    that it starts — it refuses to without an instance — and touches no real
    data. Removed afterwards."""
    structs = bound_structures(backend)
    if not structs:
        yield b
        return
    import shutil
    import tempfile
    from pathlib import Path
    from . import datastore_instances
    d = tempfile.mkdtemp(prefix="clodia-mcp-probe-")
    try:
        env = dict(b.get("env") or {})
        for st in structs:
            p = Path(d) / f"{st['name']}.db"
            try:
                if st.get("schema"):
                    datastore_instances._build_file(p, st["schema"], max(st["latest_version"], 0))
                else:
                    p.touch()
            except Exception as e:  # noqa: BLE001 — an empty file still lets it start
                LOG.warning("mcp %s: probe di %s senza schema (%s)", backend, st["id"],
                            type(e).__name__)
                p.touch()
            env[datastore_instances.env_name(st["name"])] = str(p)
        yield {**b, "env": env}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _with_instance_arg(backend: str, schema: dict | None) -> dict | None:
    """The tool's input schema with the optional `instance` argument of a
    bound backend (#686): the agent learns it can name the instance when its
    scope imports several."""
    structs = bound_structures(backend)
    if not structs:
        return schema
    s = dict(schema or {"type": "object"})
    props = dict(s.get("properties") or {})
    ids = ", ".join(f"'{st['id']}:<nome>'" for st in structs)
    props.setdefault(INSTANCE_ARG, {
        "type": "string",
        "description": (f"istanza su cui lavorare ({ids}). Serve solo se questo scope ne "
                        "importa più di una; con una sola si usa quella.")})
    s["properties"] = props
    return s


def _vault_ref_names(val) -> set[str]:
    """The vault entries a backend's strings reference (`${VAULT:name[.field]}`)."""
    out: set[str] = set()
    if isinstance(val, str):
        out.update(m.group(1).partition(".")[0] for m in _VAULT_RE.finditer(val))
    elif isinstance(val, dict):
        for v in val.values():
            out |= _vault_ref_names(v)
    elif isinstance(val, list):
        for v in val:
            out |= _vault_ref_names(v)
    return out


#: Backends the GATEWAY mounts itself (no pack), and the vault entries they
#: read: the native GitHub connector (`tools_api.github_connect`).
_CORE_BACKEND_CREDENTIALS: dict[str, frozenset[str]] = {
    "github": frozenset({"github_pat"}),
}


def _core_bound(b: dict, slug: str) -> set[str]:
    """The entries an UNSTAMPED backend may read: only the gateway's own
    mount, recognised by name AND by its official URL — an admin mount named
    `github` towards another host gets nothing (review of clodia-tools#393)."""
    entries = _CORE_BACKEND_CREDENTIALS.get(slug)
    if not entries:
        return set()
    try:
        from .tools_api import GITHUB_MCP_URL
    except Exception:  # noqa: BLE001
        return set()
    official = {"github": GITHUB_MCP_URL}.get(slug)
    if not official or str(b.get("url") or "").rstrip("/") != official.rstrip("/"):
        return set()
    return set(entries)


def _pack_bound_credentials(pack: str) -> set[str]:
    """The vault entries the VALIDATED connectors of `pack` declare
    (`providers[].credential.vault_entry`), exact names only.

    From the resolved registry, never from the raw manifest: there each entry
    has passed `vault_entry_problem` (inside the connector's own namespace,
    never a core prefix) and foreign claims on first-party connectors are
    stripped — so a pack cannot grant itself `github_pat`, `provider_*` or
    another backend's `mcp_*` by writing it (review of clodia-tools#393)."""
    out: set[str] = set()
    try:
        from .connectors import resolved
        reg = resolved.registry()
    except Exception:  # noqa: BLE001 — unreadable: nothing bound
        return out
    for c in reg.connectors:
        for p in c.providers:
            if p.pack == pack and p.credential and p.credential.vault_entry:
                out.add(p.credential.vault_entry)
    # A former builtin connector that THIS pack serves: its credential, from
    # the gateway's own table (`builtin.ADOPTED_VAULT_ENTRIES`) — the pack's
    # connector may not be held yet: the adoption of the legacy mount.
    try:
        from .connectors import builtin as _bi
        out |= _bi.released_vault_entries(pack)
    except Exception:  # noqa: BLE001
        pass
    return out


def vault_refs_problem(b: dict) -> str | None:
    """Why this backend may NOT read the vault entries it references, or None
    (clodia-platform#568).

    A backend reads only its OWN credentials (`mcp_<slug>_*`, `mcp_cred_<slug>`,
    `mcp_oauth_<slug>`) or those a connector manifest of the SAME pack binds
    (it-pack's `github` → `github_pat`). Before, `${VAULT:github_pat}` in any
    mounted backend's header sent that secret to the backend's host."""
    slug = str(b.get("name") or "")
    # EVERY field: `_resolve_secrets` resolves the whole backend (`auth`,
    # `command`… included), so the check covers the same set.
    refs = _vault_ref_names(b)
    if not refs:
        return None
    pack = str(b.get("pack") or "")
    bound = (_pack_bound_credentials(pack) if pack else _core_bound(b, slug))
    altrui = sorted(
        n for n in refs
        if not (n.startswith(f"mcp_{slug}_") or n in (f"mcp_cred_{slug}", f"mcp_oauth_{slug}")
                or n in bound))
    if not altrui:
        return None
    return (f"il backend MCP '{slug}' fa riferimento a credenziali che non sono sue "
            f"({', '.join(altrui)}): un backend legge solo le proprie "
            "(mcp_<nome>_*, mcp_cred_<nome>, mcp_oauth_<nome>) o quelle che un "
            "connettore del suo stesso pack dichiara")


class ResponseTooLarge(Exception):
    """A backend answered more bytes than its caller allows (#641 review)."""


def _bounded_http_factory(limit: int, tripped: "asyncio.Event"):
    """An `httpx_client_factory` for `streamablehttp_client` whose responses
    stop being read past `limit` bytes IN TOTAL for the session (#641 review).

    The MCP client buffers a whole response before the caller sees it, so a
    cap checked on the answer is checked after the memory is spent: a hostile
    transport could stream gigabytes into the gateway. Here the count is on
    the wire: past the limit the stream raises and `tripped` is set, which the
    caller (`call_backend_tool_sync`) watches to fail at once instead of
    waiting for its timeout.
    """
    import httpx

    class _Counting(httpx.AsyncByteStream):
        def __init__(self, inner, state):
            self._inner, self._state = inner, state

        async def __aiter__(self):
            async for chunk in self._inner:
                self._state["n"] += len(chunk)
                if self._state["n"] > limit:
                    tripped.set()
                    raise ResponseTooLarge(f"backend answer over {limit} bytes")
                yield chunk

        async def aclose(self):
            await self._inner.aclose()

    class _Bounded(httpx.AsyncBaseTransport):
        def __init__(self):
            self._inner = httpx.AsyncHTTPTransport()
            self._state = {"n": 0}

        async def handle_async_request(self, request):
            resp = await self._inner.handle_async_request(request)
            return httpx.Response(resp.status_code, headers=resp.headers,
                                  stream=_Counting(resp.stream, self._state),
                                  extensions=resp.extensions)

        async def aclose(self):
            await self._inner.aclose()

    def factory(headers=None, timeout=None, auth=None):
        kwargs: dict = {"timeout": timeout or httpx.Timeout(30, read=300),
                        "transport": _Bounded()}
        if headers is not None:
            kwargs["headers"] = headers
        if auth is not None:
            kwargs["auth"] = auth
        return httpx.AsyncClient(**kwargs)

    return factory


@asynccontextmanager
async def session(b: dict, *, oauth_handlers: tuple | None = None,
                  oauth_redirect: str | None = None,
                  max_bytes: int | None = None, tripped=None):
    """Apre una ClientSession verso il backend (stdio o http). I secret
    ${VAULT:cred} in env/headers/url/args sono risolti dal vault qui, al volo.

    Un backend http con `auth: {type: oauth}` non porta nessun segreto nel
    config: l'header lo compone `mcp_oauth`, dai token nella vault, con refresh
    automatico (clodia-platform#532). `oauth_handlers` lo passa SOLO il consenso
    guidato dalla card — in una chiamata di tool resta None, e un backend non
    ancora autorizzato fallisce invece di aprire un consenso che nessuno può dare.
    """
    # La credenziale inserita al «Connetti» (#565) entra qui come `${VAULT:…}`,
    # e la risolve la riga dopo come ogni altro segreto del backend.
    b = mcp_credentials.apply(b)
    # At every start, not only at mount: entries persisted before #568 are
    # checked too, and a pack that loses a connector loses its credential.
    _why = vault_refs_problem(b)
    if _why:
        LOG.error("mcp: %s — sessione rifiutata", _why)
        raise PermissionError(_why)
    b = _resolve_secrets(b)
    transport = b.get("transport", "stdio")
    if transport == "stdio":
        # `runtime_env` e non `os.environ`: i backend stdio sono i server MCP dei
        # pack, e le loro dipendenze stanno nel venv/prefix npm persistenti che
        # `packs.install_pip`/`install_npm` popolano. Senza questo PATH/PYTHONPATH
        # erano installate sul volume ma invisibili al processo che doveva
        # usarle, e il pack funzionava solo finché la stessa libreria era anche
        # nell'immagine del gateway — che ogni rebuild azzera
        # (clodia-platform#451). Da #540 la base è costruita da zero
        # (`mcp_backend_env`): nessun segreto del gateway arriva al processo di
        # un pack. L'`env` del backend resta l'ultima parola.
        params = StdioServerParameters(
            command=b["command"],
            args=b.get("args", []),
            # From zero, not the gateway's own environment (#540).
            env={**pack_runtime.mcp_backend_env(), **(b.get("env") or {})},
        )
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as s:
                await s.initialize()
                yield s
    elif transport == "http":
        auth = mcp_oauth.provider_for(b, handlers=oauth_handlers, redirect=oauth_redirect)
        extra: dict = {}
        if max_bytes is not None and tripped is not None:
            # Bounded on the wire (#641 review): see `_bounded_http_factory`.
            # A stdio backend is a process of the pack on this host; its pipe
            # is not bounded here.
            extra["httpx_client_factory"] = _bounded_http_factory(max_bytes, tripped)
        async with streamablehttp_client(b["url"], headers=b.get("headers"),
                                         auth=auth, **extra) as (read, write, _):
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


def rifiuto_http(e: BaseException) -> "httpx.HTTPStatusError | None":
    """Un 401/403 del backend dentro un guasto, anche annidato (clodia-platform#533).

    Stesso srotolamento di `riautorizzazione`: un backend senza `auth` che
    risponde 401 risale come `HTTPStatusError` dentro il gruppo di eccezioni di
    anyio, e il «Test» mostrava «unhandled errors in a TaskGroup (1
    sub-exception)» — il proprietario ha rimontato il server due volte perché
    niente sullo schermo diceva cosa non andava.
    """
    if isinstance(e, httpx.HTTPStatusError) and e.response is not None \
            and e.response.status_code in (401, 403):
        return e
    for sub in getattr(e, "exceptions", ()) or ():
        found = rifiuto_http(sub)
        if found is not None:
            return found
    cause = e.__cause__ or e.__context__
    return rifiuto_http(cause) if cause is not None else None


# ── Backend che rifiutano: «montato» non è «connesso» (clodia-platform#533) ──
#
# Un backend http senza `auth` era `connected: true` per costruzione, anche
# quando ogni chiamata prendeva 401. Qui si ricorda, per backend, l'ultimo
# rifiuto di autenticazione visto (Test, chiamata di tool, elenco dei tool) e
# lo si dimentica al primo successo, o quando il backend cambia (rimount,
# «Connetti», consenso concluso). La card e `runtime.mcp_servers` lo leggono:
# stessa regola di #451 per le dipendenze pip mancanti. In memoria: dopo un
# restart il primo Test o la prima chiamata lo ritrovano.
#
# Mai un valore di header o un token: solo lo status, se il server annuncia
# OAuth, e un messaggio scritto qui.

_AUTH_FAILURES: dict[str, dict] = {}


def auth_failure(name: str) -> dict | None:
    return _AUTH_FAILURES.get(str(name or ""))


def record_auth_failure(name: str, info: dict) -> None:
    _AUTH_FAILURES[str(name)] = {
        "status": info.get("status"),
        "oauth": bool(info.get("oauth")),
        "detail": str(info.get("detail") or "")[:300],
    }


def clear_auth_failure(name: str) -> None:
    _AUTH_FAILURES.pop(str(name or ""), None)


async def spiega_rifiuto(name: str, b: dict, err: "httpx.HTTPStatusError") -> dict:
    """Il rifiuto di un backend, letto: OAuth annunciato o credenziale sbagliata.

    Usa gli header della risposta VERA (nessuna nuova richiesta al server MCP),
    più i metadati pubblici che quegli header indicano. Lo ricorda per la card.
    """
    status = err.response.status_code
    try:
        info = await mcp_oauth.detect(str(b.get("url") or ""), status=status,
                                      headers=err.response.headers)
    except Exception as e:  # noqa: BLE001 — la diagnosi non deve diventare un altro guasto
        LOG.warning("mcp: diagnosi del %s di '%s' fallita: %s", status, name, type(e).__name__)
        info = {"status": status, "oauth": False,
                "detail": f"{status} — il server rifiuta l'autenticazione"}
    if info.get("oauth") and mcp_oauth.auth_spec(b):
        # Già configurato OAuth e comunque rifiutato: il consenso va rifatto.
        info["detail"] = (f"{status} — il token OAuth è stato rifiutato: "
                          "serve un nuovo consenso («Riautorizza»)")
    elif info.get("oauth") and b.get("headers"):
        info["detail"] = (
            f"{status} — il server annuncia OAuth (RFC 9728) e rifiuta l'header statico: "
            "rimonta il server con \"auth\": {\"type\": \"oauth\"} e senza quell'header")
    record_auth_failure(name, info)
    return info


class ToolDisabled(PermissionError):
    """A tool an admin switched off in Tools (#633)."""


def is_disabled(name: str) -> bool:
    """True if `name` (`<backend>.<tool>`) is a backend tool disabled on this
    instance (#633). Whoever asks: it is not a per-agent rule."""
    if NS_SEP not in name:
        return False
    backend, tool = name.split(NS_SEP, 1)
    from . import whitelist as _wl
    return tool in _wl.disabled_backend_tools(backend)


def disabled_refusal(name: str) -> str:
    return (f"'{name}' is disabled on this instance: an admin switched it off "
            "in Tools (the MCP server's Test list). No room, rule or approval "
            "re-enables it; only an admin can, from there.")


def is_proxied(name: str) -> bool:
    """True se ``name`` appartiene a un backend montato (namespace)."""
    if NS_SEP not in name:
        return False
    return name.split(NS_SEP, 1)[0] in _backends()


#: Quanto aspettare un backend MCP prima di dichiararlo irraggiungibile.
#: Stesso ordine di grandezza dei test HTTP dei connettori nativi in
#: tools_api.py (15s): un backend di terzi lento non deve bloccare la UI.
TEST_TIMEOUT_S = 15


#: Cap on a tool description returned by the backend test (#575): it is a
#: third party's text, shown to the owner as plain text, never a payload.
TEST_DESCRIPTION_MAX = 300


async def test_backend(name: str) -> dict:
    """Verifica REALE di un backend MCP montato: apre una sessione (i secret
    ${VAULT:cred} sono risolti qui, come per ogni chiamata proxied) e lista i
    tool esposti. Mai il segreto nel risultato — solo ok/detail, e i NOMI dei
    tool con la loro descrizione (`tools`, #575): nessuno schema di input."""
    b = _backends().get(name)
    if b is None:
        return {"ok": None, "detail": "backend non montato"}
    try:
        async def _probe():
            async with _listing_env(name, b) as lb, _session(lb) as s:
                return await s.list_tools()
        res = await asyncio.wait_for(_probe(), timeout=TEST_TIMEOUT_S)
        # A live listing refreshes the read/write hints (#634), and the Test
        # list shows the classification the PDP uses (`read`).
        from . import authz_shadow, tool_hints
        tool_hints.record(name, res.tools)
        tools = [{"name": f"{name}{NS_SEP}{t.name}",
                  "description": str(t.description or "")[:TEST_DESCRIPTION_MAX],
                  "read": _is_read_verb(authz_shadow, f"{name}{NS_SEP}{t.name}")}
                 for t in res.tools]
        clear_auth_failure(name)
        return {"ok": True, "detail": f"{len(res.tools)} tool esposti", "tools": tools}
    except TimeoutError:
        return {"ok": False, "detail": f"nessuna risposta entro {TEST_TIMEOUT_S}s"}
    except Exception as e:  # noqa: BLE001 — qualunque guasto del backend è un esito, non un crash della API
        reauth = riautorizzazione(e)
        if reauth is not None:
            return {"ok": False, "detail": str(reauth)[:200], "needs_consent": True}
        rifiuto = rifiuto_http(e)
        if rifiuto is not None:
            info = await spiega_rifiuto(name, b, rifiuto)
            out = {"ok": False, "detail": info["detail"][:300], "status": info.get("status")}
            if info.get("oauth"):
                out["oauth_detected"] = True
            return out
        return {"ok": False, "detail": str(e)[:200]}


def _is_read_verb(authz_shadow, verb: str) -> bool:
    try:
        return authz_shadow.facts(verb, {})["kind"] == "read"
    except Exception:  # noqa: BLE001 — in doubt a verb writes
        return False


async def list_proxied_tools() -> list[Tool]:
    """Tutti i tool dei backend, namespaced. Cache per backend; un backend
    irraggiungibile viene saltato senza far cadere l'intera lista. Senza i
    tool disattivati in Tools (#633)."""
    from . import tool_hints
    from . import whitelist as _wl
    tools: list[Tool] = []
    for name, b in _backends().items():
        if _is_transport(name):
            # A provider transport (#523) is a socket of the gateway, not a
            # verb: never listed, whoever asks — see `main._check_not_transport`.
            continue
        if name not in _TOOL_CACHE:
            try:
                async with _listing_env(name, b) as lb, _session(lb) as s:
                    res = await s.list_tools()
                    # The annotations are kept beside the cache, not on the
                    # Tools offered to agents: they feed the PDP (#634).
                    tool_hints.record(name, res.tools)
                    _TOOL_CACHE[name] = [
                        Tool(
                            name=f"{name}{NS_SEP}{t.name}",
                            description=f"[{name}] {t.description or ''}".strip(),
                            inputSchema=_with_instance_arg(name, t.inputSchema),
                        )
                        for t in res.tools
                    ]
            except Exception as e:
                _TOOL_CACHE[name] = []  # backend down: cache vuota (riprovabile a restart)
                tool_hints.clear(name)
                rifiuto = rifiuto_http(e)
                if rifiuto is not None:
                    try:
                        await spiega_rifiuto(name, b, rifiuto)
                    except Exception:  # noqa: BLE001 — la lista non cade per una diagnosi
                        pass
        # Disabled tools (#633) are withheld here, not in the cache: the
        # toggle takes effect at once, with no backend round trip.
        off = {f"{name}{NS_SEP}{t}" for t in _wl.disabled_backend_tools(name)}
        # A backend shadowed by a serving gateway component (#713) keeps its
        # other tools; the ones the component serves are withheld here.
        tools.extend(t for t in _TOOL_CACHE[name]
                     if t.name not in off and not _is_transport(t.name))
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
    # Second line of #633: `main.call_tool` refuses first, this holds for any
    # other path that reaches a backend on an agent's behalf.
    if is_disabled(name):
        raise ToolDisabled(disabled_refusal(name))
    # A pack MCP bound to a datastore structure works on the instance of the
    # caller's scope (#686): resolved here, per call, or refused.
    b, arguments = bind_instances(backend_name, b, arguments)
    try:
        async with _session(b) as s:
            res = await s.call_tool(tool_name, arguments)
            clear_auth_failure(backend_name)
            return _cappa(_response_text(res.content), name)
    except Exception as e:
        # Un backend OAuth non ancora autorizzato non è un guasto misterioso:
        # è una cosa che una persona deve fare nella card. Dillo con quelle
        # parole, invece di lasciare risalire il gruppo di eccezioni di anyio.
        reauth = riautorizzazione(e)
        if reauth is not None:
            raise reauth from None
        # Nemmeno un 401/403 di un backend senza `auth` (#533): la card smette
        # di dirlo connesso, e chi chiama legge perché.
        rifiuto = rifiuto_http(e)
        if rifiuto is None:
            raise
        info = await spiega_rifiuto(backend_name, b, rifiuto)
        raise mcp_oauth.ReauthorizationRequired(
            f"server MCP '{backend_name}': {info['detail']}") from None


#: Margin over the caller's own timeout for opening the session: a stdio
#: backend is spawned per call (v1), and the transport's `timeout` is the
#: budget of the OPERATION, not of the process start.
TRANSPORT_SESSION_MARGIN_S = 30


class BackendToolError(RuntimeError):
    """A backend tool answered with `isError`, or could not be reached."""


class BackendResponseTooLarge(BackendToolError):
    """The backend's answer went past the caller's `max_bytes` (#641 review)."""


class BackendUnavailable(BackendToolError):
    """The backend is not mounted, or did not answer in time (#641: a relay
    caller tells this — «try later», 503 — from a tool's own `isError`)."""


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
                           timeout: float, *, max_bytes: int | None = None,
                           margin: float | None = None,
                           entry: dict | None = None) -> str:
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

    #641: `max_bytes` bounds an http backend's answer ON THE WIRE
    (`BackendResponseTooLarge`, read no further); `margin` replaces the session
    margin added to `timeout` (a relay keeps it small, under the agent-server
    client's own timeout); `entry` is the mount entry the caller already
    resolved and checked — used as is, not looked up a second time.
    """
    b = entry if entry is not None else _backend_named(backend)
    if b is None:
        raise BackendUnavailable(f"backend MCP '{backend}' non montato")
    budget = float(timeout) + (TRANSPORT_SESSION_MARGIN_S if margin is None
                               else float(margin))

    async def _go() -> str:
        tripped = asyncio.Event()
        kw = {"max_bytes": max_bytes, "tripped": tripped} \
            if max_bytes is not None else {}

        async def _call():
            async with _session(b, **kw) as s:
                return await s.call_tool(tool, arguments)
        task = asyncio.ensure_future(_call())
        waiter = asyncio.ensure_future(tripped.wait())
        try:
            done, _pending = await asyncio.wait(
                {task, waiter}, timeout=budget,
                return_when=asyncio.FIRST_COMPLETED)
        finally:
            waiter.cancel()
        if task not in done:
            task.cancel()
            try:
                await task
            except BaseException:  # noqa: BLE001 — being torn down on purpose
                pass
            if tripped.is_set():
                raise BackendResponseTooLarge(
                    f"{backend}.{tool}: risposta oltre {max_bytes} byte")
            raise BackendUnavailable(
                f"{backend}.{tool}: nessuna risposta entro {int(budget)}s")
        if tripped.is_set():
            raise BackendResponseTooLarge(
                f"{backend}.{tool}: risposta oltre {max_bytes} byte")
        res = task.result()
        text = _response_text(res.content)
        if getattr(res, "isError", False):
            err = BackendToolError(f"{backend}.{tool}: {text[:500]}")
            err.text = text      # the tool's own answer, for a caller that relays it
            raise err
        return text

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_go())
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: asyncio.run(_go())).result()

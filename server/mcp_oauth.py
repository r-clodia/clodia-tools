"""OAuth 2.1 per i backend MCP montati (clodia-platform#532).

Il mount di un MCP remoto conosceva solo **segreti statici**: `headers` con un
token dentro, al più nascosto dietro `${VAULT:cred}`. Un servizio che parla
OAuth (Lovable e simili) non si poteva montare: non c'è nessun token da
incollare, il token lo emette un authorization server al termine di un consenso.

Qui NON è riscritto un client OAuth. L'SDK `mcp` che il gateway già usa ne
contiene uno conforme — `mcp.client.auth.OAuthClientProvider`: discovery dei
metadata (RFC 9728 + RFC 8414), dynamic client registration (RFC 7591),
authorization code + PKCE, `resource` (RFC 8707), refresh. Questo modulo mette
sotto quel client le due cose che il gateway deve dare di suo:

1. **dove stanno i segreti** — una `TokenStorage` su vault, così client
   registrato, access token e refresh token non toccano mai `config.yaml`;
2. **come si chiede il consenso senza un browser** — il gateway non ha una URL
   pubblica su cui ricevere il redirect, quindi il consenso segue la stessa
   strada del connettore Google: l'URL di autorizzazione esce dalla card, la
   persona autorizza, atterra sul loopback e incolla indietro la URL. Il `code`
   e lo `state` si leggono da lì.

Fuori dal consenso (cioè in ogni chiamata di tool) il provider NON è
interattivo: se i token mancano o non sono rinnovabili la chiamata fallisce con
`ReauthorizationRequired`, che è l'esito giusto dentro un turno — un agente non
può aprire un browser, e fingere che il backend sia su è il difetto che #451 ha
già pagato una volta.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
from mcp.client.auth import OAuthClientProvider
from mcp.client.auth.utils import (
    build_oauth_authorization_server_metadata_discovery_urls,
    build_protected_resource_metadata_discovery_urls,
    create_oauth_metadata_request,
    handle_auth_metadata_response,
    handle_protected_resource_response,
    validate_metadata_issuer,
)
from mcp.shared.auth import (
    OAuthClientInformationFull,
    OAuthClientMetadata,
    OAuthMetadata,
    OAuthToken,
    ProtectedResourceMetadata,
)

from . import vault

LOG = logging.getLogger("clodia-tools.mcp_oauth")

#: Redirect di default: loopback, come il connettore Google
#: (`google_oauth.DEFAULT_REDIRECT`). Il gateway non è raggiungibile dal
#: browser su una URL stabile, quindi nessuno "riceve" davvero questo redirect:
#: serve solo a far atterrare la URL con `code` e `state` nella barra degli
#: indirizzi, da cui la persona la incolla nella card. Sovrascrivibile con
#: `CLODIA_MCP_OAUTH_REDIRECT` o, per singolo server, con `auth.redirect_uri`.
DEFAULT_REDIRECT = "http://127.0.0.1:8000/oauth/mcp/callback"

#: Nome con cui il client si registra all'authorization server (RFC 7591).
DEFAULT_CLIENT_NAME = "Clodia gateway"

#: Quanto resta aperto un consenso iniziato e mai concluso.
FLOW_TTL_S = 600

_ENV_REDIRECT = "CLODIA_MCP_OAUTH_REDIRECT"


class ReauthorizationRequired(RuntimeError):
    """Il backend vuole un consenso che solo una persona può dare."""


def redirect_uri(auth: dict | None = None) -> str:
    import os
    if isinstance(auth, dict) and auth.get("redirect_uri"):
        return str(auth["redirect_uri"])
    return (os.environ.get(_ENV_REDIRECT) or "").strip() or DEFAULT_REDIRECT


# ── Config del backend ──────────────────────────────────────────────────────

def normalize_auth(raw: Any, *, transport: str) -> dict:
    """Valida il campo `auth` di un server mcp.json e lo normalizza.

    Fino a #532 un `auth` nel config veniva **ignorato in silenzio**: chi lo
    scriveva otteneva un backend montato e muto, e il sintomo arrivava molto
    dopo, come 401 dentro una chiamata di tool. Qui un `auth` che non sappiamo
    onorare è un errore di registrazione, non un no-op.
    """
    if isinstance(raw, str):
        raw = {"type": raw}
    if not isinstance(raw, dict):
        raise ValueError("'auth' deve essere una stringa o un oggetto")
    kind = str(raw.get("type") or "").strip().lower()
    if kind != "oauth":
        raise ValueError(f"tipo di auth non supportato: {kind or '(vuoto)'} — atteso 'oauth'")
    if transport != "http":
        raise ValueError("auth OAuth vale solo per i server http/sse, non per quelli stdio")
    out: dict[str, Any] = {"type": "oauth"}
    for key in ("scope", "client_name", "redirect_uri"):
        val = raw.get(key)
        if val:
            out[key] = str(val)
    return out


def auth_spec(backend: dict) -> dict | None:
    """Lo spec OAuth di un backend montato, o None se usa segreti statici."""
    auth = (backend or {}).get("auth")
    if isinstance(auth, str):
        auth = {"type": auth}
    if not isinstance(auth, dict):
        return None
    return auth if str(auth.get("type") or "").lower() == "oauth" else None


def credential_name(slug: str) -> str:
    return f"mcp_oauth_{slug}"


# ── Segreti: dove vivono i token ────────────────────────────────────────────

class VaultTokenStorage:
    """`TokenStorage` dell'SDK, con il bundle nella vault del gateway.

    Credenziale di **infrastruttura**: `grant_agents=[]`, nessun agente la può
    chiedere con `vault.get_secret`. Il token lo vede solo il proxy, al momento
    di comporre l'header verso il backend.
    """

    def __init__(self, slug: str):
        self.slug = slug
        self.credential = credential_name(slug)

    # — bundle —
    def _bundle(self) -> dict:
        if not vault.has_credential(self.credential):
            return {}
        try:
            return vault.read_internal(self.credential) or {}
        except Exception:  # noqa: BLE001 — una vault illeggibile è «non autorizzato», non un crash
            LOG.warning("mcp_oauth: bundle %s illeggibile", self.credential)
            return {}

    def _save(self, patch: dict) -> None:
        bundle = {**self._bundle(), **patch}
        vault.deposit(self.credential, bundle, cred_type="mcp_oauth", grant_agents=[])

    #: Scadenza assoluta dell'access token, o None se il server non l'ha detta.
    def expires_at(self) -> float | None:
        exp = self._bundle().get("expires_at")
        return float(exp) if isinstance(exp, (int, float)) else None

    # — protocollo TokenStorage —
    async def get_tokens(self) -> OAuthToken | None:
        raw = self._bundle().get("tokens")
        if not isinstance(raw, dict):
            return None
        try:
            return OAuthToken.model_validate(raw)
        except Exception:  # noqa: BLE001
            return None

    async def set_tokens(self, tokens: OAuthToken) -> None:
        # `expires_at` è calcolato QUI perché `expires_in` è una durata: salvata
        # da sola, dopo un restart non dice più niente. Senza, `is_token_valid()`
        # del provider crede valido per sempre un token scaduto e il 401 che ne
        # segue va in ri-autorizzazione completa invece che in refresh.
        patch: dict[str, Any] = {"tokens": tokens.model_dump(mode="json", exclude_none=True)}
        patch["expires_at"] = (time.time() + tokens.expires_in) if tokens.expires_in else None
        patch["obtained_at"] = time.time()
        self._save(patch)

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        raw = self._bundle().get("client_info")
        if not isinstance(raw, dict):
            return None
        try:
            return OAuthClientInformationFull.model_validate(raw)
        except Exception:  # noqa: BLE001
            return None

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self._save({"client_info": client_info.model_dump(mode="json", exclude_none=True)})

    # — metadati dell'authorization server (clodia-platform#538) —
    def metadata(self) -> dict:
        md = self._bundle().get("as_metadata")
        return md if isinstance(md, dict) else {}

    def save_metadata(self, md: dict) -> None:
        self._save({"as_metadata": md})


def forget(slug: str) -> bool:
    """Dimentica client registrato e token di un backend (smontaggio/reset)."""
    return vault.remove(credential_name(slug))


# ── Il provider ─────────────────────────────────────────────────────────────

class _Provider(OAuthClientProvider):
    """`OAuthClientProvider` che si ricorda QUANDO scade il token che ha letto.

    `_initialize` dell'SDK ricarica token e client dalla storage ma non la
    scadenza, che vive solo in memoria dal momento dello scambio: dopo un
    restart del gateway il provider crede valido un access token già morto,
    manda la richiesta, prende 401 e parte una ri-autorizzazione completa —
    che senza browser non può finire — mentre nella vault c'era un refresh
    token buono. Quattro righe qui e il refresh automatico funziona davvero.
    """

    async def _initialize(self) -> None:
        await super()._initialize()
        storage = self.context.storage
        if isinstance(storage, VaultTokenStorage):
            self.context.token_expiry_time = storage.expires_at()
            await self._restore_metadata(storage)

    # ── Metadati dell'authorization server (clodia-platform#538) ─────────────
    #
    # Il refresh dell'SDK prende il token endpoint da `context.oauth_metadata`;
    # se manca ripiega su `<origin del server MCP>/token`, che è giusto solo
    # quando AS e server MCP coincidono. Quei metadati l'SDK li scopre durante
    # il consenso e li tiene in memoria, e qui il provider nasce nuovo a ogni
    # sessione: senza salvarli, il primo refresh va a un endpoint inventato
    # (404 su Supabase per leads-mcp, 14 ott 2026) e ogni backend OAuth smette
    # di funzionare un'ora dopo il consenso.

    async def _restore_metadata(self, storage: "VaultTokenStorage") -> None:
        md = storage.metadata()
        try:
            if isinstance(md.get("oauth"), dict):
                self.context.oauth_metadata = OAuthMetadata.model_validate(md["oauth"])
            if isinstance(md.get("resource"), dict):
                self.context.protected_resource_metadata = (
                    ProtectedResourceMetadata.model_validate(md["resource"]))
            if md.get("auth_server_url"):
                self.context.auth_server_url = str(md["auth_server_url"])
        except Exception:  # noqa: BLE001 — metadati corrotti = da riscoprire, non un crash
            LOG.warning("mcp_oauth: metadati AS di %s illeggibili, li riscopro", storage.slug)
            self.context.oauth_metadata = None
        tokens = self.context.current_tokens
        if self.context.oauth_metadata is None and tokens is not None and tokens.refresh_token:
            # Credenziale salvata prima di #538: token e refresh token ci sono,
            # i metadati no. Li si riscopre una volta, con gli stessi helper e la
            # stessa verifica dell'issuer dell'SDK, invece di chiedere un nuovo
            # consenso per un refresh token buono.
            try:
                await self._discover_metadata()
            except Exception as e:  # noqa: BLE001 — senza metadati resta il percorso di prima
                LOG.warning("mcp_oauth: discovery dei metadati di %s fallita: %s", storage.slug, e)
                return
            self._persist_metadata()

    async def _discover_metadata(self) -> None:
        async with _discovery_client() as c:
            for url in build_protected_resource_metadata_discovery_urls(None, self.context.server_url):
                prm = await handle_protected_resource_response(
                    await c.send(create_oauth_metadata_request(url)))
                if prm:
                    await self._validate_resource_match(prm)
                    self.context.protected_resource_metadata = prm
                    self.context.auth_server_url = self._select_authorization_server(
                        [str(u) for u in prm.authorization_servers])
                    break
            expected = self._expected_issuer()
            for url in build_oauth_authorization_server_metadata_discovery_urls(
                    self.context.auth_server_url, self.context.server_url):
                ok, asm = await handle_auth_metadata_response(
                    await c.send(create_oauth_metadata_request(url)))
                if not ok:
                    break
                if asm:
                    validate_metadata_issuer(asm, expected)
                    self.context.oauth_metadata = asm
                    break

    def _persist_metadata(self) -> None:
        storage = self.context.storage
        if not isinstance(storage, VaultTokenStorage) or self.context.oauth_metadata is None:
            return
        md: dict[str, Any] = {
            "oauth": self.context.oauth_metadata.model_dump(mode="json", exclude_none=True)}
        if self.context.protected_resource_metadata is not None:
            md["resource"] = self.context.protected_resource_metadata.model_dump(
                mode="json", exclude_none=True)
        if self.context.auth_server_url:
            md["auth_server_url"] = self.context.auth_server_url
        if md != storage.metadata():
            storage.save_metadata(md)

    async def _handle_token_response(self, response: httpx.Response) -> None:
        await super()._handle_token_response(response)
        self._persist_metadata()

    async def _handle_refresh_response(self, response: httpx.Response) -> bool:
        ok = await super()._handle_refresh_response(response)
        if ok:
            self._persist_metadata()
        return ok


def _discovery_client() -> httpx.AsyncClient:
    """Client della discovery una tantum (sostituibile nei test)."""
    return httpx.AsyncClient(timeout=10.0, follow_redirects=True)


def client_metadata(auth: dict) -> OAuthClientMetadata:
    return OAuthClientMetadata.model_validate({
        "client_name": auth.get("client_name") or DEFAULT_CLIENT_NAME,
        "redirect_uris": [redirect_uri(auth)],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": auth.get("scope"),
        "token_endpoint_auth_method": "client_secret_post",
    })


def provider_for(backend: dict, *, handlers: tuple | None = None) -> _Provider | None:
    """Il provider httpx da passare al transport, o None se il backend non fa OAuth.

    `handlers` = `(redirect_handler, callback_handler)` e lo passa SOLO il
    consenso guidato dalla card. Senza, il provider non è interattivo: niente
    URL da aprire, niente attesa di un `code` — il che è esattamente ciò che
    serve dentro una chiamata di tool.
    """
    auth = auth_spec(backend)
    if not auth:
        return None
    slug = str(backend.get("name") or "")
    url = backend.get("url")
    if not url:
        raise ValueError(f"backend '{slug}': auth OAuth senza url")
    if handlers is None:
        handlers = (_refuse_redirect(slug), _refuse_callback(slug))
    return _Provider(
        server_url=str(url),
        client_metadata=client_metadata(auth),
        storage=VaultTokenStorage(slug),
        redirect_handler=handlers[0],
        callback_handler=handlers[1],
    )


def _refuse_redirect(slug: str):
    async def _handler(_url: str) -> None:
        raise ReauthorizationRequired(
            f"il server MCP '{slug}' richiede un consenso OAuth: aprilo dalla "
            f"pagina Tools con «Connetti». Nessun agente può autorizzarlo da sé.")
    return _handler


def _refuse_callback(slug: str):
    async def _handler() -> tuple[str, str | None]:  # pragma: no cover - mai raggiunto
        raise ReauthorizationRequired(f"server MCP '{slug}': consenso OAuth mancante")
    return _handler


# ── Stato leggibile dalla UI e dai verbi ────────────────────────────────────

def authorization_status(backend: dict) -> dict:
    """`{authorized, detail}` per un backend OAuth. Mai un pezzo di token.

    «Montato» non è «autorizzato»: un backend OAuth senza token è verde nella
    card solo se glielo lasciamo dire, e poi fallisce a ogni chiamata.
    """
    slug = str(backend.get("name") or "")
    bundle = VaultTokenStorage(slug)._bundle()
    tokens = bundle.get("tokens") if isinstance(bundle.get("tokens"), dict) else {}
    if not tokens.get("access_token"):
        return {"authorized": False, "detail": "mai autorizzato: serve il consenso OAuth"}
    exp = bundle.get("expires_at")
    scaduto = isinstance(exp, (int, float)) and time.time() > float(exp)
    if scaduto and not tokens.get("refresh_token"):
        return {"authorized": False,
                "detail": "token scaduto e non rinnovabile: serve un nuovo consenso"}
    return {"authorized": True,
            "detail": "token rinnovabile" if scaduto else "autorizzato"}


# ── Consenso guidato dalla card ─────────────────────────────────────────────

class _Flow:
    """Un consenso in corso: la richiesta che lo guida vive in un task a parte."""

    def __init__(self, slug: str):
        self.slug = slug
        self.url: asyncio.Future[str] = asyncio.get_running_loop().create_future()
        self.code: asyncio.Future[tuple[str, str | None]] = \
            asyncio.get_running_loop().create_future()
        self.task: asyncio.Task | None = None
        self.state: str | None = None
        self.exp = time.time() + FLOW_TTL_S


_flows: dict[str, _Flow] = {}


def _gc_flows() -> None:
    for state, flow in list(_flows.items()):
        if flow.exp < time.time():
            _flows.pop(state, None)
            if flow.task and not flow.task.done():
                flow.task.cancel()


def _state_of(auth_url: str) -> str | None:
    return (parse_qs(urlparse(auth_url).query).get("state") or [None])[0]


def code_from(raw: str) -> tuple[str, str | None]:
    """`code` e `state` da ciò che la persona incolla: la URL intera o il solo code.

    Incollare la URL è ciò che si fa davvero — il connettore Google accetta già
    entrambe le forme per la stessa ragione.
    """
    raw = (raw or "").strip()
    if raw.startswith("http"):
        q = parse_qs(urlparse(raw).query)
        if q.get("error"):
            raise ValueError(f"l'authorization server ha rifiutato: {q['error'][0]}")
        return (q.get("code") or [""])[0], (q.get("state") or [None])[0]
    return raw, None


async def begin(backend: dict) -> dict:
    """Avvia il consenso e ritorna `{state, auth_url}`.

    Il flusso OAuth dell'SDK è guidato dalla risposta 401 del server MCP, non
    da noi: apriamo una sessione vera in un task a parte, e quella sessione si
    ferma sulla `callback_handler` finché `finish` non le passa il `code`. Così
    discovery, registrazione del client, PKCE e scambio restano quelli
    dell'SDK, e in più il consenso che va a buon fine ha già dimostrato che il
    backend risponde.
    """
    _gc_flows()
    slug = str(backend.get("name") or "")
    auth = auth_spec(backend)
    if not auth:
        raise ValueError(f"il server MCP '{slug}' non è configurato con auth OAuth")
    flow = _Flow(slug)

    async def _redirect(url: str) -> None:
        flow.state = _state_of(url)
        if flow.state:
            _flows[flow.state] = flow
        if not flow.url.done():
            flow.url.set_result(url)

    async def _callback() -> tuple[str, str | None]:
        return await asyncio.wait_for(flow.code, timeout=FLOW_TTL_S)

    async def _drive() -> dict:
        from . import proxy  # import locale: proxy importa questo modulo
        try:
            async with proxy.session(backend, oauth_handlers=(_redirect, _callback)) as s:
                res = await s.list_tools()
                return {"ok": True, "detail": f"{len(res.tools)} tool esposti"}
        finally:
            if flow.state:
                _flows.pop(flow.state, None)

    flow.task = asyncio.ensure_future(_drive())
    done, _ = await asyncio.wait({flow.task, flow.url}, timeout=30,
                                 return_when=asyncio.FIRST_COMPLETED)
    if flow.url.done():
        return {"state": flow.state or "", "auth_url": flow.url.result(),
                "redirect_uri": redirect_uri(auth)}
    if flow.task in done:
        # Nessuna URL e il task è finito: o il backend non chiede OAuth (401 mai
        # arrivato) o è caduto. In entrambi i casi il dettaglio sta lì.
        try:
            res = flow.task.result()
        except Exception as e:  # noqa: BLE001
            raise ValueError(f"il consenso non è partito: {str(e)[:200]}") from e
        raise ValueError("il server MCP non ha chiesto nessuna autorizzazione: "
                         f"risponde già senza OAuth ({res.get('detail')})")
    flow.task.cancel()
    raise ValueError("nessuna URL di autorizzazione entro 30s: il server MCP non risponde")


async def finish(state: str, raw_code: str) -> dict:
    """Consegna `code` (+ `state`) al consenso in attesa e aspetta l'esito."""
    _gc_flows()
    code, url_state = code_from(raw_code)
    state = (state or url_state or "").strip()
    flow = _flows.get(state)
    if flow is None:
        raise ValueError("nessun consenso in attesa per questo state "
                         "(scaduto, già concluso, o gateway riavviato): rilancia «Connetti»")
    if url_state and state and url_state != state:
        raise ValueError("lo state della URL incollata non è quello del consenso in corso")
    if not code:
        raise ValueError("manca il parametro 'code' nella URL incollata")
    if not flow.code.done():
        flow.code.set_result((code, url_state or state))
    assert flow.task is not None
    try:
        res = await asyncio.wait_for(asyncio.shield(flow.task), timeout=60)
    except TimeoutError as e:
        raise ValueError("scambio del token non concluso entro 60s") from e
    return {"connected": True, "server": flow.slug, **res}

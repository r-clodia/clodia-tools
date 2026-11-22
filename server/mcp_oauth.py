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
2. **come torna il consenso** — l'URL di autorizzazione esce dalla card, la
   persona autorizza e il browser torna alla webui (`/tools/oauth/callback`,
   clodia-platform#534), che inoltra `code` e `state` a `oauth/complete`. Resta
   il ritorno al loopback con la URL da incollare, per gli authorization server
   che rifiutano una redirect http non-loopback.

E una terza (clodia-platform#533): **riconoscere un server che vuole OAuth** dal
suo 401 (`WWW-Authenticate` + RFC 9728), invece di montarlo come un backend a
header statici che fallisce a ogni chiamata.

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
from pydantic import PrivateAttr
from mcp.client.auth import OAuthClientProvider
from mcp.client.auth.utils import (
    build_oauth_authorization_server_metadata_discovery_urls,
    build_protected_resource_metadata_discovery_urls,
    create_oauth_metadata_request,
    extract_resource_metadata_from_www_auth,
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
    for key in ("scope", "client_name", "redirect_uri", "authorization_server"):
        val = raw.get(key)
        if val:
            out[key] = str(val)
    return out


def credential_cred_name(slug: str) -> str:
    """Bundle della credenziale inserita al «Connetti» (clodia-platform#565)."""
    return f"mcp_cred_{slug}"


def auth_spec(backend: dict) -> dict | None:
    """Lo spec OAuth di un backend montato, o None se non fa OAuth.

    Con `auth.methods` (clodia-platform#565) è il metodo `oauth` della lista —
    ma None se il backend è connesso con la credenziale inserita: allora il
    provider OAuth non deve nemmeno nascere, l'header lo mette l'iniezione.
    """
    auth = (backend or {}).get("auth")
    if isinstance(auth, str):
        auth = {"type": auth}
    if not isinstance(auth, dict):
        return None
    if isinstance(auth.get("methods"), list):
        oauth = next((m for m in auth["methods"] if isinstance(m, dict)
                      and str(m.get("type") or "").lower() == "oauth"), None)
        if oauth is None:
            return None
        has_cred = any(isinstance(m, dict) and m.get("type") == "credential"
                       for m in auth["methods"])
        slug = str((backend or {}).get("name") or "")
        if has_cred and vault.has_credential(credential_cred_name(slug)):
            return None
        return oauth
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

    @staticmethod
    def _token_patch(tokens: OAuthToken) -> dict[str, Any]:
        # `expires_at` è calcolato QUI perché `expires_in` è una durata: salvata
        # da sola, dopo un restart non dice più niente. Senza, `is_token_valid()`
        # del provider crede valido per sempre un token scaduto e il 401 che ne
        # segue va in ri-autorizzazione completa invece che in refresh.
        patch: dict[str, Any] = {"tokens": tokens.model_dump(mode="json", exclude_none=True)}
        patch["expires_at"] = (time.time() + tokens.expires_in) if tokens.expires_in else None
        patch["obtained_at"] = time.time()
        return patch

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self._save(self._token_patch(tokens))

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


class _ConsentStorage(VaultTokenStorage):
    """La storage di UN consenso guidato dalla card (clodia-platform#534).

    Due differenze da `VaultTokenStorage`, entrambe per la redirect URI:

    - un client registrato per un'altra redirect URI non si riusa: l'AS
      rifiuterebbe il ritorno (o peggio lo accetterebbe solo verso la vecchia).
      Allora `get_client_info` dice «nessun client» e l'SDK si registra di nuovo
      (RFC 7591) con quella giusta — è il «re-register if a new allowed origin
      appears» della issue;
    - il client registrato durante il consenso resta IN MEMORIA finché non ci
      sono i token, e va nella vault insieme a loro con una sola scrittura. Un
      consenso abbandonato a metà (o uno `state` falso) non lascia niente: non
      sostituisce il client con cui il refresh token salvato è ancora buono.
    """

    def __init__(self, slug: str, redirect: str):
        super().__init__(slug)
        self.redirect = redirect
        self._pending_client: OAuthClientInformationFull | None = None

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        if self._pending_client is not None:
            return self._pending_client
        info = await super().get_client_info()
        if info is None:
            return None
        uris = [str(u) for u in (info.redirect_uris or [])]
        return info if self.redirect in uris else None

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self._pending_client = client_info

    async def set_tokens(self, tokens: OAuthToken) -> None:
        patch = self._token_patch(tokens)
        if self._pending_client is not None:
            patch["client_info"] = self._pending_client.model_dump(mode="json", exclude_none=True)
        self._save(patch)


def forget(slug: str) -> bool:
    """Dimentica client registrato e token di un backend (smontaggio/reset)."""
    return vault.remove(credential_name(slug))


# ── Quale authorization server (clodia-platform#566) ────────────────────────

#: Suffissi di un documento di metadata (RFC 8414 §3, OIDC Discovery §4).
_METADATA_SUFFIXES = ("/.well-known/oauth-authorization-server",
                      "/.well-known/openid-configuration")


def issuer_of(advertised: str) -> str:
    """L'issuer dietro una voce di `authorization_servers`.

    RFC 9728 vuole lì l'**issuer** dell'authorization server. Invoicetronic
    (17 ott 2026) ci scrive invece la URL del suo documento di metadata,
    `https://mcp.invoicetronic.com/.well-known/oauth-authorization-server`:
    l'SDK ci costruisce sopra la discovery path-aware, prende 404 ovunque,
    ripiega su `/register` all'origin — che lì non esiste — e il consenso non
    parte. Togliere il suffisso ridà l'issuer; la verifica dell'issuer
    (`validate_metadata_issuer`) resta quella dell'SDK, quindi un server che
    pubblica metadati con un altro issuer viene ancora rifiutato.

    Copre anche la forma con path inserito (RFC 8414 §3.1):
    `https://h/.well-known/oauth-authorization-server/tenant` → `https://h/tenant`.
    """
    raw = str(advertised or "")
    parsed = urlparse(raw)
    path = parsed.path or ""
    for suffix in _METADATA_SUFFIXES:
        if path.rstrip("/").endswith(suffix):
            path = path.rstrip("/")[: -len(suffix)]
        elif path.startswith(suffix + "/"):
            path = path[len(suffix):].rstrip("/")
        else:
            continue
        return f"{parsed.scheme}://{parsed.netloc}{path}"
    return raw


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

    #: `auth.authorization_server` del backend: scavalca ciò che il server
    #: annuncia, per i server i cui metadati sono rotti in un modo che
    #: `issuer_of` non sa riparare (clodia-platform#566).
    authorization_server: str | None = None

    def _select_authorization_server(self, advertised: list[str]) -> str:
        if self.authorization_server:
            # Vale solo quando il server pubblica il protected-resource
            # metadata: è l'unico momento in cui l'SDK chiede quale AS usare.
            return issuer_of(self.authorization_server)
        return issuer_of(super()._select_authorization_server(advertised))

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


class _PinnedScopeMetadata(OAuthClientMetadata):
    """Metadati del client il cui `scope`, se dichiarato, non si allarga.

    Al passo 3 del flusso l'SDK (mcp 1.30) RISCRIVE `client_metadata.scope`
    con la «scope selection strategy» della spec MCP: lo scope del
    `WWW-Authenticate` o, in mancanza, TUTTI gli `scopes_supported` del
    protected-resource metadata. Lo scope dichiarato dall'owner nel backend
    veniva così buttato: `invoicetronic:read` diventava
    `invoicetronic:read invoicetronic:write` (clodia-platform#566, scoperto dal
    test). Uno scope scelto per restringere i permessi è una decisione
    dell'owner, non un suggerimento: qui l'assegnazione viene ignorata. Senza
    scope dichiarato resta la strategia dell'SDK.
    """

    _declared: bool = PrivateAttr(default=False)

    def __setattr__(self, name, value):
        if name == "scope" and self._declared:
            return
        super().__setattr__(name, value)


def client_metadata(auth: dict, redirect: str | None = None) -> OAuthClientMetadata:
    md = _PinnedScopeMetadata.model_validate({
        "client_name": auth.get("client_name") or DEFAULT_CLIENT_NAME,
        "redirect_uris": [redirect or redirect_uri(auth)],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "scope": auth.get("scope"),
        "token_endpoint_auth_method": "client_secret_post",
    })
    md._declared = bool(auth.get("scope"))
    return md


def provider_for(backend: dict, *, handlers: tuple | None = None,
                 redirect: str | None = None) -> _Provider | None:
    """Il provider httpx da passare al transport, o None se il backend non fa OAuth.

    `handlers` = `(redirect_handler, callback_handler)` e lo passa SOLO il
    consenso guidato dalla card. Senza, il provider non è interattivo: niente
    URL da aprire, niente attesa di un `code` — il che è esattamente ciò che
    serve dentro una chiamata di tool.

    `redirect` lo passa solo il consenso (clodia-platform#534): la redirect URI
    di QUEL consenso, con la sua storage (`_ConsentStorage`).
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
    storage = _ConsentStorage(slug, redirect) if redirect else VaultTokenStorage(slug)
    provider = _Provider(
        server_url=str(url),
        client_metadata=client_metadata(auth, redirect),
        storage=storage,
        redirect_handler=handlers[0],
        callback_handler=handlers[1],
    )
    provider.authorization_server = auth.get("authorization_server") or None
    return provider


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


# ── Dove torna il browser dopo il consenso (clodia-platform#534) ────────────
#
# Fino a #534 la redirect URI era un loopback su cui non ascoltava nessuno, e la
# persona doveva copiare la URL d'atterraggio nella card. Una redirect URI deve
# essere raggiungibile dal BROWSER di chi autorizza, non da internet: e quel
# browser raggiunge già la webui. Il consenso torna quindi a una pagina della
# webui sulla stessa origin da cui è partito, che inoltra `code` e `state` a
# `oauth/complete`. L'origin la manda la webui a `oauth/start`, e qui si
# controlla: senza il controllo `start` registrerebbe all'authorization server
# una redirect URI qualsiasi, e il `code` di un consenso andrebbe a chi l'ha
# scelta.

#: La pagina della webui che riceve il ritorno del consenso.
CALLBACK_PATH = "/tools/oauth/callback"

#: Dove si torna se la pagina di partenza non è ammessa (o non è detta).
DEFAULT_RETURN = "/tools"

#: Pagine della webui da cui un consenso può partire, e a cui può tornare.
RETURN_PREFIXES = ("/tools", "/packs", "/topics", "/databases", "/settings", "/agents")

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _origin_of(raw: str) -> tuple[str, str]:
    """`(origin normalizzata, host)` di un'origin web, o ValueError.

    Un'origin è schema + host + porta e nient'altro: niente credenziali, path,
    query o frammento — un `https://a@evil/` o un `https://ok/x?y` non sono
    l'origin di una pagina, sono un tentativo di farla sembrare tale.
    """
    from urllib.parse import urlsplit
    s = str(raw or "").strip()
    if not s or len(s) > 255 or any(c.isspace() or ord(c) < 0x20 for c in s):
        raise ValueError("origin mancante o non valida")
    p = urlsplit(s)
    if p.scheme not in ("http", "https"):
        raise ValueError("origin non valida: lo schema deve essere http o https")
    if p.username is not None or p.password is not None or p.path not in ("", "/") \
            or p.query or p.fragment or "\\" in s:
        raise ValueError("origin non valida: solo schema, host e porta")
    host = (p.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("origin non valida: manca l'host")
    try:
        port = p.port
    except ValueError as e:
        raise ValueError("origin non valida: porta") from e
    shown = f"[{host}]" if ":" in host else host
    return f"{p.scheme}://{shown}{f':{port}' if port else ''}", host


def _allowed_hosts() -> list[str]:
    import os
    return [h.strip().lower() for h in (os.environ.get("CLODIA_ALLOWED_HOSTS") or "").split(",")
            if h.strip()]


def callback_redirect(origin: str) -> str:
    """La redirect URI della webui per `origin`, se l'origin è dell'istanza.

    Ammesse, e nient'altro:
      - un loopback (`localhost`, `127.0.0.1`, `::1`): il browser sulla stessa
        macchina, come la webui sul Mac;
      - l'origin di `CLODIA_WEBUI_URL`, l'indirizzo pubblico della webui;
      - un host di `CLODIA_ALLOWED_HOSTS`, la stessa lista che la webui usa per
        i propri host (un elemento che inizia con `.` copre i sottodomini, come
        in vite). Il nome Tailscale con cui la si raggiunge da fuori sta qui.
    """
    import os
    norm, host = _origin_of(origin)
    ok = host in _LOOPBACK_HOSTS
    webui = (os.environ.get("CLODIA_WEBUI_URL") or "").strip()
    if not ok and webui:
        from urllib.parse import urlsplit
        w = urlsplit(webui)
        try:
            ok = _origin_of(f"{w.scheme}://{w.netloc}")[0] == norm
        except ValueError:
            ok = False
    if not ok:
        for entry in _allowed_hosts():
            if entry.startswith("."):
                if host == entry[1:] or host.endswith(entry):
                    ok = True
                    break
            elif host == entry:
                ok = True
                break
    if not ok:
        raise ValueError(
            f"origin {norm} non ammessa per il ritorno del consenso: non è un "
            "loopback, né CLODIA_WEBUI_URL, né un host di CLODIA_ALLOWED_HOSTS")
    return norm + CALLBACK_PATH


def safe_return_path(raw: Any) -> str:
    """La pagina della webui a cui tornare dopo il consenso, o `DEFAULT_RETURN`.

    Solo un path RELATIVO alla stessa origin e sotto una pagina che il consenso
    può davvero aver aperto: mai una URL assoluta, mai `//host` (che il browser
    legge come «altro host»), mai una barra rovesciata (che alcuni browser
    trattano come `/`), mai caratteri di controllo, mai la pagina di callback
    stessa. Tutto il resto torna a Tools: un ritorno sbagliato costa un clic,
    un open redirect costa il consenso.
    """
    from urllib.parse import urlsplit
    s = str(raw or "").strip()
    if not s or len(s) > 512 or not s.startswith("/") or s.startswith("//") \
            or "\\" in s or any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in s):
        return DEFAULT_RETURN
    p = urlsplit(s)
    if p.scheme or p.netloc:
        return DEFAULT_RETURN
    path = p.path
    if path.startswith(CALLBACK_PATH) or ".." in path.split("/"):
        return DEFAULT_RETURN
    if not any(path == pre or path.startswith(pre + "/") for pre in RETURN_PREFIXES):
        return DEFAULT_RETURN
    return s


# ── Consenso guidato dalla card ─────────────────────────────────────────────

class _Flow:
    """Un consenso in corso: la richiesta che lo guida vive in un task a parte.

    Lo `state` lo genera l'SDK (32 byte casuali) insieme al PKCE verifier, che
    non esce mai dal provider. Qui il consenso è anche LEGATO (#534): al
    backend, a chi l'ha avviato, alla redirect URI usata, e si consuma una
    volta sola.
    """

    def __init__(self, slug: str, *, principal: str = "", redirect: str = "",
                 mode: str = "paste", return_to: str = DEFAULT_RETURN):
        self.slug = slug
        self.principal = principal
        self.redirect = redirect
        self.mode = mode
        self.return_to = return_to
        self.used = False
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


async def begin(backend: dict, *, origin: str | None = None,
                return_to: str | None = None, principal: str = "") -> dict:
    """Avvia il consenso e ritorna `{state, auth_url, redirect_uri, mode, return_to}`.

    Il flusso OAuth dell'SDK è guidato dalla risposta 401 del server MCP, non
    da noi: apriamo una sessione vera in un task a parte, e quella sessione si
    ferma sulla `callback_handler` finché `finish` non le passa il `code`. Così
    discovery, registrazione del client, PKCE e scambio restano quelli
    dell'SDK, e in più il consenso che va a buon fine ha già dimostrato che il
    backend risponde.

    Con `origin` (clodia-platform#534) il consenso torna alla webui
    (`mode: "callback"`); senza, resta il loopback da incollare
    (`mode: "paste"`), che serve agli authorization server che rifiutano una
    redirect http non-loopback. Una `auth.redirect_uri` scritta nel backend è
    una scelta dell'owner e vince su entrambe.
    """
    _gc_flows()
    slug = str(backend.get("name") or "")
    auth = auth_spec(backend)
    if not auth:
        if vault.has_credential(credential_cred_name(slug)):
            raise ValueError(f"il server MCP '{slug}' è connesso con una credenziale: "
                             "«Disconnetti» prima di avviare un consenso OAuth")
        raise ValueError(f"il server MCP '{slug}' non è configurato con auth OAuth")
    if auth.get("redirect_uri"):
        redirect, mode = str(auth["redirect_uri"]), "paste"
    elif origin:
        redirect, mode = callback_redirect(origin), "callback"
    else:
        redirect, mode = redirect_uri(auth), "paste"
    flow = _Flow(slug, principal=principal, redirect=redirect, mode=mode,
                 return_to=safe_return_path(return_to))

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
            async with proxy.session(backend, oauth_handlers=(_redirect, _callback),
                                     oauth_redirect=redirect) as s:
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
                "redirect_uri": redirect, "mode": mode, "return_to": flow.return_to}
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


async def finish(state: str, raw_code: str, *, slug: str | None = None,
                 principal: str | None = None) -> dict:
    """Consegna `code` (+ `state`) al consenso in attesa e aspetta l'esito.

    Rifiuta, senza toccare la vault (clodia-platform#534):
      - uno `state` sconosciuto (falso, di un altro gateway, o già concluso);
      - uno scaduto (`FLOW_TTL_S`);
      - uno già consegnato (replay mentre lo scambio è in corso);
      - uno di un altro backend (`slug`) o avviato da un'altra persona
        (`principal`), quando la rotta li passa.
    """
    _gc_flows()
    code, url_state = code_from(raw_code)
    state = (state or url_state or "").strip()
    flow = _flows.get(state)
    if flow is None or flow.exp < time.time():
        raise ValueError("nessun consenso in attesa per questo state "
                         "(scaduto, già concluso, o gateway riavviato): rilancia «Connetti»")
    if url_state and state and url_state != state:
        raise ValueError("lo state della URL incollata non è quello del consenso in corso")
    if slug is not None and slug != flow.slug:
        raise ValueError("questo consenso non è di questo server MCP: rilancia «Connetti»")
    if principal is not None and flow.principal and principal != flow.principal:
        raise ValueError("questo consenso l'ha avviato un'altra sessione: rilancia «Connetti»")
    if flow.used:
        raise ValueError("questo consenso è già stato consegnato: un ritorno vale una volta sola")
    if not code:
        raise ValueError("manca il parametro 'code' nella URL incollata")
    if vault.has_credential(credential_cred_name(flow.slug)):
        # Un consenso partito prima di un «Connetti» con credenziale (#565).
        raise ValueError(f"il server MCP '{flow.slug}' è stato connesso con una "
                         "credenziale nel frattempo: «Disconnetti» prima del consenso")
    flow.used = True
    if not flow.code.done():
        flow.code.set_result((code, url_state or state))
    assert flow.task is not None
    try:
        res = await asyncio.wait_for(asyncio.shield(flow.task), timeout=60)
    except TimeoutError as e:
        raise ValueError("scambio del token non concluso entro 60s") from e
    finally:
        _flows.pop(state, None)
    return {"connected": True, "server": flow.slug, "return_to": flow.return_to, **res}


# ── Rilevamento: un 401 che annuncia OAuth (clodia-platform#533) ────────────
#
# Un server MCP che vuole OAuth lo dice da sé: `401` con
# `WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource"`
# (RFC 9728). Fino a #533 il gateway non lo ascoltava: un server montato senza
# `auth` diventava un backend «a header statici», verde nella card e 401 a ogni
# chiamata, e il «Test» diceva «unhandled errors in a TaskGroup». Qui il 401 si
# legge: il documento del protected resource dice quale authorization server
# usare, e i metadati di quello (RFC 8414 / OIDC) dicono che il consenso si può
# davvero avviare.
#
# Solo metadati PUBBLICI: nessuna richiesta di questo blocco porta un token o
# un header del backend, e nessun valore di un header finisce in un messaggio.

PROBE_TIMEOUT_S = 8
_PROBE_MAX_BYTES = 64 * 1024


def _probe_client() -> httpx.AsyncClient:
    """Client del rilevamento (sostituibile nei test). Niente redirect seguiti:
    un 30x verso un altro host non è un documento di metadata di questo."""
    return httpx.AsyncClient(timeout=PROBE_TIMEOUT_S, follow_redirects=False)


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.netloc.lower()) == (pb.scheme, pb.netloc.lower())


async def _get_json(c: httpx.AsyncClient, url: str) -> dict | None:
    try:
        r = await c.get(url, headers={"Accept": "application/json"})
    except httpx.HTTPError:
        return None
    if r.status_code != 200 or len(r.content) > _PROBE_MAX_BYTES:
        return None
    try:
        data = r.json()
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


async def detect(url: str, *, status: int | None = None, headers: Any = None) -> dict:
    """Che cosa vuole un server MCP che rifiuta, da come rifiuta.

    Con `status`/`headers` (la risposta di un 401 vero, presa da una chiamata
    fallita) non si manda niente al server MCP; senza, lo si sonda con un
    `initialize` anonimo. Ritorna
    `{status, oauth, resource_metadata?, authorization_server?, as_metadata?, detail}`,
    con `oauth: True` solo se il protected-resource metadata c'è e nomina un
    authorization server.
    """
    out: dict[str, Any] = {"status": status, "oauth": False}
    async with _probe_client() as c:
        if status is None:
            try:
                r = await c.post(url, json={
                    "jsonrpc": "2.0", "id": 0, "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                               "clientInfo": {"name": "clodia-gateway-probe",
                                              "version": "1"}}},
                    headers={"Accept": "application/json, text/event-stream"})
            except httpx.HTTPError as e:
                out["detail"] = f"server MCP non raggiungibile: {type(e).__name__}"
                return out
            status, headers = r.status_code, r.headers
            out["status"] = status
        if status not in (401, 403):
            out["detail"] = f"HTTP {status}: nessuna autenticazione richiesta"
            return out
        www = str((headers.get("www-authenticate") if headers is not None else None) or "")
        fake = httpx.Response(status, headers={"WWW-Authenticate": www} if www else {})
        announced = extract_resource_metadata_from_www_auth(fake)
        bearer = www.strip().lower().startswith("bearer")
        candidates: list[str] = []
        if announced:
            # Il documento annunciato si legge solo in https o sulla stessa
            # origin del server: un header non può mandare il gateway a
            # leggere un indirizzo interno qualsiasi.
            if announced.startswith("https://") or _same_origin(announced, url):
                candidates.append(announced)
        if announced or bearer or status == 401:
            candidates += [u for u in build_protected_resource_metadata_discovery_urls(None, url)
                           if u not in candidates]
        prm = None
        for cand in candidates:
            data = await _get_json(c, cand)
            if data is None:
                continue
            try:
                prm = ProtectedResourceMetadata.model_validate(data)
            except Exception:  # noqa: BLE001 — documento non conforme: il prossimo
                prm = None
                continue
            out["resource_metadata"] = cand
            break
        if prm is None or not prm.authorization_servers:
            out["detail"] = (
                f"{status} {'Unauthorized' if status == 401 else 'Forbidden'} — il server "
                "rifiuta la richiesta e non annuncia OAuth: serve una credenziale valida "
                "negli headers (o un metodo 'credential' in auth.methods)")
            if announced:
                out["detail"] = (
                    f"{status} — il server annuncia OAuth (resource_metadata) ma il "
                    "documento RFC 9728 non è leggibile: impossibile avviare il consenso")
            return out
        issuer = issuer_of(str(prm.authorization_servers[0]))
        out["oauth"] = True
        out["authorization_server"] = issuer.rstrip("/")
        for cand in build_oauth_authorization_server_metadata_discovery_urls(issuer, url):
            data = await _get_json(c, cand)
            if data is None:
                continue
            try:
                asm = OAuthMetadata.model_validate(data)
                validate_metadata_issuer(asm, issuer)
            except Exception:  # noqa: BLE001
                continue
            out["as_metadata"] = True
            break
        else:
            out["as_metadata"] = False
        out["detail"] = (
            f"{status} Unauthorized — il server richiede un consenso OAuth "
            f"(authorization server {urlparse(issuer).netloc or issuer}): premi «Connetti»")
        return out


def adoptable(backend: dict) -> bool:
    """Si può dare `auth: {type: oauth}` a questo backend senza togliere niente?

    Solo a un backend http senza `auth` e senza `headers`: uno che porta già un
    header (un token statico, magari giusto per un altro endpoint) è una
    scelta dell'owner, e lì il messaggio dice cosa cambiare invece di farlo.
    """
    return (isinstance(backend, dict) and backend.get("transport") == "http"
            and bool(backend.get("url")) and backend.get("auth") is None
            and not backend.get("headers"))

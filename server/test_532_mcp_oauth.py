"""clodia-platform#532 — i server MCP remoti con OAuth si possono montare.

Prima: `mcp.add` conosceva solo segreti statici (`headers` + vault), e un campo
`auth` nel config veniva ignorato in silenzio; il proxy apriva il transport http
senza `auth=`, quindi un server protetto da OAuth rispondeva 401 a ogni
chiamata e non c'era modo di autorizzarlo.

Qui si verifica, contro un authorization server finto (nessuna rete):
  1. il consenso completo — discovery, registrazione dinamica del client,
     authorization code + PKCE, scambio del token;
  2. che il token finisca SOLO nella vault: mai nel config, mai nelle risposte
     delle API, mai nei log;
  3. che dopo un restart un access token scaduto si **rinnovi** col refresh
     token invece di chiedere un nuovo consenso;
  4. che fuori dal consenso il provider non sia interattivo: un backend non
     autorizzato fallisce con un messaggio che dice cosa fare, e non risulta
     connesso nella card.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import httpx

from . import mcp_oauth, proxy, tools_api
from .tools import runtime as runtime_tools

MCP_URL = "https://mcp.example.test/mcp"
ORIGIN = "https://mcp.example.test"
TOKEN = "access-token-segretissimo"
REFRESH = "refresh-token-segretissimo"

BACKEND = {"name": "lovable", "label": "Lovable", "transport": "http",
           "url": MCP_URL, "auth": {"type": "oauth"}}


class _FakeVault:
    """Vault in memoria: stesso contratto di `vault.has_credential/read_internal/
    deposit/remove`, nessun file toccato."""

    def __init__(self):
        self.store: dict[str, dict] = {}

    def has_credential(self, cred):
        return cred in self.store

    def read_internal(self, cred):
        return json.loads(json.dumps(self.store[cred]))

    def deposit(self, cred, bundle, *, cred_type="opaque", grant_agents=None, actions=None):
        self.store[cred] = json.loads(json.dumps(bundle))
        self.grants = grant_agents

    def remove(self, cred):
        return self.store.pop(cred, None) is not None


def _vault(test) -> _FakeVault:
    fv = _FakeVault()
    p = patch.object(mcp_oauth, "vault", fv)
    p.start()
    test.addCleanup(p.stop)
    return fv


class _FakeAuthServer:
    """L'authorization server + il server MCP, come handler httpx.

    Legacy path di RFC 8414: niente protected-resource metadata, quindi l'AS è
    l'origin del server MCP — un caso reale e il più corto da montare.
    """

    def __init__(self, *, accept_token=TOKEN):
        self.accept_token = accept_token
        self.registered = False
        self.calls: list[str] = []
        self.token_requests: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append(f"{request.method} {path}")
        if path.startswith("/.well-known/oauth-protected-resource"):
            return httpx.Response(404)
        if path.startswith("/.well-known/oauth-authorization-server") or \
           path.startswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json={
                "issuer": ORIGIN,
                "authorization_endpoint": f"{ORIGIN}/authorize",
                "token_endpoint": f"{ORIGIN}/token",
                "registration_endpoint": f"{ORIGIN}/register",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "code_challenge_methods_supported": ["S256"],
            })
        if path == "/register":
            self.registered = True
            body = json.loads(request.content)
            return httpx.Response(201, json={
                "client_id": "client-123", "client_secret": "client-secret",
                "redirect_uris": body.get("redirect_uris") or [mcp_oauth.DEFAULT_REDIRECT],
            })
        if path == "/token":
            form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
            self.token_requests.append(form)
            return httpx.Response(200, json={
                "access_token": TOKEN, "token_type": "Bearer",
                "expires_in": 3600, "refresh_token": REFRESH,
            })
        # Il server MCP vero e proprio.
        if request.headers.get("authorization") == f"Bearer {self.accept_token}":
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(401, headers={"WWW-Authenticate": "Bearer"})


async def _call(provider, server, *, body=b"{}") -> httpx.Response:
    async with httpx.AsyncClient(transport=httpx.MockTransport(server),
                                 auth=provider) as c:
        return await c.post(MCP_URL, content=body)


class ConfigTests(unittest.TestCase):
    """`auth` nel config: accolto se lo sappiamo onorare, rifiutato se no."""

    def _register(self, spec):
        with patch.dict(tools_api.whitelist.CONFIG, {"mcp_backends": []}, clear=True), \
             patch.object(tools_api.whitelist, "save_config"), \
             patch.object(tools_api.whitelist, "reload_config"), \
             patch.object(tools_api.proxy, "clear_cache"), \
             patch.object(tools_api.instance_profile, "integrations_check"):
            tools_api.register_mcp_core({"mcpServers": {"Lovable": spec}})
            return list(tools_api.whitelist.CONFIG["mcp_backends"])

    def test_oauth_auth_is_persisted_on_the_backend(self):
        backend = self._register({"url": MCP_URL, "auth": {"type": "oauth"}})[0]
        self.assertEqual(backend["auth"], {"type": "oauth"})
        self.assertIsNotNone(mcp_oauth.auth_spec(backend))

    def test_scope_and_redirect_survive_the_registration(self):
        backend = self._register({"url": MCP_URL, "auth": {
            "type": "oauth", "scope": "read write",
            "redirect_uri": "http://127.0.0.1:9999/cb"}})[0]
        self.assertEqual(backend["auth"]["scope"], "read write")
        self.assertEqual(mcp_oauth.redirect_uri(backend["auth"]),
                         "http://127.0.0.1:9999/cb")

    def test_unknown_auth_type_is_refused_not_ignored(self):
        with self.assertRaises(tools_api.McpRegisterError) as e:
            self._register({"url": MCP_URL, "auth": {"type": "mtls"}})
        self.assertIn("mtls", str(e.exception))

    def test_oauth_on_a_stdio_server_is_refused(self):
        with self.assertRaises(tools_api.McpRegisterError) as e:
            self._register({"command": "node", "auth": "oauth"})
        self.assertIn("stdio", str(e.exception))

    def test_a_plain_http_server_stays_without_any_auth(self):
        backend = self._register({"url": MCP_URL, "headers": {"X-Key": "abc"}})[0]
        self.assertNotIn("auth", backend)
        self.assertIsNone(mcp_oauth.auth_spec(backend))


class ConsentFlowTests(unittest.IsolatedAsyncioTestCase):
    """Il consenso completo contro l'authorization server finto."""

    def setUp(self):
        self.vault = _vault(self)
        self.server = _FakeAuthServer()
        self.auth_urls: list[str] = []

    def _interactive(self):
        """Handlers del consenso: catturano la URL e rispondono col code."""
        async def redirect(url: str) -> None:
            self.auth_urls.append(url)

        async def callback() -> tuple[str, str | None]:
            state = parse_qs(urlparse(self.auth_urls[-1]).query)["state"][0]
            return "auth-code-42", state
        return (redirect, callback)

    async def test_full_flow_discovers_registers_and_exchanges(self):
        provider = mcp_oauth.provider_for(BACKEND, handlers=self._interactive())
        res = await _call(provider, self.server)

        self.assertEqual(res.status_code, 200)
        self.assertTrue(self.server.registered, "manca la registrazione dinamica (RFC 7591)")
        q = parse_qs(urlparse(self.auth_urls[0]).query)
        self.assertEqual(q["code_challenge_method"], ["S256"], "PKCE assente")
        self.assertEqual(q["redirect_uri"], [mcp_oauth.DEFAULT_REDIRECT])
        form = self.server.token_requests[0]
        self.assertEqual(form["grant_type"], "authorization_code")
        self.assertIn("code_verifier", form)

    async def test_tokens_land_in_the_vault_and_nowhere_else(self):
        provider = mcp_oauth.provider_for(BACKEND, handlers=self._interactive())
        await _call(provider, self.server)

        bundle = self.vault.store["mcp_oauth_lovable"]
        self.assertEqual(bundle["tokens"]["access_token"], TOKEN)
        self.assertEqual(bundle["tokens"]["refresh_token"], REFRESH)
        # Credenziale di infrastruttura: nessun agente la può chiedere.
        self.assertEqual(self.vault.grants, [])
        # La scadenza è assoluta: `expires_in` da solo, dopo un restart, non
        # direbbe più niente (ed è ciò che rompe il refresh).
        self.assertGreater(bundle["expires_at"], time.time())

    async def test_the_backend_config_never_sees_the_token(self):
        provider = mcp_oauth.provider_for(BACKEND, handlers=self._interactive())
        await _call(provider, self.server)
        self.assertNotIn(TOKEN, json.dumps(BACKEND))
        self.assertNotIn(REFRESH, json.dumps(BACKEND))

    async def test_no_token_in_the_status_the_api_returns(self):
        provider = mcp_oauth.provider_for(BACKEND, handlers=self._interactive())
        await _call(provider, self.server)
        status = mcp_oauth.authorization_status(BACKEND)
        self.assertTrue(status["authorized"])
        self.assertNotIn(TOKEN, json.dumps(status))
        with patch.dict(tools_api.whitelist.CONFIG, {"mcp_backends": [BACKEND]}, clear=True), \
             patch.object(tools_api.email_tool, "credential_diagnostics", return_value=[]), \
             patch.object(tools_api.vault, "has_credential", return_value=False), \
             patch.object(tools_api.instance_profile, "connectors_allowed", return_value=None):
            snapshot = json.dumps(tools_api.connectors_snapshot())
        self.assertNotIn(TOKEN, snapshot)
        self.assertNotIn(REFRESH, snapshot)
        with patch.dict(runtime_tools.whitelist.CONFIG, {"mcp_backends": [BACKEND]}, clear=True):
            self.assertNotIn(TOKEN, json.dumps(runtime_tools.mcp_servers()))

    async def test_no_token_in_the_logs(self):
        provider = mcp_oauth.provider_for(BACKEND, handlers=self._interactive())
        with self.assertLogs(level=logging.DEBUG) as logs:
            await _call(provider, self.server)
            logging.getLogger("clodia-tools").debug("marcatore")
        blob = "\n".join(logs.output)
        self.assertNotIn(TOKEN, blob)
        self.assertNotIn(REFRESH, blob)


class RefreshAfterRestartTests(unittest.IsolatedAsyncioTestCase):
    """Un token scaduto si rinnova; non si ricomincia da capo.

    `_initialize` dell'SDK ricarica i token dalla storage ma non la scadenza,
    che vive solo in memoria: senza il nostro `expires_at` il provider crede
    valido un token morto, prende 401 e va in ri-autorizzazione — che senza
    browser non può finire, mentre nella vault c'era un refresh token buono.
    """

    def setUp(self):
        self.vault = _vault(self)
        self.vault.store["mcp_oauth_lovable"] = {
            "tokens": {"access_token": "token-vecchio", "token_type": "Bearer",
                       "refresh_token": REFRESH, "expires_in": 3600},
            "expires_at": time.time() - 60,          # scaduto un minuto fa
            "client_info": {"client_id": "client-123", "client_secret": "client-secret",
                            "redirect_uris": [mcp_oauth.DEFAULT_REDIRECT]},
        }
        self.server = _FakeAuthServer()

    async def test_an_expired_token_is_refreshed_without_a_new_consent(self):
        async def never(*_a, **_k):
            raise AssertionError("il consenso non doveva ripartire: c'è un refresh token")

        provider = mcp_oauth.provider_for(BACKEND, handlers=(never, never))
        res = await _call(provider, self.server)

        self.assertEqual(res.status_code, 200)
        self.assertEqual([f["grant_type"] for f in self.server.token_requests],
                         ["refresh_token"])
        self.assertFalse(self.server.registered, "non doveva registrarsi di nuovo")
        self.assertEqual(self.vault.store["mcp_oauth_lovable"]["tokens"]["access_token"],
                         TOKEN)


class NotInteractiveTests(unittest.IsolatedAsyncioTestCase):
    """Dentro una chiamata di tool nessuno può dare un consenso."""

    def setUp(self):
        self.vault = _vault(self)
        self.server = _FakeAuthServer()

    async def test_without_tokens_the_call_says_what_to_do(self):
        provider = mcp_oauth.provider_for(BACKEND)   # nessun handler: non interattivo
        with self.assertRaises(mcp_oauth.ReauthorizationRequired) as e:
            await _call(provider, self.server)
        self.assertIn("lovable", str(e.exception))
        self.assertIn("Connetti", str(e.exception))
        self.assertFalse(self.server.token_requests)

    async def test_the_reason_survives_the_anyio_exception_group(self):
        # Il transport http gira in un task group: senza srotolamento il
        # proprietario legge «unhandled errors in a TaskGroup» e basta.
        inner = mcp_oauth.ReauthorizationRequired("serve il consenso")
        gruppo = ExceptionGroup("unhandled errors in a TaskGroup", [ValueError("x"), inner])
        self.assertIs(proxy.riautorizzazione(gruppo), inner)
        self.assertIsNone(proxy.riautorizzazione(ValueError("altro")))

    async def test_a_cause_chain_is_followed_too(self):
        inner = mcp_oauth.ReauthorizationRequired("serve il consenso")
        try:
            try:
                raise inner
            except mcp_oauth.ReauthorizationRequired as e:
                raise RuntimeError("transport chiuso") from e
        except RuntimeError as outer:
            self.assertIs(proxy.riautorizzazione(outer), inner)


class MountedStateTests(unittest.TestCase):
    """«Montato» non è «autorizzato», e la card deve dirlo."""

    def setUp(self):
        self.vault = _vault(self)

    def _snapshot(self):
        with patch.dict(tools_api.whitelist.CONFIG, {"mcp_backends": [BACKEND]}, clear=True), \
             patch.object(tools_api.email_tool, "credential_diagnostics", return_value=[]), \
             patch.object(tools_api.vault, "has_credential", return_value=False), \
             patch.object(tools_api.instance_profile, "connectors_allowed", return_value=None):
            return [c for c in tools_api.connectors_snapshot() if c["id"] == "lovable"][0]

    def test_an_unauthorized_oauth_backend_is_not_connected(self):
        row = self._snapshot()
        self.assertEqual(row["auth"], "oauth")
        self.assertFalse(row["authorized"])
        self.assertFalse(row["connected"])
        self.assertFalse(row["operational"])
        self.assertIn("consenso", row["issues"][0]["error"])

    def test_an_authorized_one_is(self):
        self.vault.store["mcp_oauth_lovable"] = {
            "tokens": {"access_token": TOKEN, "refresh_token": REFRESH},
            "expires_at": time.time() + 3600}
        row = self._snapshot()
        self.assertTrue(row["authorized"])
        self.assertTrue(row["connected"])

    def test_expired_without_refresh_token_asks_for_a_new_consent(self):
        self.vault.store["mcp_oauth_lovable"] = {
            "tokens": {"access_token": TOKEN}, "expires_at": time.time() - 1}
        self.assertFalse(mcp_oauth.authorization_status(BACKEND)["authorized"])

    def test_a_static_secret_backend_is_untouched(self):
        statico = {"name": "altro", "label": "Altro", "transport": "http",
                   "url": MCP_URL, "headers": {"X-Key": "${VAULT:mcp_altro_KEY}"}}
        with patch.dict(tools_api.whitelist.CONFIG, {"mcp_backends": [statico]}, clear=True), \
             patch.object(tools_api.email_tool, "credential_diagnostics", return_value=[]), \
             patch.object(tools_api.vault, "has_credential", return_value=False), \
             patch.object(tools_api.instance_profile, "connectors_allowed", return_value=None):
            row = [c for c in tools_api.connectors_snapshot() if c["id"] == "altro"][0]
        self.assertNotIn("auth", row)
        self.assertTrue(row["connected"])

    def test_runtime_mcp_servers_tells_the_consent_apart(self):
        with patch.dict(runtime_tools.whitelist.CONFIG, {"mcp_backends": [BACKEND]}, clear=True):
            row = runtime_tools.mcp_servers()["mcp_backends"][0]
        self.assertEqual(row["auth"], "oauth")
        self.assertFalse(row["authorized"])

    def test_unmounting_forgets_the_tokens(self):
        self.vault.store["mcp_oauth_lovable"] = {"tokens": {"access_token": TOKEN}}
        with patch.dict(tools_api.whitelist.CONFIG, {"mcp_backends": [BACKEND]}, clear=True), \
             patch.object(tools_api.whitelist, "save_config"), \
             patch.object(tools_api.whitelist, "reload_config"), \
             patch.object(tools_api.proxy, "clear_cache"):
            tools_api.unregister_mcp_core("lovable")
        self.assertNotIn("mcp_oauth_lovable", self.vault.store,
                         "un remount dello stesso nome erediterebbe i token del precedente")


class TransportWiringTests(unittest.IsolatedAsyncioTestCase):
    """Il provider deve arrivare davvero al transport, non restare in un modulo."""

    async def test_http_session_passes_the_oauth_provider(self):
        visti = {}

        class _Fake:
            async def __aenter__(self_inner):
                raise AssertionError("basta la chiamata: il transport non va aperto")

            async def __aexit__(self_inner, *a):
                return False

        def _fake_client(url, headers=None, auth=None):
            visti.update(url=url, headers=headers, auth=auth)
            return _Fake()

        _vault(self)
        with patch.object(proxy, "streamablehttp_client", _fake_client):
            with self.assertRaises(AssertionError):
                async with proxy.session(BACKEND):
                    pass
        self.assertIsInstance(visti["auth"], mcp_oauth._Provider)
        self.assertEqual(visti["url"], MCP_URL)

    async def test_a_backend_without_oauth_gets_no_provider(self):
        visti = {}

        class _Fake:
            async def __aenter__(self_inner):
                raise AssertionError("stop")

            async def __aexit__(self_inner, *a):
                return False

        def _fake_client(url, headers=None, auth=None):
            visti.update(auth=auth)
            return _Fake()

        with patch.object(proxy, "streamablehttp_client", _fake_client):
            with self.assertRaises(AssertionError):
                async with proxy.session({"name": "x", "transport": "http", "url": MCP_URL}):
                    pass
        self.assertIsNone(visti["auth"])


class PastedUrlTests(unittest.TestCase):
    """Quello che la persona incolla davvero: la URL intera."""

    def test_code_and_state_from_a_pasted_redirect_url(self):
        code, state = mcp_oauth.code_from(
            "http://127.0.0.1:8000/oauth/mcp/callback?code=abc123&state=xyz")
        self.assertEqual((code, state), ("abc123", "xyz"))

    def test_a_bare_code_still_works(self):
        self.assertEqual(mcp_oauth.code_from(" abc123 "), ("abc123", None))

    def test_a_refusal_from_the_authorization_server_is_explained(self):
        with self.assertRaises(ValueError) as e:
            mcp_oauth.code_from("http://127.0.0.1:8000/cb?error=access_denied")
        self.assertIn("access_denied", str(e.exception))


class ConsentDrivenByTheCardTests(unittest.IsolatedAsyncioTestCase):
    """`begin`/`finish`: il consenso che la card guida, in due chiamate HTTP."""

    def setUp(self):
        self.vault = _vault(self)
        mcp_oauth._flows.clear()

    async def test_begin_returns_the_url_and_finish_closes_the_flow(self):
        apri = asyncio.Event()
        risultato = {}

        async def fake_session(backend, *, oauth_handlers=None):
            redirect, callback = oauth_handlers
            await redirect("https://as.example/authorize?state=STATO&code_challenge=x")
            risultato["code"] = await callback()
            apri.set()

            class _S:
                async def list_tools(_s):
                    class _R:
                        tools = [1, 2, 3]
                    return _R()
            yield _S()

        from contextlib import asynccontextmanager
        with patch.object(proxy, "session", asynccontextmanager(fake_session)):
            started = await mcp_oauth.begin(BACKEND)
            self.assertEqual(started["state"], "STATO")
            self.assertIn("authorize", started["auth_url"])

            done = await mcp_oauth.finish(
                "", "http://127.0.0.1:8000/oauth/mcp/callback?code=C0DE&state=STATO")
        self.assertTrue(done["connected"])
        self.assertEqual(done["detail"], "3 tool esposti")
        self.assertEqual(risultato["code"], ("C0DE", "STATO"))
        self.assertEqual(mcp_oauth._flows, {}, "il consenso concluso resta appeso")

    async def test_finish_without_a_pending_flow_is_explained(self):
        with self.assertRaises(ValueError) as e:
            await mcp_oauth.finish("sconosciuto", "abc")
        self.assertIn("Connetti", str(e.exception))

    async def test_begin_refuses_a_backend_without_oauth(self):
        with self.assertRaises(ValueError):
            await mcp_oauth.begin({"name": "x", "transport": "http", "url": MCP_URL})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

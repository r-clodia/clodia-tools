"""clodia-platform#566 — `authorization_servers` che punta al documento di metadata.

Invoicetronic (17 ott 2026) annuncia nel protected-resource metadata
`authorization_servers: ["https://mcp.invoicetronic.com/.well-known/oauth-authorization-server"]`
invece dell'issuer. Prima di #566 il consenso moriva con
`OAuthRegistrationError: Registration failed: 404`.

Qui, contro un server finto che riproduce quei metadati (nessuna rete):
  1. `issuer_of` toglie il suffisso, anche nella forma con path inserito;
  2. il consenso completo arriva al token;
  3. un issuer diverso nei metadati è ancora rifiutato;
  4. `auth.authorization_server` scavalca l'annuncio.
"""
from __future__ import annotations

import json
import unittest
from urllib.parse import parse_qs, urlparse

import httpx

from . import mcp_oauth
from .test_532_mcp_oauth import _call, _vault

ORIGIN = "https://mcp.invoicetronic.test"
MCP_URL = ORIGIN
TOKEN = "access-token-566"
BACKEND = {"name": "invoicetronic", "transport": "http", "url": MCP_URL,
           "auth": {"type": "oauth", "scope": "invoicetronic:read"}}


class _Invoicetronic:
    """Metadati come quelli veri: PRM con la URL del documento, AS su /auth/*."""

    def __init__(self, *, issuer=ORIGIN):
        self.issuer = issuer
        self.calls: list[str] = []
        self.registered = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append(f"{request.method} {path}")
        if path == "/.well-known/oauth-protected-resource":
            return httpx.Response(200, json={
                "resource": ORIGIN,
                "authorization_servers": [f"{ORIGIN}/.well-known/oauth-authorization-server"],
                "bearer_methods_supported": ["header"],
                "scopes_supported": ["invoicetronic:read", "invoicetronic:write"],
            })
        if path == "/.well-known/oauth-authorization-server":
            return httpx.Response(200, json={
                "issuer": self.issuer,
                "authorization_endpoint": f"{ORIGIN}/auth/authorize",
                "token_endpoint": f"{ORIGIN}/auth/token",
                "registration_endpoint": f"{ORIGIN}/auth/register",
                "response_types_supported": ["code"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "token_endpoint_auth_methods_supported": ["none"],
                "code_challenge_methods_supported": ["S256"],
                "scopes_supported": ["invoicetronic:read", "invoicetronic:write"],
            })
        if path == "/auth/register":
            self.registered = True
            body = json.loads(request.content)
            return httpx.Response(201, json={
                "client_id": "client-566", "redirect_uris": body["redirect_uris"]})
        if path == "/auth/token":
            return httpx.Response(200, json={
                "access_token": TOKEN, "token_type": "Bearer", "expires_in": 3600})
        if path.startswith("/.well-known/"):
            return httpx.Response(404)
        if request.headers.get("authorization") == f"Bearer {TOKEN}":
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(401, headers={"WWW-Authenticate": (
            f'Bearer realm="x", resource_metadata="{ORIGIN}/.well-known/oauth-protected-resource"')})


class IssuerOfTests(unittest.TestCase):

    def test_metadata_document_url_becomes_the_issuer(self):
        self.assertEqual(mcp_oauth.issuer_of(
            "https://mcp.invoicetronic.com/.well-known/oauth-authorization-server"),
            "https://mcp.invoicetronic.com")

    def test_openid_configuration_too(self):
        self.assertEqual(mcp_oauth.issuer_of(
            "https://as.example/tenant/.well-known/openid-configuration/"),
            "https://as.example/tenant")

    def test_path_inserted_form(self):
        self.assertEqual(mcp_oauth.issuer_of(
            "https://as.example/.well-known/oauth-authorization-server/tenant"),
            "https://as.example/tenant")

    def test_a_proper_issuer_is_untouched(self):
        for issuer in ("https://as.example", "https://as.example/", "https://as.example/t1"):
            self.assertEqual(mcp_oauth.issuer_of(issuer), issuer)


class ConsentTests(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.vault = _vault(self)
        self.auth_urls: list[str] = []

    def _interactive(self):
        async def redirect(url: str) -> None:
            self.auth_urls.append(url)

        async def callback():
            state = parse_qs(urlparse(self.auth_urls[-1]).query)["state"][0]
            return "code-566", state
        return (redirect, callback)

    async def test_consent_reaches_the_token(self):
        server = _Invoicetronic()
        provider = mcp_oauth.provider_for(BACKEND, handlers=self._interactive())
        res = await _call(provider, server)
        self.assertEqual(res.status_code, 200)
        self.assertTrue(server.registered, "registrazione su /auth/register mancata")
        self.assertNotIn("POST /register", server.calls)
        q = parse_qs(urlparse(self.auth_urls[0]).query)
        self.assertEqual(urlparse(self.auth_urls[0]).path, "/auth/authorize")
        self.assertEqual(q["scope"], ["invoicetronic:read"])

    async def test_a_different_issuer_is_still_refused(self):
        server = _Invoicetronic(issuer="https://evil.example")
        provider = mcp_oauth.provider_for(BACKEND, handlers=self._interactive())
        with self.assertRaises(Exception):
            await _call(provider, server)
        self.assertFalse(server.registered)

    async def test_explicit_authorization_server_wins(self):
        backend = {**BACKEND, "auth": {**BACKEND["auth"], "authorization_server": ORIGIN}}
        provider = mcp_oauth.provider_for(backend, handlers=self._interactive())
        self.assertEqual(provider._select_authorization_server(["https://other.example"]), ORIGIN)


class PinnedScopeTests(unittest.TestCase):
    """Lo scope dichiarato non si allarga agli `scopes_supported` del server."""

    def test_declared_scope_survives_the_sdk_selection(self):
        md = mcp_oauth.client_metadata({"type": "oauth", "scope": "invoicetronic:read"})
        md.scope = "invoicetronic:read invoicetronic:write"
        self.assertEqual(md.scope, "invoicetronic:read")

    def test_without_a_declared_scope_the_sdk_chooses(self):
        md = mcp_oauth.client_metadata({"type": "oauth"})
        md.scope = "a b"
        self.assertEqual(md.scope, "a b")


if __name__ == "__main__":
    unittest.main()

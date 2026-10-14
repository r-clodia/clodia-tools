"""clodia-platform#538 — il refresh deve raggiungere il token endpoint VERO.

L'SDK prende il token endpoint da `context.oauth_metadata`; senza, ripiega su
`<origin del server MCP>/token`. I test di #532 avevano AS e server MCP sullo
stesso origin, quindi quel ripiego coincideva per caso con l'endpoint giusto.
Qui l'authorization server sta su un altro host, come Supabase per leads-mcp,
e `/token` sull'host MCP risponde 404: esattamente il guasto del 14 ott 2026.
"""
from __future__ import annotations

import json
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

import httpx

from server import mcp_oauth
from server.test_532_mcp_oauth import _vault

MCP_URL = "https://mcp.example/mcp"
AS = "https://auth.example/auth/v1"
TOKEN_EP = f"{AS}/oauth/token"
NEW_TOKEN, REFRESH = "nuovo-token", "refresh-buono"
BACKEND = {"name": "leads", "transport": "http", "url": MCP_URL, "auth": {"type": "oauth"}}


class _SplitServers:
    """Server MCP su mcp.example, authorization server su auth.example."""

    def __init__(self):
        self.calls: list[str] = []
        self.token_requests: list[dict] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        host, path = request.url.host, request.url.path
        self.calls.append(f"{request.method} {host}{path}")
        if host == "mcp.example":
            if path.startswith("/.well-known/oauth-protected-resource"):
                return httpx.Response(200, json={"resource": MCP_URL, "authorization_servers": [AS]})
            if path == "/token":
                return httpx.Response(404)                 # il ripiego dell'SDK
            if request.headers.get("authorization") == f"Bearer {NEW_TOKEN}":
                return httpx.Response(200, json={"ok": True})
            return httpx.Response(401, headers={"WWW-Authenticate": "Bearer"})
        if host == "auth.example":
            if path.startswith("/.well-known/oauth-authorization-server") or \
               path.startswith("/.well-known/openid-configuration"):
                return httpx.Response(200, json={
                    "issuer": AS,
                    "authorization_endpoint": f"{AS}/oauth/authorize",
                    "token_endpoint": TOKEN_EP,
                    "registration_endpoint": f"{AS}/oauth/clients/register",
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code", "refresh_token"],
                    "code_challenge_methods_supported": ["S256"],
                })
            if path == "/auth/v1/oauth/token":
                form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
                self.token_requests.append(form)
                return httpx.Response(200, json={"access_token": NEW_TOKEN, "token_type": "Bearer",
                                                 "expires_in": 3600, "refresh_token": REFRESH})
        return httpx.Response(404)


def _bundle(**extra) -> dict:
    return {
        "tokens": {"access_token": "token-scaduto", "token_type": "Bearer",
                   "refresh_token": REFRESH, "expires_in": 3600},
        "expires_at": time.time() - 60,
        "client_info": {"client_id": "client-123", "client_secret": "s",
                        "redirect_uris": [mcp_oauth.DEFAULT_REDIRECT]},
        **extra,
    }


async def _never(*_a, **_k):
    raise AssertionError("il consenso non doveva ripartire: c'è un refresh token buono")


class RefreshReachesTheRealTokenEndpoint(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        self.vault = _vault(self)
        self.servers = _SplitServers()
        # La discovery una tantum passa dallo stesso server finto.
        p = patch.object(mcp_oauth, "_discovery_client",
                         lambda: httpx.AsyncClient(transport=httpx.MockTransport(self.servers)))
        p.start(); self.addCleanup(p.stop)

    async def _call(self):
        provider = mcp_oauth.provider_for(BACKEND, handlers=(_never, _never))
        async with httpx.AsyncClient(transport=httpx.MockTransport(self.servers),
                                     auth=provider) as c:
            return await c.post(MCP_URL, content=b"{}")

    async def test_saved_metadata_send_the_refresh_to_the_authorization_server(self):
        self.vault.store["mcp_oauth_leads"] = _bundle(as_metadata={
            "oauth": {"issuer": AS, "authorization_endpoint": f"{AS}/oauth/authorize",
                      "token_endpoint": TOKEN_EP, "response_types_supported": ["code"]},
            "auth_server_url": AS,
        })
        res = await self._call()
        self.assertEqual(res.status_code, 200)
        self.assertEqual([f["grant_type"] for f in self.servers.token_requests], ["refresh_token"])
        self.assertNotIn("POST mcp.example/token", self.servers.calls)

    async def test_a_credential_saved_before_538_rediscovers_once_and_keeps_it(self):
        self.vault.store["mcp_oauth_leads"] = _bundle()          # nessun metadato
        res = await self._call()
        self.assertEqual(res.status_code, 200, self.servers.calls)
        self.assertEqual([f["grant_type"] for f in self.servers.token_requests], ["refresh_token"])
        self.assertNotIn("POST mcp.example/token", self.servers.calls)
        saved = self.vault.store["mcp_oauth_leads"]["as_metadata"]
        self.assertEqual(saved["oauth"]["token_endpoint"], TOKEN_EP)
        self.assertEqual(saved["auth_server_url"].rstrip("/"), AS)
        self.assertEqual(self.vault.store["mcp_oauth_leads"]["tokens"]["access_token"], NEW_TOKEN)

    async def test_after_the_rediscovery_the_next_session_does_not_rediscover(self):
        self.vault.store["mcp_oauth_leads"] = _bundle()
        await self._call()
        self.vault.store["mcp_oauth_leads"]["expires_at"] = time.time() - 60
        self.servers.calls.clear()
        res = await self._call()
        self.assertEqual(res.status_code, 200)
        self.assertFalse([c for c in self.servers.calls if "/.well-known/" in c],
                         f"metadati già salvati, niente discovery: {self.servers.calls}")


if __name__ == "__main__":
    unittest.main()

"""clodia-platform#534 — the consent returns to the webui, no URL to copy.

The redirect URI is now `<origin of the webui>/tools/oauth/callback`, where
the origin is the one the consent starts from. Here, through the real routes
and the real OAuth client of the SDK (PKCE, state, dynamic registration)
against a fake authorization server — no network:

  1. `oauth/start` refuses an origin that is not the instance's (and one that
     differs from the page's `Origin` header): it cannot register an arbitrary
     redirect URI;
  2. the full consent: the authorization URL carries the webui callback, S256
     PKCE and a state; `oauth/complete` with that state stores the token in the
     vault and hands back the page to return to;
  3. a forged, replayed, expired, other-backend or other-session state is
     refused with a readable error and NO token is stored;
  4. the page to return to is a path of the webui, never another origin;
  5. a client registered for another redirect URI is registered again, and an
     abandoned consent leaves the vault exactly as it was.
"""
from __future__ import annotations

import json
import os
import unittest
from contextlib import asynccontextmanager
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import httpx
from starlette.applications import Starlette
from starlette.testclient import TestClient

from . import mcp_oauth, proxy, tools_api
from .test_532_mcp_oauth import BACKEND, MCP_URL, REFRESH, TOKEN, _FakeAuthServer, _vault

WEBUI = "http://localhost:7843"
CALLBACK = f"{WEBUI}/tools/oauth/callback"


class _CountingAS(_FakeAuthServer):
    def __init__(self):
        super().__init__()
        self.registrations: list[list[str]] = []

    def __call__(self, request):
        if request.url.path == "/register":
            self.registrations.append(json.loads(request.content).get("redirect_uris"))
        return super().__call__(request)


class OriginTests(unittest.TestCase):

    def setUp(self):
        p = patch.dict(os.environ, {"CLODIA_WEBUI_URL": "https://clodia.example.org/",
                                    "CLODIA_ALLOWED_HOSTS": "terra, .tail1234.ts.net"})
        p.start()
        self.addCleanup(p.stop)

    def test_admitted_origins(self):
        for origin, expected in (
                ("http://localhost:7843", "http://localhost:7843/tools/oauth/callback"),
                ("http://127.0.0.1:7843/", "http://127.0.0.1:7843/tools/oauth/callback"),
                ("http://[::1]:7843", "http://[::1]:7843/tools/oauth/callback"),
                ("https://clodia.example.org", "https://clodia.example.org/tools/oauth/callback"),
                ("http://terra:7843", "http://terra:7843/tools/oauth/callback"),
                ("https://terra.tail1234.ts.net", "https://terra.tail1234.ts.net/tools/oauth/callback"),
                ("https://TERRA.tail1234.ts.net", "https://terra.tail1234.ts.net/tools/oauth/callback")):
            self.assertEqual(mcp_oauth.callback_redirect(origin), expected, origin)

    def test_refused_origins(self):
        for origin in ("https://evil.example", "https://terra.tail1234.ts.net.evil.example",
                       "https://evilterra", "http://clodia.example.org",  # other scheme
                       "https://clodia.example.org:8443",                 # other port
                       "https://localhost@evil.example", "https://evil.example#@localhost",
                       "http://localhost:7843/tools", "http://localhost:7843/?x=1",
                       "javascript:alert(1)", "file:///etc/passwd", "//localhost",
                       "", "   ", "http://local host", "http://localhost:99999"):
            with self.assertRaises(ValueError, msg=origin):
                mcp_oauth.callback_redirect(origin)

    def test_without_the_environment_only_loopback(self):
        with patch.dict(os.environ, {"CLODIA_WEBUI_URL": "", "CLODIA_ALLOWED_HOSTS": ""}):
            mcp_oauth.callback_redirect("http://localhost:7843")
            with self.assertRaises(ValueError):
                mcp_oauth.callback_redirect("https://terra.tail1234.ts.net")


class ReturnPathTests(unittest.TestCase):
    """No open redirect: only a path of the webui, under a page that starts a consent."""

    def test_admitted(self):
        for p in ("/tools", "/tools?tab=mcp", "/topics/P1/leads", "/packs/it-pack", "/tools#mcp"):
            self.assertEqual(mcp_oauth.safe_return_path(p), p)

    def test_everything_else_returns_to_tools(self):
        for p in ("https://evil.example/tools", "//evil.example/tools", "/\\evil.example",
                  "\\\\evil.example", "/tools\n/x", "/\tevil", "javascript:alert(1)",
                  "/tools/oauth/callback?code=x", "/toolsevil", "/admin", "/tools/../x",
                  "http:/evil.example", " ", None, 42, "/" + "a" * 600):
            self.assertEqual(mcp_oauth.safe_return_path(p), "/tools", repr(p))


class _RouteBase(unittest.TestCase):
    """The real routes, the real SDK provider, a fake authorization server."""

    def setUp(self):
        self.vault = _vault(self)
        mcp_oauth._flows.clear()
        self.addCleanup(mcp_oauth._flows.clear)
        proxy._AUTH_FAILURES.clear()
        self.server = _CountingAS()
        self.sessions = 0
        server = self.server
        test = self

        @asynccontextmanager
        async def fake_session(b, *, oauth_handlers=None, oauth_redirect=None, **_kw):
            test.sessions += 1
            provider = mcp_oauth.provider_for(b, handlers=oauth_handlers, redirect=oauth_redirect)
            async with httpx.AsyncClient(transport=httpx.MockTransport(server),
                                         auth=provider) as c:
                r = await c.post(MCP_URL, content=b"{}")
            if r.status_code != 200:
                raise RuntimeError(f"MCP {r.status_code}")

            class _S:
                async def list_tools(self):
                    return type("R", (), {"tools": [1, 2]})()
            yield _S()

        for target, attr, val in (
                (proxy, "session", fake_session),
                (tools_api, "_authorized", lambda request: True),
                (tools_api, "_admin_principal",
                 lambda request: request.headers.get("x-test-who", "davide")),
                (tools_api.proxy, "clear_cache", lambda: None)):
            p = patch.object(target, attr, val)
            p.start()
            self.addCleanup(p.stop)
        p = patch.dict(tools_api.whitelist.CONFIG, {"mcp_backends": [BACKEND]}, clear=True)
        p.start()
        self.addCleanup(p.stop)
        p = patch.dict(os.environ, {"CLODIA_WEBUI_URL": "", "CLODIA_ALLOWED_HOSTS": ""})
        p.start()
        self.addCleanup(p.stop)
        self.client = TestClient(Starlette(routes=tools_api.routes))
        self.client.__enter__()
        self.addCleanup(self.client.__exit__, None, None, None)

    def start(self, body=None, headers=None):
        return self.client.post("/tools/mcp/lovable/oauth/start", json=body or {},
                                headers=headers or {})

    def complete(self, state, code="auth-code-42", name="lovable", headers=None):
        return self.client.post(f"/tools/mcp/{name}/oauth/complete",
                                json={"state": state, "code": code}, headers=headers or {})

    def tokens_stored(self) -> bool:
        return bool((self.vault.store.get("mcp_oauth_lovable") or {}).get("tokens"))


class StartTests(_RouteBase):

    def test_start_refuses_an_origin_outside_the_allowed_hosts(self):
        r = self.start({"origin": "https://evil.example"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("non ammessa", r.json()["error"])
        self.assertEqual(self.sessions, 0, "no consent may start for a refused origin")
        self.assertEqual(self.server.registrations, [], "the redirect must not be registered")
        self.assertEqual(mcp_oauth._flows, {})

    def test_start_refuses_an_origin_that_is_not_the_page_s(self):
        r = self.start({"origin": WEBUI}, headers={"Origin": "http://127.0.0.1:7843"})
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.sessions, 0)

    def test_without_origin_the_paste_fallback_stays(self):
        r = self.start()
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["mode"], "paste")
        self.assertEqual(r.json()["redirect_uri"], mcp_oauth.DEFAULT_REDIRECT)


class CallbackFlowTests(_RouteBase):

    def started(self, **body):
        r = self.start({"origin": WEBUI, "return_to": "/tools", **body},
                       headers={"Origin": WEBUI})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def test_the_consent_returns_to_the_webui_and_stores_the_token(self):
        started = self.started()
        self.assertEqual(started["mode"], "callback")
        self.assertEqual(started["redirect_uri"], CALLBACK)
        q = parse_qs(urlparse(started["auth_url"]).query)
        self.assertEqual(q["redirect_uri"], [CALLBACK])
        self.assertEqual(q["code_challenge_method"], ["S256"])
        self.assertEqual(q["state"], [started["state"]])
        self.assertGreaterEqual(len(started["state"]), 32)
        self.assertEqual(self.server.registrations, [[CALLBACK]])

        r = self.complete(started["state"])
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        self.assertTrue(body["connected"])
        self.assertEqual(body["return_to"], "/tools")
        self.assertNotIn(TOKEN, r.text)
        self.assertTrue(self.tokens_stored())
        bundle = self.vault.store["mcp_oauth_lovable"]
        self.assertEqual(bundle["client_info"]["redirect_uris"], [CALLBACK])
        form = self.server.token_requests[0]
        self.assertEqual(form["redirect_uri"], CALLBACK)
        self.assertIn("code_verifier", form)
        self.assertEqual(mcp_oauth._flows, {})

    def test_a_replayed_state_is_refused(self):
        started = self.started()
        self.assertEqual(self.complete(started["state"]).status_code, 200)
        r = self.complete(started["state"], code="another-code")
        self.assertEqual(r.status_code, 400)
        self.assertIn("Connetti", r.json()["error"])
        self.assertEqual(len(self.server.token_requests), 1)

    def test_a_forged_state_is_refused_and_nothing_is_stored(self):
        self.started()
        r = self.complete("forged-state-0123456789abcdef0123456789")
        self.assertEqual(r.status_code, 400)
        self.assertIn("state", r.json()["error"])
        self.assertFalse(self.tokens_stored())
        self.assertEqual(self.server.token_requests, [])

    def test_an_expired_state_is_refused_and_nothing_is_stored(self):
        started = self.started()
        mcp_oauth._flows[started["state"]].exp = 0
        r = self.complete(started["state"])
        self.assertEqual(r.status_code, 400)
        self.assertIn("scaduto", r.json()["error"])
        self.assertFalse(self.tokens_stored())
        self.assertEqual(self.server.token_requests, [])

    def test_a_state_of_another_session_is_refused_and_stays_usable(self):
        started = self.started()
        r = self.complete(started["state"], headers={"x-test-who": "mallory"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("sessione", r.json()["error"])
        self.assertFalse(self.tokens_stored())
        # The refused attempt did not consume the consent of the right person.
        self.assertEqual(self.complete(started["state"]).status_code, 200)

    def test_a_state_of_another_backend_is_refused(self):
        started = self.started()
        r = self.complete(started["state"], name="altro")
        self.assertEqual(r.status_code, 400)
        self.assertFalse(self.tokens_stored())

    def test_a_hostile_return_page_falls_back_to_tools(self):
        started = self.started(return_to="https://evil.example/phish")
        self.assertEqual(started["return_to"], "/tools")
        self.assertEqual(self.complete(started["state"]).json()["return_to"], "/tools")

    def test_the_page_it_came_from_is_kept(self):
        started = self.started(return_to="/topics/P1/leads?tab=connettori")
        r = self.complete(started["state"])
        self.assertEqual(r.json()["return_to"], "/topics/P1/leads?tab=connettori")

    def test_the_access_token_never_reaches_the_browser(self):
        started = self.started()
        blob = json.dumps(started) + self.complete(started["state"]).text
        self.assertNotIn(TOKEN, blob)
        self.assertNotIn(REFRESH, blob)


class ReRegistrationTests(_RouteBase):
    """A client registered for the loopback is not reused for the webui callback."""

    OLD = {
        "tokens": {"access_token": "old-token", "token_type": "Bearer",
                   "refresh_token": "old-refresh"},
        "expires_at": 0,
        "client_info": {"client_id": "old-client", "client_secret": "s",
                        "redirect_uris": [mcp_oauth.DEFAULT_REDIRECT]},
    }

    def setUp(self):
        super().setUp()
        self.vault.store["mcp_oauth_lovable"] = json.loads(json.dumps(self.OLD))
        # The old refresh token no longer works: the provider must go to consent.
        orig = self.server

        def refuse_refresh(request):
            if request.url.path == "/token" and b"refresh_token=old-refresh" in request.content:
                return httpx.Response(400, json={"error": "invalid_grant"})
            return orig(request)
        self._server_fn = refuse_refresh
        # The pre-#538 bundle has no AS metadata: the provider rediscovers it
        # once, and that discovery must hit the fake server, not the network.
        p = patch.object(mcp_oauth, "_discovery_client", lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(refuse_refresh), follow_redirects=True))
        p.start()
        self.addCleanup(p.stop)

    def test_a_new_redirect_registers_again_and_an_abandoned_consent_changes_nothing(self):
        server = self.server
        server_fn = self._server_fn

        @asynccontextmanager
        async def fake_session(b, *, oauth_handlers=None, oauth_redirect=None, **_kw):
            provider = mcp_oauth.provider_for(b, handlers=oauth_handlers, redirect=oauth_redirect)
            async with httpx.AsyncClient(transport=httpx.MockTransport(server_fn),
                                         auth=provider) as c:
                r = await c.post(MCP_URL, content=b"{}")
            if r.status_code != 200:
                raise RuntimeError(f"MCP {r.status_code}")

            class _S:
                async def list_tools(self):
                    return type("R", (), {"tools": []})()
            yield _S()

        with patch.object(proxy, "session", fake_session):
            r = self.start({"origin": WEBUI})
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(server.registrations, [[CALLBACK]],
                             "a client registered for the loopback was reused")
            # Abandoned: nothing written, the old client and refresh token intact.
            self.assertEqual(self.vault.store["mcp_oauth_lovable"]["client_info"],
                             self.OLD["client_info"])
            self.assertEqual(self.vault.store["mcp_oauth_lovable"]["tokens"],
                             self.OLD["tokens"])
            done = self.complete(r.json()["state"])
        self.assertEqual(done.status_code, 200, done.text)
        bundle = self.vault.store["mcp_oauth_lovable"]
        self.assertEqual(bundle["client_info"]["redirect_uris"], [CALLBACK])
        self.assertEqual(bundle["tokens"]["access_token"], TOKEN)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

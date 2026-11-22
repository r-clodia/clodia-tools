"""clodia-platform#533 — a server that announces OAuth in its 401 is recognised.

Before: a remote MCP server mounted without `"auth": {"type": "oauth"}` became
a static-header backend. Every call got 401, the card said `connected: true`,
and the «Test» button showed «unhandled errors in a TaskGroup (1
sub-exception)».

Here, against fake servers (no network):
  1. `detect` reads `WWW-Authenticate` + the RFC 9728 document + the RFC 8414
     metadata, and tells OAuth apart from a plain 401 (static token wrong);
  2. a mount with no `auth` that meets an OAuth 401 ends with an OAuth backend
     whose card offers «Connetti», without changing `config_sha256`;
  3. a backend whose last test or call returned 401 is never `connected: true`,
     in `connectors_snapshot()` nor in `runtime.mcp_servers()`;
  4. the 401 inside anyio's exception group is unwrapped into a readable reason;
  5. no header value, token or static secret ends up in a message, and the
     discovery requests carry no credential.
"""
from __future__ import annotations

import asyncio
import json
import unittest
from contextlib import asynccontextmanager
from unittest.mock import patch

import httpx

from . import mcp_oauth, proxy, tools_api
from .test_532_mcp_oauth import _vault
from .tools import runtime as runtime_tools

ORIGIN = "https://leads.example.test"
MCP_URL = f"{ORIGIN}/mcp"
AS_ORIGIN = "https://auth.example.test"
STATIC = "static-token-segretissimo"


class _OAuthServer:
    """An MCP server behind OAuth, the way leadspot answers (13 Oct 2026)."""

    def __init__(self, *, resource_metadata=f"{ORIGIN}/.well-known/oauth-protected-resource",
                 publish_prm=True):
        self.resource_metadata = resource_metadata
        self.publish_prm = publish_prm
        self.requests: list[httpx.Request] = []

    @property
    def calls(self) -> list[str]:
        return [f"{r.method} {r.url.host}{r.url.path}" for r in self.requests]

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        host, path = request.url.host, request.url.path
        if host == "auth.example.test":
            if path == "/.well-known/oauth-authorization-server":
                return httpx.Response(200, json={
                    "issuer": AS_ORIGIN,
                    "authorization_endpoint": f"{AS_ORIGIN}/authorize",
                    "token_endpoint": f"{AS_ORIGIN}/token",
                    "registration_endpoint": f"{AS_ORIGIN}/register",
                    "response_types_supported": ["code"],
                    "code_challenge_methods_supported": ["S256"],
                })
            return httpx.Response(404)
        if host != "leads.example.test":
            return httpx.Response(599)  # any other host must never be reached
        if path.startswith("/.well-known/oauth-protected-resource"):
            if not self.publish_prm:
                return httpx.Response(404)
            return httpx.Response(200, json={
                "resource": MCP_URL, "authorization_servers": [AS_ORIGIN]})
        if path.startswith("/.well-known/"):
            return httpx.Response(404)
        www = 'Bearer realm="mcp"'
        if self.resource_metadata:
            www += f', resource_metadata="{self.resource_metadata}"'
        return httpx.Response(401, headers={"WWW-Authenticate": www})


class _PlainServer:
    """A server that wants a static token and does not speak OAuth."""

    def __init__(self):
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path.startswith("/.well-known/"):
            return httpx.Response(404)
        return httpx.Response(401, json={"error": "unauthorized"})


def _probe_with(test, server) -> None:
    p = patch.object(mcp_oauth, "_probe_client", lambda: httpx.AsyncClient(
        transport=httpx.MockTransport(server), follow_redirects=False))
    p.start()
    test.addCleanup(p.stop)


def _no_failures(test) -> None:
    proxy._AUTH_FAILURES.clear()
    test.addCleanup(proxy._AUTH_FAILURES.clear)


class DetectTests(unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        _no_failures(self)

    async def test_a_401_with_resource_metadata_is_oauth(self):
        server = _OAuthServer()
        _probe_with(self, server)
        info = await mcp_oauth.detect(MCP_URL)
        self.assertTrue(info["oauth"])
        self.assertEqual(info["status"], 401)
        self.assertEqual(info["authorization_server"], AS_ORIGIN)
        self.assertTrue(info["as_metadata"], "the AS metadata (RFC 8414) was not discovered")
        self.assertIn("Connetti", info["detail"])
        self.assertIn("GET auth.example.test/.well-known/oauth-authorization-server", server.calls)

    async def test_the_headers_of_a_real_401_need_no_new_request_to_the_mcp_server(self):
        server = _OAuthServer()
        _probe_with(self, server)
        www = f'Bearer resource_metadata="{ORIGIN}/.well-known/oauth-protected-resource"'
        info = await mcp_oauth.detect(MCP_URL, status=401,
                                      headers=httpx.Headers({"WWW-Authenticate": www}))
        self.assertTrue(info["oauth"])
        self.assertNotIn("POST leads.example.test/mcp", server.calls)

    async def test_a_plain_401_is_a_static_credential_problem(self):
        server = _PlainServer()
        _probe_with(self, server)
        info = await mcp_oauth.detect(MCP_URL)
        self.assertFalse(info["oauth"])
        self.assertEqual(info["status"], 401)
        self.assertIn("non annuncia OAuth", info["detail"])
        self.assertIn("headers", info["detail"])

    async def test_well_known_discovery_without_the_header_parameter(self):
        # MCP spec: the client falls back to the well-known RFC 9728 URIs.
        server = _OAuthServer(resource_metadata=None)
        _probe_with(self, server)
        info = await mcp_oauth.detect(MCP_URL)
        self.assertTrue(info["oauth"])

    async def test_an_announced_document_on_another_host_over_http_is_not_fetched(self):
        # The header must not send the gateway to read an arbitrary address.
        server = _OAuthServer(resource_metadata="http://169.254.169.254/latest/meta-data",
                              publish_prm=False)
        _probe_with(self, server)
        info = await mcp_oauth.detect(MCP_URL)
        self.assertFalse(any("169.254.169.254" in c for c in server.calls), server.calls)
        self.assertFalse(info["oauth"])
        self.assertIn("RFC 9728", info["detail"])

    async def test_a_server_that_answers_is_not_oauth(self):
        _probe_with(self, lambda r: httpx.Response(200, json={"jsonrpc": "2.0", "id": 0}))
        info = await mcp_oauth.detect(MCP_URL)
        self.assertFalse(info["oauth"])
        self.assertEqual(info["status"], 200)

    async def test_the_probe_carries_no_credential(self):
        server = _OAuthServer()
        _probe_with(self, server)
        await mcp_oauth.detect(MCP_URL)
        for r in server.requests:
            self.assertNotIn("authorization", {k.lower() for k in r.headers.keys()})


class _MountBase(unittest.TestCase):

    def setUp(self):
        self.vault = _vault(self)
        _no_failures(self)
        for target, val in ((tools_api.whitelist, "save_config"),
                            (tools_api.whitelist, "reload_config"),
                            (tools_api.proxy, "clear_cache"),
                            (tools_api.instance_profile, "integrations_check")):
            p = patch.object(target, val)
            p.start()
            self.addCleanup(p.stop)
        p = patch.dict(tools_api.whitelist.CONFIG, {"mcp_backends": []}, clear=True)
        p.start()
        self.addCleanup(p.stop)

    def mount(self, spec, name="leads-mcp"):
        cfg = {"mcpServers": {name: spec}}
        out = tools_api.register_mcp_core(cfg, detected=tools_api.detect_oauth_sync(cfg))
        return out, tools_api.whitelist.CONFIG["mcp_backends"][-1]

    def card(self, name="leads-mcp"):
        with patch.object(tools_api.email_tool, "credential_diagnostics", return_value=[]), \
             patch.object(tools_api.vault, "has_credential", return_value=False), \
             patch.object(tools_api.instance_profile, "connectors_allowed", return_value=None):
            return next(c for c in tools_api.connectors_snapshot() if c.get("id") == name)

    def runtime_row(self, name="leads-mcp"):
        return next(r for r in runtime_tools.mcp_servers()["mcp_backends"] if r["name"] == name)


class MountTests(_MountBase):

    def test_mounting_an_oauth_server_without_auth_offers_connetti(self):
        _probe_with(self, _OAuthServer())
        out, backend = self.mount({"url": MCP_URL})
        self.assertEqual(out["oauth_detected"], ["leads-mcp"])
        self.assertEqual(backend["auth"], {"type": "oauth"})
        card = self.card()
        self.assertEqual(card["auth"], "oauth")
        self.assertFalse(card["authorized"])
        self.assertFalse(card["connected"])
        self.assertEqual([m["type"] for m in card["auth_methods"]], ["oauth"])

    def test_detection_does_not_change_the_mounted_config_hash(self):
        _probe_with(self, _OAuthServer())
        _, detected = self.mount({"url": MCP_URL})
        _probe_with(self, lambda r: httpx.Response(200, json={}))
        _, plain = self.mount({"url": MCP_URL}, name="other")
        self.assertEqual(detected["config_sha256"], plain["config_sha256"])

    def test_a_plain_401_at_mount_is_never_connected(self):
        _probe_with(self, _PlainServer())
        out, backend = self.mount({"url": MCP_URL})
        self.assertNotIn("auth", backend)
        self.assertNotIn("oauth_detected", out)
        card = self.card()
        self.assertFalse(card["connected"])
        self.assertIn("non annuncia OAuth", card["issues"][0]["error"])
        self.assertFalse(self.runtime_row()["connected"])

    def test_a_server_mounted_with_headers_is_not_probed_nor_rewritten(self):
        server = _OAuthServer()
        _probe_with(self, server)
        out, backend = self.mount({"url": MCP_URL, "headers": {"Authorization": f"Bearer {STATIC}"}})
        self.assertEqual(server.requests, [])
        self.assertNotIn("auth", backend)
        self.assertNotIn("oauth_detected", out)

    def test_an_unreachable_server_still_mounts(self):
        def down(_r):
            raise httpx.ConnectError("down")
        _probe_with(self, down)
        out, backend = self.mount({"url": MCP_URL})
        self.assertEqual(out["registered"], ["leads-mcp"])
        self.assertNotIn("auth", backend)
        self.assertTrue(self.card()["connected"])


class _Group:
    """What the http transport raises: an HTTPStatusError inside anyio's group."""

    @staticmethod
    def of(status: int, www: str | None) -> BaseException:
        req = httpx.Request("POST", MCP_URL)
        resp = httpx.Response(status, request=req,
                              headers={"WWW-Authenticate": www} if www else {})
        err = httpx.HTTPStatusError(f"Client error '{status}'", request=req, response=resp)
        return BaseExceptionGroup("unhandled errors in a TaskGroup", [err])


def _session_raising(exc):
    @asynccontextmanager
    async def _s(_b, **_kw):
        raise exc
        yield  # pragma: no cover
    return _s


class TestAndCallTests(_MountBase, unittest.IsolatedAsyncioTestCase):

    def setUp(self):
        super().setUp()
        tools_api.whitelist.CONFIG["mcp_backends"] = [
            {"name": "leads-mcp", "label": "leads-mcp", "transport": "http", "url": MCP_URL}]

    def _raise(self, exc):
        p = patch.object(proxy, "_session", _session_raising(exc))
        p.start()
        self.addCleanup(p.stop)

    async def test_the_test_unwraps_the_group_and_names_oauth(self):
        _probe_with(self, _OAuthServer())
        self._raise(_Group.of(401, f'Bearer resource_metadata="{ORIGIN}/.well-known/oauth-protected-resource"'))
        res = await proxy.test_backend("leads-mcp")
        self.assertFalse(res["ok"])
        self.assertTrue(res["oauth_detected"])
        self.assertNotIn("TaskGroup", res["detail"])
        self.assertIn("OAuth", res["detail"])
        card = self.card()
        self.assertFalse(card["connected"])
        self.assertTrue(card["oauth_detected"])
        self.assertEqual(card["auth"], "oauth")
        row = self.runtime_row()
        self.assertFalse(row["connected"])
        self.assertTrue(row["oauth_detected"])

    async def test_a_plain_401_in_the_test_says_the_credential_is_wrong(self):
        _probe_with(self, _PlainServer())
        self._raise(_Group.of(401, None))
        res = await proxy.test_backend("leads-mcp")
        self.assertNotIn("oauth_detected", res)
        self.assertIn("401", res["detail"])
        self.assertNotIn("TaskGroup", res["detail"])
        self.assertFalse(self.card()["connected"])

    async def test_a_success_clears_the_refusal(self):
        proxy.record_auth_failure("leads-mcp", {"status": 401, "detail": "x"})

        class _S:
            async def list_tools(self):
                return type("R", (), {"tools": []})()

        @asynccontextmanager
        async def ok(_b, **_kw):
            yield _S()

        @asynccontextmanager
        async def env(_n, b):
            yield b
        with patch.object(proxy, "_session", ok), patch.object(proxy, "_listing_env", env):
            res = await proxy.test_backend("leads-mcp")
        self.assertTrue(res["ok"])
        self.assertIsNone(proxy.auth_failure("leads-mcp"))
        self.assertTrue(self.card()["connected"])

    async def test_a_call_that_gets_401_raises_a_readable_reason(self):
        _probe_with(self, _OAuthServer())
        self._raise(_Group.of(401, f'Bearer resource_metadata="{ORIGIN}/.well-known/oauth-protected-resource"'))
        with patch.object(proxy, "bind_instances", lambda n, b, a: (b, a)), \
             patch.object(proxy, "is_disabled", return_value=False):
            with self.assertRaises(mcp_oauth.ReauthorizationRequired) as e:
                await proxy.call_proxied("leads-mcp.search", {})
        self.assertIn("leads-mcp", str(e.exception))
        self.assertIn("OAuth", str(e.exception))
        self.assertFalse(self.card()["connected"])

    async def test_a_static_header_is_never_echoed(self):
        tools_api.whitelist.CONFIG["mcp_backends"] = [
            {"name": "leads-mcp", "label": "leads-mcp", "transport": "http", "url": MCP_URL,
             "headers": {"Authorization": f"Bearer {STATIC}"}}]
        server = _OAuthServer()
        _probe_with(self, server)
        self._raise(_Group.of(401, f'Bearer error="invalid_token", error_description="{STATIC}", '
                                   f'resource_metadata="{ORIGIN}/.well-known/oauth-protected-resource"'))
        res = await proxy.test_backend("leads-mcp")
        blob = json.dumps([res, self.card(), self.runtime_row()])
        self.assertNotIn(STATIC, blob)
        self.assertIn("auth", res["detail"])  # says what to change
        for r in server.requests:
            self.assertNotIn(STATIC, json.dumps(dict(r.headers)))

    def test_adopt_sets_oauth_only_on_a_backend_with_nothing_declared(self):
        proxy.record_auth_failure("leads-mcp", {"status": 401, "oauth": True, "detail": "x"})
        self.assertTrue(tools_api.adopt_detected_oauth("leads-mcp"))
        self.assertEqual(tools_api.whitelist.CONFIG["mcp_backends"][0]["auth"], {"type": "oauth"})
        self.assertIsNone(proxy.auth_failure("leads-mcp"))
        self.assertFalse(tools_api.adopt_detected_oauth("leads-mcp"), "already OAuth")
        tools_api.whitelist.CONFIG["mcp_backends"] = [
            {"name": "h", "transport": "http", "url": MCP_URL, "headers": {"X-Key": "k"}}]
        self.assertFalse(tools_api.adopt_detected_oauth("h"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

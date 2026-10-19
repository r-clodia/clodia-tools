"""#575 — testing an MCP backend lists its verbs and whether each is enabled.

The owner asked to see, after «Test», which verbs a mounted backend offers.
`enabled` is the gateway's own answer (the checks `call_tool` runs before any
per-agent rule, via `main.proxied_verb_refusal`), never a parallel rule. The
answer carries names and descriptions only: no input schema, no secret.
"""
from __future__ import annotations

import asyncio
import json
import unittest
from contextlib import asynccontextmanager
from unittest.mock import patch

from starlette.requests import Request

from server import main, proxy, tools_api


class _T:
    def __init__(self, name, description="", schema=None):
        self.name, self.description = name, description
        self.inputSchema = schema or {"type": "object",
                                      "properties": {"token": {"default": "s3cr3t"}}}


class _R:
    def __init__(self, tools):
        self.tools = tools


def _session_with(tools):
    @asynccontextmanager
    async def _fake(_b):
        class _S:
            async def list_tools(self):
                return _R(tools)
        yield _S()
    return _fake


def _post_test(cid):
    req = Request({"type": "http", "method": "POST", "path": f"/tools/{cid}/test",
                   "headers": [], "query_string": b"", "path_params": {"id": cid}})
    with patch.object(tools_api, "_authorized", lambda r: True):
        resp = asyncio.run(tools_api.test_connector(req))
    return json.loads(resp.body)


class BackendVerbsTests(unittest.TestCase):
    def _env(self, tools, refusals=None):
        refusals = refusals or {}
        cfg = {"mcp_backends": [{"name": "buffer", "transport": "http"}]}
        return [patch.object(proxy, "_backends", return_value={"buffer": {"transport": "http"}}),
                patch.object(proxy, "_session", _session_with(tools)),
                patch.object(tools_api.whitelist, "CONFIG", cfg),
                patch.object(main, "proxied_verb_refusal", lambda n: refusals.get(n, ""))]

    def _run(self, tools, refusals=None):
        ps = self._env(tools, refusals)
        for p in ps:
            p.start()
        try:
            return _post_test("buffer")
        finally:
            for p in reversed(ps):
                p.stop()

    def test_every_verb_by_its_gateway_name(self):
        r = self._run([_T("list_posts", "List posts"), _T("create_post", "Create")])
        self.assertTrue(r["ok"])
        self.assertEqual([v["name"] for v in r["verbs"]],
                         ["buffer.create_post", "buffer.list_posts"])
        self.assertTrue(all(v["enabled"] for v in r["verbs"]))
        self.assertIn("2 tool", r["detail"])
        self.assertNotIn("tools", r)

    def test_a_refused_verb_is_listed_last_with_its_reason(self):
        r = self._run([_T("a"), _T("b")], {"buffer.a": "trasporto interno"})
        self.assertEqual([(v["name"], v["enabled"]) for v in r["verbs"]],
                         [("buffer.b", True), ("buffer.a", False)])
        self.assertEqual(r["verbs"][1]["reason"], "trasporto interno")
        self.assertNotIn("reason", r["verbs"][0])

    def test_no_schema_and_no_secret_in_the_answer(self):
        r = self._run([_T("a", "desc")])
        blob = json.dumps(r)
        self.assertNotIn("s3cr3t", blob)
        self.assertNotIn("inputSchema", blob)
        self.assertEqual(set(r["verbs"][0]), {"name", "description", "enabled"})

    def test_a_long_description_is_capped(self):
        r = self._run([_T("a", "x" * 5000)])
        self.assertEqual(len(r["verbs"][0]["description"]), proxy.TEST_DESCRIPTION_MAX)

    def test_a_failed_test_keeps_its_shape(self):
        @asynccontextmanager
        async def _boom(_b):
            raise RuntimeError("401 Unauthorized")
            yield  # pragma: no cover
        cfg = {"mcp_backends": [{"name": "buffer", "transport": "http"}]}
        with patch.object(proxy, "_backends", return_value={"buffer": {}}), \
                patch.object(proxy, "_session", _boom), \
                patch.object(tools_api.whitelist, "CONFIG", cfg):
            r = _post_test("buffer")
        self.assertFalse(r["ok"])
        self.assertNotIn("verbs", r)


class RefusalIsTheCallPathsTests(unittest.TestCase):
    """`proxied_verb_refusal` answers with the call path's own checks."""

    def test_a_transport_backend_is_not_enabled(self):
        with patch.object(main, "_component_verb", lambda n: None), \
                patch.object(proxy, "is_proxied", lambda n: True), \
                patch("server.connectors.resolved.is_transport_backend", lambda n: True):
            why = main.proxied_verb_refusal("mail-transport.read")
        self.assertIn("trasporto interno", why)

    def test_a_name_served_by_a_component_shadows_the_backend(self):
        with patch.object(main, "_component_verb", lambda n: object()):
            self.assertIn("never reached", main.proxied_verb_refusal("x.y"))

    def test_an_ordinary_tool_is_enabled(self):
        with patch.object(main, "_component_verb", lambda n: None), \
                patch.object(main, "_check_not_transport", lambda n: None), \
                patch.object(main, "_check_pack_connector_held", lambda n: None), \
                patch.object(main, "_check_component", lambda n: None):
            self.assertEqual(main.proxied_verb_refusal("buffer.list_posts"), "")

    def test_it_uses_call_tool_s_checks(self):
        """Whatever refuses the call refuses the listing: same functions."""
        def _refuse(n):
            raise main._PackVerbRefused("connettore non attivo")
        with patch.object(main, "_component_verb", lambda n: None), \
                patch.object(main, "_check_not_transport", lambda n: None), \
                patch.object(main, "_check_pack_connector_held", _refuse), \
                patch.object(main, "_check_component", lambda n: None):
            self.assertEqual(main.proxied_verb_refusal("x.y"), "connettore non attivo")
            out = asyncio.run(main.call_tool("x.y", {}))
        self.assertIn("connettore non attivo", out[0].text)


if __name__ == "__main__":
    unittest.main()

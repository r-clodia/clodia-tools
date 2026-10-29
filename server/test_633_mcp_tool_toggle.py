"""#633 — an admin can switch single tools of a mounted MCP server off in Tools.

Every tool is enabled until an admin unticks it in the list the backend's Test
shows, new tools included. A disabled tool is an instance decision: withheld
from every listing, refused at every call before any other rule, the refusal
audited; only a human admin flips it; it goes with the mount.
"""
from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

import yaml
from starlette.requests import Request

from server import main, proxy, tools_api, whitelist


class _T:
    def __init__(self, name, description=""):
        self.name, self.description = name, description
        self.inputSchema = {"type": "object", "properties": {}}


class _R:
    def __init__(self, tools):
        self.tools = tools


def _session_with(tools, calls=None):
    @asynccontextmanager
    async def _fake(_b):
        class _S:
            async def list_tools(self):
                return _R(tools)

            async def call_tool(self, name, arguments):
                if calls is not None:
                    calls.append(name)

                class _Res:
                    content = []
                    isError = False
                return _Res()
        yield _S()
    return _fake


def _request(method, path, path_params, body=None):
    raw = json.dumps(body).encode() if body is not None else b""

    async def _receive():
        return {"type": "http.request", "body": raw, "more_body": False}
    return Request({"type": "http", "method": method, "path": path, "headers": [],
                    "query_string": b"", "path_params": path_params}, _receive)


class _ConfigFile(unittest.TestCase):
    """A real config file in a temp dir: the toggle is persisted state."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "clodia-tools-config.yaml"
        self.path.write_text(yaml.safe_dump(
            {"mcp_backends": [{"name": "clickup", "transport": "http"}], "agents": {}}))
        self._saved = dict(whitelist.CONFIG)
        self._saved_loaded = dict(whitelist._LOADED)
        self.patches = [patch.object(whitelist, "CONFIG_PATH", self.path)]
        for p in self.patches:
            p.start()
        whitelist.reload_config()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        whitelist.CONFIG.clear(); whitelist.CONFIG.update(self._saved)
        whitelist._LOADED.clear(); whitelist._LOADED.update(self._saved_loaded)
        self.tmp.cleanup()

    def on_disk(self):
        return yaml.safe_load(self.path.read_text())


class ToggleStateTests(_ConfigFile):
    def test_everything_is_enabled_by_default(self):
        self.assertEqual(whitelist.disabled_backend_tools("clickup"), set())
        self.assertFalse(proxy.is_disabled("clickup.delete_task"))

    def test_disable_persists_and_enable_restores(self):
        whitelist.set_backend_tool_enabled("clickup", "delete_task", False)
        self.assertEqual(self.on_disk()[whitelist.DISABLED_TOOLS_KEY],
                         {"clickup": ["delete_task"]})
        self.assertTrue(proxy.is_disabled("clickup.delete_task"))
        self.assertFalse(proxy.is_disabled("clickup.get_task"))
        whitelist.set_backend_tool_enabled("clickup", "delete_task", True)
        self.assertEqual(self.on_disk().get(whitelist.DISABLED_TOOLS_KEY), {})
        self.assertFalse(proxy.is_disabled("clickup.delete_task"))

    def _unmount(self):
        with patch.object(tools_api.mcp_oauth, "forget", lambda n: None), \
                patch.object(tools_api.vault, "remove", lambda n: None):
            tools_api.unregister_mcp_core("clickup")

    def test_unmount_and_remount_never_re_enable(self):
        """Review of #633: `mcp.remove` + `mcp.add` are within an agent's reach,
        and a pack Update remounts. Neither may turn a disabled tool back on."""
        whitelist.set_backend_tool_enabled("clickup", "delete_task", False)
        whitelist.set_known_backend_tools("clickup", ["delete_task", "get_task"])
        self._unmount()
        disk = self.on_disk()
        self.assertEqual(disk[whitelist.DISABLED_TOOLS_KEY], {"clickup": ["delete_task"]})
        self.assertNotIn("clickup", disk.get(whitelist.KNOWN_TOOLS_KEY) or {})
        tools_api.register_mcp_core(
            {"mcpServers": {"clickup": {"url": "https://mcp.clickup.com/mcp"}}})
        self.assertTrue(proxy.is_disabled("clickup.delete_task"))

    def test_a_respelled_remount_carries_the_list(self):
        whitelist.reload_config()
        whitelist.CONFIG["mcp_backends"] = [{"name": "my_server", "url": "https://x.example/mcp",
                                             "transport": "http"}]
        whitelist.save_config()
        whitelist.set_backend_tool_enabled("my_server", "wipe", False)
        tools_api.register_mcp_core(
            {"mcpServers": {"my_server": {"url": "https://x.example/mcp"}}})
        names = [b["name"] for b in self.on_disk()["mcp_backends"]]
        self.assertIn("my-server", names)
        self.assertTrue(proxy.is_disabled("my-server.wipe"))
        self.assertNotIn("my_server", self.on_disk()[whitelist.DISABLED_TOOLS_KEY])


class ListingAndCallTests(_ConfigFile):
    def setUp(self):
        super().setUp()
        self.calls = []
        tools = [_T("get_task"), _T("delete_task")]
        self.more = [patch.object(proxy, "_backends",
                                  return_value={"clickup": {"transport": "http"}}),
                     patch.object(proxy, "_session", _session_with(tools, self.calls)),
                     patch.object(proxy, "_is_transport", lambda n: False)]
        for p in self.more:
            p.start()
        proxy._TOOL_CACHE.clear()

    def tearDown(self):
        proxy._TOOL_CACHE.clear()
        for p in reversed(self.more):
            p.stop()
        super().tearDown()

    def listed(self):
        return {t.name for t in asyncio.run(proxy.list_proxied_tools())}

    def test_a_disabled_tool_leaves_the_listing_at_once(self):
        self.assertEqual(self.listed(), {"clickup.get_task", "clickup.delete_task"})
        whitelist.set_backend_tool_enabled("clickup", "delete_task", False)
        # Same cache, no backend round trip: the toggle alone hides it.
        self.assertEqual(self.listed(), {"clickup.get_task"})

    def test_call_tool_refuses_before_any_other_rule_and_audits(self):
        whitelist.set_backend_tool_enabled("clickup", "delete_task", False)
        decisions = []
        from server.audit import policy as apol
        with patch.object(apol, "decision", lambda *a, **k: decisions.append((a, k))), \
                patch.object(main, "_call_tool_recorded",
                             side_effect=AssertionError("must not get this far")):
            out = asyncio.run(main.call_tool("clickup.delete_task", {}))
        self.assertTrue(out[0].text.startswith("DENIED:"))
        self.assertIn("disabled on this instance", out[0].text)
        self.assertEqual(decisions[0][0], ("clickup.delete_task", "tool_toggle", "deny"))
        self.assertEqual(decisions[0][1]["reason_class"], "tool_disabled")
        self.assertEqual(self.calls, [])

    def test_the_proxy_refuses_too(self):
        whitelist.set_backend_tool_enabled("clickup", "delete_task", False)
        with self.assertRaises(proxy.ToolDisabled):
            asyncio.run(proxy.call_proxied("clickup.delete_task", {}))
        self.assertEqual(self.calls, [])
        asyncio.run(proxy.call_proxied("clickup.get_task", {}))
        self.assertEqual(self.calls, ["get_task"])

    def test_the_test_list_shows_every_tool_with_its_toggle_and_what_is_new(self):
        whitelist.set_backend_tool_enabled("clickup", "delete_task", False)
        req = _request("POST", "/tools/clickup/test", {"id": "clickup"})
        with patch.object(tools_api, "_authorized", lambda r: True), \
                patch.object(main, "proxied_verb_refusal", lambda n: ""):
            first = json.loads(asyncio.run(tools_api.test_connector(req)).body)
        rows = {v["tool"]: v for v in first["verbs"]}
        self.assertEqual(set(rows), {"get_task", "delete_task"})  # disabled ones too
        self.assertTrue(rows["delete_task"]["disabled"])
        self.assertFalse(rows["get_task"]["disabled"])
        self.assertEqual(first["disabled"], 1)
        # First Test ever: nothing is "new", the whole list is.
        self.assertFalse(any(v["new"] for v in first["verbs"]))
        # The server grows a tool: enabled, and marked new once.
        proxy_tools = [_T("get_task"), _T("delete_task"), _T("bulk_export")]
        with patch.object(proxy, "_session", _session_with(proxy_tools)), \
                patch.object(tools_api, "_authorized", lambda r: True), \
                patch.object(main, "proxied_verb_refusal", lambda n: ""):
            second = json.loads(asyncio.run(tools_api.test_connector(req)).body)
            third = json.loads(asyncio.run(tools_api.test_connector(req)).body)
        rows = {v["tool"]: v for v in second["verbs"]}
        self.assertTrue(rows["bulk_export"]["new"])
        self.assertFalse(rows["bulk_export"]["disabled"])
        self.assertFalse(rows["get_task"]["new"])
        self.assertFalse(any(v["new"] for v in third["verbs"]))

    def test_a_disabled_tool_the_server_dropped_stays_tickable(self):
        whitelist.set_backend_tool_enabled("clickup", "old_tool", False)
        rows = tools_api._backend_verbs(
            [{"name": "clickup.get_task", "description": ""}], "clickup")
        gone = [r for r in rows if r["tool"] == "old_tool"]
        self.assertEqual(len(gone), 1)
        self.assertTrue(gone[0]["disabled"] and gone[0]["gone"])

    def test_the_room_panel_does_not_offer_it(self):
        from server import room_tools
        self.listed()  # discovery fills the cache
        whitelist.set_backend_tool_enabled("clickup", "delete_task", False)
        self.assertEqual(room_tools._backend_verbs("clickup"), {"clickup.get_task"})


class RouteTests(_ConfigFile):
    def post(self, name, body, owner=True):
        req = _request("POST", f"/tools/mcp/{name}/tools", {"name": name}, body)
        with patch.object(tools_api, "_authorized_owner", lambda r: owner):
            resp = asyncio.run(tools_api.mcp_tool_toggle(req))
        return resp.status_code, json.loads(resp.body)

    def test_only_a_human_admin(self):
        code, _ = self.post("clickup", {"tool": "delete_task", "enabled": False}, owner=False)
        self.assertEqual(code, 401)
        self.assertEqual(whitelist.disabled_backend_tools("clickup"), set())

    def test_toggle_round_trip(self):
        code, body = self.post("clickup", {"tool": "delete_task", "enabled": False})
        self.assertEqual((code, body["disabled"]), (200, ["delete_task"]))
        code, body = self.post("clickup", {"tool": "delete_task", "enabled": True})
        self.assertEqual((code, body["disabled"]), (200, []))

    def test_the_tool_name_is_taken_as_is(self):
        """A backend may expose a tool literally named `clickup.x`: switching it
        off must not switch off `x` (review of #633)."""
        code, body = self.post("clickup", {"tool": "clickup.x", "enabled": False})
        self.assertEqual(body["disabled"], ["clickup.x"])
        self.assertTrue(proxy.is_disabled("clickup.clickup.x"))
        self.assertFalse(proxy.is_disabled("clickup.x"))

    def test_bad_requests(self):
        self.assertEqual(self.post("clickup", {"tool": "x"})[0], 400)
        self.assertEqual(self.post("clickup", {"tool": "", "enabled": False})[0], 400)
        self.assertEqual(self.post("clickup", {"tool": "x", "enabled": "no"})[0], 400)
        self.assertEqual(self.post("nope", {"tool": "x", "enabled": False})[0], 404)

    def test_the_card_counts_disabled_tools(self):
        whitelist.set_backend_tool_enabled("clickup", "delete_task", False)
        rows = [r for r in self._cards() if r.get("id") == "clickup"]
        self.assertEqual(rows[0]["disabled_tools"], ["delete_task"])

    def _cards(self):
        req = _request("GET", "/tools", {})
        with patch.object(tools_api, "_authorized", lambda r: True):
            resp = asyncio.run(tools_api.list_tools(req))
        return json.loads(resp.body).get("connectors") or []


if __name__ == "__main__":
    unittest.main()

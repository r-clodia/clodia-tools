"""#632 — «Add MCP server» takes a URL, and translates mcp-remote.

A bare `https://` URL and the `npx -y mcp-remote <url>` wrapper both become
the same `http` backend; no `mcp-remote` process is ever started. What does
not map is refused with a message. An `mcp.json` without wrappers is mounted
as before.
"""
from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from server import mcp_input as mi, tools_api, whitelist
from server.test_633_mcp_tool_toggle import _request

CLICKUP = "https://mcp.clickup.com/mcp"
WRAPPED = {"mcpServers": {"clickup": {"command": "npx",
                                      "args": ["-y", "mcp-remote", CLICKUP]}}}


class NormalizeTests(unittest.TestCase):
    def test_a_url_becomes_an_http_server_named_from_its_host(self):
        cfg, notes = mi.normalize(CLICKUP)
        self.assertEqual(cfg, {"mcpServers": {"clickup": {"url": CLICKUP}}})
        self.assertTrue(notes)

    def test_the_name_can_be_given(self):
        cfg, _ = mi.normalize(f"  {CLICKUP}  ", "tasks")
        self.assertEqual(list(cfg["mcpServers"]), ["tasks"])

    def test_names_from_hosts(self):
        for url, name in (("https://mcp.lovable.dev/", "lovable"),
                          ("https://leadspot-dashboard.lovable.app/mcp", "leadspot-dashboard"),
                          ("https://api.example.org/mcp", "example"),
                          ("http://localhost:8080/mcp", "localhost")):
            with self.subTest(url=url):
                self.assertEqual(mi.name_from_url(url), name)

    def test_only_https_or_loopback(self):
        for bad in ("http://mcp.example.com/mcp", "ftp://x.example/mcp", "https:///nohost"):
            with self.subTest(url=bad), self.assertRaises(mi.McpInputError):
                mi.normalize(bad)
        for ok in ("http://127.0.0.1:9000/mcp", "http://localhost/mcp", "http://[::1]/mcp"):
            with self.subTest(url=ok):
                mi.normalize(ok)

    def test_mcp_remote_is_translated_not_run(self):
        for cmd, args in (("npx", ["-y", "mcp-remote", CLICKUP]),
                          ("npx", ["mcp-remote@latest", CLICKUP]),
                          ("/usr/bin/npx", ["--yes", "mcp-remote", CLICKUP]),
                          ("mcp-remote", [CLICKUP])):
            with self.subTest(cmd=cmd, args=args):
                cfg, notes = mi.normalize({"mcpServers": {"clickup": {"command": cmd,
                                                                      "args": args}}})
                self.assertEqual(cfg["mcpServers"]["clickup"], {"url": CLICKUP})
                self.assertIn("mcp-remote", notes[0])

    def test_a_placeholder_header_maps_to_headers(self):
        cfg, _ = mi.normalize({"mcpServers": {"x": {"command": "npx", "args": [
            "-y", "mcp-remote", CLICKUP, "--header", "Authorization: Bearer ${TOKEN}"]}}})
        self.assertEqual(cfg["mcpServers"]["x"],
                         {"url": CLICKUP, "headers": {"Authorization": "Bearer ${TOKEN}"}})

    def test_what_does_not_map_is_refused(self):
        for args, env in ((["-y", "mcp-remote", CLICKUP, "--header", "Authorization: Bearer abc"], None),
                          (["-y", "mcp-remote", CLICKUP, "--transport", "sse-only"], None),
                          (["-y", "mcp-remote", CLICKUP], {"MCP_REMOTE_CONFIG_DIR": "/x"}),
                          (["-y", "mcp-remote"], None),
                          (["-y", "mcp-remote", "http://mcp.example.com/mcp"], None)):
            spec = {"command": "npx", "args": args}
            if env:
                spec["env"] = env
            with self.subTest(args=args, env=env), self.assertRaises(mi.McpInputError):
                mi.normalize({"mcpServers": {"x": spec}})

    def test_other_stdio_and_http_entries_are_untouched(self):
        cfg = {"mcpServers": {
            "fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/x"]},
            "py": {"command": "python3", "args": ["-m", "srv"], "env": {"K": "${K}"}},
            "web": {"url": "http://internal.example/mcp", "headers": {"X": "${X}"}}}}
        out, notes = mi.normalize(cfg)
        self.assertEqual(out, cfg)
        self.assertEqual(notes, [])

    def test_garbage_is_refused(self):
        for bad in ("not json", "{}", '{"mcpServers": {}}', 42):
            with self.subTest(bad=bad), self.assertRaises(mi.McpInputError):
                mi.normalize(bad)


class MountTests(unittest.TestCase):
    """Through the route, on a real config file."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "clodia-tools-config.yaml"
        self.path.write_text(yaml.safe_dump({"mcp_backends": [], "agents": {}}))
        self._saved = dict(whitelist.CONFIG)
        self._saved_loaded = dict(whitelist._LOADED)
        self.patches = [patch.object(whitelist, "CONFIG_PATH", self.path),
                        patch.object(tools_api, "_authorized", lambda r: True)]
        for p in self.patches:
            p.start()
        whitelist.reload_config()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        whitelist.CONFIG.clear(); whitelist.CONFIG.update(self._saved)
        whitelist._LOADED.clear(); whitelist._LOADED.update(self._saved_loaded)
        self.tmp.cleanup()

    def _post(self, body):
        r = asyncio.run(tools_api.register_mcp(_request("POST", "/tools/mcp", {}, body)))
        import json
        return r.status_code, json.loads(r.body)

    def _backend(self, name):
        disk = yaml.safe_load(self.path.read_text())
        return next(b for b in disk["mcp_backends"] if b["name"] == name)

    def test_a_url_mounts_an_http_backend(self):
        status, out = self._post({"config": CLICKUP})
        self.assertEqual(status, 200, out)
        self.assertEqual(out["registered"], ["clickup"])
        self.assertTrue(out["notes"])
        b = self._backend("clickup")
        self.assertEqual((b["transport"], b["url"]), ("http", CLICKUP))

    def test_the_wrapper_mounts_the_same_backend_and_no_command(self):
        status, out = self._post({"config": WRAPPED})
        self.assertEqual(status, 200, out)
        b = self._backend("clickup")
        self.assertEqual((b["transport"], b["url"]), ("http", CLICKUP))
        self.assertNotIn("command", b)

    def test_a_refusal_is_a_400_with_the_reason(self):
        status, out = self._post({"config": "http://mcp.example.com/mcp"})
        self.assertEqual(status, 400)
        self.assertIn("https", out["error"])
        self.assertEqual(yaml.safe_load(self.path.read_text())["mcp_backends"], [])

    def test_a_pack_config_is_mounted_as_written(self):
        """Its hash is what the agent-server compares before mounting it back
        (#563): a pack's config is not rewritten here."""
        with self.assertRaises(tools_api.McpRegisterError):
            # As a pack, a URL is not an mcp.json: refused, not translated.
            tools_api.register_mcp_core(CLICKUP, pack="some-pack")


if __name__ == "__main__":
    unittest.main()

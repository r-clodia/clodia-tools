"""#634 — MCP `readOnlyHint` / `destructiveHint` classify a backend's verbs.

A fake MCP backend lists annotated tools through the real listing path
(`proxy.list_proxied_tools`, `proxy.test_backend`); the classification is then
read where A·V·R·Q reads it: `authz_shadow.facts`, the room panel
(`room_tools._is_write`), the role classifier (`authz_roles.is_read`) and the
enforced decision in a room (`authz_runtime.check`).
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
import unittest
from contextlib import asynccontextmanager
from unittest.mock import patch

from mcp.types import Tool, ToolAnnotations

from . import authz as A
from . import authz_roles, authz_runtime as R, authz_shadow as S
from . import main, proxy, room_tools as RT, tool_hints, whitelist
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicService

_SCHEMA = {"type": "object", "properties": {}}


def _tool(name, ro=None, destructive=None):
    ann = None
    if ro is not None or destructive is not None:
        ann = ToolAnnotations(readOnlyHint=ro, destructiveHint=destructive)
    return Tool(name=name, description="", inputSchema=_SCHEMA, annotations=ann)


CLICKUP = [
    _tool("clickup_get_task", ro=True),
    _tool("clickup_get_task_comments", ro=True),
    _tool("clickup_create_task", ro=False),
    _tool("clickup_delete_comment", ro=False, destructive=True),
    _tool("clickup_send_chat_message", ro=False, destructive=False),
    _tool("clickup_contradictory", ro=True, destructive=True),
    _tool("clickup_delete_everything", ro=True),        # lies: platform says write
    _tool("clickup_publish", ro=True),                  # gated below: write
    _tool("clickup_sync"),                              # no hint: name decides
]
NORMATTIVA = [_tool("risolvi", ro=True), _tool("articolo", ro=True)]
FOO = [_tool("foo_get_x"), _tool("foo_sync"), _tool("foo-list-y"), _tool("foo.search_z"),
       _tool("foo")]


class _Backend:
    """A fake MCP server: `list_tools` returns what `self.tools` holds."""

    def __init__(self, tools_by_backend):
        self.by = dict(tools_by_backend)
        self.down = set()

    def session(self):
        test = self

        @asynccontextmanager
        async def _fake(b):
            name = b["name"]
            if name in test.down:
                raise ConnectionError("backend down")

            class _S:
                async def list_tools(self):
                    class _R:
                        tools = list(test.by[name])
                    return _R()
            yield _S()
        return _fake


class _Env(unittest.TestCase):
    def setUp(self):
        self.backend = _Backend({"clickup": CLICKUP, "normattiva": NORMATTIVA, "foo": FOO})
        backends = {n: {"name": n, "transport": "http"} for n in self.backend.by}
        gated = {"clickup.clickup_publish"}
        for p in (patch.object(proxy, "_backends", lambda: backends),
                  patch.object(proxy, "_session", self.backend.session()),
                  patch.object(proxy, "_is_transport", lambda n: False),
                  patch.object(whitelist, "disabled_backend_tools", lambda b: set()),
                  patch("server.gate.is_gated", lambda v: v in gated)):
            p.start(); self.addCleanup(p.stop)
        proxy.clear_cache()
        self.addCleanup(proxy.clear_cache)

    def listed(self):
        return {t.name for t in asyncio.run(proxy.list_proxied_tools())}

    def kind(self, verb):
        return S.facts(verb, {})["kind"]


class ClassificationTests(_Env):
    def setUp(self):
        super().setUp()
        self.listed()

    def test_read_only_hint_is_a_read(self):
        for v in ("clickup.clickup_get_task", "clickup.clickup_get_task_comments"):
            f = S.facts(v, {})
            self.assertEqual((f["kind"], f["basis"]), (A.READ, S.BASIS_HINT), v)
            self.assertFalse(RT._is_write(v))
            self.assertTrue(authz_roles.is_read(v))

    def test_declared_writes_are_writes(self):
        for v in ("clickup.clickup_create_task", "clickup.clickup_delete_comment",
                  "clickup.clickup_send_chat_message"):
            self.assertEqual(self.kind(v), A.WRITE, v)
            self.assertTrue(RT._is_write(v))
            self.assertFalse(authz_roles.is_read(v))

    def test_destructive_is_write_and_irreversible(self):
        self.assertEqual(self.kind("clickup.clickup_contradictory"), A.WRITE)
        self.assertTrue(tool_hints.irreversible("clickup.clickup_contradictory"))
        self.assertTrue(tool_hints.irreversible("clickup.clickup_delete_comment"))
        self.assertFalse(tool_hints.irreversible("clickup.clickup_create_task"))

    def test_a_server_cannot_downgrade_a_platform_write(self):
        # Irreversible by name, and a gated verb: the server's `readOnlyHint`
        # does not make either a read.
        self.assertEqual(self.kind("clickup.clickup_delete_everything"), A.WRITE)
        self.assertEqual(self.kind("clickup.clickup_publish"), A.WRITE)
        self.assertFalse(authz_roles.is_read("clickup.clickup_delete_everything"))

    def test_a_connector_mapping_wins_over_the_hint(self):
        from .connectors import resolved
        with patch.object(resolved, "egress_mappings",
                          lambda v: ("m",) if v == "clickup.clickup_get_task" else ()), \
                patch.object(resolved, "destinations", lambda m, a: ["https://x.example/"]):
            f = S.facts("clickup.clickup_get_task", {})
        self.assertEqual((f["kind"], f["basis"]), (A.WRITE, S.BASIS_MAPPING))

    def test_non_english_read_only_tools_are_reads(self):
        """#649: Normattiva's Italian names are reads once it declares them."""
        for v in ("normattiva.risolvi", "normattiva.articolo"):
            self.assertEqual(self.kind(v), A.READ, v)

    def test_no_hint_falls_back_to_the_name_without_the_server_prefix(self):
        self.assertEqual(self.kind("foo.foo_get_x"), A.READ)
        self.assertEqual(self.kind("foo.foo-list-y"), A.READ)
        self.assertEqual(self.kind("foo.foo.search_z"), A.READ)
        self.assertEqual(self.kind("foo.foo_sync"), A.WRITE)
        self.assertEqual(self.kind("foo.foo"), A.WRITE)          # nothing left: as is
        self.assertEqual(self.kind("clickup.clickup_sync"), A.WRITE)
        self.assertEqual(S.facts("foo.foo_get_x", {})["basis"], S.BASIS_NAME)
        # Native verbs are unchanged.
        self.assertEqual(self.kind("topic.list_files"), A.READ)
        self.assertEqual(self.kind("telegram.listen"), A.WRITE)


class CacheTests(_Env):
    def test_no_listing_no_hint(self):
        self.assertEqual(self.kind("normattiva.risolvi"), A.WRITE)
        self.listed()
        self.assertEqual(self.kind("normattiva.risolvi"), A.READ)

    def test_remount_drops_hints_and_relisting_refreshes_them(self):
        self.listed()
        self.assertEqual(self.kind("normattiva.risolvi"), A.READ)
        proxy.clear_cache()                       # what every mount/unmount does
        self.assertEqual(self.kind("normattiva.risolvi"), A.WRITE)
        self.backend.by["normattiva"] = [_tool("risolvi", ro=False)]
        self.listed()
        self.assertEqual(self.kind("normattiva.risolvi"), A.WRITE)
        self.assertEqual(S.facts("normattiva.risolvi", {})["basis"], S.BASIS_HINT)

    def test_a_backend_down_keeps_no_stale_hint(self):
        tool_hints.record("normattiva", NORMATTIVA)
        self.backend.down.add("normattiva")
        self.listed()
        self.assertEqual(self.kind("normattiva.risolvi"), A.WRITE)

    def test_hints_are_not_offered_to_agents(self):
        tools = asyncio.run(proxy.list_proxied_tools())
        self.assertTrue(all(t.annotations is None for t in tools))

    def test_the_backend_test_refreshes_hints_and_shows_the_classification(self):
        res = asyncio.run(proxy.test_backend("clickup"))
        self.assertTrue(res["ok"])
        read = {t["name"]: t["read"] for t in res["tools"]}
        self.assertTrue(read["clickup.clickup_get_task"])
        self.assertFalse(read["clickup.clickup_create_task"])
        self.assertFalse(read["clickup.clickup_delete_everything"])
        self.assertEqual(self.kind("clickup.clickup_get_task"), A.READ)


class RoleTests(_Env):
    def test_a_destructive_backend_verb_is_no_role_tool(self):
        tool_hints.record("github", [_tool("list_issues", ro=True),
                                     _tool("close_everything", ro=False, destructive=True),
                                     _tool("delete_file", ro=False, destructive=False)])
        keep, _ = authz_roles.github_verbs(["list_issues", "close_everything", "delete_file"])
        self.assertEqual(keep, ["github.list_issues"])


class RoomDecisionTests(_Env):
    """In a room with the MCP authorised and no rows: read = allow, a declared
    write asks; a write guessed from the name only keeps #650's read default."""

    def setUp(self):
        super().setUp()
        R.invalidate()
        self.addCleanup(R.invalidate)
        self.dir = tempfile.mkdtemp(prefix="hints634-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        tdir = tempfile.mkdtemp(prefix="topics634-")
        self.addCleanup(shutil.rmtree, tdir, ignore_errors=True)
        cat = {"clickup": {"id": "clickup", "label": "clickup", "kind": "mcp",
                           "namespaces": ["clickup"], "enumerable": True,
                           "verbs": sorted(f"clickup.{t.name}" for t in CLICKUP),
                           "write": [], "schemes": []}}
        for p in (patch.dict(os.environ, {"CLODIA_TOOLS_STATE_DIR": self.dir}),
                  patch.object(whitelist, "CONFIG", {"authz_mode": "enforce"}),
                  patch.object(whitelist, "save_config", lambda: None),
                  patch.object(whitelist, "reload_config", lambda: None),
                  patch.object(RT, "mcp_catalogue", lambda: cat)):
            p.start(); self.addCleanup(p.stop)
        self.svc = TopicService(LocalFsStorage(tdir))
        p = patch.object(main, "_topics", lambda: self.svc)
        p.start(); self.addCleanup(p.stop)
        self.svc.new("SEAL-1", "moneyviz", {"owner": "davide", "participants": ["clodia"]})
        S._global_path().write_text(json.dumps({"tuples": []}))
        RT.enable_mcp("SEAL-1", "moneyviz", "clickup")
        self.listed()

    def effect(self, verb):
        R.invalidate()
        return R.check("clodia", verb, {}, "SEAL-1/moneyviz", False).effect

    def test_reads_run_and_declared_writes_ask(self):
        self.assertEqual(self.effect("clickup.clickup_get_task"), A.ALLOW)
        self.assertEqual(self.effect("clickup.clickup_get_task_comments"), A.ALLOW)
        for v in ("clickup.clickup_create_task", "clickup.clickup_delete_comment",
                  "clickup.clickup_send_chat_message", "clickup.clickup_delete_everything"):
            self.assertEqual(self.effect(v), A.ASK, v)

    def test_a_name_only_write_keeps_the_650_room_default(self):
        self.assertEqual(self.effect("clickup.clickup_sync"), A.ALLOW)


if __name__ == "__main__":
    unittest.main()

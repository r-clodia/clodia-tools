"""Room tools by MCP, with resource rows and three exception levels (#620)."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from . import authz as A
from . import authz_runtime as R
from . import authz_shadow as S
from . import main, room_tools as RT, whitelist
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicService

CAT = {
    "google": {"id": "google", "label": "Google Workspace", "kind": "connector",
               "namespaces": ["gdrive", "gdocs"], "enumerable": True,
               "verbs": ["gdocs.read", "gdrive.download", "gdrive.list", "gdrive.upload"],
               "write": ["gdrive.upload"],
               "schemes": [{"scheme": "gdrive", "direction": "egress", "verbs": ["gdrive.upload"]},
                           {"scheme": "gdrive", "direction": "source",
                            "verbs": ["gdrive.download", "gdrive.list"]},
                           {"scheme": "mailto", "direction": "egress", "verbs": ["gdrive.upload"]}]},
    "normattiva": {"id": "normattiva", "label": "normattiva", "kind": "mcp",
                   "namespaces": ["normattiva"], "enumerable": False,
                   "verbs": [], "write": [], "schemes": []},
}
FOLDER = "gdrive:folder/F1"


class _Env(unittest.TestCase):
    def setUp(self):
        R.invalidate()
        self.addCleanup(R.invalidate)
        self.dir = tempfile.mkdtemp(prefix="mcp620-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        tdir = tempfile.mkdtemp(prefix="topics620-")
        self.addCleanup(shutil.rmtree, tdir, ignore_errors=True)
        for p in (patch.dict(os.environ, {"CLODIA_TOOLS_STATE_DIR": self.dir}),
                  patch.object(whitelist, "CONFIG", {"authz_mode": "enforce"}),
                  patch.object(whitelist, "save_config", lambda: None),
                  patch.object(whitelist, "reload_config", lambda: None),
                  patch.object(RT, "mcp_catalogue", lambda: CAT),
                  patch("server.egress.canonical", lambda u: u)):
            p.start(); self.addCleanup(p.stop)
        self.svc = TopicService(LocalFsStorage(tdir))
        p = patch.object(main, "_topics", lambda: self.svc)
        p.start(); self.addCleanup(p.stop)
        self.svc.new("SEAL-1", "blog", {"owner": "davide", "participants": ["clodia", "officer"]})
        S._global_path().write_text(json.dumps({"tuples": []}))

    def meta(self):
        return self.svc._read_meta("SEAL-1", "blog")[0]


class MutationTests(_Env):
    def test_an_authorised_mcp_gives_all_its_namespaces(self):
        RT.enable_mcp("SEAL-1", "blog", "google")
        tb = RT.toolbox(self.meta())
        self.assertIn("gdrive.*", tb["enabled"])
        self.assertIn("gdocs.*", tb["enabled"])

    def test_the_two_forms_never_erase_each_other(self):
        RT.enable_mcp("SEAL-1", "blog", "google")
        with patch.object(RT, "check", lambda v: v):
            RT.enable("SEAL-1", "blog", "web.fetch")
        raw = self.meta()["tools"]
        self.assertEqual(raw["enabled"], ["web.fetch"])       # compiled form not baked in
        self.assertIn("google", raw["mcp"])
        RT.enable_mcp("SEAL-1", "blog", "normattiva")
        self.assertEqual(self.meta()["tools"]["enabled"], ["web.fetch"])

    def test_an_unknown_mcp_is_refused(self):
        with self.assertRaises(RT.ToolboxError):
            RT.enable_mcp("SEAL-1", "blog", "packs")

    def test_a_resource_must_be_of_the_mcp(self):
        RT.enable_mcp("SEAL-1", "blog", "google")
        RT.set_resource("SEAL-1", "blog", "google", FOLDER, "allow")
        with self.assertRaises(RT.ToolboxError):
            RT.set_resource("SEAL-1", "blog", "google", "tg:-100", "allow")
        with self.assertRaises(RT.ToolboxError):
            RT.set_resource("SEAL-1", "blog", "google", FOLDER, "maybe")
        self.assertEqual(RT.resources(self.meta())["google"], [{"uri": FOLDER, "effect": "allow"}])
        RT.set_resource("SEAL-1", "blog", "google", FOLDER, None)
        self.assertEqual(RT.resources(self.meta())["google"], [])

    def test_a_resource_needs_the_mcp_authorised(self):
        with self.assertRaises(RT.ToolboxError):
            RT.set_resource("SEAL-1", "blog", "google", FOLDER, "allow")

    def test_revoking_drops_rows(self):
        RT.enable_mcp("SEAL-1", "blog", "google")
        RT.set_resource("SEAL-1", "blog", "google", FOLDER, "allow")
        RT.enable_mcp("SEAL-1", "blog", "google", on=False)
        self.assertNotIn("mcp", self.meta()["tools"])


class TupleTests(_Env):
    def _decide(self, agent, verb, target):
        R.invalidate()
        g, t = R.tuples_for(agent, "SEAL-1/blog")
        return A.decide(g, t, agent=agent, verb=verb, resource="*",
                        targets=[target], kind=A.WRITE).effect

    def test_a_row_decides_its_target_the_rest_keep_the_default(self):
        RT.enable_mcp("SEAL-1", "blog", "google")
        RT.set_resource("SEAL-1", "blog", "google", FOLDER, "allow")
        self.assertEqual(self._decide("clodia", "gdrive.upload", FOLDER), "allow")
        self.assertEqual(self._decide("clodia", "gdrive.upload", "gdrive:folder/ALTRA"), "ask")
        RT.set_resource("SEAL-1", "blog", "google", "mailto:*@x.it", "deny")
        self.assertEqual(self._decide("clodia", "gdrive.upload", "mailto:a@x.it"), "deny")

if __name__ == "__main__":
    unittest.main()


class CatalogueTests(unittest.TestCase):
    def test_a_connector_namespace_served_by_a_transport_is_listed(self):
        """GitHub: the backend is the connector's transport, the namespace
        is the MCP — it must be authorisable (26 Oct)."""
        from types import SimpleNamespace as NS
        conn = [NS(id="github", label="GitHub", pack="it-pack", namespace="github",
                   extends="", verbs=())]
        with patch.object(RT, "_catalogue", lambda: {"github": {"github.clone"},
                                                       "mail-reader": set()}), \
                patch.object(RT, "_registry", lambda: NS(connectors=conn)), \
                patch("server.connectors.resolved.transport_backends",
                      lambda: frozenset({"github", "mail-reader"})), \
                patch.object(RT, "_is_write", lambda v: True):
            cat = RT.mcp_catalogue()
        self.assertIn("github", cat)
        self.assertNotIn("mail-reader", cat)


class FamilyRowTests(_Env):
    def test_a_row_on_a_verb_family_reaches_the_family(self):
        cat = dict(CAT)
        cat["github"] = {"id": "github", "label": "GitHub", "kind": "connector",
                         "namespaces": ["github"], "enumerable": False, "verbs": [],
                         "write": [], "schemes": [{"scheme": "https", "direction": "egress",
                                                   "verbs": ["github.create_*", "github.push"]}]}
        with patch.object(RT, "mcp_catalogue", lambda: cat):
            RT.enable_mcp("SEAL-1", "blog", "github")
            RT.set_resource("SEAL-1", "blog", "github", "https://github.com/r-clodia/x", "deny")
            R.invalidate()
            g, t = R.tuples_for("clodia", "SEAL-1/blog")
            d = A.decide(g, t, agent="clodia", verb="github.create_issue", resource="*",
                         targets=["https://github.com/r-clodia/x"], kind=A.WRITE)
        self.assertEqual(d.effect, "deny")


class RuntimeVerbTests(_Env):
    """`runtime.room_*`: agents add tools and resources behind a consent."""

    def _run(self, name, args, scope="SEAL-1/blog", unattended=False):
        import asyncio
        from unittest.mock import AsyncMock
        g = AsyncMock(return_value=None)
        with patch("server.egress._scope_of_call", lambda: scope), \
                patch.object(main, "is_unattended", lambda: unattended), \
                patch.object(main, "_require_gate_consent", g):
            try:
                out = asyncio.run(main._room_tools_verb(name, args, "segretario"))
            except Exception as e:  # noqa: BLE001
                out = e
        return out, g

    def test_reading_needs_no_consent(self):
        out, g = self._run("runtime.room_tools", {})
        self.assertEqual(out["room"], "SEAL-1/blog")
        self.assertIn("google", out["catalogue"])
        self.assertFalse(g.await_count)

    def test_authorising_asks_the_owner_then_writes(self):
        out, g = self._run("runtime.room_authorize_mcp", {"mcp": "google"})
        self.assertEqual(g.await_count, 1)
        self.assertTrue(g.await_args.args[1].startswith("authz:runtime.room_authorize_mcp|SEAL-1/blog"))
        self.assertIn("google", RT._mcp_entries(self.meta()))
        out, g = self._run("runtime.room_resource",
                           {"mcp": "google", "uri": FOLDER, "effect": "allow"})
        self.assertEqual(g.await_count, 1)
        self.assertEqual(RT.resources(self.meta())["google"], [{"uri": FOLDER, "effect": "allow"}])
        self._run("runtime.room_resource", {"mcp": "google", "uri": FOLDER, "effect": "remove"})
        self.assertEqual(RT.resources(self.meta())["google"], [])

    def test_a_refused_consent_writes_nothing(self):
        import asyncio
        from unittest.mock import AsyncMock
        g = AsyncMock(side_effect=PermissionError("negato"))
        with patch("server.egress._scope_of_call", lambda: "SEAL-1/blog"), \
                patch.object(main, "is_unattended", lambda: False), \
                patch.object(main, "_require_gate_consent", g):
            with self.assertRaises(PermissionError):
                asyncio.run(main._room_tools_verb("runtime.room_authorize_mcp",
                                                  {"mcp": "google"}, "segretario"))
        self.assertNotIn("google", RT._mcp_entries(self.meta()))

    def test_in_a_room_only_that_room(self):
        out, g = self._run("runtime.room_authorize_mcp",
                           {"mcp": "google", "tier": "SEAL-1", "name": "altra"})
        self.assertIsInstance(out, PermissionError)
        self.assertFalse(g.await_count)

    def test_outside_a_room_an_admin_answers(self):
        out, g = self._run("runtime.room_authorize_mcp",
                           {"mcp": "google", "tier": "SEAL-1", "name": "blog"}, scope=None)
        self.assertTrue(g.await_args.args[1].startswith("authz-global:"))

    def test_bad_input_and_jobs_open_no_card(self):
        for args in ({"mcp": "packs"}, ):
            out, g = self._run("runtime.room_authorize_mcp", args)
            self.assertIsInstance(out, Exception)
            self.assertFalse(g.await_count)
        out, g = self._run("runtime.room_resource", {"mcp": "google", "uri": "tg:-1", "effect": "allow"})
        self.assertIsInstance(out, ValueError)
        self.assertFalse(g.await_count)
        out, g = self._run("runtime.room_authorize_mcp", {"mcp": "google"}, unattended=True)
        self.assertIsInstance(out, PermissionError)
        self.assertFalse(g.await_count)

    def test_no_room_can_grant_these_verbs(self):
        with self.assertRaises(RT.ToolboxError):
            RT.check("runtime.room_authorize_mcp")

"""#590 — topic-scoped data: the instance catalog (D1), topic imports (D2),
per-agent grants (D3) and the gateway's decision on the signed topic (D4)."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import data_catalog as cat, topic_data as td, whitelist
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicError, TopicService

DS = [{"pack": "tomato-pack", "name": "clienti", "clearance": "SEAL-2",
       "abs_path": "/x", "seeds": ["vecchio"]}]


class _Base(unittest.TestCase):
    def setUp(self):
        d = Path(tempfile.mkdtemp(prefix="cat-"))
        self.svc = TopicService(LocalFsStorage(tempfile.mkdtemp(prefix="topics-")))
        self.patches = [
            patch.object(cat, "_path", lambda: d / "data-catalog.json"),
            patch("server.datastores.declared", lambda: list(DS)),
            patch("server.tools.eu_corpus.collections",
                  lambda: {"collections": [{"collection": "eu-normativa", "tier": "SEAL-0"}]}),
            patch("server.tools.eu_corpus.collection_tier", lambda c: "SEAL-0"),
            patch.object(td, "_svc", lambda: self.svc),
            patch.object(whitelist, "CONFIG", {"data_access": "topic"}),
        ]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
        cat.sync()
        self.svc.new("SEAL-2", "commerciale", {"owner": "davide",
                                               "participants": ["davide", "tomato.commerciale", "clodia"]})
        self.svc.new("SEAL-1", "blog", {"owner": "davide", "participants": ["davide", "clodia"]})

    def imp(self, tier="SEAL-2", name="commerciale", kind="datastore",
            res="tomato-pack/clienti", who="davide", admin=True, clearance="SEAL-3"):
        return td.import_resource(tier, name, kind, res, principal=who, is_admin=admin,
                                  clearance=clearance)

    def auth(self, agent, write=False, scope="SEAL-2/commerciale", clearance="SEAL-2",
             kind="datastore", res="tomato-pack/clienti"):
        return td.authorize(kind, res, write=write, agent=agent, clearance=clearance, scope=scope)


class CatalogTests(_Base):
    def test_sync_lists_what_exists_once(self):
        keys = {e["key"] for e in cat.entries()}
        self.assertEqual(keys, {"datastore:tomato-pack/clienti", "rag:eu-normativa"})
        self.assertEqual(cat.sync(), 0)
        e = cat.get("datastore", "tomato-pack/clienti")
        self.assertEqual((e["tier"], e["importers"]), ("SEAL-2", ["@admin"]))

    def test_the_tier_can_be_raised_never_lowered_below_the_data(self):
        cat.update("datastore", "tomato-pack/clienti", tier="SEAL-0")
        self.assertEqual(cat.effective_tier(cat.get("datastore", "tomato-pack/clienti")), "SEAL-2")
        cat.update("datastore", "tomato-pack/clienti", tier="SEAL-3")
        self.assertEqual(cat.effective_tier(cat.get("datastore", "tomato-pack/clienti")), "SEAL-3")

    def test_retiring_keeps_nothing_reachable(self):
        self.imp()
        td.grant("SEAL-2", "commerciale", "datastore", "tomato-pack/clienti",
                 "tomato.commerciale", "read")
        self.assertTrue(cat.retire("datastore", "tomato-pack/clienti"))
        with patch("server.datastores.declared", lambda: []):
            with self.assertRaises(PermissionError):
                self.auth("tomato.commerciale")


class ImportTests(_Base):
    def test_one_resource_many_topics(self):
        self.svc.new("SEAL-3", "bilancio", {"owner": "davide", "participants": ["davide"]})
        self.imp()
        self.imp(tier="SEAL-3", name="bilancio")
        self.assertEqual(self.imp()["already"], True)

    def test_data_never_moves_down_a_level(self):
        with self.assertRaises(PermissionError) as c:
            self.imp(tier="SEAL-1", name="blog")
        self.assertIn("tier del topic", str(c.exception))

    def test_only_allowed_importers_with_clearance(self):
        with self.assertRaises(PermissionError):
            self.imp(who="mario", admin=False)
        with self.assertRaises(PermissionError):
            self.imp(clearance="SEAL-1")
        with self.assertRaises(PermissionError):
            self.imp(clearance=None)
        cat.update("datastore", "tomato-pack/clienti", importers=["mario"])
        self.assertTrue(self.imp(who="mario", admin=False)["ok"])

    def test_importing_topics(self):
        self.imp()
        self.assertEqual(td.importing_topics(),
                         {"datastore:tomato-pack/clienti": ["SEAL-2/commerciale"]})

    def test_unknown_resource(self):
        with self.assertRaises(td.DataError):
            self.imp(res="tomato-pack/fantasma")

    def test_a_topic_cannot_go_below_its_data(self):
        self.imp()
        meta = self.svc._read_meta("SEAL-2", "commerciale")[0]
        with self.assertRaises(td.DataError):
            td.check_retier(meta, "SEAL-1")
        td.check_retier(meta, "SEAL-3")


class GrantTests(_Base):
    def setUp(self):
        super().setUp()
        self.imp()

    def test_default_none_then_read_then_write(self):
        with self.assertRaises(PermissionError):
            self.auth("tomato.commerciale")
        td.grant("SEAL-2", "commerciale", "datastore", "tomato-pack/clienti",
                 "tomato.commerciale", "read")
        self.auth("tomato.commerciale")
        with self.assertRaises(PermissionError):
            self.auth("tomato.commerciale", write=True)
        td.grant("SEAL-2", "commerciale", "datastore", "tomato-pack/clienti",
                 "tomato.commerciale", "write")
        self.auth("tomato.commerciale", write=True)
        td.grant("SEAL-2", "commerciale", "datastore", "tomato-pack/clienti",
                 "tomato.commerciale", None)
        with self.assertRaises(PermissionError):
            self.auth("tomato.commerciale")

    def test_a_participant_demoted_to_reader_loses_write(self):
        td.grant("SEAL-2", "commerciale", "datastore", "tomato-pack/clienti",
                 "tomato.commerciale", "write")
        self.auth("tomato.commerciale", write=True)
        meta, ver = self.svc._read_meta("SEAL-2", "commerciale")
        meta["participants"] = {"tomato.commerciale": "reader", "clodia": "contributor"}
        self.svc._write_meta("SEAL-2", "commerciale", meta, ver)
        with self.assertRaises(PermissionError):
            self.auth("tomato.commerciale", write=True)
        self.auth("tomato.commerciale")

    def test_only_participants(self):
        with self.assertRaises(td.DataError):
            td.grant("SEAL-2", "commerciale", "datastore", "tomato-pack/clienti", "estraneo", "read")

    def test_a_participant_who_leaves_keeps_no_grant(self):
        td.grant("SEAL-2", "commerciale", "datastore", "tomato-pack/clienti",
                 "tomato.commerciale", "write")
        self.svc.remove_participant("SEAL-2", "commerciale", "tomato.commerciale")
        meta = self.svc._read_meta("SEAL-2", "commerciale")[0]
        self.assertEqual(td.imports(meta)[0]["grants"], {})

    def test_the_grant_is_per_topic(self):
        self.svc.new("SEAL-2", "altro", {"owner": "davide",
                                         "participants": ["davide", "tomato.commerciale"]})
        self.imp(name="altro")
        td.grant("SEAL-2", "commerciale", "datastore", "tomato-pack/clienti",
                 "tomato.commerciale", "write")
        td.grant("SEAL-2", "altro", "datastore", "tomato-pack/clienti",
                 "tomato.commerciale", "read")
        self.auth("tomato.commerciale", write=True)
        with self.assertRaises(PermissionError):
            self.auth("tomato.commerciale", write=True, scope="SEAL-2/altro")
        self.auth("tomato.commerciale", scope="SEAL-2/altro")

    def test_no_topic_no_access_and_clearance_still_counts(self):
        td.grant("SEAL-2", "commerciale", "datastore", "tomato-pack/clienti",
                 "tomato.commerciale", "read")
        with self.assertRaises(PermissionError):
            self.auth("tomato.commerciale", scope=None)
        with self.assertRaises(PermissionError):
            self.auth("tomato.commerciale", clearance="SEAL-1")

    def test_listing_shows_only_granted_imports(self):
        self.imp(kind="rag", res="eu-normativa")
        self.assertEqual(td.visible("rag", agent="clodia", scope="SEAL-2/commerciale",
                                    clearance="SEAL-2"), set())
        td.grant("SEAL-2", "commerciale", "rag", "eu-normativa", "clodia", "read")
        self.assertEqual(td.visible("rag", agent="clodia", scope="SEAL-2/commerciale",
                                    clearance="SEAL-2"), {"eu-normativa"})


class GatewayTests(_Base):
    """The two reference monitors in `main` follow the switch."""

    def setUp(self):
        super().setUp()
        self.imp()
        from . import main
        self.main = main

    def call_ds(self, agent, write=False, scope="SEAL-2/commerciale", clearance="SEAL-2"):
        m = self.main
        with patch.object(m, "agent_name", lambda: agent), \
                patch.object(m, "is_on_behalf", lambda: False), \
                patch.object(m, "current_clearance", lambda: clearance), \
                patch("server.egress._scope_of_call", lambda: scope), \
                patch("server.datastores.find", lambda p, n: dict(DS[0])):
            return m._datastore_authorize("tomato-pack/clienti", write=write)

    def test_topic_mode_ignores_the_seed_list(self):
        with self.assertRaises(PermissionError):
            self.call_ds("vecchio")              # in the manifest's seeds, not granted here
        td.grant("SEAL-2", "commerciale", "datastore", "tomato-pack/clienti", "clodia", "read")
        self.assertEqual(self.call_ds("clodia")["name"], "clienti")

    def test_legacy_mode_keeps_todays_rules(self):
        with patch.object(whitelist, "CONFIG", {"data_access": "legacy"}):
            self.assertEqual(self.call_ds("vecchio")["name"], "clienti")
            with self.assertRaises(PermissionError):
                self.call_ds("clodia")

    def test_rag_in_topic_mode(self):
        self.imp(kind="rag", res="eu-normativa")
        m = self.main
        with patch.object(m, "agent_name", lambda: "clodia"), \
                patch.object(m, "current_clearance", lambda: "SEAL-2"), \
                patch("server.egress._scope_of_call", lambda: "SEAL-2/commerciale"), \
                patch.object(m.instance_profile, "rag_check_collection", lambda c: None):
            with self.assertRaises(PermissionError):
                m._rag_authorize("eu-normativa", write=False)
            td.grant("SEAL-2", "commerciale", "rag", "eu-normativa", "clodia", "read")
            m._rag_authorize("eu-normativa", write=False)
            with self.assertRaises(PermissionError):
                m._rag_authorize("eu-normativa", write=True)
            with patch.object(m, "agent_name", lambda: "sysadmin"):
                m._rag_authorize("eu-normativa", write=True, verb="ingest")   # the provisioner


class SnapshotTests(unittest.TestCase):
    def test_an_archive_carries_no_import(self):
        import json
        from .topics_api import _snapshot_meta_bytes
        raw = json.dumps({"schema_version": 2, "tier": "SEAL-2", "title": "x",
                          "data": [{"kind": "datastore", "name": "a/b", "grants": {"x": "write"}}]}).encode()
        self.assertNotIn("data", json.loads(_snapshot_meta_bytes(raw, "SEAL-2")))


class RoutesTests(unittest.TestCase):
    """The admin catalog route and the owner data route, through Starlette."""

    def _client(self, payload):
        from starlette.applications import Starlette
        from starlette.testclient import TestClient
        from . import topics_api

        def fake_authorize(request):
            request.state.auth_payload = payload
            return payload.get("principal") or payload.get("agent"), None
        self.addCleanup(patch.stopall)
        patch.object(topics_api, "_authorize", fake_authorize).start()
        return TestClient(Starlette(routes=topics_api.routes))

    def test_s7_agents_do_not_read_the_catalog(self):
        patch.object(whitelist, "CONFIG", {}).start()
        c = self._client({"agent": "clodia"})
        self.assertEqual(c.get("/internal/data-catalog").status_code, 403)

    def test_the_topic_data_route_takes_the_signed_person(self):
        from . import topics_api, topic_data
        seen = {}
        def owner_ok(request):
            request.state.auth_payload = {"principal": "mario", "on_behalf": True,
                                          "human_role": "user", "clearance": "SEAL-1"}
            return "mario", None
        patch.object(topics_api, "_authorize_topic_owner", owner_ok).start()
        patch.object(topic_data, "import_resource",
                     lambda *a, **k: seen.update(k) or {"ok": True}).start()
        c = self._client({"principal": "mario", "on_behalf": True, "human_role": "user",
                          "clearance": "SEAL-1"})
        r = c.post("/internal/topics/SEAL-1/x/data", json={
            "action": "import", "kind": "rag", "resource": "c",
            "by": "davide", "by_admin": True, "by_clearance": "SEAL-4"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual((seen["principal"], seen["is_admin"], seen["clearance"]),
                         ("mario", False, "SEAL-1"))

    def test_only_admins_or_the_agent_server_write_the_catalog(self):
        saved = {}
        patch.object(whitelist, "CONFIG", {}).start()
        patch.object(whitelist, "save_config", lambda: saved.update(ok=True)).start()
        c = self._client({"agent": "clodia"})
        self.assertEqual(c.post("/internal/data-catalog",
                                json={"action": "set_mode", "mode": "topic"}).status_code, 403)
        c = self._client({"agent": "clodia", "role": "agent-server"})
        r = c.post("/internal/data-catalog", json={"action": "set_mode", "mode": "topic"})
        self.assertEqual((r.status_code, whitelist.CONFIG.get("data_access")), (200, "topic"))
        self.assertEqual(c.post("/internal/data-catalog",
                                json={"action": "set_mode", "mode": "x"}).status_code, 400)


class MigrationTests(_Base):
    def setUp(self):
        super().setUp()
        from . import data_migration as dm
        self.dm = dm
        p = patch("server.main._topics", lambda: self.svc)
        p.start(); self.addCleanup(p.stop)
        cfg = {"data_access": "legacy", "agents": {
            "vecchio": {"allowed_tools": ["datastore.read", "datastore.write"]},
            "lettore": {"allowed_tools": ["datastore.read"]},
            "clodia": {"allowed_tools": ["*"]}}}
        p = patch.object(whitelist, "CONFIG", cfg)
        p.start(); self.addCleanup(p.stop)
        DS[0]["seeds"] = ["vecchio", "lettore"]
        self.addCleanup(lambda: DS[0].__setitem__("seeds", ["vecchio"]))
        self.svc.new("SEAL-2", "vendite", {"owner": "davide",
                                           "participants": ["davide", "vecchio", "lettore"]})
        self.svc.new("SEAL-1", "basso", {"owner": "davide", "participants": ["davide", "vecchio"]})
        grants = {"clodia": {"rag_read": {"eu-normativa"}, "rag_write": set()}}
        p = patch("server.tools.runtime.rag_grants",
                  lambda a: grants.get(a, {"rag_read": set(), "rag_write": set()}))
        p.start(); self.addCleanup(p.stop)

    def test_the_plan_maps_seed_grants_to_topics(self):
        plan = self.dm.plan()
        by = {(i["topic"], i["kind"], i["name"]): i for i in plan["items"]}
        v = by[("SEAL-2/vendite", "datastore", "tomato-pack/clienti")]
        self.assertEqual((v["status"], v["grants"]), ("ok", {"vecchio": "write", "lettore": "read"}))
        self.assertEqual(by[("SEAL-1/basso", "datastore", "tomato-pack/clienti")]["status"], "skipped")
        self.assertEqual(by[("SEAL-1/blog", "rag", "eu-normativa")]["grants"], {"clodia": "read"})
        self.assertNotIn(("SEAL-2/commerciale", "datastore", "tomato-pack/clienti"), by)

    def test_apply_writes_only_approved_items_and_never_switches(self):
        plan = self.dm.plan()
        out = self.dm.apply(plan["items"], by="davide", is_admin=True, clearance="SEAL-3")
        self.assertEqual(out["failed"], [])
        meta = self.svc._read_meta("SEAL-2", "vendite")[0]
        self.assertEqual(td.imports(meta)[0]["grants"], {"vecchio": "write", "lettore": "read"})
        basso = td.imports(self.svc._read_meta("SEAL-1", "basso")[0])
        self.assertNotIn("datastore", {e["kind"] for e in basso})     # SEAL-2 data, SEAL-1 topic
        self.assertEqual(whitelist.CONFIG["data_access"], "legacy")


class ReviewFixesTests(_Base):
    """Review of clodia-tools#420."""

    def test_b1_a_creator_never_brings_imports(self):
        m = self.svc.new("SEAL-3", "mio", {"owner": "rogue", "participants": ["rogue"],
                                         "data": [{"kind": "datastore", "name": "tomato-pack/clienti",
                                                   "grants": {"rogue": "write"}}]})
        self.assertNotIn("data", m)
        with self.assertRaises(PermissionError):
            self.auth("rogue", write=True, scope="SEAL-3/mio", clearance="SEAL-3")

    def test_s2_reader_gets_no_write_and_owner_may_be_granted(self):
        self.svc.new("SEAL-2", "ruoli", {"owner": "davide", "participants": ["davide"]})
        meta, ver = self.svc._read_meta("SEAL-2", "ruoli")
        meta["participants"] = {"lett": "reader", "scrive": "contributor"}
        self.svc._write_meta("SEAL-2", "ruoli", meta, ver)
        self.imp(name="ruoli")
        with self.assertRaises(td.DataError):
            td.grant("SEAL-2", "ruoli", "datastore", "tomato-pack/clienti", "lett", "write")
        td.grant("SEAL-2", "ruoli", "datastore", "tomato-pack/clienti", "lett", "read")
        td.grant("SEAL-2", "ruoli", "datastore", "tomato-pack/clienti", "scrive", "write")
        td.grant("SEAL-2", "ruoli", "datastore", "tomato-pack/clienti", "davide", "read")

    def test_s3_unknown_levels_have_nothing(self):
        self.imp()
        td.grant("SEAL-2", "commerciale", "datastore", "tomato-pack/clienti",
                 "tomato.commerciale", "read")
        for bogus in ("bogus", "", None):
            with self.subTest(clearance=bogus):
                with self.assertRaises(PermissionError):
                    self.auth("tomato.commerciale", clearance=bogus)
        self.assertTrue(cat.may_import(cat.get("datastore", "tomato-pack/clienti"), "davide",
                                       is_admin=True, clearance="x"))
        with self.assertRaises(ValueError):
            cat.update("datastore", "tomato-pack/clienti", tier="SEAL-9")

    def test_visible_matches_authorize(self):
        self.imp(kind="rag", res="eu-normativa")
        td.grant("SEAL-2", "commerciale", "rag", "eu-normativa", "clodia", "read")
        self.assertEqual(td.visible("rag", agent="clodia", scope="SEAL-2/commerciale",
                                    clearance="SEAL-2"), {"eu-normativa"})
        self.assertEqual(td.visible("rag", agent="clodia", scope="SEAL-2/commerciale",
                                    clearance=None), set())


class IngestTests(_Base):
    def setUp(self):
        super().setUp()
        from . import main
        self.main = main

    def check(self, agent, scope, src_tier, src_name="x"):
        m = self.main
        with patch.object(m, "agent_name", lambda: agent), \
                patch("server.egress._scope_of_call", lambda: scope):
            return m._ingest_source_ok("eu-normativa", src_tier, src_name)

    def test_s1_data_never_moves_down_through_an_ingest(self):
        with self.assertRaises(PermissionError):
            self.check("sysadmin", None, "SEAL-3")             # SEAL-3 file, SEAL-0 collection
        self.check("sysadmin", None, "SEAL-0")
        with self.assertRaises(PermissionError):
            self.check("clodia", "SEAL-0/altro", "SEAL-0")     # not the call's own topic
        self.check("clodia", "SEAL-0/x", "SEAL-0")

    def test_legacy_mode_does_not_check(self):
        with patch.object(whitelist, "CONFIG", {"data_access": "legacy"}):
            self.check("clodia", None, "SEAL-3")

    def test_s5_the_provisioner_removes_like_anyone(self):
        m = self.main
        with patch.object(m, "agent_name", lambda: "sysadmin"), \
                patch.object(m, "current_clearance", lambda: "SEAL-4"), \
                patch("server.egress._scope_of_call", lambda: None), \
                patch.object(m.instance_profile, "rag_check_collection", lambda c: None):
            m._rag_authorize("eu-normativa", write=True, verb="ingest")
            with self.assertRaises(PermissionError):
                m._rag_authorize("eu-normativa", write=True)          # a remove


class MigrationReviewTests(_Base):
    def test_s4_the_plan_never_grants_beyond_the_member_list(self):
        from . import data_migration as dm
        cfg = {"data_access": "legacy", "agents": {"clodia": {"allowed_tools": ["*"]},
                                                     "estraneo": {"allowed_tools": []}}}
        with patch.object(whitelist, "CONFIG", cfg), \
                patch("server.main._topics", lambda: self.svc), \
                patch("server.main._rag_declared_members", lambda c: ["clodia"]), \
                patch("server.tools.runtime.rag_grants",
                      lambda a: {"rag_read": {"*"}, "rag_write": set()}):
            self.svc.new("SEAL-1", "tutti", {"owner": "davide",
                                            "participants": ["davide", "clodia", "estraneo"]})
            items = [i for i in dm.plan()["items"] if i["topic"] == "SEAL-1/tutti"]
        self.assertEqual(items[0]["grants"], {"clodia": "read"})


if __name__ == "__main__":
    unittest.main()

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
       "abs_path": "/x"}]


class _Base(unittest.TestCase):
    def setUp(self):
        from . import authz_runtime as _azr
        _azr.invalidate()               # the room view is cached per scope
        self.addCleanup(_azr.invalidate)
        d = Path(tempfile.mkdtemp(prefix="cat-"))
        self.svc = TopicService(LocalFsStorage(tempfile.mkdtemp(prefix="topics-")))
        self.patches = [
            patch.object(cat, "_path", lambda: d / "data-catalog.json"),
            patch("server.datastores.declared", lambda: list(DS)),
            patch("server.tools.eu_corpus.collections",
                  lambda: {"collections": [{"collection": "eu-normativa", "tier": "SEAL-0"}]}),
            patch("server.tools.eu_corpus.collection_tier", lambda c: "SEAL-0"),
            patch.object(td, "_svc", lambda: self.svc),
            patch.object(whitelist, "CONFIG", {}),
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

    def test_the_admins_level_is_the_level(self):
        """The source's level is the starting value; an admin's choice wins,
        also downward (owner, 27 Oct 2026)."""
        self.assertEqual(cat.effective_tier(cat.get("datastore", "tomato-pack/clienti")), "SEAL-2")
        cat.update("datastore", "tomato-pack/clienti", tier="SEAL-0")
        self.assertEqual(cat.effective_tier(cat.get("datastore", "tomato-pack/clienti")), "SEAL-0")
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
        self.assertIn("tier dello scope", str(c.exception))

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

    def test_a_participant_reads_and_writes_an_outsider_nothing(self):
        """#653 (owner, 5 Nov 2026): no per-agent roles — being in the room is
        read AND write; leaving the room is neither."""
        self.auth("tomato.commerciale")
        self.auth("tomato.commerciale", write=True)
        with self.assertRaises(PermissionError):
            self.auth("estraneo")
        self.svc.remove_participant("SEAL-2", "commerciale", "tomato.commerciale")
        with self.assertRaises(PermissionError):
            self.auth("tomato.commerciale")

    def test_a_former_reader_keeps_write(self):
        """The reader role is abolished (24 Oct 2026, epic #604): a `reader`
        left in a meta reads as contributor and keeps its write grant."""
        td.grant("SEAL-2", "commerciale", "datastore", "tomato-pack/clienti",
                 "tomato.commerciale", "write")
        self.auth("tomato.commerciale", write=True)
        meta, ver = self.svc._read_meta("SEAL-2", "commerciale")
        meta["participants"] = {"tomato.commerciale": "reader", "clodia": "contributor"}
        self.svc._write_meta("SEAL-2", "commerciale", meta, ver)
        self.auth("tomato.commerciale", write=True)

    def test_only_participants(self):
        with self.assertRaises(td.DataError):
            td.grant("SEAL-2", "commerciale", "datastore", "tomato-pack/clienti", "estraneo", "read")

    def test_a_participant_who_leaves_keeps_no_grant(self):
        td.grant("SEAL-2", "commerciale", "datastore", "tomato-pack/clienti",
                 "tomato.commerciale", "write")
        self.svc.remove_participant("SEAL-2", "commerciale", "tomato.commerciale")
        meta = self.svc._read_meta("SEAL-2", "commerciale")[0]
        self.assertEqual(td.imports(meta)[0]["grants"], {})

    def test_access_is_per_topic(self):
        self.svc.new("SEAL-2", "altro", {"owner": "davide", "participants": ["davide"]})
        self.imp(name="altro")
        self.auth("tomato.commerciale", write=True)
        with self.assertRaises(PermissionError):
            self.auth("tomato.commerciale", scope="SEAL-2/altro")       # not in that room

    def test_no_topic_no_access_and_clearance_still_counts(self):
        td.grant("SEAL-2", "commerciale", "datastore", "tomato-pack/clienti",
                 "tomato.commerciale", "read")
        with self.assertRaises(PermissionError):
            self.auth("tomato.commerciale", scope=None)
        with self.assertRaises(PermissionError):
            self.auth("tomato.commerciale", clearance="SEAL-1")

    def test_listing_shows_every_import_to_participants(self):
        self.assertEqual(td.visible("datastore", agent="clodia", scope="SEAL-2/commerciale",
                                    clearance="SEAL-3"), {"tomato-pack/clienti"})
        self.imp(kind="rag", res="eu-normativa")
        self.assertEqual(td.visible("rag", agent="clodia", scope="SEAL-2/commerciale",
                                    clearance="SEAL-2"), {"eu-normativa"})
        self.assertEqual(td.visible("rag", agent="estraneo", scope="SEAL-2/commerciale",
                                    clearance="SEAL-2"), set())

    def test_every_participant_reads_and_writes_the_rooms_rag_but_not_its_index(self):
        self.imp(kind="rag", res="eu-normativa")
        self.auth("clodia", kind="rag", res="eu-normativa")
        self.auth("clodia", kind="rag", res="eu-normativa", write=True)
        with self.assertRaises(PermissionError):
            self.auth("estraneo", kind="rag", res="eu-normativa")
        meta, ver = self.svc._read_meta("SEAL-2", "commerciale")
        meta["data"] = meta.get("data", []) + [{"kind": "rag", "name": "topic-abcd", "grants": {}}]
        self.svc._write_meta("SEAL-2", "commerciale", meta, ver)
        with patch.object(td.cat, "get", lambda k, n: {"tier": "SEAL-0", "name": n}), \
                patch.object(td.cat, "effective_tier", lambda e: "SEAL-0"):
            self.auth("clodia", kind="rag", res="topic-abcd")
            with self.assertRaises(PermissionError):
                self.auth("clodia", kind="rag", res="topic-abcd", write=True)
        self.svc.remove_participant("SEAL-2", "commerciale", "clodia")
        with self.assertRaises(PermissionError):
            self.auth("clodia", kind="rag", res="eu-normativa")
        self.svc.add_participant("SEAL-2", "commerciale", "clodia")
        self.auth("clodia", kind="rag", res="eu-normativa")
        self.assertIn("rag.search", td.room_verbs("clodia", "SEAL-2/commerciale"))


class GatewayTests(_Base):
    """The two reference monitors in `main` decide on the scope's imports only
    (#669: no legacy mode, no seed list, no super-agent bypass)."""

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
                patch("server.topic_data.scope_of_call", lambda: scope), \
                patch("server.datastores.find", lambda p, n: dict(DS[0])):
            return m._datastore_authorize("tomato-pack/clienti", write=write)

    def test_the_seed_list_grants_nothing(self):
        with self.assertRaises(PermissionError):
            self.call_ds("vecchio")              # not in the room: no seed list to fall back on
        self.assertEqual(self.call_ds("clodia")["name"], "clienti")

    def test_a_super_agent_has_no_bypass(self):
        m = self.main
        with patch.object(m, "_is_super", lambda a: True):
            with self.assertRaises(PermissionError):
                self.call_ds("sysadmin")
            with self.assertRaises(PermissionError):
                self.call_ds("clodia", scope=None)   # no scope, no data

    def test_rag_in_topic_mode(self):
        self.imp(kind="rag", res="eu-normativa")
        m = self.main
        with patch.object(m, "agent_name", lambda: "clodia"), \
                patch.object(m, "current_clearance", lambda: "SEAL-2"), \
                patch("server.topic_data.scope_of_call", lambda: "SEAL-2/commerciale"), \
                patch.object(m.instance_profile, "rag_check_collection", lambda c: None):
            m._rag_authorize("eu-normativa", write=False)          # a participant reads
            m._rag_authorize("eu-normativa", write=True)           # and writes (#653)
            with patch.object(m, "agent_name", lambda: "estraneo"):
                with self.assertRaises(PermissionError):
                    m._rag_authorize("eu-normativa", write=False)
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
        from . import topic_data
        patch.object(whitelist, "CONFIG", {}).start()
        patch.object(topic_data, "check_import",
                     lambda *a, **k: {"kind": a[0], "name": a[1], "tier": "SEAL-0"}).start()
        body = {"action": "check_import", "kind": "rag", "resource": "c", "tier": "SEAL-1",
                "by": "davide", "by_admin": True}
        c = self._client({"agent": "clodia"})
        self.assertEqual(c.post("/internal/data-catalog", json=body).status_code, 403)
        c = self._client({"agent": "clodia", "role": "agent-server"})
        self.assertEqual(c.post("/internal/data-catalog", json=body).status_code, 200)

    def test_the_legacy_switch_and_the_migration_are_gone(self):
        """#669: scope imports are the only mode — nothing to switch, nothing
        to migrate."""
        patch.object(whitelist, "CONFIG", {}).start()
        c = self._client({"agent": "clodia", "role": "agent-server"})
        for action in ("set_mode", "migration_plan", "migration_apply"):
            r = c.post("/internal/data-catalog", json={"action": action, "mode": "topic"})
            self.assertEqual(r.status_code, 400, action)
        self.assertNotIn("data_access", whitelist.CONFIG)


class ReviewFixesTests(_Base):
    """Review of clodia-tools#420."""

    def test_b1_a_creator_never_brings_imports(self):
        m = self.svc.new("SEAL-3", "mio", {"owner": "rogue", "participants": ["rogue"],
                                         "data": [{"kind": "datastore", "name": "tomato-pack/clienti",
                                                   "grants": {"rogue": "write"}}]})
        self.assertNotIn("data", m)
        with self.assertRaises(PermissionError):
            self.auth("rogue", write=True, scope="SEAL-3/mio", clearance="SEAL-3")

    def test_s2_a_former_reader_may_get_write_and_owner_may_be_granted(self):
        self.svc.new("SEAL-2", "ruoli", {"owner": "davide", "participants": ["davide"]})
        meta, ver = self.svc._read_meta("SEAL-2", "ruoli")
        meta["participants"] = {"lett": "reader", "scrive": "contributor"}
        self.svc._write_meta("SEAL-2", "ruoli", meta, ver)
        self.imp(name="ruoli")
        td.grant("SEAL-2", "ruoli", "datastore", "tomato-pack/clienti", "lett", "write")
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
                patch("server.topic_data.scope_of_call", lambda: scope):
            return m._ingest_source_ok("eu-normativa", src_tier, src_name)

    def test_s1_data_never_moves_down_through_an_ingest(self):
        with self.assertRaises(PermissionError):
            self.check("sysadmin", None, "SEAL-3")             # SEAL-3 file, SEAL-0 collection
        self.check("sysadmin", None, "SEAL-0")
        with self.assertRaises(PermissionError):
            self.check("clodia", "SEAL-0/altro", "SEAL-0")     # not the call's own topic
        self.check("clodia", "SEAL-0/x", "SEAL-0")

    def test_s5_the_provisioner_removes_like_anyone(self):
        m = self.main
        with patch.object(m, "agent_name", lambda: "sysadmin"), \
                patch.object(m, "current_clearance", lambda: "SEAL-4"), \
                patch("server.topic_data.scope_of_call", lambda: None), \
                patch.object(m.instance_profile, "rag_check_collection", lambda c: None):
            m._rag_authorize("eu-normativa", write=True, verb="ingest")
            with self.assertRaises(PermissionError):
                m._rag_authorize("eu-normativa", write=True)          # a remove


class RoomVerbsTests(_Base):
    """An agent granted an imported index can query it in that room even when
    its seed never declared rag.* (tomato.sales-rep, 23 Oct 2026)."""

    def test_being_in_the_room_brings_the_verbs_in_that_room_only(self):
        self.imp(kind="rag", res="eu-normativa")
        self.imp()
        self.assertEqual(td.room_verbs("tomato.commerciale", "SEAL-2/commerciale"),
                         {"rag.search", "rag.list", "rag.collections", "rag.ingest",
                          "rag.remove", "datastore.read", "datastore.write"})
        self.assertEqual(td.room_verbs("tomato.commerciale", "SEAL-1/blog"), set())
        self.assertEqual(td.room_verbs("tomato.commerciale", None), set())

    def test_reachability_follows_the_room(self):
        from . import main
        self.imp(kind="rag", res="eu-normativa")
        td.grant("SEAL-2", "commerciale", "rag", "eu-normativa", "tomato.commerciale", "read")
        # The room's imported data are tuples (#617): the gateway reads the
        # room through `main._topics()`, the same store.
        with patch.object(main, "_topics", lambda: self.svc), \
                patch.object(main, "current_scoped_tools", lambda: ()):
            with patch("server.egress._scope_of_call", lambda: "SEAL-2/commerciale"):
                self.assertTrue(main._agent_tool_reachable("rag.search", "tomato.commerciale"))
                self.assertFalse(main._agent_tool_reachable("datastore.write", "tomato.commerciale"))
            with patch("server.egress._scope_of_call", lambda: "SEAL-1/blog"):
                self.assertFalse(main._agent_tool_reachable("rag.search", "tomato.commerciale"))


if __name__ == "__main__":
    unittest.main()

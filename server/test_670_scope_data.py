"""#669/#670 — scope imports are the only data access, and a DM or an agentic
job is a scope like a topic.

- the scope comes from the signed `chat` claim (`topic_data.scope_of_call`);
- a DM (`kind: dm`, SEAL-0) imports and authorizes exactly like a topic;
- a job's `data` (read live from the agent-server) is used by the agent that
  executes it, within the job's tier (declared, else the agent's clearance);
- the A·V·R·Q global level carries a job's data tuples in that job's turn;
- the pack provisioner keeps its create/ingest exception and its listing.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import data_catalog as cat, topic_data as td, whitelist
from .test_590_topic_data import _Base


def _job(**over):
    j = {"id": 12, "agent": "clodia", "mode": "agentic", "tier": "",
         "data": [{"kind": "datastore", "name": "tomato-pack/clienti"},
                  {"kind": "rag", "name": "eu-normativa"}], "enabled": True}
    j.update(over)
    return j


class ScopeOfCallTests(unittest.TestCase):
    def _scope(self, chat):
        with patch.object(whitelist, "current_chat", lambda: chat):
            return td.scope_of_call()

    def test_the_signed_chat_names_the_scope(self):
        self.assertEqual(self._scope("chan:SEAL-2:commerciale:clodia"), "SEAL-2/commerciale")
        self.assertEqual(self._scope("chan:SEAL-0:dm-clodia--davide:clodia"),
                         "SEAL-0/dm-clodia--davide")
        self.assertEqual(self._scope("job:12:20261111-101010-abc123"), "job:12")

    def test_anything_else_is_no_scope(self):
        for chat in (None, "", "20261111-101010-abc123", "job:", "job:x:1", "jobs:1:2"):
            with self.subTest(chat=chat):
                self.assertIsNone(self._scope(chat))

    def test_job_id(self):
        self.assertEqual(td.job_id("job:7"), 7)
        self.assertIsNone(td.job_id("SEAL-1/x"))
        self.assertIsNone(td.job_id(None))


class DmScopeTests(_Base):
    """A DM is a topic (`kind: dm`, SEAL-0): it imports and decides the same."""

    def setUp(self):
        super().setUp()
        self.svc.new("SEAL-0", "dm-clodia--davide", {
            "kind": "dm", "type": "dm", "owner": "davide",
            "participants": ["davide", "clodia"], "contact_agent": "clodia"})
        cat.update("datastore", "tomato-pack/clienti", tier="SEAL-0")

    def test_a_dm_imports_and_its_agent_uses_it(self):
        self.imp(tier="SEAL-0", name="dm-clodia--davide")
        self.assertEqual(self.auth("clodia", write=True, scope="SEAL-0/dm-clodia--davide",
                                   clearance="SEAL-1")["name"], "tomato-pack/clienti")
        with self.assertRaises(PermissionError):
            self.auth("ophelia", scope="SEAL-0/dm-clodia--davide", clearance="SEAL-1")

    def test_a_dm_takes_only_seal0_data(self):
        """The owner decision of #670: DMs are fixed at SEAL-0 today."""
        cat.update("datastore", "tomato-pack/clienti", tier="SEAL-1")
        with self.assertRaises(PermissionError):
            self.imp(tier="SEAL-0", name="dm-clodia--davide")


class JobScopeTests(_Base):
    def setUp(self):
        super().setUp()
        td._job_cache.clear()
        self.addCleanup(td._job_cache.clear)
        self.job = _job()
        p = patch("server.tools.runtime.job_scope", lambda jid: dict(self.job))
        p.start()
        self.addCleanup(p.stop)

    def jauth(self, agent="clodia", write=False, clearance="SEAL-2",
              kind="datastore", res="tomato-pack/clienti"):
        td._job_cache.clear()
        return td.authorize(kind, res, write=write, agent=agent, clearance=clearance,
                            scope="job:12")

    def test_the_jobs_agent_reads_and_writes_what_the_job_imports(self):
        self.assertEqual(self.jauth()["name"], "tomato-pack/clienti")
        self.jauth(write=True)
        self.jauth(kind="rag", res="eu-normativa", write=True)

    def test_only_the_jobs_agent(self):
        with self.assertRaises(PermissionError) as c:
            self.jauth(agent="ophelia")
        self.assertIn("non esegue il job 12", str(c.exception))

    def test_only_what_the_job_imports(self):
        self.job["data"] = [{"kind": "rag", "name": "eu-normativa"}]
        with self.assertRaises(PermissionError):
            self.jauth()

    def test_the_declared_tier_bounds_the_data(self):
        self.job["tier"] = "SEAL-1"                 # clienti is SEAL-2
        with self.assertRaises(PermissionError) as c:
            self.jauth(clearance="SEAL-3")
        self.assertIn("tier del job", str(c.exception))
        self.job["tier"] = "SEAL-3"
        self.jauth(clearance="SEAL-3")

    def test_undeclared_tier_is_the_agents_clearance(self):
        self.assertEqual(td.job_tier({"tier": ""}, "SEAL-2"), "SEAL-2")
        with self.assertRaises(PermissionError):
            self.jauth(clearance="SEAL-1")

    def test_not_an_agentic_job_no_data(self):
        for mode in ("logic", "topic_trigger"):
            with self.subTest(mode=mode):
                self.job["mode"] = mode
                with self.assertRaises(PermissionError):
                    self.jauth()

    def test_an_unreadable_job_refuses(self):
        def boom(jid):
            raise RuntimeError("agent-server giù")
        with patch("server.tools.runtime.job_scope", boom):
            with self.assertRaises(PermissionError) as c:
                self.jauth()
        self.assertIn("non leggibile", str(c.exception))

    def test_a_retired_resource_is_out(self):
        self.assertTrue(cat.retire("datastore", "tomato-pack/clienti"))
        with patch("server.datastores.declared", lambda: []):
            with self.assertRaises(PermissionError):
                self.jauth()

    def test_visible_matches_authorize(self):
        td._job_cache.clear()
        self.assertEqual(td.visible("rag", agent="clodia", scope="job:12", clearance="SEAL-2"),
                         {"eu-normativa"})
        td._job_cache.clear()
        self.assertEqual(td.visible("rag", agent="ophelia", scope="job:12",
                                    clearance="SEAL-2"), set())

    def test_the_gateway_monitors_take_the_job_from_the_claim(self):
        from . import main
        with patch.object(main, "agent_name", lambda: "clodia"), \
                patch.object(main, "is_on_behalf", lambda: False), \
                patch.object(main, "current_clearance", lambda: "SEAL-2"), \
                patch.object(whitelist, "current_chat", lambda: "job:12:20261111-x"), \
                patch.object(main.instance_profile, "rag_check_collection", lambda c: None), \
                patch("server.datastores.find", lambda p, n: {"name": "clienti", "clearance": "SEAL-2"}):
            td._job_cache.clear()
            self.assertEqual(main._datastore_authorize("tomato-pack/clienti",
                                                       write=True)["name"], "clienti")
            main._rag_authorize("eu-normativa", write=False)
            res = main._dispatch_rag("rag.collections", {})
            self.assertEqual([c["collection"] for c in res["collections"]], ["eu-normativa"])
            with patch.object(whitelist, "current_chat", lambda: "20261111-x"):
                with self.assertRaises(PermissionError):
                    main._rag_authorize("eu-normativa", write=False)

    def test_a_job_does_not_import_a_rooms_index(self):
        with self.assertRaises(td.DataError):
            td.check_import("rag", "topic-abc", "SEAL-2", principal="davide",
                            is_admin=True, clearance="SEAL-3", scope_kind="job")

    def test_check_import_applies_the_topic_rules(self):
        out = td.check_import("datastore", "tomato-pack/clienti", "SEAL-2",
                              principal="davide", is_admin=True, clearance="SEAL-3")
        self.assertEqual(out["tier"], "SEAL-2")
        with self.assertRaises(PermissionError):
            td.check_import("datastore", "tomato-pack/clienti", "SEAL-1",
                            principal="davide", is_admin=True, clearance="SEAL-3",
                            scope_kind="job")
        with self.assertRaises(PermissionError):
            td.check_import("datastore", "tomato-pack/clienti", "SEAL-2",
                            principal="mario", is_admin=False, clearance="SEAL-3")


class JobTuplesTests(_Base):
    """The job's data as A·V·R·Q tuples, on the global level, in its turn."""

    def setUp(self):
        super().setUp()
        td._job_cache.clear()
        self.addCleanup(td._job_cache.clear)
        p = patch("server.tools.runtime.job_scope", lambda jid: _job())
        p.start()
        self.addCleanup(p.stop)

    def _tuples(self, agent, chat):
        from . import authz_runtime as azr
        with patch.object(whitelist, "current_chat", lambda: chat):
            td._job_cache.clear()
            return azr.tuples_for(agent, None)

    def test_in_the_jobs_turn_its_agent_gets_the_data_verbs(self):
        g, t = self._tuples("clodia", "job:12:20261111-x")
        self.assertIsNone(t)                         # a job is not a room
        mine = {(x.verb, x.resource) for x in g if x.id.startswith("job-data:12:")}
        self.assertIn(("rag.search", "rag:eu-normativa"), mine)
        self.assertIn(("datastore.write", "datastore:tomato-pack/clienti"), mine)

    def test_nobody_else_and_nowhere_else(self):
        g, _ = self._tuples("ophelia", "job:12:20261111-x")
        self.assertFalse([x for x in g if x.id.startswith("job-data:")])
        g, _ = self._tuples("clodia", "20261111-x")
        self.assertFalse([x for x in g if x.id.startswith("job-data:")])


class ProvisionerTests(_Base):
    """`CLODIA_RAG_PROVISIONERS` keeps creating and ingesting for a pack, and
    lists the collections within its clearance (#669 keeps the exception)."""

    def _call(self, agent, clearance, fn):
        from . import main
        with patch.object(main, "agent_name", lambda: agent), \
                patch.object(main, "current_clearance", lambda: clearance), \
                patch("server.topic_data.scope_of_call", lambda: None), \
                patch.object(main.instance_profile, "rag_check_collection", lambda c: None), \
                patch("server.tools.eu_corpus.collection_tier", lambda c: "SEAL-1"):
            return fn(main)

    def test_create_and_ingest_within_clearance(self):
        self._call("sysadmin", "SEAL-2",
                   lambda m: m._rag_authorize("kb", write=True, verb="create_collection"))
        self._call("sysadmin", "SEAL-2",
                   lambda m: m._rag_authorize("kb", write=True, verb="ingest"))
        with self.assertRaises(PermissionError):
            self._call("sysadmin", "SEAL-0",
                       lambda m: m._rag_authorize("kb", write=True, verb="ingest"))

    def test_reading_is_not_part_of_the_exception(self):
        with self.assertRaises(PermissionError):
            self._call("sysadmin", "SEAL-4", lambda m: m._rag_authorize("kb", write=False))

    def test_the_provisioner_lists_within_clearance_and_others_nothing(self):
        cols = {"collections": [{"collection": "a", "tier": "SEAL-0"},
                                {"collection": "b", "tier": "SEAL-3"},
                                {"collection": "topic-x", "tier": "SEAL-0"}]}
        with patch("server.tools.eu_corpus.collections", lambda: cols):
            res = self._call("sysadmin", "SEAL-1",
                             lambda m: m._dispatch_rag("rag.collections", {}))
            self.assertEqual([c["collection"] for c in res["collections"]], ["a"])
            from . import main
            with patch.object(main, "_is_super", lambda a: True):
                res = self._call("clodia", "SEAL-4",
                                 lambda m: m._dispatch_rag("rag.collections", {}))
            self.assertEqual(res["collections"], [])     # no scope, no bypass


if __name__ == "__main__":
    unittest.main()

"""#669/#670 — scope imports are the only data access, and a DM or an agentic
job is a scope like a topic.

- the scope comes from the signed `chat` claim (`topic_data.scope_of_call`);
- a DM (`kind: dm`, SEAL-0) imports and authorizes exactly like a topic;
- a job's `data` (read live from the agent-server) is used by the agent that
  executes it; the job must declare a tier (owner, 11 Nov 2026) and resource
  tier ≤ job tier ≤ the agent's clearance;
- the A·V·R·Q global level carries a job's data tuples in that job's turn;
- the pack provisioner keeps its create/ingest exception and its listing.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import data_catalog as cat, topic_data as td, whitelist
from .test_590_topic_data import _Base


def _job(**over):
    j = {"id": 12, "agent": "clodia", "mode": "agentic", "tier": "SEAL-2",
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

    def test_a_seal0_dm_takes_only_seal0_data(self):
        """A new DM is SEAL-0: SEAL-1 data needs the owner to raise it first."""
        cat.update("datastore", "tomato-pack/clienti", tier="SEAL-1")
        with self.assertRaises(PermissionError):
            self.imp(tier="SEAL-0", name="dm-clodia--davide")

    def test_a_dm_follows_the_topic_retier_rules(self):
        """Owner, 11 Nov 2026: the DM's owner sets its tier. Raised, it takes
        the data of that level; it cannot go below what it imports."""
        cat.update("datastore", "tomato-pack/clienti", tier="SEAL-1")
        self.svc.set_tier("SEAL-0", "dm-clodia--davide", "SEAL-1", by="davide",
                          reason="CRM nel DM")
        self.imp(tier="SEAL-1", name="dm-clodia--davide")
        self.assertEqual(self.auth("clodia", scope="SEAL-1/dm-clodia--davide",
                                   clearance="SEAL-1")["name"], "tomato-pack/clienti")
        meta = self.svc._read_meta("SEAL-1", "dm-clodia--davide")[0]
        with self.assertRaises(td.DataError):
            td.check_retier(meta, "SEAL-0")
        # an agent below the DM's tier is out, as in a topic
        with self.assertRaises(PermissionError):
            self.auth("clodia", scope="SEAL-1/dm-clodia--davide", clearance="SEAL-0")


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

    def test_a_job_without_a_tier_uses_no_data(self):
        """Owner, 11 Nov 2026: no fallback to the agent's clearance."""
        self.assertEqual(td.job_tier({"tier": ""}), "")
        self.job["tier"] = ""
        with self.assertRaises(PermissionError) as c:
            self.jauth(clearance="SEAL-4")
        self.assertIn(td.JOB_TIER_MARK, str(c.exception))

    def test_an_agent_below_the_job_tier_is_refused(self):
        self.job["tier"] = "SEAL-3"                 # clienti is SEAL-2
        with self.assertRaises(PermissionError) as c:
            self.jauth(clearance="SEAL-2")
        self.assertIn("sotto il tier del job 12", str(c.exception))
        self.jauth(clearance="SEAL-3")

    def test_the_run_record_names_the_job_tier(self):
        """The refusal reaches the run record as its own class."""
        from . import main
        self.job["tier"] = "SEAL-3"
        try:
            self.jauth(clearance="SEAL-2")
        except PermissionError as e:
            self.assertEqual(main._denial_class(str(e)), "job_tier")
        self.job["tier"] = ""
        try:
            self.jauth()
        except PermissionError as e:
            self.assertEqual(main._denial_class(str(e)), "job_tier")
        self.assertEqual(main._denial_class("agent 'x': clearance insufficiente"), "clearance")

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

    def test_importing_into_a_job_without_a_tier_is_refused(self):
        for tier in ("", None):
            with self.subTest(tier=tier):
                with self.assertRaises(td.DataError) as c:
                    td.check_import("rag", "eu-normativa", tier, principal="davide",
                                    is_admin=True, clearance="SEAL-3", scope_kind="job")
                self.assertIn("imposta il tier del job prima di importare dati",
                              str(c.exception))

    def test_a_job_cannot_go_below_its_imports(self):
        data = [{"kind": "datastore", "name": "tomato-pack/clienti"}]   # SEAL-2
        td.check_imports_tier(data, "SEAL-2")
        td.check_imports_tier(data, "SEAL-4")
        with self.assertRaises(td.DataError):
            td.check_imports_tier(data, "SEAL-1")
        with self.assertRaises(td.DataError):
            td.check_imports_tier(data, "")                  # no tier while importing
        td.check_imports_tier([], "")                        # nothing imported: free

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


class ArchivedScopeTests(_Base):
    """An archived topic or DM opens nothing it imports, like A·V·R·Q, which
    drops a room's tuples once archived (review of #473)."""

    def test_an_archived_topic_refuses_with_its_reason(self):
        self.imp()
        self.assertEqual(self.auth("clodia")["name"], "tomato-pack/clienti")
        self.svc.archive("SEAL-2", "commerciale")
        with self.assertRaises(PermissionError) as c:
            self.auth("clodia")
        self.assertIn("il topic SEAL-2/commerciale è archiviato", str(c.exception))
        self.assertEqual(td.visible("datastore", agent="clodia", scope="SEAL-2/commerciale",
                                    clearance="SEAL-2"), set())

    def test_an_archived_dm_refuses_too(self):
        self.svc.new("SEAL-0", "dm-clodia--davide", {
            "kind": "dm", "type": "dm", "owner": "davide", "participants": ["davide", "clodia"]})
        cat.update("datastore", "tomato-pack/clienti", tier="SEAL-0")
        self.imp(tier="SEAL-0", name="dm-clodia--davide")
        self.svc.archive("SEAL-0", "dm-clodia--davide")
        with self.assertRaises(PermissionError) as c:
            self.auth("clodia", scope="SEAL-0/dm-clodia--davide", clearance="SEAL-1")
        self.assertIn("il DM SEAL-0/dm-clodia--davide è archiviato", str(c.exception))


class ClearanceBelowTierTests(_Base):
    """A non-admin below the resource's level is refused, and told why."""

    def test_a_non_admin_importer_below_the_resource_tier(self):
        cat.update("datastore", "tomato-pack/clienti", importers=["mario"])
        with self.assertRaises(PermissionError) as c:
            self.imp(who="mario", admin=False, clearance="SEAL-1")       # clienti is SEAL-2
        self.assertEqual(str(c.exception),
                         "clearance di 'mario' (SEAL-1) insufficiente per datastore "
                         "'tomato-pack/clienti' (SEAL-2)")

    def test_an_agent_below_the_resource_tier(self):
        self.imp()
        with self.assertRaises(PermissionError) as c:
            self.auth("tomato.commerciale", clearance="SEAL-1")
        self.assertEqual(str(c.exception),
                         "agent 'tomato.commerciale': clearance insufficiente per datastore "
                         "'tomato-pack/clienti' (SEAL-2)")


class ScopeTierRouteTests(_Base):
    def test_check_scope_tier_through_the_route(self):
        from starlette.applications import Starlette
        from starlette.testclient import TestClient
        from . import topics_api

        def fake_authorize(request):
            request.state.auth_payload = {"agent": "agent-server", "role": "agent-server"}
            return "agent-server", None
        with patch.object(topics_api, "_authorize", fake_authorize):
            c = TestClient(Starlette(routes=topics_api.routes))
            body = {"action": "check_scope_tier",
                    "data": [{"kind": "datastore", "name": "tomato-pack/clienti"}]}
            self.assertEqual(c.post("/internal/data-catalog",
                                    json={**body, "tier": "SEAL-2"}).status_code, 200)
            r = c.post("/internal/data-catalog", json={**body, "tier": "SEAL-1"})
            self.assertEqual(r.status_code, 400)
            self.assertIn("non può scendere", r.json()["error"])


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

    def test_no_tier_no_tuples(self):
        with patch("server.tools.runtime.job_scope", lambda jid: _job(tier="")):
            g, _ = self._tuples("clodia", "job:12:20261111-x")
        self.assertFalse([x for x in g if x.id.startswith("job-data:")])

    def test_nobody_else_and_nowhere_else(self):
        g, _ = self._tuples("ophelia", "job:12:20261111-x")
        self.assertFalse([x for x in g if x.id.startswith("job-data:")])
        g, _ = self._tuples("clodia", "20261111-x")
        self.assertFalse([x for x in g if x.id.startswith("job-data:")])


class ProvisionerTests(_Base):
    """`CLODIA_RAG_PROVISIONERS` creates and feeds ONLY collections declared by
    an installed pack, at the catalogue's effective level (unknown → refused),
    and lists the collections within its clearance (#669; review of #473)."""

    DECLARED = {"kb": {"pack": "legal-pack", "tier": "SEAL-1"},
                "senza-tier": {"pack": "legal-pack", "tier": None}}

    def _call(self, agent, clearance, fn, service_tier="SEAL-0"):
        from . import main
        with patch.object(main, "agent_name", lambda: agent), \
                patch.object(main, "current_clearance", lambda: clearance), \
                patch("server.topic_data.scope_of_call", lambda: None), \
                patch.object(main.instance_profile, "rag_check_collection", lambda c: None), \
                patch("server.datastores.declared_collections", lambda: dict(self.DECLARED)), \
                patch("server.tools.eu_corpus.collection_tier", lambda c: service_tier):
            return fn(main)

    def _refusal(self, *a, **k) -> str:
        with self.assertRaises(PermissionError) as c:
            self._call(*a, **k)
        return str(c.exception)

    def test_create_and_ingest_a_declared_collection_within_clearance(self):
        self.assertEqual(self._call("sysadmin", "SEAL-2",
                                    lambda m: m._provisioner_tier("kb")), "SEAL-1")
        self._call("sysadmin", "SEAL-2",
                   lambda m: m._rag_authorize("kb", write=True, verb="create_collection"))
        self._call("sysadmin", "SEAL-2",
                   lambda m: m._rag_authorize("kb", write=True, verb="ingest"))
        why = self._refusal("sysadmin", "SEAL-0",
                            lambda m: m._rag_authorize("kb", write=True, verb="ingest"))
        self.assertIn("clearance insufficiente per la collection 'kb' (tier SEAL-1)", why)

    def test_a_collection_no_pack_declares_is_not_provisioning(self):
        """eu-normativa is in the catalogue but no installed pack declares it
        here: the provisioner goes through a scope like everyone."""
        why = self._refusal("sysadmin", "SEAL-4",
                            lambda m: m._rag_authorize("eu-normativa", write=True, verb="ingest"))
        self.assertIn("non è dichiarata da un pack installato", why)

    def test_an_unknown_level_is_refused_not_seal0(self):
        why = self._refusal("sysadmin", "SEAL-4",
                            lambda m: m._rag_authorize("senza-tier", write=True, verb="ingest"))
        self.assertIn("livello della collection 'senza-tier' sconosciuto", why)

    def test_the_catalogue_level_wins_over_the_services_cache(self):
        """The service answers SEAL-0 (cached/unknown); the admin set SEAL-3
        in the catalogue: SEAL-3 decides."""
        cat.register("rag", "kb", tier="SEAL-1", source="pack:legal-pack")
        cat.update("rag", "kb", tier="SEAL-3")
        why = self._refusal("sysadmin", "SEAL-2",
                            lambda m: m._rag_authorize("kb", write=True, verb="ingest"),
                            service_tier="SEAL-0")
        self.assertIn("(tier SEAL-3)", why)
        self._call("sysadmin", "SEAL-3",
                   lambda m: m._rag_authorize("kb", write=True, verb="ingest"))

    def test_a_declared_collection_is_not_created_below_its_level(self):
        created = []
        with patch("server.tools.eu_corpus.create_collection",
                   lambda c, **k: created.append((c, k)) or {"ok": True}):
            why = self._refusal("sysadmin", "SEAL-2", lambda m: m._dispatch_rag(
                "rag.create_collection", {"collection": "kb", "tier": "SEAL-0"}))
            self.assertIn("è SEAL-1: non si crea a SEAL-0", why)
            self._call("sysadmin", "SEAL-2", lambda m: m._dispatch_rag(
                "rag.create_collection", {"collection": "kb", "tier": "SEAL-1"}))
        self.assertEqual([c for c, _ in created], ["kb"])

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

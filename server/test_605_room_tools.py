"""#605 R1 — the verbs a ROOM enables (toolbox), `topic.*` for every
participant, the exceptions, and the toolbox of the sessions outside a room.

What each test is here to catch, in one line:

- the toolbox makes a verb reachable IN ITS ROOM and nowhere else;
- `topic.*` reaches every participant and NOBODY else;
- `artifact.render` is in `_TOPIC_TOOLS` but is not a `topic.` verb: it must
  not ride in on the floor the room gives (the trap of the file's layout);
- an exception actually bites a `ns.*` that would otherwise swallow it;
- governance namespaces are NOT enablable, and the refusal says why.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import main, room_tools as rt, whitelist
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicService


class _Base(unittest.TestCase):
    def setUp(self):
        self.svc = TopicService(LocalFsStorage(tempfile.mkdtemp(prefix="topics-")))
        for p in (patch.object(rt, "_svc", lambda: self.svc),
                  patch.object(main, "_topics", lambda: self.svc)):
            p.start()
            self.addCleanup(p.stop)
        self.svc.new("SEAL-1", "blog", {"owner": "davide",
                                        "participants": ["davide", "redattore", "fact-checker"]})
        self.svc.new("SEAL-1", "altra", {"owner": "davide", "participants": ["davide", "redattore"]})

    def meta(self, tier="SEAL-1", name="blog"):
        return self.svc._read_meta(tier, name)[0]


class EnablableTests(_Base):
    def test_governance_is_not_a_room_decision(self):
        enablable = rt.enablable()
        for ns in ("jobs", "packs", "settings", "agents", "egress", "mcp",
                   "providers", "integrations", "runtime", "profile"):
            self.assertNotIn(ns, enablable, ns)

    def test_what_another_list_already_governs_stays_there(self):
        enablable = rt.enablable()
        for ns in ("topic", "memory", "rag", "datastore", "eu_corpus"):
            self.assertNotIn(ns, enablable, ns)

    def test_the_tools_of_the_trade_are(self):
        enablable = rt.enablable()
        self.assertIn("web", enablable)
        self.assertIn("web.fetch", enablable["web"])
        self.assertIn("channel", enablable)
        self.assertIn("artifact", enablable)       # enablable, but never implicit

    def test_a_connector_of_a_pack_stays_enablable_without_its_component(self):
        """From the manifest (`_packaged_namespaces`), not from the loaded
        component: a restart in which the component is not up yet must not make
        `email.*` unenablable — and the owner's panel would show it missing."""
        with patch.object(main, "_packaged_namespaces", lambda: frozenset({"email"})):
            self.assertEqual(rt.enablable().get("email"), [])
            self.assertEqual(rt.check("email.send"), "email.send")

    def test_the_refusal_says_which_list_owns_the_verb(self):
        with self.assertRaises(rt.ToolboxError) as e:
            rt.check("jobs.run")
        self.assertIn("governance", str(e.exception))
        with self.assertRaises(rt.ToolboxError) as e:
            rt.check("rag.search")
        self.assertIn("#590", str(e.exception))
        with self.assertRaises(rt.ToolboxError) as e:
            rt.check("topic.write_file")
        self.assertIn("già incluso", str(e.exception))

    def test_a_typo_is_refused_instead_of_granting_nothing(self):
        for bad in ("web.fetchh", "web", "", "inesistente.*"):
            with self.assertRaises(rt.ToolboxError, msg=bad):
                rt.check(bad)
        self.assertEqual(rt.check(" web.fetch "), "web.fetch")
        self.assertEqual(rt.check("web.*"), "web.*")


class RoomFloorTests(_Base):
    def test_every_participant_reaches_topic_star(self):
        self.assertIn("topic.*", rt.verbs_for("redattore", "SEAL-1/blog"))

    def test_who_does_not_participate_reaches_nothing(self):
        self.assertEqual(rt.verbs_for("estraneo", "SEAL-1/blog"), set())
        self.assertEqual(rt.verbs_for("redattore", "SEAL-1/inesistente"), set())
        self.assertEqual(rt.verbs_for("", "SEAL-1/blog"), set())

    def test_artifact_render_does_not_ride_in_on_the_floor(self):
        """It lives in `_TOPIC_TOOLS` next to the `topic.` verbs, and its
        namespace is `artifact`: the floor is a namespace, not a file."""
        with patch.object(main, "_declared_tools", lambda a: set()), \
                patch.object(main, "current_scoped_tools", lambda: ()), \
                patch("server.egress._scope_of_call", lambda: "SEAL-1/blog"):
            self.assertTrue(main._agent_tool_reachable("topic.write_file", "redattore"))
            self.assertFalse(main._agent_tool_reachable("artifact.render", "redattore"))


class ToolboxTests(_Base):
    def test_a_verb_enabled_here_is_reachable_here_only(self):
        rt.enable("SEAL-1", "blog", "web.fetch")
        with patch.object(main, "_declared_tools", lambda a: set()), \
                patch.object(main, "current_scoped_tools", lambda: ()):
            with patch("server.egress._scope_of_call", lambda: "SEAL-1/blog"):
                self.assertTrue(main._agent_tool_reachable("web.fetch", "redattore"))
            with patch("server.egress._scope_of_call", lambda: "SEAL-1/altra"):
                self.assertFalse(main._agent_tool_reachable("web.fetch", "redattore"))
            with patch("server.egress._scope_of_call", lambda: None):
                self.assertFalse(main._agent_tool_reachable("web.fetch", "redattore"))

    def test_discovery_and_dispatch_say_the_same_thing(self):
        """`list_tools` resolves the tree once; the two must not diverge."""
        rt.enable("SEAL-1", "blog", "web.fetch")
        with patch.object(main, "_declared_tools", lambda a: set()), \
                patch.object(main, "current_scoped_tools", lambda: ()), \
                patch("server.egress._scope_of_call", lambda: "SEAL-1/blog"):
            resolved = (main._declared_tools("redattore") | set(main.current_scoped_tools())
                        | main._room_data_verbs("redattore") | main._room_tool_verbs("redattore"))
            self.assertTrue(main._agent_tool_reachable("web.fetch", "redattore", resolved))
            self.assertEqual(main._agent_tool_reachable("web.fetch", "redattore"),
                             main._agent_tool_reachable("web.fetch", "redattore", resolved))

    def test_disable_takes_it_back(self):
        rt.enable("SEAL-1", "blog", "web.fetch")
        rt.enable("SEAL-1", "blog", "web.fetch", on=False)
        self.assertEqual(rt.toolbox(self.meta())["enabled"], [])
        self.assertNotIn("web.fetch", rt.verbs_for("redattore", "SEAL-1/blog"))

    def test_the_room_never_subtracts_from_the_seed(self):
        """Additive in R1 (owner, 23 Oct): the subtraction is #610."""
        rt.exception("SEAL-1", "blog", "fact-checker", "web.fetch")
        with patch.object(main, "_declared_tools", lambda a: {"web.fetch"}), \
                patch.object(main, "current_scoped_tools", lambda: ()), \
                patch("server.egress._scope_of_call", lambda: "SEAL-1/blog"):
            self.assertTrue(main._agent_tool_reachable("web.fetch", "fact-checker"))


class ExceptionTests(_Base):
    def test_an_exception_bites_through_the_wildcard(self):
        """`web.*` would swallow its own exception: the wildcard is expanded."""
        rt.enable("SEAL-1", "blog", "web.*")
        rt.exception("SEAL-1", "blog", "fact-checker", "web.post")
        tutti = rt.verbs_for("redattore", "SEAL-1/blog")
        uno = rt.verbs_for("fact-checker", "SEAL-1/blog")
        self.assertIn("web.*", tutti)
        self.assertNotIn("web.*", uno)
        self.assertIn("web.fetch", uno)
        self.assertNotIn("web.post", uno)
        with patch.object(main, "_declared_tools", lambda a: set()), \
                patch.object(main, "current_scoped_tools", lambda: ()), \
                patch("server.egress._scope_of_call", lambda: "SEAL-1/blog"):
            self.assertTrue(main._agent_tool_reachable("web.post", "redattore"))
            self.assertFalse(main._agent_tool_reachable("web.post", "fact-checker"))
            self.assertTrue(main._agent_tool_reachable("web.fetch", "fact-checker"))

    def test_a_wildcard_that_cannot_be_cut_is_not_given(self):
        """A mounted MCP backend does not name its verbs here: with an
        exception on it, the gift goes away instead of leaking past it."""
        with patch.object(rt, "_catalogue", lambda: {"backend": set()}):
            self.assertEqual(rt._minus({"backend.*"}, {"backend.pericoloso"}), set())
            self.assertEqual(rt._minus({"backend.*"}, set()), {"backend.*"})

    def test_an_exception_on_topic_star_leaves_the_floor_of_the_archseed(self):
        rt.exception("SEAL-1", "blog", "fact-checker", "topic.delete_file")
        v = rt.verbs_for("fact-checker", "SEAL-1/blog")
        self.assertNotIn("topic.delete_file", v)
        self.assertIn("topic.post_message", v)

    def test_only_a_participant_can_be_excepted(self):
        with self.assertRaises(rt.ToolboxError):
            rt.exception("SEAL-1", "blog", "estraneo", "web.fetch")
        rt.exception("SEAL-1", "blog", "fact-checker", "web.fetch")
        rt.exception("SEAL-1", "blog", "fact-checker", "web.fetch", on=False)
        self.assertEqual(rt.toolbox(self.meta())["except"], {})


class MetaReadingTests(_Base):
    def test_an_unreadable_toolbox_grants_nothing(self):
        for raw in ("", [], {"enabled": "web.fetch"}, {"except": ["x"]}, None):
            self.assertEqual(rt.toolbox({"tools": raw}),
                             {"enabled": [], "except": {}}, repr(raw))

    def test_an_empty_exception_list_is_not_an_agent(self):
        self.assertEqual(rt.toolbox({"tools": {"except": {"a": []}}})["except"], {})


class DmToolboxTests(_Base):
    def test_outside_a_room_the_instance_list_decides(self):
        with patch.object(whitelist, "CONFIG", {"dm_tools": ["web.fetch"]}):
            self.assertEqual(rt.verbs_for("redattore", None), {"web.fetch"})
            # In a room the room decides: the DM list does not add itself.
            self.assertNotIn("web.fetch", rt.verbs_for("redattore", "SEAL-1/blog"))
            with patch.object(main, "_declared_tools", lambda a: set()), \
                    patch.object(main, "current_scoped_tools", lambda: ()), \
                    patch("server.egress._scope_of_call", lambda: None):
                self.assertTrue(main._agent_tool_reachable("web.fetch", "redattore"))
                self.assertFalse(main._agent_tool_reachable("web.post", "redattore"))

    def test_an_unreadable_list_grants_nothing(self):
        for raw in ("web.fetch", {"web.fetch": True}, None):
            with patch.object(whitelist, "CONFIG", {"dm_tools": raw}):
                self.assertEqual(rt.dm_toolbox(), [], repr(raw))

    def test_it_is_written_where_the_deciding_state_already_lives(self):
        """`clodia-tools-config.yaml` in the state dir (#80), not a new file in
        the datadir the agent-server also mounts."""
        cfg = {}
        with patch.object(whitelist, "CONFIG", cfg), \
                patch.object(whitelist, "save_config", lambda: None), \
                patch.object(whitelist, "reload_config", lambda: None):
            rt.set_dm("web.fetch")
            self.assertEqual(cfg["dm_tools"], ["web.fetch"])
            rt.set_dm("web.fetch", on=False)
            self.assertEqual(cfg["dm_tools"], [])
        with self.assertRaises(rt.ToolboxError):
            rt.set_dm("jobs.run")


class SnapshotTests(_Base):
    def test_an_archive_does_not_carry_authority_into_another_instance(self):
        import json

        from . import topics_api
        raw = json.dumps({"owner": "davide", "tier": "SEAL-1", "name": "blog",
                          "tools": {"enabled": ["web.fetch"]},
                          "data": [], "participants": ["davide"]}).encode()
        out = json.loads(topics_api._snapshot_meta_bytes(raw, "SEAL-1"))
        self.assertNotIn("tools", out)


class GatesUnchangedTests(_Base):
    def test_enabling_a_verb_does_not_touch_its_gate(self):
        """Decision 3 of the epic: included ≠ ungated. Reachability is one
        answer, the gate another — and this module must not have an opinion."""
        from . import gate
        prima = gate.is_gated("topic.egress_add")
        rt.enable("SEAL-1", "blog", "web.fetch")
        self.assertIn("topic.*", rt.verbs_for("redattore", "SEAL-1/blog"))
        self.assertEqual(gate.is_gated("topic.egress_add"), prima)
        self.assertTrue(prima, "topic.egress_add muove i muri: resta gated")


class RoutesTests(_Base):
    """Owner-only and audited: the toolbox widens what EVERY participant
    reaches, so it is a wall of the room, and an agent does not move a wall."""

    def _client(self, payload):
        from starlette.applications import Starlette
        from starlette.testclient import TestClient

        from . import topics_api

        def fake_authorize(request):
            request.state.auth_payload = payload
            return payload.get("principal") or payload.get("agent"), None
        for p in (patch.object(topics_api, "_authorize", fake_authorize),
                  patch.object(topics_api, "_service", lambda: self.svc)):
            p.start()
            self.addCleanup(p.stop)
        self.events = []
        e = patch("server.audit.control.emit",
                  lambda *a, **k: self.events.append((a, k)))
        e.start()
        self.addCleanup(e.stop)
        return TestClient(Starlette(routes=topics_api.routes))

    def _owner(self):
        return self._client({"principal": "davide", "on_behalf": True, "human_role": "user"})

    def test_the_owner_enables_and_it_is_written_and_audited(self):
        c = self._owner()
        r = c.post("/internal/topics/SEAL-1/blog/tools",
                   json={"action": "enable", "verb": "web.fetch"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["enabled"], ["web.fetch"])
        self.assertEqual(rt.toolbox(self.meta())["enabled"], ["web.fetch"])
        self.assertTrue(any(a[:2] == ("room_tools", "enable") for a, _ in self.events))

    def test_an_agent_does_not_move_this_wall(self):
        c = self._client({"agent": "redattore", "execution_id": "redattore-1"})
        self.assertEqual(c.post("/internal/topics/SEAL-1/blog/tools",
                                json={"action": "enable", "verb": "web.fetch"}).status_code, 403)
        self.assertEqual(rt.toolbox(self.meta())["enabled"], [])

    def test_the_panel_reads_what_it_may_offer(self):
        body = self._owner().get("/internal/topics/SEAL-1/blog/tools").json()
        self.assertEqual(body["enabled"], [])
        self.assertIn("web", body["enablable"])
        self.assertNotIn("jobs", body["enablable"])

    def test_a_refused_verb_answers_400_with_the_reason(self):
        r = self._owner().post("/internal/topics/SEAL-1/blog/tools",
                               json={"action": "enable", "verb": "jobs.run"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("governance", r.json()["error"])

    def test_an_unknown_action_is_not_a_silent_no_op(self):
        r = self._owner().post("/internal/topics/SEAL-1/blog/tools",
                               json={"action": "svuota", "verb": "web.fetch"})
        self.assertEqual(r.status_code, 400)

    def test_the_exception_goes_through_the_same_door(self):
        c = self._owner()
        r = c.post("/internal/topics/SEAL-1/blog/tools",
                   json={"action": "except", "verb": "web.post", "agent": "fact-checker"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(rt.toolbox(self.meta())["except"], {"fact-checker": ["web.post"]})

    def test_the_dm_list_is_read_by_a_person_and_written_by_an_admin(self):
        with patch.object(whitelist, "CONFIG", {}), \
                patch.object(whitelist, "save_config", lambda: None), \
                patch.object(whitelist, "reload_config", lambda: None):
            c = self._client({"principal": "davide", "on_behalf": True, "human_role": "user"})
            self.assertEqual(c.get("/internal/dm-tools").status_code, 200)
            self.assertEqual(c.post("/internal/dm-tools",
                                    json={"action": "enable", "verb": "web.fetch"}).status_code,
                             403)
        with patch.object(whitelist, "CONFIG", {}), \
                patch.object(whitelist, "save_config", lambda: None), \
                patch.object(whitelist, "reload_config", lambda: None):
            a = self._client({"principal": "davide", "on_behalf": True, "human_role": "admin"})
            r = a.post("/internal/dm-tools", json={"action": "enable", "verb": "web.fetch"})
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(r.json()["dm_tools"], ["web.fetch"])
            self.assertTrue(any(x[:2] == ("dm_tools", "enable") for x, _ in self.events))

    def test_a_superadmin_writes_the_dm_list(self):
        with patch.object(whitelist, "CONFIG", {}), \
                patch.object(whitelist, "save_config", lambda: None), \
                patch.object(whitelist, "reload_config", lambda: None):
            c = self._client({"principal": "davide", "on_behalf": True,
                              "human_role": "superadmin"})
            r = c.post("/internal/dm-tools", json={"action": "enable", "verb": "web.fetch"})
            self.assertEqual(r.status_code, 200, r.text)

    def test_the_panel_knows_which_verbs_still_ask(self):
        """#609: enabling is not ungating (epic decision 3), so the panel marks
        the gated verbs."""
        body = self._owner().get("/internal/topics/SEAL-1/blog/tools").json()
        self.assertIn("web.post", body["gated"])
        self.assertNotIn("web.fetch", body["gated"])

    def test_the_agent_server_names_the_person_in_the_audit(self):
        from .pki_mint import ROLE_AGENT_SERVER
        c = self._client({"role": ROLE_AGENT_SERVER, "agent": "agent-server"})
        r = c.post("/internal/topics/SEAL-1/blog/tools",
                   json={"action": "enable", "verb": "web.fetch", "by": "davide"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(any(k.get("by") == "davide" for a, k in self.events
                            if a[:2] == ("room_tools", "enable")))

    def test_a_missing_topic_is_404(self):
        """An admin passes the owner's door; the topic that is not there is a
        404, not a malformed request (review N3)."""
        c = self._client({"principal": "davide", "on_behalf": True, "human_role": "admin"})
        r = c.post("/internal/topics/SEAL-1/inesistente/tools",
                   json={"action": "enable", "verb": "web.fetch"})
        self.assertEqual(r.status_code, 404, r.text)


    def test_an_agent_does_not_read_the_dm_list(self):
        c = self._client({"agent": "redattore"})
        self.assertEqual(c.get("/internal/dm-tools").status_code, 403)


class ReviewB1Tests(_Base):
    """Review of #429, B1: a toolbox written by anything but the owner's route
    — `topic.new` with a ready-made `tools`, or a hand-edited meta — must not
    give a single verb that the route would have refused."""

    def test_a_creator_never_brings_a_toolbox(self):
        self.svc.new("SEAL-1", "x", {"owner": "davide", "participants": ["sales-rep"],
                                     "tools": {"enabled": ["*", "packs.*", "web.fetch"]}})
        self.assertNotIn("tools", self.meta(name="x"))
        self.assertEqual(rt.verbs_for("sales-rep", "SEAL-1/x"), {"topic.*"})

    def test_a_hand_written_toolbox_gives_only_what_a_room_may_give(self):
        meta = {"tools": {"enabled": ["*", "packs.*", "agents.grant_tool", "runtime.*",
                                      "*.*", "web.f*", "topic.delete_file", "web.fetch"]}}
        self.assertEqual(rt.toolbox(meta)["enabled"], ["web.fetch"])

    def test_through_dispatch_the_bare_star_reaches_nothing(self):
        meta, ver = self.svc._read_meta("SEAL-1", "blog")
        meta["tools"] = {"enabled": ["*", "packs.*", "agents.*"]}
        self.svc._write_meta("SEAL-1", "blog", meta, base_version=ver)
        with patch.object(main, "_declared_tools", lambda a: set()), \
                patch.object(main, "current_scoped_tools", lambda: ()), \
                patch("server.egress._scope_of_call", lambda: "SEAL-1/blog"):
            for verb in ("packs.import_url", "agents.grant_tool", "copybrain.ask",
                         "runtime.status"):
                self.assertFalse(main._agent_tool_reachable(verb, "redattore"), verb)
            self.assertTrue(main._agent_tool_reachable("topic.write_file", "redattore"))

    def test_the_dm_list_is_filtered_the_same_way(self):
        with patch.object(whitelist, "CONFIG", {"dm_tools": ["*", "packs.*", "web.fetch"]}):
            self.assertEqual(rt.dm_toolbox(), ["web.fetch"])


class WildcardExceptionTests(_Base):
    """Review of #429, S1: an exception bites by name, by namespace or on all."""

    def test_a_namespace_exception_removes_the_namespace(self):
        rt.enable("SEAL-1", "blog", "web.*")
        rt.exception("SEAL-1", "blog", "fact-checker", "web.*")
        v = rt.verbs_for("fact-checker", "SEAL-1/blog")
        self.assertFalse({x for x in v if x.startswith("web.")}, v)
        self.assertIn("web.*", rt.verbs_for("redattore", "SEAL-1/blog"))

    def test_it_also_bites_point_verbs_of_that_namespace(self):
        rt.enable("SEAL-1", "blog", "web.fetch")
        rt.exception("SEAL-1", "blog", "fact-checker", "web.*")
        self.assertNotIn("web.fetch", rt.verbs_for("fact-checker", "SEAL-1/blog"))

    def test_an_exception_on_topic_star_removes_the_floor_for_that_agent(self):
        rt.exception("SEAL-1", "blog", "fact-checker", "topic.*")
        self.assertEqual(rt.verbs_for("fact-checker", "SEAL-1/blog"), set())
        self.assertIn("topic.*", rt.verbs_for("redattore", "SEAL-1/blog"))

    def test_star_removes_everything_the_room_gives(self):
        rt.enable("SEAL-1", "blog", "web.fetch")
        rt.exception("SEAL-1", "blog", "fact-checker", "*")
        self.assertEqual(rt.verbs_for("fact-checker", "SEAL-1/blog"), set())

    def test_a_namespace_exception_on_an_unenumerable_backend(self):
        with patch.object(rt, "_catalogue", lambda: {"backend": set()}):
            self.assertEqual(rt._minus({"backend.*"}, {"backend.*"}), set())

    def test_an_exception_that_would_change_nothing_is_refused(self):
        for bad in ("packs.*", "jobs.run", "rag.search", "web.fetchh", "web", "**", "inesistente.*"):
            with self.assertRaises(rt.ToolboxError, msg=bad):
                rt.exception("SEAL-1", "blog", "fact-checker", bad)
        self.assertEqual(rt.toolbox(self.meta())["except"], {})

    def test_a_hand_written_malformed_exception_is_dropped(self):
        meta = {"tools": {"except": {"a": ["web.*", "*", "web f", "x.y*"]}}}
        self.assertEqual(rt.toolbox(meta)["except"], {"a": ["*", "web.*"]})


class ArchivedRoomTests(_Base):
    def test_an_archived_room_keeps_the_floor_and_drops_the_toolbox(self):
        rt.enable("SEAL-1", "blog", "web.fetch")
        meta, ver = self.svc._read_meta("SEAL-1", "blog")
        meta["status"] = "archived"
        self.svc._write_meta("SEAL-1", "blog", meta, base_version=ver)
        self.assertEqual(rt.verbs_for("redattore", "SEAL-1/blog"), {"topic.*"})


class ReaderAbolishedTests(_Base):
    """Owner's decision, 24 Oct 2026: there is no read-only participant."""

    def test_a_reader_written_before_reads_as_contributor(self):
        meta = {"owner": "davide", "participants": {"redattore": "reader"}}
        self.assertEqual(TopicService.participant_role(meta, "redattore"), "contributor")
        self.assertTrue(TopicService.may_mutate(meta, "redattore"))

    def test_nobody_is_invited_as_reader_any_more(self):
        from .topics.service import TopicError
        with self.assertRaises(TopicError) as e:
            self.svc.add_participant("SEAL-1", "blog", "nuovo", role="reader")
        self.assertIn("abolito", str(e.exception))


if __name__ == "__main__":
    unittest.main()

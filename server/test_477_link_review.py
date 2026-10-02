"""Security review fixes of the topic link (clodia-platform#477).

B1 — a link is effective only with the consent of the owner of BOTH topics
(or of an admin), and whoever reads through it must be entitled to read the
linked topic on its own terms: participant of THAT topic, clearance for its
tier. Participation in the topic one reads from is never lent.

Plus: the audit names the topic that owns the bytes, the internal route checks
ownership itself, and an archive import does not bring links back.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.testclient import TestClient

from . import main, topics_api
from .topics import service as service_mod
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicError, TopicService, topic_links


class _Two(unittest.TestCase):
    """`acme` belongs to davide, `legale` to giovanni; estraneo takes part in
    acme only, avvocato in legale only, both are on SEAL-1."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="link-review-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.svc = TopicService(LocalFsStorage(str(self.root)))
        self.svc.new("SEAL-1", "acme", {"title": "Acme", "owner": "davide",
                                        "participants": ["estraneo"]})
        self.svc.new("SEAL-1", "legale", {"title": "Legale", "owner": "giovanni",
                                          "participants": ["avvocato"]})
        self.svc.put_file("SEAL-1", "legale", "parere.md", b"# parere", "agent",
                          by="avvocato")
        for target, attr, val in ((TopicService, "_link_ingress", lambda *a: {}),
                                  (main, "_topics", lambda: self.svc)):
            p = patch.object(target, attr, val)
            p.start()
            self.addCleanup(p.stop)

    def _approve_both(self):
        self.svc.link_add("SEAL-1", "acme", "SEAL-1", "legale", approver="davide")
        self.svc.link_add("SEAL-1", "legale", "SEAL-1", "acme", approver="giovanni")

    def _as_agent(self, agent, clearance="SEAL-4"):
        for attr, val in (("agent_name", lambda: agent),
                          ("current_clearance", lambda: clearance),
                          ("_token_is_bound_to_a_room", lambda: False),
                          ("_crosstopic_grant_active", lambda caller: False)):
            p = patch.object(main, attr, val)
            p.start()
            self.addCleanup(p.stop)


class ReaderMustBeEntitledToTheLinkedTopic(_Two):
    def test_the_gateway_registers_its_guard(self):
        self.assertIs(service_mod._LINK_READER_GUARD, main._require_link_reader)

    def test_a_participant_of_a_only_is_refused_even_with_an_approved_link(self):
        self._approve_both()
        self._as_agent("estraneo")
        self.assertIn("legale", [f["name"] for f in self.svc.list_files("SEAL-1", "acme")])
        with self.assertRaises(PermissionError) as e:
            self.svc.read_file("SEAL-1", "acme", "legale/parere.md")
        self.assertIn("legale", str(e.exception))
        with self.assertRaises(PermissionError):
            self.svc.list_files("SEAL-1", "acme", "legale")

    def test_a_participant_of_b_reads_through_the_link(self):
        self._approve_both()
        self._as_agent("avvocato")
        self.assertEqual(self.svc.read_file("SEAL-1", "acme", "legale/parere.md"),
                         b"# parere")

    def test_clearance_below_the_linked_tier_is_refused(self):
        self._approve_both()
        self._as_agent("avvocato", clearance="SEAL-0")
        with self.assertRaises(PermissionError) as e:
            self.svc.read_file("SEAL-1", "acme", "legale/parere.md")
        self.assertIn("clearance", str(e.exception))


class LinkAddNeedsBothOwners(_Two):
    def setUp(self):
        super().setUp()
        self.posted = []
        for attr, val in (("_require_topic_member", lambda *a, **k: None),
                          ("agent_name", lambda: "clodia"),
                          ("is_on_behalf", lambda: False)):
            p = patch.object(main, attr, val)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(self.svc, "post_message",
                         lambda t, n, **k: self.posted.append((t, n, k.get("text"))))
        p.start()
        self.addCleanup(p.stop)
        p = patch("server.human.is_admin", lambda name: name == "root")
        p.start()
        self.addCleanup(p.stop)

    def _call(self, by, tier="SEAL-1", name="acme", other="legale"):
        tok = main._GATE_APPROVAL.set({"by": by} if by else None)
        try:
            return main._dispatch_topic("topic.link_add", {
                "tier": tier, "name": name, "other_tier": "SEAL-1", "other_name": other})
        finally:
            main._GATE_APPROVAL.reset(tok)

    def test_b_owner_not_consulted_the_link_is_pending_and_refused(self):
        res = self._call("davide")
        self.assertEqual(res["state"], "pending")
        self.assertEqual(res["awaiting_owner_of"], ["SEAL-1/legale"])
        with self.assertRaises(TopicError):
            self.svc.read_file("SEAL-1", "acme", "legale/parere.md")
        # The room whose owner must decide is told so.
        self.assertEqual([(t, n) for t, n, _ in self.posted], [("SEAL-1", "legale")])
        self.assertIn("SEAL-1/acme", self.posted[0][2])

    def test_different_owners_both_approvals_are_needed(self):
        self._call("davide")
        res = self._call("giovanni", name="legale", other="acme")
        self.assertEqual(res["state"], "active")
        self.assertIn("legale", [f["name"] for f in self.svc.list_files("SEAL-1", "acme")])

    def test_no_consent_no_link(self):
        """Observation mode, or a gate switched off by configuration: no signed
        approver, nothing is written."""
        with self.assertRaises(TopicError):
            self._call("")
        meta, _ = self.svc._read_meta("SEAL-1", "legale")
        self.assertEqual(topic_links(meta), [])

    def test_an_admin_acting_on_behalf_consents_for_both(self):
        with patch.object(main, "is_on_behalf", lambda: True), \
                patch.object(main, "_human_is_admin", lambda: True), \
                patch.object(main, "current_principal", lambda: "root"):
            res = self._call("")
        self.assertEqual(res["state"], "active")

    def test_the_approver_comes_from_the_signed_consent_not_the_arguments(self):
        tok = main._GATE_APPROVAL.set({"by": "davide"})
        try:
            res = main._dispatch_topic("topic.link_add", {
                "tier": "SEAL-1", "name": "acme", "other_tier": "SEAL-1",
                "other_name": "legale", "approver": "giovanni",
                "approver_admin": True})
        finally:
            main._GATE_APPROVAL.reset(tok)
        self.assertEqual(res["state"], "pending")


class AuditNamesTheOwningTopic(_Two):
    def test_a_linked_read_is_recorded_under_the_topic_that_owns_the_bytes(self):
        self._approve_both()
        ref, via = main._topic_read_ref("SEAL-1", "acme", "legale/parere.md")
        self.assertEqual(ref, "topic:SEAL-1/legale/local/parere.md")
        self.assertEqual(via, "topic:SEAL-1/acme/legale/parere.md")
        self.assertEqual(main._ingress_source("topic.read_file", {
            "tier": "SEAL-1", "name": "acme", "path": "legale/parere.md"}), ref)

    def test_a_local_read_is_unchanged(self):
        self.assertEqual(main._topic_read_ref("SEAL-1", "acme", "local/x.md"),
                         ("topic:SEAL-1/acme/local/x.md", None))


class InternalRouteChecksOwnership(_Two):
    def setUp(self):
        super().setUp()
        self.payload = {"agent": "clodia", "principal": "davide", "on_behalf": True,
                        "human_role": "user"}
        for target, attr, val in (
                (topics_api, "_service", lambda: self.svc),
                (topics_api.internal_auth, "authorize",
                 lambda *a, **k: (self.payload, None)),
                (topics_api.human_mcp, "principal_kind_of", lambda p: "human")):
            p = patch.object(target, attr, val)
            p.start()
            self.addCleanup(p.stop)
        self.c = TestClient(Starlette(routes=topics_api.routes))

    def _post(self, name, **body):
        return self.c.post(f"/internal/topics/SEAL-1/{name}/link", json=body)

    def _as(self, principal, role="user"):
        self.payload = {**self.payload, "principal": principal, "human_role": role}

    def test_owning_one_topic_is_not_enough_to_add(self):
        r = self._post("acme", action="add", other_tier="SEAL-1", other_name="legale")
        self.assertEqual(r.status_code, 403)
        meta, _ = self.svc._read_meta("SEAL-1", "legale")
        self.assertEqual(topic_links(meta), [])

    def test_owning_both_adds_an_active_link(self):
        p = self.root / "SEAL-1/legale/meta.json"
        meta = json.loads(p.read_text())
        meta["owner"] = "davide"
        p.write_text(json.dumps(meta))
        r = self._post("acme", action="add", other_tier="SEAL-1", other_name="legale")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["state"], "active")

    def test_an_admin_adds(self):
        self._as("root", role="admin")
        with patch("server.human.is_admin", lambda name: name == "root"):
            r = self._post("acme", action="add", other_tier="SEAL-1", other_name="legale")
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(r.json()["state"], "active")

    def test_the_other_owner_approves_a_pending_link_from_their_side(self):
        self.svc.link_add("SEAL-1", "acme", "SEAL-1", "legale", approver="davide")
        r = self._post("legale", action="approve", other_tier="SEAL-1", other_name="acme")
        self.assertEqual(r.status_code, 403)          # davide does not own legale
        self._as("giovanni")
        r = self._post("legale", action="approve", other_tier="SEAL-1", other_name="acme")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["state"], "active")

    def test_remove_needs_the_owner_of_one_side(self):
        self._approve_both()
        self._as("mallory")
        self.assertEqual(self._post("acme", action="remove", mount="legale").status_code, 403)
        self._as("giovanni")
        r = self._post("acme", action="remove", mount="legale")
        self.assertEqual(r.status_code, 200, r.text)

    def test_a_system_call_without_a_person_is_refused(self):
        self.payload = {"agent": "clodia", "principal": "clodia"}
        r = self._post("acme", action="add", other_tier="SEAL-1", other_name="legale")
        self.assertEqual(r.status_code, 403)


class ArchiveImportDropsLinks(unittest.TestCase):
    def test_links_are_stripped_from_an_imported_meta(self):
        raw = json.dumps({"schema_version": 2, "tier": "SEAL-1", "title": "Acme",
                          "owner": "davide",
                          "links": [{"name": "legale", "tier": "SEAL-1", "topic": "legale",
                                     "approval": {"by": "davide", "as": "owner"}}]})
        meta = json.loads(topics_api._snapshot_meta_bytes(raw.encode(), "SEAL-1"))
        self.assertNotIn("links", meta)
        self.assertEqual(meta["owner"], "davide")


if __name__ == "__main__":
    unittest.main()

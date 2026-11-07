"""#658 — the to-do verbs at the gateway: offered, topic-scoped (every
participant, membership checked as a mutation), and signed by who asked."""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import authz_migration, human, main as M
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicService

VERBS = ("todo_add", "todo_update", "todo_remove")


class Declared(unittest.TestCase):
    def test_offered_scoped_and_mutating(self):
        offered = {t.name: t for t in M._TOPIC_TOOLS}
        for v in VERBS:
            with self.subTest(verb=v):
                self.assertIn(f"topic.{v}", offered)
                self.assertIn("base_version", offered[f"topic.{v}"].inputSchema["required"])
                self.assertIn(v, M._TOPIC_SCOPED_VERBS)
                self.assertIn(v, M._TOPIC_MUTATING_VERBS)

    def test_the_room_floor_covers_them(self):
        """Every participant gets `topic.*` in every room (#604, 23 Oct): the
        new verbs ride on the floor, no grant to add."""
        self.assertIn("topic.*", {p for p, _ in authz_migration.FLOOR})

    def test_a_persons_client_has_them(self):
        for v in VERBS:
            self.assertIn(f"topic.{v}", human._MEMBER_VERBS)


class Dispatch(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="t658-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.svc = TopicService(LocalFsStorage(str(self.root)))
        self.svc.new("SEAL-1", "acme", {"title": "acme", "owner": "davide"})
        self.checked = []

    def call(self, verb, **a):
        def member(svc, tier, name, mutating=False):
            self.checked.append((tier, name, mutating))
        with patch.object(M, "_topics", lambda: self.svc), \
             patch.object(M, "_require_topic_member", member), \
             patch.object(M, "agent_name", lambda: "segretario"), \
             patch.object(M, "is_on_behalf", lambda: False):
            return M._dispatch_topic(f"topic.{verb}", {"tier": "SEAL-1", "name": "acme", **a})

    def test_round_trip_checks_membership_and_signs(self):
        v = self.svc.open("SEAL-1", "acme")["todos_version"]
        r = self.call("todo_add", text="Send the LOI", due="2026-11-20", base_version=v)
        self.assertEqual(r["todo"]["updated_by"], "segretario")
        self.assertEqual(r["deadline"], "2026-11-20")
        # a client sending every optional key as null does not blank the item
        r = self.call("todo_update", id=r["todo"]["id"], text=None, status=None,
                      due=None, base_version=r["todos_version"])
        self.assertEqual(r["todo"]["text"], "Send the LOI")
        self.assertIsNone(r["deadline"])
        r = self.call("todo_remove", id=r["todo"]["id"], base_version=r["todos_version"])
        self.assertEqual(r["todos"], [])
        self.assertEqual(self.checked, [("SEAL-1", "acme", True)] * 3)


if __name__ == "__main__":
    unittest.main()

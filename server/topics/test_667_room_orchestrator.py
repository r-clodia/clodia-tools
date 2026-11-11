"""#667 — the room chooses its orchestrator among its participants."""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from .local_fs import LocalFsStorage
from .service import TopicError, TopicService


class RoomOrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="orch-667-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.svc = TopicService(LocalFsStorage(str(self.root)))
        self.svc.new("SEAL-1", "acme", {"title": "Acme",
                                         "participants": ["segretario", "clodia", "worker"]})

    def meta(self):
        return self.svc._read_meta("SEAL-1", "acme")[0]

    def test_a_participant_seed_is_chosen_and_stored(self):
        r = self.svc.set_orchestrator("SEAL-1", "acme", "Clodia", by="davide")
        self.assertEqual((r["orchestrator"], r["previous"], r["changed"]), ("clodia", None, True))
        self.assertEqual(self.meta().get("orchestrator"), "clodia")

    def test_none_goes_back_to_the_default(self):
        self.svc.set_orchestrator("SEAL-1", "acme", "clodia")
        r = self.svc.set_orchestrator("SEAL-1", "acme", None)
        self.assertEqual(r["previous"], "clodia")
        self.assertNotIn("orchestrator", self.meta())

    def test_a_seed_that_cannot_orchestrate_is_refused(self):
        with self.assertRaises(TopicError):
            self.svc.set_orchestrator("SEAL-1", "acme", "worker")

    def test_a_seed_not_in_the_room_is_refused(self):
        with self.assertRaises(TopicError):
            self.svc.set_orchestrator("SEAL-1", "acme", "ophelia")


if __name__ == "__main__":
    unittest.main()

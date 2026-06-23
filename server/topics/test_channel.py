"""Test dei metodi canale del TopicService (Fase 1: partecipanti/messaggi/file)."""
from __future__ import annotations

import tempfile
import unittest

from .local_fs import LocalFsStorage
from .service import TopicService


class ChannelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.svc = TopicService(LocalFsStorage(tempfile.mkdtemp()))
        self.svc.new("P1", "ch", {"title": "Canale", "owner": "owner"})

    def test_owner_and_default_participant(self) -> None:
        meta = self.svc.open("P1", "ch")["meta"]
        self.assertEqual(meta["owner"], "owner")
        self.assertEqual(meta["participants"], ["owner"])

    def test_participants_add_remove(self) -> None:
        self.svc.add_participant("P1", "ch", "clodia")
        self.svc.add_participant("P1", "ch", "clodia")  # idempotente
        self.assertEqual(self.svc.open("P1", "ch")["meta"]["participants"], ["owner", "clodia"])
        self.svc.remove_participant("P1", "ch", "owner")
        self.assertEqual(self.svc.open("P1", "ch")["meta"]["participants"], ["clodia"])

    def test_messages_ordered_with_kind_and_attachments(self) -> None:
        self.svc.post_message("P1", "ch", "owner", "ciao", kind="human")
        self.svc.post_message("P1", "ch", "clodia", "ecco il file", kind="ai",
                              attachments=["r.md"])
        msgs = self.svc.list_messages("P1", "ch")
        self.assertEqual([(m["author"], m["kind"]) for m in msgs],
                         [("owner", "human"), ("clodia", "ai")])
        self.assertEqual(msgs[1]["attachments"], ["r.md"])

    def test_files_upload_and_list(self) -> None:
        self.svc.put_file("P1", "ch", "report.md", b"# R\n")
        files = self.svc.list_files("P1", "ch")
        self.assertEqual([f["name"] for f in files], ["report.md"])
        self.assertEqual(self.svc.read_file("P1", "ch", "files/report.md"), b"# R\n")

    def test_put_file_rejects_traversal(self) -> None:
        from .service import TopicError
        with self.assertRaises(TopicError):
            self.svc.put_file("P1", "ch", "../evil", b"x")


if __name__ == "__main__":
    unittest.main()

"""Test dei metodi canale del TopicService (Fase 1: partecipanti/messaggi/file)."""
from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from .local_fs import LocalFsStorage
from .service import TopicService


class ChannelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.svc = TopicService(LocalFsStorage(tempfile.mkdtemp()))
        # Il profilo dell'istanza locale non deve alterare le aspettative unit.
        with patch("server.instance_profile.topic_default_participants", return_value=[]):
            self.svc.new("P1", "ch", {"title": "Canale", "owner": "owner"})

    def test_owner_and_default_participant(self) -> None:
        meta = self.svc.open("P1", "ch")["meta"]
        self.assertEqual(meta["owner"], "owner")
        self.assertEqual(meta["participants"], ["owner"])

    def test_participants_add_remove(self) -> None:
        first = self.svc.add_participant("P1", "ch", "clodia")
        again = self.svc.add_participant("P1", "ch", "clodia")  # idempotente
        self.assertEqual(self.svc.open("P1", "ch")["meta"]["participants"], ["owner", "clodia"])
        self.assertTrue(first["added"])
        self.assertFalse(again["added"])
        messages = self.svc.list_messages("P1", "ch")
        self.assertEqual(
            [(m["author"], m["kind"], m["text"]) for m in messages],
            [("system", "system", "clodia è entrato nel topic")],
        )
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
        # list_files starts from the topic ROOT, not from files/ — the navigator
        # shows the real structure and one navigates into it. The test predates
        # that change and used to assert the old files/-relative listing.
        root = self.svc.list_files("P1", "ch")
        self.assertEqual([f["name"] for f in root], ["files", "meta.json", "summary.md"])
        inside = self.svc.list_files("P1", "ch", "files")
        self.assertEqual([f["name"] for f in inside], ["report.md"])
        self.assertEqual(self.svc.read_file("P1", "ch", "files/report.md"), b"# R\n")

    def test_subfolders_are_navigable_not_links(self) -> None:
        """#117: a subfolder must be a navigable dir, whatever the backend.

        On a Drive remote a folder's mime is `application/vnd.google-apps.folder`,
        which matches the native-Google-document prefix. Classified by mime
        before kind, every subfolder was emitted as a remote FILE carrying a
        webViewLink, so the UI opened the Drive web app instead of navigating.
        """
        self.svc.put_field = None  # noqa: B010 - guard against accidental reuse
        self.svc.put_file("P1", "ch", "archivio/2026/nota.md", b"x")
        entries = self.svc.list_files("P1", "ch", "files")
        arch = [f for f in entries if f["name"] == "archivio"]
        self.assertEqual(len(arch), 1)
        self.assertEqual(arch[0]["kind"], "dir")
        self.assertEqual(arch[0]["path"], "files/archivio")
        # and it is navigable one level deeper
        deeper = self.svc.list_files("P1", "ch", "files/archivio")
        self.assertEqual([f["name"] for f in deeper], ["2026"])
        self.assertEqual(deeper[0]["kind"], "dir")

    def test_put_file_rejects_traversal(self) -> None:
        from .service import TopicError
        with self.assertRaises(TopicError):
            self.svc.put_file("P1", "ch", "../evil", b"x")


if __name__ == "__main__":
    unittest.main()

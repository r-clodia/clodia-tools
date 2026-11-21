"""clodia-platform#598 — empty, missing, and file paths are distinct."""
from __future__ import annotations

import tempfile
import unittest

from .local_fs import LocalFsStorage
from .service import TopicError, TopicService


class ListPathErrorsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.svc = TopicService(LocalFsStorage(self.tmp.name))
        self.svc.new("SEAL-1", "acme", {"title": "Acme", "owner": "davide"})
        self.svc.put_file("SEAL-1", "acme", "documenti/contratto.txt", b"testo")
        store, base = self.svc._local_mount("SEAL-1", "acme")
        store.mkdir(f"{base}/vuota")

    def test_empty_existing_folder_is_an_empty_list(self):
        self.assertEqual([], self.svc.list_files("SEAL-1", "acme", "local/vuota"))

    def test_unmaterialized_local_mount_is_an_empty_list(self):
        self.svc.new("SEAL-1", "nuovo", {"title": "Nuovo", "owner": "davide"})
        self.assertEqual([], self.svc.list_files("SEAL-1", "nuovo", "local"))
        self.assertEqual([], self.svc.list_files("SEAL-1", "nuovo", "files"))

    def test_missing_folder_is_a_clear_error(self):
        with self.assertRaisesRegex(TopicError, "cartella non esistente: local/manca"):
            self.svc.list_files("SEAL-1", "acme", "local/manca")

    def test_file_points_to_the_read_verb(self):
        with self.assertRaisesRegex(TopicError, "è un file: leggilo con topic.read_file"):
            self.svc.list_files("SEAL-1", "acme", "local/documenti/contratto.txt")


if __name__ == "__main__":
    unittest.main()

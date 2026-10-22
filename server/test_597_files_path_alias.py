"""`topic.files` takes `path` too, and `read_file` on a folder says so
(clodia-platform#597).

The case that opened the issue: Davide filled `shared/uncommon-conto-titoli`
with five signed PDFs. The agent called `topic.files` with `path=` — the name
`topic.read_file` uses and that every returned entry carries — the argument
was dropped without a word and the root came back. It then called
`topic.read_file` on the folder, got «non trovato», and told Davide the folder
did not exist on the server.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import main as M
from .topics.local_fs import LocalFsStorage
from .topics.service import LOCAL_SHARED_ROOT, TopicError, TopicService


class Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="t597-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        (self.root / LOCAL_SHARED_ROOT).mkdir(parents=True)
        self.svc = TopicService(LocalFsStorage(str(self.root)))
        self.svc.new("SEAL-1", "acme", {"title": "acme"})
        self.svc.local_folder_add("SEAL-1", "acme")
        sub = self.root / LOCAL_SHARED_ROOT / "acme" / "firmati"
        sub.mkdir()
        (sub / "contratto.pdf").write_bytes(b"%PDF-1.4 x")
        self.svc.put_file("SEAL-1", "acme", "local/cartella/nota.txt", b"n")

    def files(self, **a):
        with patch.object(M, "_topics", lambda: self.svc), \
             patch.object(M, "_require_topic_member", lambda *x, **k: None):
            return M._dispatch_topic("topic.files", {"tier": "SEAL-1", "name": "acme", **a})


class FilesTakesPath(Base):
    def test_path_lists_the_folder_not_the_root(self):
        got = [e["path"] for e in self.files(path="shared/firmati")]
        self.assertEqual(got, ["shared/firmati/contratto.pdf"])

    def test_a_dir_entry_path_is_passed_back_as_is(self):
        entry = next(e for e in self.files(path="shared") if e["kind"] == "dir")
        self.assertEqual([e["name"] for e in self.files(path=entry["path"])],
                         ["contratto.pdf"])

    def test_subpath_still_works_and_empty_is_the_root(self):
        self.assertEqual([e["name"] for e in self.files(subpath="shared/firmati")],
                         ["contratto.pdf"])
        self.assertEqual(sorted(e["name"] for e in self.files()), ["local", "shared"])

    def test_both_given_and_equal_is_fine(self):
        got = self.files(subpath="shared/firmati", path="shared/firmati/")
        self.assertEqual([e["name"] for e in got], ["contratto.pdf"])

    def test_both_given_and_different_is_refused(self):
        with self.assertRaises(TopicError):
            self.files(subpath="shared", path="local")

    def test_the_schema_declares_path(self):
        tool = next(t for t in M._TOPIC_TOOLS if t.name == "topic.files")
        self.assertIn("path", tool.inputSchema["properties"])


class TheAuditSeesASubpath(unittest.TestCase):
    """A listing is not an ingress: `path=` must not reach the audit as the
    path of a file read."""

    def test_path_becomes_subpath_at_the_door(self):
        got = M._files_path_as_subpath("topic.files",
                                       {"tier": "SEAL-1", "name": "acme", "path": "shared/x"})
        self.assertEqual(got, {"tier": "SEAL-1", "name": "acme", "subpath": "shared/x"})

    def test_other_verbs_keep_path(self):
        a = {"tier": "SEAL-1", "name": "acme", "path": "local/a.md"}
        self.assertIs(M._files_path_as_subpath("topic.read_file", a), a)

    def test_a_conflict_is_left_for_dispatch_to_refuse(self):
        a = {"tier": "SEAL-1", "name": "acme", "subpath": "shared", "path": "local"}
        self.assertIs(M._files_path_as_subpath("topic.files", a), a)


class ReadingAFolder(Base):
    def test_shared_folder_says_it_is_a_folder(self):
        with self.assertRaises(TopicError) as cm:
            self.svc.read_file("SEAL-1", "acme", "shared/firmati")
        self.assertIn("è una cartella", str(cm.exception))
        self.assertIn("subpath='shared/firmati'", str(cm.exception))

    def test_local_folder_says_it_is_a_folder(self):
        with self.assertRaises(TopicError) as cm:
            self.svc.read_file("SEAL-1", "acme", "local/cartella/")
        self.assertIn("subpath='local/cartella'", str(cm.exception))

    def test_a_missing_file_is_still_not_found(self):
        from .topics.storage import NotFound
        with self.assertRaises(NotFound):
            self.svc.read_file("SEAL-1", "acme", "shared/firmati/manca.pdf")

    def test_a_file_reads_as_before(self):
        self.assertEqual(self.svc.read_file("SEAL-1", "acme", "shared/firmati/contratto.pdf"),
                         b"%PDF-1.4 x")


if __name__ == "__main__":
    unittest.main()

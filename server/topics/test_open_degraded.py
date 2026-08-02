"""`open` must survive an unreachable file backend.

Regression test for the production incident of 2 Aug 2026: a single revoked
Google OAuth token made `topic.open` return 500 for the topic whose remote is a
Drive folder — and, because the topic list opens every topic, it took the whole
list down with it. `recent_files` is a decoration for the card: it must never be
able to make a topic unreadable, since meta and summary live in the local
control plane and are perfectly available.
"""
from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from .local_fs import LocalFsStorage
from .service import TopicService


class OpenDegradedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.svc = TopicService(LocalFsStorage(tempfile.mkdtemp()))
        with patch("server.instance_profile.topic_default_participants", return_value=[]):
            self.svc.new("SEAL-1", "t", {"title": "Topic", "owner": "owner"})
        self.svc.put_file("SEAL-1", "t", "note.md", b"content")

    def test_open_succeeds_when_file_backend_raises(self) -> None:
        boom = RuntimeError("invalid_grant: Token has been expired or revoked.")
        with patch.object(TopicService, "_files_backend", side_effect=boom):
            out = self.svc.open("SEAL-1", "t")
        # the topic is readable: meta and summary come from the control plane
        self.assertEqual(out["meta"]["title"], "Topic")
        self.assertEqual(out["name"], "t")
        # and the caller can tell "no files" from "files not listable"
        self.assertEqual(out["recent_files"], [])
        self.assertTrue(out["files_unavailable"])

    def test_healthy_backend_reports_files_and_no_flag(self) -> None:
        out = self.svc.open("SEAL-1", "t")
        self.assertIn("note.md", [f["name"] for f in out["recent_files"]])
        self.assertFalse(out["files_unavailable"])


if __name__ == "__main__":
    unittest.main()

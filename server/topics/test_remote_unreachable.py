"""An unreachable remote must produce an actionable error, never silence.

Reported by @ddbit on 3 Aug 2026: browsing files/ in a topic backed by Drive
"fails silently". The gateway was letting the provider library's own exception
escape (`RefreshError: invalid_grant`), which became an opaque 500 and, in the
UI, an empty folder — indistinguishable from a topic with no files.

Reading files is not decoration (unlike `recent_files` in `open`, which
degrades on purpose): the caller asked for them, so it must be told why they
are missing.
"""
from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from .local_fs import LocalFsStorage
from .service import TopicService, TopicError


class RemoteUnreachableTests(unittest.TestCase):
    def setUp(self) -> None:
        self.svc = TopicService(LocalFsStorage(tempfile.mkdtemp()))
        with patch("server.instance_profile.topic_default_participants", return_value=[]):
            self.svc.new("SEAL-1", "t", {"title": "T", "owner": "owner"})
        self.svc.put_file("SEAL-1", "t", "note.md", b"x")

    def test_list_files_raises_actionable_error_on_revoked_token(self) -> None:
        boom = RuntimeError("('invalid_grant: Token has been expired or revoked.', {})")
        with patch.object(TopicService, "_files_backend", side_effect=boom):
            with self.assertRaises(TopicError) as cm:
                self.svc.list_files("SEAL-1", "t", "files")
        msg = str(cm.exception)
        # the marker callers key on, plus a human-actionable reason
        self.assertIn("remote-unavailable:", msg)
        self.assertIn("riautorizza", msg.lower())
        # and NOT the raw library exception
        self.assertNotIn("RefreshError", msg)

    def test_generic_backend_failure_is_also_reported(self) -> None:
        with patch.object(TopicService, "_files_backend",
                          side_effect=RuntimeError("connection reset")):
            with self.assertRaises(TopicError) as cm:
                self.svc.list_files("SEAL-1", "t", "files")
        self.assertIn("remote-unavailable:", str(cm.exception))

    def test_healthy_backend_still_lists(self) -> None:
        out = self.svc.list_files("SEAL-1", "t", "files")
        self.assertIn("note.md", [e["name"] for e in out])

    def test_topic_root_listing_is_unaffected(self) -> None:
        """La radice non tocca il backend remoto: deve funzionare col remote
        morto. La proprieta' resta, l'aspettativa cambia — dal 7 ago 2026 la
        radice e' quella dei DATI e mostra i mount, non piu' meta/summary.

        Anzi la proprieta' e' piu' forte di prima: `data_mounts` legge il meta
        LOCALE per sapere se un remote c'e', e non prova mai a raggiungerlo. Se
        un giorno lo facesse, un token Drive scaduto renderebbe illeggibile
        anche l'elenco delle cartelle."""
        with patch.object(TopicService, "_files_backend",
                          side_effect=RuntimeError("invalid_grant")):
            out = self.svc.list_files("SEAL-1", "t", "")
        # La fixture non configura un remote nel meta: qui conta che la radice
        # RISPONDA invece di propagare il guasto del backend.
        self.assertEqual([e["name"] for e in out], ["local"])


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import unittest
from unittest.mock import patch

from . import main


class _Topics:
    def __init__(self):
        self.reads = []

    def read_file(self, tier, name, path):
        self.reads.append((tier, name, path))
        return b"document"


class MessengerAttachmentTests(unittest.TestCase):

    def test_telegram_materializes_a_topic_file_inside_the_gateway(self) -> None:
        topics = _Topics()
        with patch.object(main, "_topics", return_value=topics), \
             patch.object(main, "_require_topic_member"), \
             patch("server.tools.telegram._resolve_chat", return_value="123"), \
             patch("server.tools.telegram.send_file", return_value={"ok": True}) as send:
            out = main._dispatch_telegram("telegram.send_file", {
                "chat_id": "gruppo",
                "tier": "SEAL-1",
                "name": "pratica",
                "path": "files/contratto.pdf",
            })

        self.assertEqual(out, {"ok": True})
        self.assertEqual(topics.reads,
                         [("SEAL-1", "pratica", "files/contratto.pdf")])
        send.assert_called_once_with("123", "contratto.pdf", "ZG9jdW1lbnQ=", "")

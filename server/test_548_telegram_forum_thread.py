"""clodia-platform#548 — invio in un thread di un gruppo-forum Telegram.

Il supergruppo di `cop-pilot-uncommon` è un forum: senza `message_thread_id`
ogni messaggio va nel thread «Generale», e «#funding» era irraggiungibile
(15 ott 2026). Qui si fissa che il thread arriva a Telegram, che la sua assenza
non cambia nulla, che un valore insensato è rifiutato e che i messaggi in
entrata ricordano il thread da cui arrivano.
"""
from __future__ import annotations

import base64
import unittest
from unittest.mock import patch

from server.tools import telegram as tg


class SendIntoThreadTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        def fake_api(token, method, params=None, timeout=15):
            self.calls.append((method, dict(params or {})))
            return {"message_id": 7}
        def fake_multipart(token, method, fields, *a, **k):
            self.calls.append((method, dict(fields)))
            return {"message_id": 8}
        for name, val in (("api_call", fake_api), ("_post_multipart", fake_multipart),
                          ("_token", lambda: "T"), ("_token_internal", lambda: "T"),
                          ("tool_allowed", lambda *_: None),
                          ("_resolve_chat_or_current", lambda c: c),
                          ("_resolve_chat", lambda c: c)):
            p = patch.object(tg, name, val); p.start(); self.addCleanup(p.stop)

    def test_send_forwards_the_thread(self):
        tg.send("-1004433615610", "ciao", thread_id=42)
        self.assertEqual(self.calls[-1], ("sendMessage", {
            "chat_id": -1004433615610, "text": "ciao", "message_thread_id": 42}))

    def test_without_thread_the_payload_is_unchanged(self):
        tg.send("-1004433615610", "ciao")
        self.assertNotIn("message_thread_id", self.calls[-1][1])

    def test_send_file_and_send_internal_forward_the_thread(self):
        tg.send_file("-100", "a.pdf", base64.b64encode(b"x").decode(), "", thread_id="5")
        self.assertEqual(self.calls[-1][1].get("message_thread_id"), 5)
        tg.send_internal("-100", "ok", thread_id=9)
        self.assertEqual(self.calls[-1][1].get("message_thread_id"), 9)

    def test_a_meaningless_thread_is_refused_before_calling_telegram(self):
        for bad in (0, -3, "abc", 1.5, True):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                tg.send("-100", "x", thread_id=bad)
        self.assertEqual(self.calls, [])


class InboundThreadTests(unittest.TestCase):
    def test_thread_id_of_accepts_only_positive_ints(self):
        self.assertIsNone(tg.thread_id_of(None))
        self.assertIsNone(tg.thread_id_of(""))
        self.assertEqual(tg.thread_id_of("12"), 12)
        with self.assertRaises(ValueError):
            tg.thread_id_of(0)

    def test_the_source_keeps_the_forum_thread_of_inbound_messages(self):
        import inspect
        src = inspect.getsource(tg)
        self.assertGreaterEqual(src.count('"thread_id": (msg.get("message_thread_id")'), 2)
        self.assertIn('if msg.get("is_topic_message")', src)


if __name__ == "__main__":
    unittest.main()

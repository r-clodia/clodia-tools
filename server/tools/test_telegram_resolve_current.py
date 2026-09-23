"""`telegram.send`/`send_file` senza `chat_id`: risolvono la chat dal TOPIC
corrente, non da un nome indovinato.

Trovato da Davide il 23 set 2026 su `tomato-blogging`: due gruppi Telegram
con nomi quasi identici — "Davide & Clodia" e "Davide & Clodia Colony
Blogging" — hanno prodotto invii ripetuti al gruppo SBAGLIATO, perché chi
chiamava (umano o agente) indovinava/ricordava un nome invece di usare il
binding del topic corrente — l'unica fonte che non può sbagliare per
costruzione (`telegram_bindings`: una chat → un solo topic).
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import telegram as tg
from . import telegram_bindings as tb


class GetForTopicTests(unittest.TestCase):
    def test_finds_the_chat_bound_to_a_topic(self):
        with patch.object(tb, "load", return_value={
            "-100": {"instance": "messaggero", "tier": "SEAL-1", "topic": "acme"},
            "-200": {"instance": "messaggero", "tier": "SEAL-1", "topic": "beta"},
        }):
            self.assertEqual(tb.get_for_topic("SEAL-1", "acme"), "-100")
            self.assertEqual(tb.get_for_topic("SEAL-1", "beta"), "-200")

    def test_none_when_no_binding_exists(self):
        with patch.object(tb, "load", return_value={}):
            self.assertIsNone(tb.get_for_topic("SEAL-1", "acme"))


class ResolveChatOrCurrentTests(unittest.TestCase):
    def test_an_explicit_chat_still_uses_the_normal_resolver(self):
        """Non cambia niente quando il chiamante SA cosa vuole: id o nome
        esplicito passano dal resolver di sempre, non dal binding."""
        with patch.object(tg, "_resolve_chat", return_value="-999") as m:
            out = tg._resolve_chat_or_current("Un Nome Qualunque")
        m.assert_called_once_with("Un Nome Qualunque")
        self.assertEqual(out, "-999")

    def test_omitted_chat_uses_the_current_topics_binding(self):
        with patch.object(tg, "current_channel", return_value="SEAL-1/tomato-blogging"), \
             patch.object(tb, "get_for_topic", return_value="-5461904850") as m:
            out = tg._resolve_chat_or_current(None)
        m.assert_called_once_with("SEAL-1", "tomato-blogging")
        self.assertEqual(out, "-5461904850")

    def test_omitted_chat_outside_any_topic_is_a_clear_error(self):
        with patch.object(tg, "current_channel", return_value=None):
            with self.assertRaises(ValueError) as cm:
                tg._resolve_chat_or_current(None)
            self.assertIn("chat_id", str(cm.exception))

    def test_omitted_chat_with_no_binding_names_the_remedy(self):
        with patch.object(tg, "current_channel", return_value="SEAL-1/tomato-blogging"), \
             patch.object(tb, "get_for_topic", return_value=None):
            with self.assertRaises(ValueError) as cm:
                tg._resolve_chat_or_current(None)
            msg = str(cm.exception)
            self.assertIn("telegram.listen", msg)
            self.assertIn("tomato-blogging", msg)


if __name__ == "__main__":
    unittest.main()

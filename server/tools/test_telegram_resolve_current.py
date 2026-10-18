"""`telegram.send`/`send_file` senza `chat_id`: risolvono la chat dal TOPIC
corrente, non da un nome indovinato.

Trovato da Davide il 23 set 2026 su `tomato-blogging`: due gruppi Telegram
con nomi quasi identici — "Davide & Clodia" e "Davide & Clodia Colony
Blogging" — hanno prodotto invii ripetuti al gruppo SBAGLIATO, perché chi
chiamava (umano o agente) indovinava/ricordava un nome invece di usare il
binding del topic corrente — l'unica fonte che non può sbagliare per
costruzione (`telegram_bindings`: una chat → un solo topic).

The resolution itself is the gateway's (the manifest's `defaults:` fill
`chat_id` from this registry, tested in `test_522_pack_files_and_relay`); the
native client's own resolver went with it (#522). What stays here is the
registry lookup.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

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


if __name__ == "__main__":
    unittest.main()

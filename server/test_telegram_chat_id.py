"""`telegram.send` rifiuta un chat_id che non è una chat (clodia-platform#402).

Il 26 set 2026 il messaggero ha passato il TITOLO del gruppo («Clodia
Sviluppo») come chat_id: il gateway ne ha fatto `tg:Clodia Sviluppo`, che
nessuna lista contiene, e ha aperto un gate per approvare un indirizzo
inesistente — col gruppo vero (`tg:-5411149155`) già in whitelist.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import main


class ChatIdTests(unittest.TestCase):
    def test_a_group_id_and_a_handle_pass(self):
        main._telegram_chat_id_or_raise({"chat_id": "-5411149155"})
        main._telegram_chat_id_or_raise({"chat_id": "@therealdadabit"})

    def test_a_group_title_is_refused_naming_the_bound_chat(self):
        with patch.object(main, "current_channel", return_value="SEAL-1/software-house"), \
                patch("server.topics_api._telegram_binding_for",
                      return_value=("-5411149155", {"topic": "software-house"})):
            with self.assertRaises(ValueError) as ctx:
                main._telegram_chat_id_or_raise({"chat_id": "Clodia Sviluppo"})
        self.assertIn("chat_id='-5411149155'", str(ctx.exception))

    def test_outside_a_channel_the_refusal_still_says_what_is_expected(self):
        with patch.object(main, "current_channel", return_value=None):
            with self.assertRaises(ValueError) as ctx:
                main._telegram_chat_id_or_raise({"chat_id": "Clodia Sviluppo"})
        self.assertIn("id numerico", str(ctx.exception))

    def test_the_check_runs_before_the_egress_verdict(self):
        import inspect
        src = inspect.getsource(main.call_tool)
        self.assertLess(src.index("_telegram_chat_id_or_raise(arguments)"),
                        src.index("_egress.check("))


if __name__ == "__main__":
    unittest.main()

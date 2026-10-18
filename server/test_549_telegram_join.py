"""clodia-platform#549 — a Telegram group joins a topic by `startgroup` link.

A bot cannot join from an invite link. The gateway mints a one-time token bound
to the topic; Telegram delivers `/start <token>` in the group the human picked;
the gateway records a proposal for the topic's owner and does NOT relay the
command. Here: the token is single-use and expiring, only groups qualify, a
`/start` for another bot is left alone, the proposal reaches the owner's action
state, and connecting it consumes it.
"""
from __future__ import annotations

import os
import tempfile
import time
import unittest
from unittest.mock import patch

from server.tools import telegram_join as tj


class _TmpJoin(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        p = patch.dict(os.environ, {
            "CLODIA_TELEGRAM_JOIN": os.path.join(self.tmp.name, "join.json"),
            "CLODIA_TELEGRAM_STATE": os.path.join(self.tmp.name, "tg.json")})
        p.start(); self.addCleanup(p.stop)
        self.announced = []
        a = patch.object(tj, "announce", self.announced.append)
        a.start(); self.addCleanup(a.stop)


def _msg(text, chat_id=-1004433615610, ctype="supergroup", title="cop-pilot"):
    return {"message_id": 1, "text": text,
            "chat": {"id": chat_id, "type": ctype, "title": title},
            "from": {"id": 7, "username": "dadabit"}}


class TokenTests(_TmpJoin):
    def test_claim_records_a_proposal_once(self):
        tok = tj.mint("SEAL-1", "funding", by="messaggero-79")["token"]
        self.assertTrue(tj.intercept(_msg(f"/start@clodia_bot {tok}"), "clodia_bot"))
        props = tj.proposals("SEAL-1", "funding")
        self.assertEqual([p["chat_id"] for p in props], ["-1004433615610"])
        self.assertEqual(props[0]["requested_by"], "messaggero-79")
        self.assertEqual(len(self.announced), 1)
        # single use: the same token again is an ordinary /start
        self.assertFalse(tj.intercept(_msg(f"/start {tok}", chat_id=-100999), "clodia_bot"))
        self.assertEqual(len(tj.proposals("SEAL-1", "funding")), 1)

    def test_expired_and_unknown_tokens_are_ignored(self):
        tok = tj.mint("SEAL-1", "funding", by="x")["token"]
        with patch.object(tj.time, "time", return_value=time.time() + tj.TOKEN_TTL + 5):
            self.assertFalse(tj.intercept(_msg(f"/start {tok}"), "clodia_bot"))
        self.assertFalse(tj.intercept(_msg("/start " + "A" * 32), "clodia_bot"))
        self.assertEqual(tj.proposals("SEAL-1", "funding"), [])

    def test_private_chat_does_not_qualify(self):
        tok = tj.mint("SEAL-1", "funding", by="x")["token"]
        self.assertFalse(tj.intercept(_msg(f"/start {tok}", chat_id=5, ctype="private"),
                                      "clodia_bot"))

    def test_start_for_another_bot_is_left_alone(self):
        tok = tj.mint("SEAL-1", "funding", by="x")["token"]
        self.assertIsNone(tj.parse_start(f"/start@other_bot {tok}", "clodia_bot"))
        self.assertFalse(tj.intercept(_msg(f"/start@other_bot {tok}"), "clodia_bot"))
        # the token is still usable by the right bot
        self.assertTrue(tj.intercept(_msg(f"/start {tok}"), "clodia_bot"))

    def test_ordinary_messages_are_untouched(self):
        for text in ("ciao", "/start", "/help x", ""):
            with self.subTest(text=text):
                self.assertIsNone(tj.parse_start(text, "clodia_bot"))

    def test_drop_forgets_the_proposal(self):
        tok = tj.mint("SEAL-1", "funding", by="x")["token"]
        tj.intercept(_msg(f"/start {tok}"), "clodia_bot")
        self.assertTrue(tj.drop("SEAL-1", "funding", "-1004433615610"))
        self.assertEqual(tj.proposals("SEAL-1", "funding"), [])


class RelayInterceptTests(_TmpJoin):
    def test_the_relay_poll_consumes_the_join_and_relays_the_rest(self):
        """The relay's `/poll` (comms-pack's component, #522) is the only door
        updates come in by: the join is consumed there, the rest relayed."""
        from server import telegram_api
        tok = tj.mint("SEAL-1", "funding", by="x")["token"]
        msgs = [{"text": f"/start@clodia_bot {tok}", "chat_id": -1004433615610,
                 "chat_title": "cop-pilot", "chat_type": "supergroup",
                 "from_username": "dadabit", "from_id": 7},
                {"text": "buongiorno", "chat_id": -1004433615610,
                 "chat_title": "cop-pilot", "chat_type": "supergroup",
                 "from_username": "dadabit", "from_id": 7}]
        out = telegram_api._intercetta_join(msgs, "clodia_bot")
        self.assertEqual([m["text"] for m in out], ["buongiorno"])
        self.assertEqual(len(tj.proposals("SEAL-1", "funding")), 1)


class ActionStateTests(_TmpJoin):
    def test_suggestions_and_connect_consumes_them(self):
        from server.connectors import actions as ca
        tok = tj.mint("SEAL-1", "funding", by="x")["token"]
        tj.intercept(_msg(f"/start {tok}"), "clodia_bot")

        class _F: name = "chat"
        class _A: fields = [_F()]
        class _C: id = "telegram"
        sugg = ca._suggestions(_C(), _A(), "SEAL-1", "funding", None)
        self.assertEqual(sugg[0]["values"], {"chat": "-1004433615610"})
        self.assertEqual(sugg[0]["label"], "cop-pilot")
        # already bound → not suggested again
        self.assertEqual(ca._suggestions(_C(), _A(), "SEAL-1", "funding",
                                         "-1004433615610"), [])
        # another connector never gets Telegram's proposals
        class _D: id = "mail"
        self.assertEqual(ca._suggestions(_D(), _A(), "SEAL-1", "funding", None), [])


if __name__ == "__main__":
    unittest.main()

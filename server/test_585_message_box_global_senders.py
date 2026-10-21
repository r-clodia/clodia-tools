"""#585 — global `mailfrom:` entries count for the topic's message box, not for
a linked mailbox.

| mail reaches the room through      | global | room's own |
|------------------------------------|--------|------------|
| its message box (`box+CODE@`)      | yes    | yes        |
| a mailbox it links (`inbox:`)      | no     | yes        |

The subaddress already names the one room, so a global sender cannot fan out.
A strict-ingress room keeps its own list."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import egress, mail_courier_api as C, whitelist
from .components.host import Perimeter

ROOM = "SEAL-1/tomato-blogging"
BOXES = [{"account": "devnullboxx", "email": "devnullboxx@gmail.com", "send_only": False}]


def _cfg(own=(), glob=(), strict=False):
    cfg = {C.COLONY_KEY: "devnullboxx",
           "scope_source_allow": {ROOM: ["tg:-1", *own]},
           "source_allow": ["https://example.org", *glob]}
    if strict:
        cfg["scope_ingress_strict"] = {ROOM: True}
    return cfg


def setUpModule():
    # `mailfrom:` is declared by comms-pack, not loaded here: the global list
    # is validated against the declared schemes.
    global _schemes
    _schemes = patch.object(egress, "source_schemes", lambda: ("mailfrom", "tg", "https"))
    _schemes.start()


def tearDownModule():
    _schemes.stop()


class SenderRulesTests(unittest.TestCase):
    def _ask(self, cfg, sender, with_global):
        with patch.object(whitelist, "CONFIG", cfg):
            return egress.room_declares_sender(sender, ROOM, with_global=with_global)

    def test_global_counts_only_with_global(self):
        cfg = _cfg(glob=["mailfrom:dcarboni@gmail.com"])
        self.assertTrue(self._ask(cfg, "Davide <dcarboni@gmail.com>", True))
        self.assertFalse(self._ask(cfg, "Davide <dcarboni@gmail.com>", False))

    def test_own_counts_either_way(self):
        cfg = _cfg(own=["mailfrom:*@brightnode.io"])
        for wg in (False, True):
            with self.subTest(with_global=wg):
                self.assertTrue(self._ask(cfg, "a@brightnode.io", wg))
                self.assertFalse(self._ask(cfg, "a@other.io", wg))

    def test_a_strict_room_keeps_its_own_list(self):
        cfg = _cfg(glob=["mailfrom:dcarboni@gmail.com"], strict=True)
        self.assertFalse(self._ask(cfg, "dcarboni@gmail.com", True))

    def test_only_mailfrom_entries_of_the_global_list(self):
        with patch.object(whitelist, "CONFIG", _cfg(glob=["mailfrom:a@b.it"])):
            self.assertEqual(egress.room_sender_rules(ROOM, with_global=True),
                             ["mailfrom:a@b.it"])


class ColonyRowTests(unittest.TestCase):
    def _rooms(self, cfg):
        fake = type("T", (), {"mailbox_codes": lambda self: {"UD54G": ("SEAL-1", "tomato-blogging")}})()
        with patch.object(whitelist, "CONFIG", cfg), \
                patch("server.tools.mail_switch.system_mailboxes", return_value=BOXES), \
                patch.object(C, "_topic_exists", lambda t, n: True), \
                patch("server.components.loader.service", lambda pack, name: object()), \
                patch("server.main._topics", lambda: fake):
            return C.rooms()

    def test_a_global_sender_alone_opens_the_tagged_row(self):
        (row,) = self._rooms(_cfg(glob=["mailfrom:dcarboni@gmail.com"]))
        self.assertEqual((row["tag"], row["senders"]), ("UD54G", 1))

    def test_the_signature_covers_the_global_entries(self):
        a = self._rooms(_cfg(glob=["mailfrom:dcarboni@gmail.com"]))[0]["senders_sig"]
        b = self._rooms(_cfg(glob=["mailfrom:dcarboni@gmail.com", "mailfrom:x@y.it"]))[0]["senders_sig"]
        self.assertNotEqual(a, b)

    def test_a_linked_mailbox_row_ignores_global_entries(self):
        cfg = _cfg(own=["inbox:studio@x.it"], glob=["mailfrom:dcarboni@gmail.com"])
        with patch.object(whitelist, "CONFIG", cfg):
            self.assertEqual(C._senders(ROOM)["senders"], 0)


class PerimeterTests(unittest.TestCase):
    def test_the_union_only_inside_a_tagged_courier_call(self):
        cfg = _cfg(glob=["mailfrom:dcarboni@gmail.com"])
        per = Perimeter()
        with patch.object(whitelist, "CONFIG", cfg), \
                patch.object(egress, "_scope_of_call", lambda: ROOM):
            self.assertFalse(per.room_declares_sender("dcarboni@gmail.com"))
            tok = C.COURIER_TAG.set("UD54G")
            try:
                self.assertTrue(per.room_declares_sender("dcarboni@gmail.com"))
            finally:
                C.COURIER_TAG.reset(tok)


if __name__ == "__main__":
    unittest.main()

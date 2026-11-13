"""Mailboxes are configured globally; a room only says which senders it
listens to (owner, 14 Nov 2026).

Every room with senders of its own gets a courier row for every globally
authorised receiving mailbox; the colony mailbox is excepted (it reaches a room
through the room's own address), and a room without senders gets none.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import egress, mail_courier_api as C, whitelist

BOXES = [{"account": "devnullboxx", "email": "devnullboxx@gmail.com", "send_only": False},
         {"account": "studio", "email": "studio@x.it", "send_only": False},
         {"account": "uncommon", "email": "uncommon@x.it", "send_only": False},
         {"account": "alias", "email": "alias@x.it", "send_only": True}]


def _rooms(scope_lists, global_sources, codes=None, strict=None):
    cfg = {C.COLONY_KEY: "devnullboxx", "scope_source_allow": scope_lists,
           "source_allow": global_sources, "scope_ingress_strict": strict or {}}
    fake = type("T", (), {"mailbox_codes": lambda self: codes or {}})()
    with patch.object(whitelist, "CONFIG", cfg), \
            patch("server.tools.mail_switch.system_mailboxes", return_value=BOXES), \
            patch.object(C, "_topic_exists", lambda t, n: True), \
            patch.object(C, "_email_authorised", lambda t, n: True), \
            patch.object(egress, "source_schemes", lambda: ("mailfrom", "inbox", "https")), \
            patch("server.components.loader.service", lambda pack, name: object()), \
            patch("server.main._topics", lambda: fake):
        return sorted((r["name"], r["address"], r.get("tag") or "") for r in C.rooms())


class GlobalMailboxRowsTests(unittest.TestCase):
    def test_a_room_with_senders_reads_every_global_mailbox(self):
        got = _rooms({"SEAL-1/acme": ["mailfrom:a@b.it"]},
                     ["inbox:studio@x.it", "inbox:uncommon@x.it"])
        self.assertEqual(got, [("acme", "studio@x.it", ""), ("acme", "uncommon@x.it", "")])

    def test_a_room_without_senders_gets_none(self):
        self.assertEqual(_rooms({"SEAL-1/acme": ["https:*"]}, ["inbox:studio@x.it"]), [])

    def test_the_colony_mailbox_is_excepted(self):
        got = _rooms({"SEAL-1/acme": ["mailfrom:a@b.it"]},
                     ["inbox:devnullboxx@gmail.com", "inbox:studio@x.it"])
        self.assertEqual(got, [("acme", "studio@x.it", "")])

    def test_a_send_only_or_unknown_mailbox_is_not_read(self):
        got = _rooms({"SEAL-1/acme": ["mailfrom:a@b.it"]},
                     ["inbox:alias@x.it", "inbox:nobody@x.it"])
        self.assertEqual(got, [])

    def test_an_old_room_link_does_not_double_the_row(self):
        got = _rooms({"SEAL-1/acme": ["mailfrom:a@b.it", "inbox:studio@x.it"]},
                     ["inbox:studio@x.it"])
        self.assertEqual(got, [("acme", "studio@x.it", "")])

    def test_a_strict_room_reads_only_its_own_list(self):
        got = _rooms({"SEAL-1/acme": ["mailfrom:a@b.it"]}, ["inbox:studio@x.it"],
                     strict={"SEAL-1/acme": True})
        self.assertEqual(got, [])

    def test_global_senders_do_not_make_a_room_read_mailboxes(self):
        got = _rooms({"SEAL-1/acme": ["https:*"]},
                     ["inbox:studio@x.it", "mailfrom:x@y.it"])
        self.assertEqual(got, [])


if __name__ == "__main__":
    unittest.main()

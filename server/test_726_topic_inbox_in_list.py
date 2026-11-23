"""clodia-platform#726 — the topics list carries each room's inbox address.

The /topics cards show a 📧 that copies the room's message box address. The
gateway adds it to the rows of the list, with one read of the codes for the
whole list; a room without a code, or an instance without the colony mailbox,
gets no field (and so no icon).
"""
from __future__ import annotations

import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch

from server import mail_courier_api, topics_api

ROWS = [{"tier": "SEAL-1", "name": "acme"}, {"tier": "SEAL-2", "name": "senza-codice"}]


def _svc(codes):
    return NS(list=lambda tier, include_archived=False: [dict(r) for r in ROWS],
              mailbox_codes=lambda: codes)


class InboxInListTests(unittest.TestCase):
    def test_a_room_with_a_code_has_its_address(self):
        with patch.object(topics_api, "_service", lambda: _svc({"k7q2": ("SEAL-1", "acme")})), \
                patch.object(mail_courier_api, "colony_mailbox",
                             lambda: ("colonia", "clodia@example.org")):
            rows = topics_api._list_with_inbox(None, True)
        self.assertEqual(rows[0]["inbox"], "clodia+k7q2@example.org")
        self.assertNotIn("inbox", rows[1])

    def test_without_the_colony_mailbox_no_address(self):
        with patch.object(topics_api, "_service", lambda: _svc({"k7q2": ("SEAL-1", "acme")})), \
                patch.object(mail_courier_api, "colony_mailbox", lambda: ("", "")):
            rows = topics_api._list_with_inbox(None, True)
        self.assertNotIn("inbox", rows[0])

    def test_unreadable_codes_never_fail_the_list(self):
        def boom():
            raise RuntimeError("x")
        svc = NS(list=lambda tier, include_archived=False: [dict(r) for r in ROWS],
                 mailbox_codes=boom)
        with patch.object(topics_api, "_service", lambda: svc):
            self.assertEqual(len(topics_api._list_with_inbox(None, True)), 2)


if __name__ == "__main__":
    unittest.main()

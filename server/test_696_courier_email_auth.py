"""The courier delivers a linked mailbox only where the room authorised Email
(clodia-platform#696).

Since #683 agents have no `email.*` verbs, so the room's toolbox never
contains them: the courier's old test («does the toolbox give `email.*`?») was
always false under enforce and dropped every linked-mailbox row. The room's
authorisation is what it stores, `meta.tools.mcp.email`.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import authz_runtime, egress, mail_courier_api as C, room_tools, whitelist

BOXES = [{"account": "devnullboxx", "email": "devnullboxx@gmail.com", "send_only": False},
         {"account": "studio", "email": "studio@x.it", "send_only": False}]

EMAIL_MCP = {"tools": {"enabled": [], "mcp": {"email": {"resources": []}}}}
EMAIL_MCP_ROWS = {"tools": {"enabled": [], "mcp": {"email": {"resources": [
    {"uri": "mailto:a@b.it", "effect": "allow"}]}}}}
LEGACY_VERB = {"tools": {"enabled": ["email.*"]}}
OTHER_MCP = {"tools": {"enabled": [], "mcp": {"web": {"resources": []}}}}
NOTHING: dict = {}


class _FakeTopics:
    def __init__(self, metas, codes=None):
        self.metas, self.codes = metas, codes or {}

    def mailbox_codes(self):
        return self.codes

    def _read_meta(self, tier, name):
        if (tier, name) not in self.metas:
            raise FileNotFoundError(name)
        return self.metas[(tier, name)], 1


def _rooms(metas, scope_lists, global_sources=(), codes=None, enforce=True,
           indexed=False):
    cfg = {C.COLONY_KEY: "devnullboxx", "scope_source_allow": scope_lists,
           "source_allow": list(global_sources), "scope_ingress_strict": {}}
    fake = _FakeTopics(metas, codes)
    with patch.object(whitelist, "CONFIG", cfg), \
            patch("server.tools.mail_switch.system_mailboxes", return_value=BOXES), \
            patch.object(C, "_topic_exists", lambda t, n: True), \
            patch.object(authz_runtime, "enforcing", lambda: enforce), \
            patch.object(egress, "source_schemes", lambda: ("mailfrom", "inbox", "https")), \
            patch("server.main._topics", lambda: fake):
        return sorted((r["name"], r["address"], r.get("tag") or "")
                      for r in C.rooms(indexed))


class EmailAuthorisedTests(unittest.TestCase):
    """`room_tools.email_authorised`, on the real connector registry."""

    def test_the_stored_email_mcp_authorises(self):
        self.assertTrue(room_tools.email_authorised(EMAIL_MCP))
        self.assertTrue(room_tools.email_authorised(EMAIL_MCP_ROWS))

    def test_a_legacy_per_verb_entry_still_authorises(self):
        self.assertTrue(room_tools.email_authorised(LEGACY_VERB))
        self.assertTrue(room_tools.email_authorised({"tools": {"enabled": ["email.send"]}}))

    def test_nothing_or_another_mcp_does_not(self):
        for meta in (NOTHING, OTHER_MCP, {"tools": "garbage"}, {"tools": {"mcp": []}},
                     {"tools": {"enabled": ["emails.x", "web.*"]}}):
            self.assertFalse(room_tools.email_authorised(meta), meta)

    def test_not_derived_from_the_toolbox(self):
        # The old test: the toolbox of a room with the Email MCP has no
        # `email.*` since #683. If it ever has again, both agree.
        self.assertTrue(room_tools.email_authorised(EMAIL_MCP))
        self.assertNotIn("email.*", room_tools.toolbox(EMAIL_MCP)["enabled"])

    def test_the_canonical_id_is_the_mail_connectors_mcp(self):
        ids = room_tools.email_mcp_ids()
        self.assertIn("email", ids)
        owners = {mid for mid, g in room_tools._groups().items()
                  if room_tools.MAIL_CONNECTOR in g["connectors"]}
        self.assertTrue(owners, "the builtin mail connector is in the registry")
        self.assertLessEqual(owners, ids)

    def test_a_registry_that_fails_keeps_the_stored_key(self):
        with patch.object(room_tools, "_groups", side_effect=RuntimeError("x")):
            self.assertEqual(room_tools.email_mcp_ids(), frozenset({"email"}))
            self.assertTrue(room_tools.email_authorised(EMAIL_MCP))


class CourierRowsUnderEnforceTests(unittest.TestCase):
    ROOM = ("SEAL-2", "acme")
    LISTS = {"SEAL-2/acme": ["mailfrom:*@brightnode.io", "inbox:studio@x.it"]}

    def test_a_room_with_email_gets_its_linked_mailbox_rows(self):
        got = _rooms({self.ROOM: EMAIL_MCP}, self.LISTS)
        self.assertEqual(got, [("acme", "studio@x.it", "")])

    def test_a_room_with_email_gets_the_global_mailbox_rows(self):
        got = _rooms({self.ROOM: EMAIL_MCP}, {"SEAL-2/acme": ["mailfrom:*@brightnode.io"]},
                     ["inbox:studio@x.it"])
        self.assertEqual(got, [("acme", "studio@x.it", "")])

    def test_the_legacy_entry_is_accepted(self):
        got = _rooms({self.ROOM: LEGACY_VERB}, self.LISTS)
        self.assertEqual(got, [("acme", "studio@x.it", "")])

    def test_a_room_without_email_gets_none(self):
        for meta in (NOTHING, OTHER_MCP):
            self.assertEqual(_rooms({self.ROOM: meta}, self.LISTS), [], meta)
            self.assertEqual(_rooms({self.ROOM: meta},
                                    {"SEAL-2/acme": ["mailfrom:*@brightnode.io"]},
                                    ["inbox:studio@x.it"]), [], meta)

    def test_an_unreadable_room_gets_none(self):
        self.assertEqual(_rooms({}, self.LISTS), [])

    def test_without_enforce_unchanged(self):
        self.assertEqual(_rooms({self.ROOM: NOTHING}, self.LISTS, enforce=False),
                         [("acme", "studio@x.it", "")])

    def test_tagged_rows_unchanged(self):
        # The room's own address delivers whether or not Email is authorised.
        lists = {"SEAL-2/acme": ["mailfrom:a@b.it"], "SEAL-2/other": ["mailfrom:c@d.it"]}
        metas = {self.ROOM: EMAIL_MCP, ("SEAL-2", "other"): NOTHING}
        codes = {"AAA": ("SEAL-2", "acme"), "BBB": ("SEAL-2", "other")}
        got = _rooms(metas, lists, codes=codes)
        self.assertEqual(got, [("acme", "devnullboxx@gmail.com", "AAA"),
                               ("other", "devnullboxx@gmail.com", "BBB")])

    def test_mixed_rooms(self):
        lists = {"SEAL-2/acme": ["mailfrom:a@b.it", "inbox:studio@x.it"],
                 "SEAL-1/plain": ["mailfrom:c@d.it", "inbox:studio@x.it"]}
        metas = {self.ROOM: EMAIL_MCP, ("SEAL-1", "plain"): NOTHING}
        self.assertEqual(_rooms(metas, lists), [("acme", "studio@x.it", "")])


if __name__ == "__main__":
    unittest.main()

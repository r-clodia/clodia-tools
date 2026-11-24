"""clodia-platform#734 — a room connects mailboxes like MCPs.

`meta.tools.mcp["mailbox:<account>"]`: the courier reads that mailbox for the
room's senders, and the room may send with it. The colony mailbox is not
offered (the room's own address on it is always on). The rooms' old
`inbox:`/`outbox:` entries become connections once, then go away.
"""
from __future__ import annotations

from unittest.mock import patch

from . import egress, main, room_mailboxes as RM, room_tools as RT, whitelist
from .test_620_room_mcp import CAT, _Env

BOXES = [
    {"account": "studio", "email": "studio@x.it", "send_only": False},
    {"account": "info", "email": "info@x.it", "send_only": False},
    {"account": "alias", "email": "alias@x.it", "send_only": True},
    {"account": "devnullboxx", "email": "box@gmail.com", "send_only": False},
]


class _Rooms(_Env):
    def setUp(self):
        super().setUp()
        whitelist.CONFIG["colony_mailbox"] = "devnullboxx"
        for p in (patch("server.tools.mail_switch.system_mailboxes", return_value=BOXES),
                  patch.object(RT, "mcp_catalogue", lambda: {**CAT, **RT._mailbox_entries()}),
                  patch("server.mail_courier_api.colony_mailbox",
                        return_value=("devnullboxx", "box@gmail.com"))):
            p.start(); self.addCleanup(p.stop)
        self.svc.new("SEAL-1", "other", {"owner": "davide", "participants": ["clodia"]})


class Catalogue(_Rooms):
    def test_every_mailbox_but_the_colony_one_can_be_connected(self):
        e = RT._mailbox_entries()
        self.assertEqual(sorted(e), ["mailbox:alias", "mailbox:info", "mailbox:studio"])
        s = e["mailbox:studio"]
        self.assertEqual((s["label"], s["kind"], s["agent_verbs"]), ("studio@x.it", "mailbox", False))
        self.assertTrue(e["mailbox:alias"]["send_only"])

    def test_connecting_authorises_mail_in_the_room_and_gives_no_verb(self):
        RT.enable_mcp("SEAL-1", "blog", "mailbox:studio")
        meta = self.meta()
        self.assertTrue(RT.email_authorised(meta))
        self.assertEqual(RM.connected_accounts(meta), ["studio"])
        self.assertFalse(any(v.startswith("email.") for v in RT.toolbox(meta)["enabled"]))


class Decisions(_Rooms):
    def test_the_room_reads_and_sends_only_what_it_connects(self):
        RT.enable_mcp("SEAL-1", "blog", "mailbox:studio")
        RT.enable_mcp("SEAL-1", "blog", "mailbox:alias")
        self.assertTrue(RM.scope_allows("inbox", "studio@x.it", "SEAL-1/blog"))
        self.assertTrue(RM.scope_allows("outbox", "Studio@x.it", "SEAL-1/blog"))
        self.assertFalse(RM.scope_allows("inbox", "info@x.it", "SEAL-1/blog"))
        self.assertFalse(RM.scope_allows("inbox", "studio@x.it", "SEAL-1/other"))
        # A send-only mailbox is never read.
        self.assertFalse(RM.scope_allows("inbox", "alias@x.it", "SEAL-1/blog"))
        self.assertTrue(RM.scope_allows("outbox", "alias@x.it", "SEAL-1/blog"))

    def test_the_gateway_check_counts_the_connection(self):
        RT.enable_mcp("SEAL-1", "blog", "mailbox:info")
        self.assertTrue(egress.mailbox_allowed("inbox", "info@x.it", "SEAL-1/blog"))
        self.assertFalse(egress.mailbox_allowed("inbox", "info@x.it", "SEAL-1/other"))

    def test_an_archived_room_is_not_read(self):
        RT.enable_mcp("SEAL-1", "other", "mailbox:info")
        meta, ver = self.svc._read_meta("SEAL-1", "other")
        meta["status"] = "archived"
        self.svc._write_meta("SEAL-1", "other", meta, base_version=ver)
        self.assertEqual(RM.reading_rooms(), [])

    def test_a_mailbox_switched_off_is_not_used(self):
        RT.enable_mcp("SEAL-1", "blog", "mailbox:info")
        with patch("server.tools.mail_switch.system_mailboxes",
                   return_value=[b for b in BOXES if b["account"] != "info"]):
            self.assertFalse(RM.scope_allows("inbox", "info@x.it", "SEAL-1/blog"))
            self.assertEqual(RM.reading_rooms(), [])

    def test_the_courier_reads_the_connected_receiving_mailboxes(self):
        RT.enable_mcp("SEAL-1", "blog", "mailbox:studio")
        RT.enable_mcp("SEAL-1", "blog", "mailbox:alias")
        RT.enable_mcp("SEAL-1", "other", "mailbox:info")
        self.assertEqual(sorted(RM.reading_rooms()), [
            ("SEAL-1", "blog", "studio", "studio@x.it"),
            ("SEAL-1", "other", "info", "info@x.it")])

    def test_the_room_sends_with_its_one_connected_mailbox(self):
        RT.enable_mcp("SEAL-1", "blog", "mailbox:studio")
        self.assertEqual(main._room_outbox_account("SEAL-1", "blog"), "studio")
        RT.enable_mcp("SEAL-1", "blog", "mailbox:info")
        with self.assertRaisesRegex(ValueError, "più caselle"):
            main._room_outbox_account("SEAL-1", "blog")
        with self.assertRaisesRegex(ValueError, "collegata"):
            main._room_outbox_account("SEAL-1", "other")

    def test_removing_a_mailbox_disconnects_it_everywhere(self):
        RT.enable_mcp("SEAL-1", "blog", "mailbox:studio")
        RT.enable_mcp("SEAL-1", "other", "mailbox:studio")
        RT.enable_mcp("SEAL-1", "other", "mailbox:info")
        self.assertEqual(RM.forget("studio"), ["SEAL-1/blog", "SEAL-1/other"])
        self.assertEqual(RM.connected_accounts(self.meta()), [])
        self.assertEqual(RM.connected_accounts(self.svc._read_meta("SEAL-1", "other")[0]),
                         ["info"])


class Migration(_Rooms):
    def setUp(self):
        super().setUp()
        whitelist.CONFIG["scope_source_allow"] = {
            "SEAL-1/blog": ["mailfrom:*@acme.it", "inbox:studio@x.it"],
            "SEAL-1/other": ["inbox:info@x.it", "inbox:gone@x.it"],
            "SEAL-1/deleted": ["inbox:studio@x.it", "inbox:info@x.it"],
        }
        whitelist.CONFIG["scope_egress_allow"] = {
            "SEAL-1/blog": ["outbox:studio@x.it", "mailto:a@b.it"],
            "SEAL-1/deleted": ["outbox:info@x.it"],
        }
        whitelist.CONFIG["source_allow"] = ["inbox:box@gmail.com"]

    def test_an_archived_room_only_loses_its_entries(self):
        with patch("server.mail_courier_api._topic_exists",
                   lambda t, n: (t, n) != ("SEAL-1", "other")):
            out = RM.migrate()
        self.assertNotIn("SEAL-1/other", out["connected"])
        self.assertIn("SEAL-1/other", out["dropped_rooms"])
        self.assertEqual(RM.connected_accounts(self.svc._read_meta("SEAL-1", "other")[0]), [])

    def test_the_plan_writes_nothing(self):
        p = RM.plan()["rooms"]
        self.assertEqual(p["SEAL-1/blog"]["accounts"], ["studio"])
        self.assertEqual(p["SEAL-1/other"]["unknown"], ["inbox:gone@x.it"])
        self.assertFalse(p["SEAL-1/deleted"]["exists"])
        self.assertEqual(RM.connected_accounts(self.meta()), [])
        self.assertNotIn(RM.MIGRATED_KEY, whitelist.CONFIG)

    def test_entries_become_connections_once(self):
        out = RM.migrate()
        self.assertTrue(out["done"])
        self.assertEqual(out["connected"], {"SEAL-1/blog": ["studio"], "SEAL-1/other": ["info"]})
        self.assertEqual(out["dropped_rooms"], ["SEAL-1/deleted"])
        self.assertEqual(out["kept_unknown"], {"SEAL-1/other": ["inbox:gone@x.it"]})
        self.assertEqual(RM.connected_accounts(self.meta()), ["studio"])
        # Senders and recipients stay: they are not mailboxes.
        self.assertEqual(egress.scope_uris("ingress", "SEAL-1/blog"), ["mailfrom:*@acme.it"])
        self.assertEqual(egress.scope_uris("egress", "SEAL-1/blog"), ["mailto:a@b.it"])
        self.assertEqual(egress.scope_uris("ingress", "SEAL-1/other"), ["inbox:gone@x.it"])
        self.assertEqual(egress.scope_uris("ingress", "SEAL-1/deleted"), [])
        self.assertEqual(egress.scope_uris("egress", "SEAL-1/deleted"), [])
        # The colony mailbox's global entry is the room inbox: untouched.
        self.assertEqual(whitelist.CONFIG["source_allow"], ["inbox:box@gmail.com"])
        self.assertIn(RM.MIGRATED_KEY, whitelist.CONFIG)
        self.assertEqual(RM.migrate(), {"done": False, "reason": "already migrated"})

    def test_behaviour_is_unchanged_for_the_room(self):
        before = (egress.mailbox_allowed("inbox", "studio@x.it", "SEAL-1/blog"),
                  egress.mailbox_allowed("outbox", "studio@x.it", "SEAL-1/blog"),
                  egress.mailbox_allowed("inbox", "info@x.it", "SEAL-1/blog"))
        RM.migrate()
        after = (egress.mailbox_allowed("inbox", "studio@x.it", "SEAL-1/blog"),
                 egress.mailbox_allowed("outbox", "studio@x.it", "SEAL-1/blog"),
                 egress.mailbox_allowed("inbox", "info@x.it", "SEAL-1/blog"))
        self.assertEqual(before, (True, True, False))
        self.assertEqual(after, before)

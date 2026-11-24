"""clodia-platform#733 — one integration per mailbox.

Each `mailbox_<account>` is its own integration: listed with its own status,
tested on its own, switched on and off from Tools while its credential
stays. A mailbox switched off is not a system mailbox (no room reads it, no
delivery sends with it) and the client refuses to run on it.
"""
from __future__ import annotations

from unittest.mock import patch

from . import verbs
from ._test_harness import OnFakeGateway


class InstanceTests(OnFakeGateway):
    def setUp(self) -> None:
        super().setUp()
        self.svc("mailbox_add", {"account": "info", "email": "info@x.it",
                                 "password": "p", "smtp_server": "smtp.x.it",
                                 "imap_server": "imap.x.it"})

    def test_each_mailbox_has_its_own_status_and_switch(self) -> None:
        rows = {r["account"]: r for r in self.svc("mailboxes_list")["statuses"]}
        self.assertEqual(set(rows), {"info", "studio"})
        self.assertTrue(all(r["enabled"] for r in rows.values()))
        self.assertEqual(rows["info"]["email"], "info@x.it")
        self.assertNotIn("password", str(rows))

    def test_switched_off_it_is_no_system_mailbox_and_back_on_it_is(self) -> None:
        out = self.svc("mailbox_set_enabled", "info", False)
        self.assertEqual(out, {"status": 200, "body": {"account": "info", "enabled": False}})
        self.assertEqual([m["account"] for m in self.mail.system_mailboxes()], ["studio"])
        rows = {r["account"]: r for r in self.svc("mailboxes_list")["statuses"]}
        self.assertFalse(rows["info"]["enabled"])
        self.assertIn("mailbox_info", self.host.vault)    # the credential stays
        self.svc("mailbox_set_enabled", "info", True)
        self.assertEqual([m["account"] for m in self.mail.system_mailboxes()],
                         ["info", "studio"])

    def test_the_other_mailboxes_are_untouched(self) -> None:
        self.svc("mailbox_set_enabled", "info", False)
        self.assertEqual(self.svc("mailbox_set_enabled", "nessuna", False)["status"], 404)
        self.assertEqual([m["account"] for m in self.mail.system_mailboxes()], ["studio"])

    def test_a_switched_off_mailbox_does_not_send(self) -> None:
        self.svc("mailbox_set_enabled", "studio", False)
        with patch.object(self.mail.subprocess, "run") as run, \
                self.assertRaisesRegex(PermissionError, "spenta"):
            verbs.send({"account": "studio", "to": "a@b.it", "subject": "s", "body": "t"})
        run.assert_not_called()

    def test_one_mailbox_is_tested_alone(self) -> None:
        import imaplib
        logins = []

        class _Imap:
            def __init__(self, server, *a, **k):
                self.server = server

            def login(self, user, pwd):
                logins.append(user)

            def logout(self):
                pass
        with patch.object(imaplib, "IMAP4_SSL", _Imap):
            out = self.svc("test_mailboxes", "info")
        self.assertEqual(logins, ["info@x.it"])
        self.assertEqual(out, {"ok": True, "detail": "info: ok"})
        with patch.object(imaplib, "IMAP4_SSL", _Imap):
            self.assertEqual(self.svc("test_mailboxes", "nessuna")["ok"], None)

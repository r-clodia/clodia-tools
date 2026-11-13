"""#676 — a connector declares the kinds of source a room can listen to.

Owner, 12 Nov 2026: «l'utente semplicemente mette il canale in ascolto di
messaggi su determinati mittenti». Listening = trusted.
"""
from __future__ import annotations

import copy
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from . import manifest as M
from .test_manifest import _examples

SENDER = {"kind": "sender", "label": "Mittente email",
          "field": {"name": "sender", "placeholder": "nome@dominio.it"},
          "ingress": "mailfrom:{sender}", "egress": "mailto:{sender}", "reply": "choice"}
CHAT = {"kind": "chat", "label": "Chat Telegram", "action": "telegram-link"}


def _conn(cid, listen):
    entry = copy.deepcopy(next(c for c in _examples()["comms-pack"]["connectors"]
                               if c["id"] == cid))
    entry["listen"] = listen
    return M.parse_connector(entry, pack="comms-pack")


class GrammarTests(unittest.TestCase):
    def test_a_pack_scheme_without_forms_is_accepted(self):
        """comms-pack's `mailfrom`/`mailto` declare no forms; listening to a
        sender must not get the whole pack refused."""
        entry = copy.deepcopy(next(c for c in _examples()["comms-pack"]["connectors"]
                                   if c["id"] == "mail"))
        for sch in entry["schemes"]:
            if sch["scheme"] in ("mailfrom", "mailto"):
                sch.pop("forms", None)
        entry["listen"] = [SENDER]
        self.assertEqual(M.parse_connector(entry, pack="comms-pack").listen[0].kind, "sender")

    def test_a_template_kind(self):
        (k,) = _conn("mail", [SENDER]).listen
        self.assertEqual((k.kind, k.ingress, k.egress, k.reply, k.field.name),
                         ("sender", "mailfrom:{sender}", "mailto:{sender}", "choice", "sender"))

    def test_an_action_kind_replies_implicitly(self):
        (k,) = _conn("telegram", [CHAT]).listen
        self.assertEqual((k.action, k.reply), ("telegram-link", "implicit"))

    def test_an_action_without_a_channel_binding_is_refused(self):
        with self.assertRaises(M.ManifestError):
            _conn("mail", [{"kind": "box", "label": "x", "action": "mailbox-link"}])

    def test_a_foreign_scheme_is_refused(self):
        bad = dict(SENDER, ingress="https://{sender}")
        with self.assertRaises(M.ManifestError):
            _conn("mail", [bad])

    def test_the_address_must_be_the_tail(self):
        with self.assertRaises(M.ManifestError):
            _conn("mail", [dict(SENDER, ingress="mailfrom:{sender}x")])

    def test_reply_needs_an_egress(self):
        with self.assertRaises(M.ManifestError):
            _conn("mail", [dict(SENDER, egress="")])

    def test_unknown_keys_and_duplicates_are_refused(self):
        with self.assertRaises(M.ManifestError):
            _conn("mail", [dict(SENDER, trust=False)])
        with self.assertRaises(M.ManifestError):
            _conn("mail", [SENDER, SENDER])


class RoomListenTests(unittest.TestCase):
    """The room's list is derived from its lists and bindings."""

    def setUp(self):
        from .. import room_listen as R
        self.R = R
        self.mail = _conn("mail", [SENDER])
        self.tg = _conn("telegram", [CHAT])
        self.lists = {"ingress": ["mailfrom:a@b.it", "mailfrom:*@c.it", "https:*"],
                      "egress": ["mailto:a@b.it"]}
        self.calls = []
        ps = [
            patch.object(R, "_connectors", lambda: iter([self.mail, self.tg])),
            patch("server.egress.scope_uris", lambda d, s, cfg=None: list(self.lists[d])),
            patch("server.egress.scope_allow",
                  lambda d, s, u: self.calls.append(("allow", d, u)) or {"uri": u}),
            patch("server.egress.scope_revoke",
                  lambda d, s, u: self.calls.append(("revoke", d, u)) or {"uri": u}),
            patch("server.connectors.actions._bound_chat",
                  lambda cid, t, n: "-100123" if cid == "telegram" else None),
            patch.object(R, "_inbox", lambda t, n: None),
        ]
        for p in ps:
            p.start(); self.addCleanup(p.stop)

    def test_sources_are_derived(self):
        got = sorted((s["kind"], s["address"], s["reply"])
                     for s in self.R.sources("SEAL-1", "acme"))
        self.assertEqual(got, [("chat", "-100123", True), ("sender", "*@c.it", False),
                               ("sender", "a@b.it", True)])

    def test_the_room_inbox_is_source_number_one(self):
        inbox = {"connector": "mail", "kind": "inbox", "label": "Inbox del canale",
                 "address": "box+ABCDE@x.it", "reply": False, "action": "",
                 "fixed": True, "active": True}
        with patch.object(self.R, "_inbox", lambda t, n: inbox):
            got = self.R.sources("SEAL-1", "acme")
        self.assertEqual(got[0], inbox)
        self.assertEqual(len(got), 4)

    def test_add_without_reply_writes_only_the_trusted_source(self):
        self.R.add("SEAL-1", "acme", "mail", "sender", "x@y.it")
        self.assertEqual(self.calls, [("allow", "ingress", "mailfrom:x@y.it")])

    def test_add_with_reply_writes_the_recipient_too(self):
        self.R.add("SEAL-1", "acme", "mail", "sender", "mailfrom:x@y.it", reply=True)
        self.assertEqual(self.calls, [("allow", "ingress", "mailfrom:x@y.it"),
                                      ("allow", "egress", "mailto:x@y.it")])

    def test_remove_takes_both(self):
        self.R.remove("SEAL-1", "acme", "mail", "sender", "a@b.it")
        self.assertEqual(self.calls, [("revoke", "ingress", "mailfrom:a@b.it"),
                                      ("revoke", "egress", "mailto:a@b.it")])

    def test_an_action_kind_is_not_written_here(self):
        with self.assertRaises(self.R.ListenError):
            self.R.add("SEAL-1", "acme", "telegram", "chat", "-1")

    def test_kinds_for_the_dialog(self):
        ks = {(k["connector"], k["kind"], k["reply"]) for k in self.R.kinds()}
        self.assertEqual(ks, {("mail", "sender", "choice"), ("telegram", "chat", "implicit")})


class InboxTests(unittest.TestCase):
    """The room's own address, read from its message-box code."""

    def _inbox(self, codes, addr_of):
        from .. import room_listen as R
        fake = SimpleNamespace(mailbox_codes=lambda: codes)
        with patch("server.main._topics", lambda: fake), \
                patch("server.mail_courier_api.message_box_address", addr_of):
            return R._inbox("SEAL-1", "acme")

    def test_the_address_of_the_room_code(self):
        got = self._inbox({"ABCDE": ("SEAL-1", "acme"), "ZZZZZ": ("SEAL-1", "other")},
                          lambda c: f"box+{c}@x.it")
        self.assertEqual((got["address"], got["fixed"], got["active"]),
                         ("box+ABCDE@x.it", True, True))

    def test_without_the_colony_mailbox_the_code_is_shown_inactive(self):
        got = self._inbox({"ABCDE": ("SEAL-1", "acme")}, lambda c: "")
        self.assertEqual((got["address"], got["active"]), ("ABCDE", False))

    def test_a_room_without_a_code_lists_no_inbox(self):
        self.assertIsNone(self._inbox({"ZZZZZ": ("SEAL-1", "other")}, lambda c: "x"))


if __name__ == "__main__":
    unittest.main()


class SummaryOptionsTests(unittest.TestCase):
    """The registry tells the webui which field is a gateway option set: a
    mailbox action is recognised as such and kept out of Strumenti."""

    def test_an_option_set_field_carries_its_name(self):
        from . import validate as V
        entry = copy.deepcopy(next(c for c in _examples()["comms-pack"]["connectors"]
                                   if c["id"] == "mail"))
        entry["topic_actions"][0]["fields"] = [{"name": "account", "options": "mailboxes"}]
        row = V.summary(M.parse_connector(entry, pack="comms-pack"))
        self.assertEqual(row["topic_actions"][0]["fields"][0].get("options"), "mailboxes")

    def test_a_free_field_carries_none(self):
        from . import validate as V
        row = V.summary(_conn("telegram", [CHAT]))
        self.assertNotIn("options", row["topic_actions"][0]["fields"][0])

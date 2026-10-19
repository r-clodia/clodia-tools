"""#576 — the mail courier delivers into a room only the mail of the senders
that room ITSELF declares (`mailfrom:` among its own ingress entries).

The same mailbox feeds many rooms: global `mailfrom:` entries and the room's
participants must not count, or the same mail would reach all of them."""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from . import egress, mail_courier_api as C, whitelist
from .components.host import Perimeter

ROOM = "SEAL-2/preventivi"


def _cfg(own=(), glob=(), strict=False):
    cfg = {"scope_source_allow": {ROOM: ["inbox:info@tomato.blue", *own]},
           "source_allow": list(glob)}
    if strict:
        cfg["scope_ingress_strict"] = {ROOM: True}
    return cfg


class RoomDeclaresSenderTests(unittest.TestCase):
    def _ask(self, cfg, sender, scope=ROOM):
        with patch.object(whitelist, "CONFIG", cfg), \
                patch.object(egress, "perimeter_addresses", lambda s=None: {"davide@x.it"}):
            return egress.room_declares_sender(sender, scope)

    def test_no_declared_sender_delivers_nothing(self):
        self.assertFalse(self._ask(_cfg(), "mario@foo.bar"))

    def test_the_rooms_own_entry_passes(self):
        cfg = _cfg(own=["mailfrom:mario@foo.bar"])
        self.assertTrue(self._ask(cfg, "Mario Rossi <Mario@Foo.bar>"))
        self.assertFalse(self._ask(cfg, "luigi@foo.bar"))

    def test_a_global_entry_does_not_count(self):
        self.assertFalse(self._ask(_cfg(glob=["mailfrom:mario@foo.bar"]), "mario@foo.bar"))

    def test_a_participant_does_not_count(self):
        self.assertFalse(self._ask(_cfg(), "davide@x.it"))

    def test_another_rooms_entry_does_not_count(self):
        cfg = _cfg()
        cfg["scope_source_allow"]["SEAL-1/altro"] = ["mailfrom:mario@foo.bar"]
        self.assertFalse(self._ask(cfg, "mario@foo.bar"))

    def test_strict_or_not_the_rule_is_the_same(self):
        for strict in (False, True):
            with self.subTest(strict=strict):
                cfg = _cfg(own=["mailfrom:mario@foo.bar"], strict=strict)
                self.assertTrue(self._ask(cfg, "mario@foo.bar"))
                self.assertFalse(self._ask(cfg, "luigi@foo.bar"))

    def test_outside_a_room_nothing(self):
        self.assertFalse(self._ask(_cfg(own=["mailfrom:mario@foo.bar"]), "mario@foo.bar",
                                   scope=None))

    def test_no_parsable_address_never_falls_back_to_the_raw_text(self):
        """Review of #411 (B1): an unparsable header compared as raw text
        matched `mailfrom:*@declared.it`."""
        cfg = _cfg(own=["mailfrom:*@declared.it"])
        for header in ("evil@x.it <@declared.it", "", "nessuno", "<>"):
            with self.subTest(header=header):
                self.assertFalse(self._ask(cfg, header))

    def test_an_encoded_display_name_is_not_an_address(self):
        """B2: the header as SENT — its encoded display name decodes into a
        declared address, the real address is the attacker's."""
        cfg = _cfg(own=["mailfrom:ok@declared.it"])
        self.assertFalse(self._ask(cfg, "=?utf-8?b?PG9rQGRlY2xhcmVkLml0Piw=?= <evil@x.it>"))
        self.assertTrue(self._ask(cfg, "=?utf-8?b?T2s=?= <ok@declared.it>"))

    def test_two_addresses_are_refused(self):
        cfg = _cfg(own=["mailfrom:ok@declared.it"])
        self.assertFalse(self._ask(cfg, "<ok@declared.it>, <evil@x.it>"))
        self.assertFalse(self._ask(cfg, "ok@declared.it, evil@x.it"))

    def test_a_wildcard_entry_works_like_elsewhere(self):
        cfg = _cfg(own=["mailfrom:*@foo.bar"])
        self.assertTrue(self._ask(cfg, "anyone@foo.bar"))
        self.assertFalse(self._ask(cfg, "anyone@foo.bar.evil"))


class HostApiTests(unittest.TestCase):
    def test_the_room_is_the_calls(self):
        with patch.object(whitelist, "CONFIG", _cfg(own=["mailfrom:mario@foo.bar"])), \
                patch.object(egress, "_scope_of_call", lambda: ROOM):
            self.assertTrue(Perimeter().room_declares_sender("mario@foo.bar"))
        with patch.object(whitelist, "CONFIG", _cfg(own=["mailfrom:mario@foo.bar"])), \
                patch.object(egress, "_scope_of_call", lambda: None):
            self.assertFalse(Perimeter().room_declares_sender("mario@foo.bar"))


class RoutesTests(unittest.TestCase):
    def test_rooms_count_their_senders(self):
        boxes = [{"account": "info", "email": "info@tomato.blue", "send_only": False}]
        with patch.object(whitelist, "CONFIG", _cfg(own=["mailfrom:a@b.it", "mailfrom:c@d.it",
                                                          "https://x.it/"])), \
                patch("server.tools.mail_switch.system_mailboxes", return_value=boxes), \
                patch.object(C, "_topic_exists", lambda t, n: True):
            out = C.rooms()
        self.assertEqual(out[0]["senders"], 2)
        with patch.object(whitelist, "CONFIG", _cfg(own=["mailfrom:a@b.it"])), \
                patch("server.tools.mail_switch.system_mailboxes", return_value=boxes), \
                patch.object(C, "_topic_exists", lambda t, n: True):
            altra = C.rooms()
        self.assertNotEqual(out[0]["senders_sig"], altra[0]["senders_sig"])

    def test_the_eml_route_runs_the_component_in_the_room(self):
        seen = {}

        def call(service, args):
            seen["service"], seen["args"] = service, args
            seen["scope"] = egress._scope_of_call()
            return {"size": 1, "content_b64": "eA=="}

        class _Req:
            headers, method = {}, "POST"

            async def json(self):
                return {"tier": "SEAL-2", "name": "preventivi", "account": "info",
                        "email_id": "7", "path": "../x"}
        with patch.object(C, "_authorize", lambda r: ({"agent": "clodia"}, None)), \
                patch.object(C, "_topic_exists", lambda t, n: True), \
                patch.object(C, "rooms", lambda: [{"tier": "SEAL-2", "name": "preventivi",
                                                   "account": "info"}]), \
                patch.object(whitelist, "CONFIG", {"agents": {"clodia": {}}}), \
                patch("server.tools.mail_switch.call", call):
            r = asyncio.run(C.eml_route(_Req()))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(seen["service"], "courier_eml")
        self.assertEqual(seen["args"], {"account": "info", "email_id": "7"})
        self.assertEqual(seen["scope"], ROOM)


if __name__ == "__main__":
    unittest.main()

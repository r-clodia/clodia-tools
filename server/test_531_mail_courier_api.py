"""#531 — the mail courier's internal routes: which rooms have a mailbox, and
each component call made inside that room's claims."""
from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import patch

from . import egress, mail_courier_api as C, whitelist


class _Req:
    def __init__(self, body=None):
        self._body = body or {}
        self.headers, self.method = {}, "POST"

    async def json(self):
        return self._body


BOXES = [{"account": "info", "email": "Info@Tomato.blue", "send_only": False},
         {"account": "alias", "email": "team@x.it", "send_only": True}]


class RoomsTests(unittest.TestCase):
    def _rooms(self, cfg, topics=("SEAL-2/preventivi", "SEAL-1/altro")):
        with patch.object(whitelist, "CONFIG", cfg), \
                patch("server.tools.mail_switch.system_mailboxes", return_value=BOXES), \
                patch.object(C, "_topic_exists", lambda t, n: f"{t}/{n}" in topics):
            return C.rooms()

    def test_a_room_with_its_own_inbox_entry(self):
        out = self._rooms({"scope_source_allow": {
            "SEAL-2/preventivi": ["inbox:info@tomato.blue", "mailfrom:a@b.it"]}})
        sig = out[0].pop("senders_sig") if out else ""
        self.assertEqual(len(sig), 16)
        self.assertEqual(out, [{"tier": "SEAL-2", "name": "preventivi", "account": "info",
                                "address": "info@tomato.blue", "strict": False,
                                "senders": 1}])

    def test_global_entries_send_only_boxes_and_missing_topics_are_not_rooms(self):
        out = self._rooms({"source_allow": ["inbox:info@tomato.blue"],
                           "scope_source_allow": {
                               "SEAL-1/altro": ["inbox:team@x.it"],
                               "SEAL-1/sparito": ["inbox:info@tomato.blue"]}})
        self.assertEqual(out, [])


class InRoomTests(unittest.TestCase):
    def test_the_component_runs_in_the_rooms_claims(self):
        seen = {}

        def call(service, args):
            seen["service"], seen["args"] = service, args
            seen["scope"] = egress._scope_of_call()
            from .whitelist import current_spawn
            seen["spawn"] = current_spawn()
            return {"envelopes": []}
        with patch.object(C, "_authorize", lambda r: ({"agent": "clodia"}, None)), \
                patch.object(C, "_topic_exists", lambda t, n: True), \
                patch.object(C, "rooms", lambda *a: [{"tier": "SEAL-2", "name": "preventivi",
                                                   "account": "info"}]), \
                patch.object(whitelist, "CONFIG", {"agents": {"clodia": {}}}), \
                patch("server.tools.mail_switch.call", call):
            r = asyncio.run(C.envelopes_route(_Req({
                "tier": "SEAL-2", "name": "preventivi", "account": "info",
                "skip": ["k1"], "keys_only": True, "body": "ignored"})))
        self.assertEqual(r.status_code, 200)
        self.assertEqual(seen["service"], "courier_envelopes")
        self.assertEqual(seen["args"], {"account": "info", "skip": ["k1"],
                                        "keys_only": True})
        self.assertEqual(seen["scope"], "SEAL-2/preventivi")
        self.assertEqual(seen["spawn"], "courier-SEAL-2-preventivi")

    def test_a_refusal_of_the_room_is_a_403(self):
        def call(service, args):
            raise PermissionError("la casella non è nella whitelist inbox")
        with patch.object(C, "_authorize", lambda r: ({"agent": "clodia"}, None)), \
                patch.object(C, "_topic_exists", lambda t, n: True), \
                patch.object(C, "rooms", lambda *a: [{"tier": "SEAL-2", "name": "x",
                                                   "account": "info"}]), \
                patch("server.tools.mail_switch.call", call):
            r = asyncio.run(C.attachment_route(_Req({
                "tier": "SEAL-2", "name": "x", "account": "info",
                "email_id": "1", "filename": "a.pdf"})))
        self.assertEqual(r.status_code, 403)

    def test_an_unknown_room_is_refused_before_the_component(self):
        with patch.object(C, "_authorize", lambda r: ({"agent": "clodia"}, None)), \
                patch.object(C, "_topic_exists", lambda t, n: False), \
                patch("server.tools.mail_switch.call",
                      lambda *a: self.fail("component called")):
            r = asyncio.run(C.envelopes_route(_Req({"tier": "SEAL-1", "name": "x",
                                                    "account": "info"})))
        self.assertEqual(r.status_code, 400)

    def test_a_mailbox_the_room_does_not_list_is_refused_before_the_component(self):
        with patch.object(C, "_authorize", lambda r: ({"agent": "clodia"}, None)), \
                patch.object(C, "_topic_exists", lambda t, n: True), \
                patch.object(C, "rooms", lambda *a: [{"tier": "SEAL-2", "name": "a",
                                                   "account": "info"}]), \
                patch("server.tools.mail_switch.call",
                      lambda *a: self.fail("component called")):
            r = asyncio.run(C.envelopes_route(_Req({"tier": "SEAL-2", "name": "b",
                                                    "account": "info"})))
        self.assertEqual(r.status_code, 403)

    def test_unauthorized_callers_are_refused(self):
        from starlette.responses import JSONResponse
        with patch.object(C, "_authorize",
                          lambda r: (None, JSONResponse({"error": "no"}, status_code=401))):
            r = asyncio.run(C.envelopes_route(_Req({})))
        self.assertEqual(r.status_code, 401)

    def test_the_routes_are_mounted(self):
        paths = {r.path for r in C.routes}
        self.assertEqual(paths, {"/internal/mail/courier/rooms",
                                 "/internal/mail/courier/envelopes",
                                 "/internal/mail/courier/attachment",
                                 "/internal/mail/courier/eml",
                                 "/internal/mail/courier/box"})


if __name__ == "__main__":
    unittest.main()

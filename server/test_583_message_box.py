"""#583 — every topic has a message box: a random code, used as the plus
sub-address of the colony mailbox (`box+CODE@…`), that routes a mail to its
channel when the sender is one the topic itself declares."""
from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import mail_courier_api as C, whitelist
from .components.host import Perimeter
from .topics.service import (MAILBOX_CODE_ALPHABET, MAILBOX_CODE_KEY, TopicService,
                             new_mailbox_code, normalize_mailbox_code)
from .topics.local_fs import LocalFsStorage

BOXES = [{"account": "devnullboxx", "email": "DevNullBoxx@gmail.com", "send_only": False},
         {"account": "studio", "email": "studio@x.it", "send_only": False},
         {"account": "alias", "email": "alias@x.it", "send_only": True}]


class CodeTests(unittest.TestCase):
    def setUp(self):
        self.svc = TopicService(LocalFsStorage(tempfile.mkdtemp(prefix="mbox-")))

    def test_a_new_topic_gets_a_well_formed_random_code(self):
        a = self.svc.new("SEAL-1", "alfa")
        b = self.svc.new("SEAL-2", "beta")
        for m in (a, b):
            code = m[MAILBOX_CODE_KEY]
            self.assertEqual(normalize_mailbox_code(code), code)
            self.assertTrue(all(c in MAILBOX_CODE_ALPHABET for c in code))
        self.assertNotEqual(a[MAILBOX_CODE_KEY], b[MAILBOX_CODE_KEY])

    def test_the_creator_cannot_choose_it(self):
        m = self.svc.new("SEAL-1", "gamma", {MAILBOX_CODE_KEY: "AAAAA"})
        self.assertNotEqual(m[MAILBOX_CODE_KEY], "AAAAA")

    def test_existing_topics_get_one_once(self):
        self.svc.new("SEAL-1", "vecchio")
        meta, ver = self.svc._read_meta("SEAL-1", "vecchio")
        meta.pop(MAILBOX_CODE_KEY)
        self.svc._write_meta("SEAL-1", "vecchio", meta, ver)
        self.assertEqual(self.svc.ensure_mailbox_codes(), 1)
        self.assertEqual(self.svc.ensure_mailbox_codes(), 0)
        code = self.svc._read_meta("SEAL-1", "vecchio")[0][MAILBOX_CODE_KEY]
        self.assertEqual(self.svc.by_mailbox_code(code.lower()), ("SEAL-1", "vecchio"))

    def test_a_shared_code_delivers_to_nobody_and_is_reassigned(self):
        a = self.svc.new("SEAL-1", "uno")
        self.svc.new("SEAL-3", "due")
        meta, ver = self.svc._read_meta("SEAL-3", "due")
        meta[MAILBOX_CODE_KEY] = a[MAILBOX_CODE_KEY]        # an imported copy
        self.svc._write_meta("SEAL-3", "due", meta, ver)
        self.assertIsNone(self.svc.by_mailbox_code(a[MAILBOX_CODE_KEY]))
        self.assertEqual(self.svc.ensure_mailbox_codes(), 2)
        c1 = self.svc._read_meta("SEAL-1", "uno")[0][MAILBOX_CODE_KEY]
        c2 = self.svc._read_meta("SEAL-3", "due")[0][MAILBOX_CODE_KEY]
        self.assertNotEqual(c1, c2)
        self.assertNotIn(a[MAILBOX_CODE_KEY], (c1, c2))
        self.assertEqual(self.svc.by_mailbox_code(c1), ("SEAL-1", "uno"))

    def test_a_taken_code_is_never_reused(self):
        taken = {c1 + c2 + c3 + c4 + c5 for c1 in "AB" for c2 in "AB" for c3 in "AB"
                 for c4 in "AB" for c5 in "AB"}
        self.assertNotIn(new_mailbox_code(taken), taken)

    def test_malformed_codes_are_not_codes(self):
        for c in ("", "AB", "ABCDEF", "O0O0O", "AB1IL"):
            self.assertEqual(normalize_mailbox_code(c), "")


class ColonyMailboxTests(unittest.TestCase):
    def _with(self, account):
        cfg = {C.COLONY_KEY: account} if account else {}
        return [patch.object(whitelist, "CONFIG", cfg),
                patch("server.tools.mail_switch.system_mailboxes", return_value=BOXES)]

    def _run(self, account, fn):
        ps = self._with(account)
        for p in ps:
            p.start()
        try:
            return fn()
        finally:
            for p in reversed(ps):
                p.stop()

    def test_unset_means_off(self):
        self.assertEqual(self._run(None, C.colony_mailbox), ("", ""))
        self.assertEqual(self._run(None, lambda: C.message_box_address("DJ56K")), "")

    def test_the_address_is_a_plus_sub_address(self):
        self.assertEqual(self._run("devnullboxx", lambda: C.message_box_address("DJ56K")),
                         "devnullboxx+DJ56K@gmail.com")

    def test_a_send_only_or_unknown_account_is_not_a_colony(self):
        self.assertEqual(self._run("alias", C.colony_mailbox), ("", ""))
        self.assertEqual(self._run("nessuna", C.colony_mailbox), ("", ""))


class ColonyRoomsTests(unittest.TestCase):
    def _rooms(self, own, codes):
        cfg = {C.COLONY_KEY: "devnullboxx",
               "scope_source_allow": {k: v for k, v in own.items()}}
        fake = type("T", (), {"mailbox_codes": lambda self: codes})()
        with patch.object(whitelist, "CONFIG", cfg), \
                patch("server.tools.mail_switch.system_mailboxes", return_value=BOXES), \
                patch.object(C, "_topic_exists", lambda t, n: True), \
                patch("server.components.loader.service",
                      lambda pack, name: object() if self.capable else None), \
                patch("server.main._topics", lambda: fake):
            return C.rooms()

    capable = True

    def test_an_older_comms_pack_gets_no_tagged_row(self):
        self.capable = False
        self.assertEqual(self._rooms({"SEAL-2/titulon": ["mailfrom:a@b.it"]},
                                     {"DJ56K": ("SEAL-2", "titulon")}), [])

    def test_a_topic_with_a_code_and_a_sender_is_reached_by_tag(self):
        out = self._rooms({"SEAL-2/titulon": ["mailfrom:*@brightnode.io"]},
                          {"DJ56K": ("SEAL-2", "titulon")})
        (row,) = out
        self.assertEqual((row["account"], row["tag"], row["senders"]),
                         ("devnullboxx", "DJ56K", 1))

    def test_no_declared_sender_no_row(self):
        self.assertEqual(self._rooms({}, {"DJ56K": ("SEAL-2", "titulon")}), [])

    def test_a_room_already_reading_the_colony_mailbox_gets_no_second_row(self):
        out = self._rooms({"SEAL-2/titulon": ["inbox:devnullboxx@gmail.com",
                                               "mailfrom:a@b.it"]},
                          {"DJ56K": ("SEAL-2", "titulon")})
        self.assertEqual([r.get("tag") for r in out], [None])


class TagIsPartOfThePairTests(unittest.TestCase):
    class _Req:
        headers, method = {}, "POST"

        def __init__(self, body):
            self._b = body

        async def json(self):
            return self._b

    def _call(self, body, offered):
        seen = {}

        def call(service, args):
            seen["tag"] = C.COURIER_TAG.get()
            return {"envelopes": []}
        with patch.object(C, "_authorize", lambda r: ({"agent": "clodia"}, None)), \
                patch.object(C, "_topic_exists", lambda t, n: True), \
                patch.object(C, "rooms", lambda *a: offered), \
                patch.object(whitelist, "CONFIG", {"agents": {"clodia": {}}}), \
                patch("server.tools.mail_switch.call", call):
            r = asyncio.run(C.envelopes_route(self._Req(body)))
        return r.status_code, seen.get("tag")

    def test_only_the_offered_tag_is_accepted_and_reaches_the_component(self):
        offered = [{"tier": "SEAL-2", "name": "t", "account": "devnullboxx", "tag": "DJ56K"}]
        self.assertEqual(self._call({"tier": "SEAL-2", "name": "t", "account": "devnullboxx",
                                     "tag": "DJ56K"}, offered), (200, "DJ56K"))
        self.assertEqual(self._call({"tier": "SEAL-2", "name": "t", "account": "devnullboxx",
                                     "tag": "ZZZZZ"}, offered)[0], 403)
        self.assertEqual(self._call({"tier": "SEAL-2", "name": "t", "account": "devnullboxx"},
                                    offered)[0], 403)

    def test_the_tag_does_not_outlive_the_call(self):
        offered = [{"tier": "SEAL-2", "name": "t", "account": "devnullboxx", "tag": "DJ56K"}]
        self._call({"tier": "SEAL-2", "name": "t", "account": "devnullboxx", "tag": "DJ56K"},
                   offered)
        self.assertEqual(C.COURIER_TAG.get(), "")


class PerimeterTests(unittest.TestCase):
    def test_the_colony_mailbox_only_inside_a_tagged_courier_call(self):
        with patch.object(C, "colony_mailbox", lambda: ("devnullboxx", "devnullboxx@gmail.com")), \
                patch("server.egress.mailbox_allowed", lambda *a, **k: False):
            per = Perimeter()
            self.assertFalse(per.mailbox_allowed("inbox", "devnullboxx@gmail.com"))
            tok = C.COURIER_TAG.set("DJ56K")
            try:
                self.assertTrue(per.mailbox_allowed("inbox", "DevNullBoxx@gmail.com"))
                self.assertFalse(per.mailbox_allowed("inbox", "studio@x.it"))
                self.assertFalse(per.mailbox_allowed("outbox", "devnullboxx@gmail.com"))
                self.assertEqual(per.courier_tag(), "DJ56K")
            finally:
                C.COURIER_TAG.reset(tok)
            self.assertEqual(per.courier_tag(), "")


class CourierRoleTests(unittest.TestCase):
    """Review of #416: only the agent-server (service role) is the courier."""

    def _auth(self, payload):
        with patch.object(C.internal_auth, "authorize", lambda r, log=None: (payload, None)):
            return C._authorize(object())

    def test_a_clodia_spawn_token_is_refused(self):
        p, err = self._auth({"agent": "clodia", "execution_id": "clodia-636"})
        self.assertIsNone(p)
        self.assertEqual(err.status_code, 403)

    def test_the_agent_server_passes(self):
        p, err = self._auth({"agent": "clodia", "role": "agent-server"})
        self.assertIsNone(err)
        self.assertEqual(p["role"], "agent-server")


if __name__ == "__main__":
    unittest.main()

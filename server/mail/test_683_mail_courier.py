"""The courier's reads in the gateway's mail code (clodia-platform#683).

Ported from comms-pack's component suites (clodia-logic
`test_558_mail_component.py` CourierTests, `test_585_586_comms_courier.py`):

- #531: envelopes and attachment bytes, never the body; the room's `inbox:`
  list applies;
- #576: only the senders the room ITSELF declares pass, checked again on what
  was read (a shifted IMAP id, a forged From); only the header as sent counts;
- #400 / review of #553: an `.eml` or attachment is checked on its own
  sender, recipients and key, not on the listing's;
- #583: a message-box call keeps only mail to `box+TAG@`; message-box mail is
  hidden from every other read of the colony mailbox (review of #416);
- #585: ONE search per cycle for every code, keys only, under the index tag
  and on the colony mailbox only; `only` restricts a per-room read;
- #586: whether the receiving server authenticated the sender (topmost
  trusted `Authentication-Results`, DMARC or aligned DKIM), fail closed.
"""
from __future__ import annotations

import base64
from unittest.mock import patch

from ._test_harness import OnFakeGateway


class _Courier(OnFakeGateway):
    LIST = [{"id": "1", "from": "Fornitore <ordini@f.it>",
             "from_raw": "Fornitore <ordini@f.it>", "to": "studio@example.it",
             "rcpt_raw": ["studio+DJ56K@example.it", "Studio <studio@example.it>"],
             "subject": "fattura", "date": "Sat, 18 Oct 2026 10:00:00 +0200",
             "message_id": "<m1@x>"},
            {"id": "2", "from": "spam@x.it", "from_raw": "spam@x.it",
             "to": "studio@example.it", "rcpt_raw": ["studio@example.it"],
             "subject": "offerta riservata", "date": "Sat, 18 Oct 2026 11:00:00 +0200",
             "message_id": "<m2@x>"}]

    def setUp(self) -> None:
        super().setUp()
        self.host.perimeter.room_senders = {"ordini@f.it", "spam@x.it"}

    def _fake(self, account, args, **kw):
        cmd = args[0]
        if cmd == "search":
            # The message-box search by recipient (#583): an IMAP server
            # answers with the rows addressed to the box.
            box = args[1].split('"')[1].lower()
            return [dict(r) for r in self.LIST
                    if any(box in x.lower() for x in r.get("rcpt_raw") or [])]
        if cmd == "list":
            return [dict(r) for r in self.LIST]
        if cmd == "read":
            row = next(r for r in self.LIST if r["id"] == args[1])
            return {**row, "body": "SEGRETO DEL CORPO", "attachments": ["a/b.pdf"]}
        if cmd == "get-attachment":
            row = next(r for r in self.LIST if r["id"] == args[1])
            return {"filename": "a/b.pdf", "content_type": "application/pdf",
                    "from_raw": row["from_raw"], "rcpt_raw": row["rcpt_raw"],
                    "data": base64.b64encode(b"%PDF-1").decode()}
        if cmd == "get-eml":
            row = next(r for r in self.LIST if r["id"] == args[1])
            return {"id": args[1], "message_id": row["message_id"], "size": 9,
                    "from_raw": row["from_raw"], "rcpt_raw": row["rcpt_raw"],
                    "data": base64.b64encode(b"RAW-EML-1").decode()}
        raise AssertionError(cmd)


class CourierTests(_Courier):
    def test_envelopes_carry_no_body(self) -> None:
        with patch.object(self.mail, "_run_json", side_effect=self._fake):
            out = self.svc("courier_envelopes", {"account": "studio"})
        self.assertEqual([e["id"] for e in out["envelopes"]], ["1", "2"])
        self.assertNotIn("SEGRETO DEL CORPO", repr(out))
        self.assertNotIn("body", out["envelopes"][0])
        self.assertEqual(out["envelopes"][0]["attachments"], ["a/b.pdf"])

    def test_keys_only_reads_no_message(self) -> None:
        reads = []

        def fake(account, args, **kw):
            if args[0] == "read":
                reads.append(args[1])
            return self._fake(account, args)
        with patch.object(self.mail, "_run_json", side_effect=fake):
            out = self.svc("courier_envelopes", {"account": "studio", "keys_only": True})
        self.assertEqual(reads, [])
        self.assertEqual(out["keys"], [self.mail.envelope_key(r) for r in self.LIST])
        self.assertNotIn("envelopes", out)

    def test_known_keys_are_not_read_again(self) -> None:
        reads = []

        def fake(account, args, **kw):
            if args[0] == "read":
                reads.append(args[1])
            return self._fake(account, args)
        key = self.mail.envelope_key(self.LIST[0])
        with patch.object(self.mail, "_run_json", side_effect=fake):
            out = self.svc("courier_envelopes", {"account": "studio", "skip": [key]})
        self.assertEqual([e["id"] for e in out["envelopes"]], ["2"])
        self.assertEqual(reads, ["2"])

    def test_a_room_gets_only_its_declared_senders(self) -> None:
        self.host.perimeter.room_senders = {"ordini@f.it"}
        with patch.object(self.mail, "_run_json", side_effect=self._fake):
            out = self.svc("courier_envelopes", {"account": "studio"})
        self.assertEqual([e["id"] for e in out["envelopes"]], ["1"])
        self.assertEqual(out["withheld"], 1)
        self.assertNotIn("offerta riservata", repr(out))

    def test_a_shifted_sequence_id_never_posts_another_message(self) -> None:
        """Between the listing and the read an expunge can make id 1 name
        another message: it is skipped, not posted under the listed key."""
        other = {"id": "1", "from": "Estraneo <x@y.it>", "subject": "altro",
                 "date": "ieri", "message_id": "<altro@y>", "body": "B",
                 "attachments": []}

        def fake(account, args, **kw):
            if args[0] == "read" and args[1] == "1":
                return dict(other)
            return self._fake(account, args)
        with patch.object(self.mail, "_run_json", side_effect=fake):
            out = self.svc("courier_envelopes", {"account": "studio"})
        self.assertEqual([e["id"] for e in out["envelopes"]], ["2"])
        self.assertNotIn("Estraneo", repr(out))

    def test_the_sender_read_is_checked_again(self) -> None:
        """The listed row was declared, but what was read carries another sender
        (same Message-ID, forged): withheld."""
        self.host.perimeter.room_senders = {"ordini@f.it"}

        def fake(account, args, **kw):
            if args[0] == "read" and args[1] == "1":
                return {**self.LIST[0], "from": "spam@x.it", "from_raw": "spam@x.it",
                        "body": "B", "attachments": []}
            return self._fake(account, args)
        with patch.object(self.mail, "_run_json", side_effect=fake):
            out = self.svc("courier_envelopes", {"account": "studio"})
        self.assertEqual(out["envelopes"], [])
        self.assertEqual(out["withheld"], 2)

    def test_a_mailbox_outside_the_rooms_inbox_list_is_refused(self) -> None:
        self.host.perimeter.inbox.clear()
        with self.assertRaises(PermissionError):
            self.svc("courier_envelopes", {"account": "studio"})

    def test_the_attachment_is_byte_identical_and_its_name_a_name(self) -> None:
        with patch.object(self.mail, "_run_json", side_effect=self._fake):
            out = self.svc("courier_attachment", {"account": "studio", "email_id": "1",
                                                  "filename": "a/b.pdf"})
        self.assertEqual(base64.b64decode(out["content_b64"]), b"%PDF-1")
        self.assertEqual(out["filename"], "a-b.pdf")
        self.assertEqual(out["size"], 6)

    def test_a_strangers_attachment_is_refused(self) -> None:
        self.host.perimeter.room_senders = {"ordini@f.it"}
        with patch.object(self.mail, "_run_json", side_effect=self._fake):
            with self.assertRaises(PermissionError):
                self.svc("courier_attachment", {"account": "studio", "email_id": "2",
                                                "filename": "a/b.pdf"})

    def test_an_eml_read_from_another_message_is_refused(self) -> None:
        """Review of #553 (B3): between the check and the download the same
        IMAP id can name another message — the bytes are checked."""
        self.host.perimeter.room_senders = {"ordini@f.it"}

        def fake(account, args, **kw):
            if args[0] in ("get-eml", "get-attachment"):
                out = self._fake(account, args)
                return {**out, "from_raw": "spam@x.it"}
            return self._fake(account, args)
        with patch.object(self.mail, "_run_json", side_effect=fake):
            with self.assertRaises(PermissionError):
                self.svc("courier_eml", {"account": "studio", "email_id": "1"})
            with self.assertRaises(PermissionError):
                self.svc("courier_attachment", {"account": "studio", "email_id": "1",
                                                "filename": "a/b.pdf"})

    def test_only_the_header_as_sent_counts(self) -> None:
        """B2: a client row without `from_raw` (decoded `from` only) is not
        delivered — the decoded header can be forged into a declared address."""
        rows = [{**r} for r in self.LIST]
        for r in rows:
            r.pop("from_raw")
        with patch.object(self.mail, "_run_json",
                          side_effect=lambda a, args, **k: [dict(r) for r in rows]
                          if args[0] in ("list", "search") else self._fake(a, args)):
            out = self.svc("courier_envelopes", {"account": "studio"})
        self.assertEqual(out["envelopes"], [])
        self.assertEqual(out["withheld"], 2)

    # ── #576 ───────────────────────────────────────────────────────────────
    def test_a_room_that_declares_nobody_gets_nothing(self) -> None:
        self.host.perimeter.room_senders = set()
        with patch.object(self.mail, "_run_json", side_effect=self._fake):
            out = self.svc("courier_envelopes", {"account": "studio"})
            keys = self.svc("courier_envelopes", {"account": "studio", "keys_only": True})
        self.assertEqual(out["envelopes"], [])
        self.assertEqual(out["withheld"], 2)
        self.assertEqual(keys["keys"], [])

    def test_the_eml_is_the_whole_message_of_a_declared_sender(self) -> None:
        with patch.object(self.mail, "_run_json", side_effect=self._fake):
            out = self.svc("courier_eml", {"account": "studio", "email_id": "1"})
        self.assertEqual(base64.b64decode(out["content_b64"]), b"RAW-EML-1")
        self.assertEqual(out["size"], 9)

    def test_a_strangers_eml_is_refused(self) -> None:
        self.host.perimeter.room_senders = {"ordini@f.it"}
        with patch.object(self.mail, "_run_json", side_effect=self._fake):
            with self.assertRaises(PermissionError):
                self.svc("courier_eml", {"account": "studio", "email_id": "2"})

    # ── #583: the message box ──────────────────────────────────────────────
    def test_outside_a_message_box_call_the_tag_changes_nothing(self) -> None:
        with patch.object(self.mail, "_run_json", side_effect=self._fake):
            out = self.svc("courier_envelopes", {"account": "studio"})
        self.assertEqual([e["id"] for e in out["envelopes"]], ["1", "2"])

    def test_a_message_box_call_keeps_only_mail_to_box_plus_tag(self) -> None:
        self.host.perimeter.tag = "DJ56K"
        with patch.object(self.mail, "_run_json", side_effect=self._fake):
            out = self.svc("courier_envelopes", {"account": "studio"})
            keys = self.svc("courier_envelopes", {"account": "studio", "keys_only": True})
        self.assertEqual([e["id"] for e in out["envelopes"]], ["1"])
        self.assertEqual(keys["keys"], [self.mail.envelope_key(self.LIST[0])])

    def test_another_tag_gets_nothing(self) -> None:
        self.host.perimeter.tag = "ZZZZZ"
        with patch.object(self.mail, "_run_json", side_effect=self._fake):
            out = self.svc("courier_envelopes", {"account": "studio"})
        self.assertEqual(out["envelopes"], [])

    def test_eml_and_attachment_are_checked_on_their_own_recipients(self) -> None:
        self.host.perimeter.tag = "DJ56K"

        def fake(account, args, **kw):
            out = self._fake(account, args)
            if args[0] in ("get-eml", "get-attachment"):
                return {**out, "rcpt_raw": ["studio@example.it"]}
            return out
        with patch.object(self.mail, "_run_json", side_effect=fake):
            with self.assertRaises(PermissionError):
                self.svc("courier_eml", {"account": "studio", "email_id": "1"})
            with self.assertRaises(PermissionError):
                self.svc("courier_attachment", {"account": "studio", "email_id": "1",
                                                "filename": "a/b.pdf"})

    def test_a_client_without_recipients_delivers_nothing_in_a_box_call(self) -> None:
        self.host.perimeter.tag = "DJ56K"
        rows = [{k: v for k, v in r.items() if k != "rcpt_raw"} for r in self.LIST]

        def fake(a, args, **k):
            if args[0] in ("list", "search"):
                return [dict(r) for r in rows]
            out = self._fake(a, args)
            return {k2: v for k2, v in out.items() if k2 != "rcpt_raw"} \
                if isinstance(out, dict) else out
        with patch.object(self.mail, "_run_json", side_effect=fake):
            out = self.svc("courier_envelopes", {"account": "studio"})
        self.assertEqual(out["envelopes"], [])

    # ── review of #416: message-box mail is the topic's only ──────────────
    def test_untagged_rows_never_see_message_box_mail(self) -> None:
        self.host.perimeter.colony = "studio@example.it"
        with patch.object(self.mail, "_run_json", side_effect=self._fake):
            out = self.svc("courier_envelopes", {"account": "studio"})
            self.assertEqual([e["id"] for e in out["envelopes"]], ["2"])
            with self.assertRaises(PermissionError):
                self.svc("courier_eml", {"account": "studio", "email_id": "1"})

    def test_the_tagged_courier_call_still_gets_it(self) -> None:
        self.host.perimeter.colony = "studio@example.it"
        self.host.perimeter.tag = "DJ56K"
        with patch.object(self.mail, "_run_json", side_effect=self._fake):
            out = self.svc("courier_envelopes", {"account": "studio"})
        self.assertEqual([e["id"] for e in out["envelopes"]], ["1"])

    def test_another_mailbox_is_untouched(self) -> None:
        self.host.perimeter.colony = "colony@altrove.it"
        with patch.object(self.mail, "_run_json", side_effect=self._fake):
            out = self.svc("courier_envelopes", {"account": "studio"})
        self.assertEqual([e["id"] for e in out["envelopes"]], ["1", "2"])


# ── #585: one search for every message box ─────────────────────────────────

class BoxIndexTests(_Courier):
    def setUp(self) -> None:
        super().setUp()
        self.host.perimeter.colony = "studio@example.it"
        self.host.perimeter.tag = "*"
        self.searches = []

    def fake(self, account, args, **kw):
        if args[0] == "search":
            self.searches.append(args[1])
            return [dict(r) for r in self.LIST]
        return self._fake(account, args)

    def test_one_search_gives_every_code_with_its_keys(self) -> None:
        with patch.object(self.mail, "_run_json", side_effect=self.fake):
            out = self.svc("courier_box_index", {"account": "studio"})
        self.assertEqual(out["tags"], {"DJ56K": [self.mail.envelope_key(self.LIST[0])]})
        (query,) = self.searches
        self.assertTrue(query.startswith("SINCE "))

    def test_keys_only_nothing_else(self) -> None:
        with patch.object(self.mail, "_run_json", side_effect=self.fake):
            out = self.svc("courier_box_index", {"account": "studio"})
        self.assertNotIn("fattura", repr(out))
        self.assertNotIn("ordini@f.it", repr(out))

    def test_only_under_the_index_tag(self) -> None:
        for tag in ("", "DJ56K"):
            with self.subTest(tag=tag):
                self.host.perimeter.tag = tag
                with patch.object(self.mail, "_run_json", side_effect=self.fake):
                    with self.assertRaises(PermissionError):
                        self.svc("courier_box_index", {"account": "studio"})

    def test_only_on_the_colony_mailbox(self) -> None:
        self.host.perimeter.colony = "altro@example.it"
        with patch.object(self.mail, "_run_json", side_effect=self.fake):
            with self.assertRaises(PermissionError):
                self.svc("courier_box_index", {"account": "studio"})

    def test_the_index_tag_opens_no_per_room_read(self) -> None:
        with patch.object(self.mail, "_run_json", side_effect=self.fake):
            for name, args in (("courier_envelopes", {"account": "studio"}),
                               ("courier_eml", {"account": "studio", "email_id": "1"}),
                               ("courier_attachment", {"account": "studio", "email_id": "1",
                                                       "filename": "a/b.pdf"})):
                with self.subTest(service=name):
                    with self.assertRaises(PermissionError):
                        self.svc(name, args)


class OnlyTests(_Courier):
    def test_only_the_named_keys_are_read(self) -> None:
        k2 = self.mail.envelope_key(self.LIST[1])
        with patch.object(self.mail, "_run_json", side_effect=self._fake):
            out = self.svc("courier_envelopes", {"account": "studio", "only": [k2]})
            none = self.svc("courier_envelopes", {"account": "studio", "only": []})
            every = self.svc("courier_envelopes", {"account": "studio"})
        self.assertEqual([e["id"] for e in out["envelopes"]], ["2"])
        self.assertEqual(none["envelopes"], [])
        self.assertEqual([e["id"] for e in every["envelopes"]], ["1", "2"])

    def test_refused_keys_are_reported_for_an_only_pass(self) -> None:
        """Review of clodia-logic#558."""
        self.host.perimeter.room_senders = {"ordini@f.it"}
        k1, k2 = (self.mail.envelope_key(r) for r in self.LIST)
        with patch.object(self.mail, "_run_json", side_effect=self._fake):
            out = self.svc("courier_envelopes", {"account": "studio", "only": [k1, k2]})
            plain = self.svc("courier_envelopes", {"account": "studio"})
        self.assertEqual([e["id"] for e in out["envelopes"]], ["1"])
        self.assertEqual(out["withheld_keys"], [k2])
        self.assertNotIn("withheld_keys", plain)

    def test_an_unreachable_message_is_not_reported_refused(self) -> None:
        k1 = self.mail.envelope_key(self.LIST[0])

        def fake(account, args, **kw):
            if args[0] == "read":
                return None                     # the read failed
            return self._fake(account, args)
        with patch.object(self.mail, "_run_json", side_effect=fake):
            out = self.svc("courier_envelopes", {"account": "studio", "only": [k1]})
        self.assertEqual((out["envelopes"], out["withheld_keys"]), ([], []))

    def test_the_eml_of_another_message_is_refused(self) -> None:
        with patch.object(self.mail, "_run_json", side_effect=self._fake):
            with self.assertRaises(PermissionError):
                self.svc("courier_eml", {"account": "studio", "email_id": "1",
                                         "key": self.mail.envelope_key(self.LIST[1])})
            ok = self.svc("courier_eml", {"account": "studio", "email_id": "1",
                                          "key": self.mail.envelope_key(self.LIST[0])})
        self.assertEqual(ok["size"], 9)

    def test_the_eml_carries_the_authentication_result(self) -> None:
        with patch.object(self.mail, "_run_json", side_effect=self._fake):
            out = self.svc("courier_eml", {"account": "studio", "email_id": "1"})
        self.assertIs(out["auth"]["authenticated"], False)   # RAW-EML-1: no headers


# ── #586: was the sender authenticated? ────────────────────────────────────

GMAIL_AR = ("mx.google.com; dkim=pass header.i=@gmail.com header.s=20251104 "
            "header.b=eGe3ouF4; arc=pass (i=1); spf=pass (google.com: domain of "
            "a@gmail.com designates 1.2.3.4 as permitted sender) smtp.mailfrom=a@gmail.com; "
            "dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com")


def _raw(*headers: str, body: str = "ciao") -> bytes:
    return ("\r\n".join(headers) + "\r\n\r\n" + body + "\r\n").encode()


class AuthenticationTests(_Courier):
    IDS = {"mx.google.com"}

    def auth(self, raw, ids=None):
        return self.mail.mail_authentication(raw, self.IDS if ids is None else ids)

    def ar(self, ar, frm="From: a@gmail.com"):
        return self.auth(_raw(f"Authentication-Results: {ar}", frm))

    def test_gmail_dmarc_pass_is_authenticated(self) -> None:
        out = self.ar(GMAIL_AR, "From: Davide <a@gmail.com>")
        self.assertEqual((out["authenticated"], out["method"], out["domain"]),
                         (True, "dmarc", "gmail.com"))

    def test_aligned_dkim_alone_is_enough(self) -> None:
        out = self.ar("mx.google.com; dkim=pass header.i=@mail.example.it header.s=s1; "
                      "spf=none", "From: x@example.it")
        self.assertEqual((out["authenticated"], out["method"]), (True, "dkim"))

    def test_unaligned_dkim_is_not(self) -> None:
        self.assertFalse(self.ar("mx.google.com; dkim=pass header.d=mailer.com; "
                                 "dmarc=fail header.from=example.it",
                                 "From: x@example.it")["authenticated"])

    def test_dmarc_for_another_domain_is_not(self) -> None:
        self.assertFalse(self.ar("mx.google.com; dmarc=pass header.from=evil.com")
                         ["authenticated"])

    def test_a_forged_header_below_the_receivers_does_not_count(self) -> None:
        receiver = "mx.google.com; dkim=fail header.i=@gmail.com; dmarc=fail header.from=gmail.com"
        out = self.auth(_raw(f"Authentication-Results: {receiver}",
                             f"Authentication-Results: {GMAIL_AR}",
                             "From: a@gmail.com"))
        self.assertFalse(out["authenticated"])

    def test_an_untrusted_authserv_id_does_not_count(self) -> None:
        out = self.ar("evil.example; dmarc=pass header.from=gmail.com")
        self.assertFalse(out["authenticated"])
        self.assertIn("evil.example", out["reason"])

    def test_no_trusted_id_nothing_authenticated(self) -> None:
        self.assertFalse(self.auth(_raw(f"Authentication-Results: {GMAIL_AR}",
                                        "From: a@gmail.com"), ids=set())["authenticated"])

    def test_from_must_be_one_address(self) -> None:
        for frm in ("From: a@gmail.com, b@gmail.com", "From: nessuno"):
            with self.subTest(frm=frm):
                self.assertFalse(self.ar(GMAIL_AR, frm)["authenticated"])
        two = _raw(f"Authentication-Results: {GMAIL_AR}", "From: a@gmail.com",
                   "From: b@evil.com")
        self.assertFalse(self.auth(two)["authenticated"])

    def test_no_header_no_authentication(self) -> None:
        out = self.auth(_raw("From: a@gmail.com"))
        self.assertEqual((out["authenticated"], out["reason"]),
                         (False, "no Authentication-Results"))

    def test_trusted_ids_follow_the_mailbox_kind(self) -> None:
        self.assertEqual(self.mail._authserv_ids("studio"), set())
        self.host.vault["mailbox_studio"] = {**self.host.vault["mailbox_studio"],
                                             "authserv_id": "mx.example.it"}
        self.assertEqual(self.mail._authserv_ids("studio"), {"mx.example.it"})

    # ── the parser (review of clodia-logic#558) ────────────────────────────
    def test_a_result_injected_in_a_quoted_string_or_comment_is_data(self) -> None:
        ar = ('mx.google.com; spf=pass (x;dmarc=pass header.from=gmail.com;y) '
              'smtp.mailfrom="a);dmarc=pass header.from=gmail.com;(b"@evil.com; '
              'dmarc=fail header.from=gmail.com')
        self.assertFalse(self.ar(ar)["authenticated"])

    def test_a_failing_dmarc_wins_over_a_passing_one(self) -> None:
        self.assertFalse(self.ar("mx.google.com; dmarc=pass header.from=gmail.com; "
                                 "dmarc=fail header.from=gmail.com")["authenticated"])

    def test_dmarc_fail_is_not_rescued_by_dkim(self) -> None:
        self.assertFalse(self.ar("mx.google.com; dkim=pass header.i=@gmail.com; "
                                 "dmarc=fail header.from=gmail.com")["authenticated"])

    def test_a_parent_domain_signer_is_not_aligned(self) -> None:
        self.assertFalse(self.ar("mx.google.com; dkim=pass header.d=myshopify.com",
                                 "From: x@shop1.myshopify.com")["authenticated"])

    def test_nested_comments(self) -> None:
        self.assertTrue(self.ar("mx.google.com (a (b; dmarc=fail) c); dmarc=pass "
                                "(p=NONE) header.from=gmail.com")["authenticated"])

    def test_unterminated_comment_or_quote_fails_closed(self) -> None:
        self.assertFalse(self.ar("mx.google.com; dkim=pass header.i=@gmail.com; "
                                 "spf=pass (domain of a(b@evil.com) x; dmarc=fail "
                                 "header.from=gmail.com")["authenticated"])
        self.assertFalse(self.ar('mx.google.com; dkim=pass header.i=@gmail.com; '
                                 'spf=pass smtp.mailfrom="a@x')["authenticated"])

    def test_spaces_around_equals(self) -> None:
        self.assertFalse(self.ar("mx.google.com; dkim=pass header.i=@gmail.com; "
                                 "dmarc = fail header.from=gmail.com")["authenticated"])

    # ── on the courier's `.eml` ────────────────────────────────────────────
    def test_an_eml_without_message_id_is_never_authenticated(self) -> None:
        raw = _raw(f"Authentication-Results: {GMAIL_AR}", "From: ordini@f.it")

        def fake(account, args, **kw):
            out = self._fake(account, args)
            if args[0] == "get-eml":
                return {**out, "message_id": "", "data": base64.b64encode(raw).decode()}
            return out
        with patch.object(self.mail, "_run_json", side_effect=fake), \
                patch.object(self.mail, "_authserv_ids", lambda a: {"mx.google.com"}):
            out = self.svc("courier_eml", {"account": "studio", "email_id": "1", "key": "k"})
        self.assertFalse(out["auth"]["authenticated"])

    def eml_auth(self, to_header):
        raw = _raw(f"Authentication-Results: {GMAIL_AR}", "From: ordini@f.it",
                   "Message-ID: <m1@x>", to_header)
        raw = raw.replace(b"header.from=gmail.com", b"header.from=f.it")
        self.host.perimeter.tag = "DJ56K"

        def fake(account, args, **kw):
            out = self._fake(account, args)
            if args[0] == "get-eml":
                return {**out, "data": base64.b64encode(raw).decode()}
            return out
        with patch.object(self.mail, "_run_json", side_effect=fake), \
                patch.object(self.mail, "_authserv_ids", lambda a: {"mx.google.com"}):
            return self.svc("courier_eml", {"account": "studio", "email_id": "1"})["auth"]

    def test_a_replayed_mail_is_not_trusted_on_the_box(self) -> None:
        self.assertFalse(self.eml_auth("To: someone@else.it")["authenticated"])
        self.assertTrue(self.eml_auth("To: Studio <studio+DJ56K@example.it>")["authenticated"])

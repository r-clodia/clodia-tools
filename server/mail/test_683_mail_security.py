"""Security of the gateway's mail code: the client run, sending, accounts and
mailboxes (clodia-platform#683).

Ported from comms-pack's component suites (clodia-logic
`test_558_mail_component.py`, `test_523_mail_security_moved.py`), which went
away with the pack. What still exists is tested here, on the gateway's own
`server/mail/`; the agent read verbs (folders, list, read, search, reply,
get/save attachment) and their strict-ingress filtering are gone, and so are
their tests.

- the client runs on ONE mailbox's credential, in a 0700 directory removed
  after the run, with a minimal environment;
- the mailbox whitelist comes first (#503), sending is weighed on the OUTBOX
  (#428); legacy accounts are refused; a Google account without google-pack
  is refused, never served by a same-named IMAP mailbox (review of #384);
- Gmail goes to google-pack's `mail_exec` without a secret passing here;
- #461: an agent's attachment stays in its own scratch; topic files go by
  reference with their crossing notes;
- #420: an attachment name is one file name;
- #400: `message/rfc822` (.eml) attachments are retrievable by the client;
- #556/#560: TLS verifies the server; a non-ASCII attachment name survives;
- mailbox management validates, never reports the secret, and a removal
  returns the address.
"""
from __future__ import annotations

import base64
import contextlib
import email as email_mod
import importlib.util
import json
import os
import ssl
import sys
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import MagicMock, patch

from . import verbs
from ._test_harness import SECRET, STUDIO, OnFakeGateway

CLIENT = Path(__file__).resolve().parent / "email_client.py"


def _client():
    """The gateway's `email_client.py`, loaded as its own module."""
    spec = importlib.util.spec_from_file_location("gateway_email_client_683", CLIENT)
    mod = importlib.util.module_from_spec(spec)
    before = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.dont_write_bytecode = before
    return mod


# ── the client run ─────────────────────────────────────────────────────────

class ClientRunTests(OnFakeGateway):
    def test_the_client_runs_on_this_calls_mailbox_only(self) -> None:
        self.host.vault["mailbox_altra"] = {"email": "a@x.it", "password": "other",
                                            "smtp_server": "s", "smtp_port": 1}
        seen = self.mail._run_json("studio", ["folders"])
        self.assertEqual(seen["argv"], ["--account", "studio", "folders"])
        self.assertEqual(seen["config"], {"default": "studio",
                                          "accounts": {"studio": STUDIO}})
        self.assertEqual(seen["dir_mode"], "0o700")
        # Minimal environment; Python itself may add LC_CTYPE, macOS its CF encoding.
        extra = set(seen["env"]) - {"PATH", "LANG", "HOME", "CLODIA_SECRETS_DIR",
                                    "PYTHONDONTWRITEBYTECODE"}
        self.assertLessEqual(extra, {"LC_CTYPE", "__CF_USER_TEXT_ENCODING"}, extra)
        self.assertFalse(Path(seen["secrets_dir"]).exists())

    def test_the_mailbox_whitelist_comes_first(self) -> None:
        self.host.perimeter.inbox.clear()
        with patch.object(self.mail.subprocess, "run") as run:
            with self.assertRaises(PermissionError) as e:
                self.mail._run_json("studio", ["list"])
        run.assert_not_called()
        self.assertIn("inbox:studio@example.it", str(e.exception))

    def test_a_send_only_mailbox_is_not_read(self) -> None:
        self.host.vault["mailbox_studio"].pop("imap_server")
        with self.assertRaises(PermissionError) as e:
            self.mail._run_json("studio", ["list"])
        self.assertIn("SOLO INVIO", str(e.exception))

    def test_an_unknown_account_names_the_valid_ones(self) -> None:
        with self.assertRaises(ValueError) as e:
            self.mail._run_json("demo", ["list"])
        self.assertIn("unknown account 'demo'", str(e.exception))
        self.assertIn("studio", str(e.exception))


class LegacyTests(OnFakeGateway):
    def test_listed_and_refused(self) -> None:
        self.host.perimeter.legacy = {"demo": "studio@example.it"}
        self.assertIn("demo", self.mail.known_accounts())
        with patch.object(self.mail.subprocess, "run") as run:
            with self.assertRaises(PermissionError) as e:
                self.mail._run_json("demo", ["list"])
        run.assert_not_called()
        self.assertIn("legacy", str(e.exception))

    def test_without_an_address_it_is_refused_too(self) -> None:
        self.host.perimeter.legacy = {"demo": None}
        with self.assertRaises(PermissionError) as e:
            self.mail._run_json("demo", ["list"])
        self.assertIn("email_config.json", str(e.exception))

    def test_not_offered_as_a_system_mailbox(self) -> None:
        self.host.perimeter.legacy = {"demo": "demo@example.it"}
        self.assertEqual([r["account"] for r in self.mail.system_mailboxes()], ["studio"])


# ── sending: the delivery-only `email.send` ────────────────────────────────

class SendTests(OnFakeGateway):
    def _send(self, **args):
        return verbs.send({"account": "studio", "to": "a@b.it", "subject": "s",
                           "body": "t", **args})

    def _directions(self, **args):
        seen = []

        @contextlib.contextmanager
        def env(account, direction):
            seen.append(direction)
            yield {}

        done = MagicMock(returncode=0, stdout="sent", stderr="")
        with patch.object(self.mail, "_secrets_env", env), \
                patch.object(self.mail.subprocess, "run", return_value=done) as run:
            out = self._send(**args)
        return seen, run, out

    def test_send_is_checked_on_the_outbox(self) -> None:
        """#428."""
        seen, run, out = self._directions(cc="c@b.it")
        self.assertEqual(seen, ["outbox"])
        cmd = run.call_args[0][0]
        self.assertIn("send", cmd)
        self.assertIn("c@b.it", cmd)
        self.assertTrue(out["ok"])

    def test_without_the_outbox_entry_nothing_is_sent(self) -> None:
        self.host.perimeter.outbox.clear()
        with patch.object(self.mail.subprocess, "run") as run:
            with self.assertRaises(PermissionError) as e:
                self._send()
        run.assert_not_called()
        self.assertIn("outbox:studio@example.it", str(e.exception))

    def test_an_inbox_entry_alone_does_not_send(self) -> None:
        self.host.perimeter.outbox.clear()
        self.assertIn("studio@example.it", self.host.perimeter.inbox)
        with self.assertRaises(PermissionError):
            self._send()

    def test_invalid_recipient_or_subject(self) -> None:
        with self.assertRaises(ValueError):
            self.mail.send("non-un-indirizzo", "s", "b", account="studio")
        with self.assertRaises(ValueError):
            self.mail.send("a@b.it", "", "b", account="studio")
        with self.assertRaises(ValueError):
            self.mail.send("a@b.it", "s", None, account="studio")

    def test_a_single_account_is_selected(self) -> None:
        self.assertEqual(verbs._email_account({}), "studio")

    def test_the_account_must_be_named_when_there_are_several(self) -> None:
        self.host.vault["mailbox_altra"] = dict(STUDIO, email="a@x.it")
        with self.assertRaises(ValueError) as e:
            verbs._email_account({})
        self.assertIn("obbligatorio", str(e.exception))

    def test_an_unknown_account_names_the_valid_ones(self) -> None:
        with self.assertRaises(ValueError) as e:
            verbs._email_account({"account": "demo"})
        self.assertIn("'demo' non esistente", str(e.exception))
        self.assertIn("studio", str(e.exception))


class AttachmentsConfinedTests(OnFakeGateway):
    """#461: an agent's attachment path is confined to ITS scratch."""

    def setUp(self) -> None:
        super().setUp()
        self.mine = Path(self.tmp) / "spawns" / "clodia-320"
        self.other = Path(self.tmp) / "spawns" / "ophelia-7"
        self.mine.mkdir(parents=True)
        self.other.mkdir(parents=True)
        self.host.scratch = str(self.mine)
        self.sent: list = []
        p = patch.object(self.mail, "send",
                         lambda *a, **k: self.sent.append(k.get("attachments")) or {"ok": True})
        p.start()
        self.addCleanup(p.stop)

    def _call(self, attachments):
        return verbs.send({"account": "studio", "to": "x@example.com", "subject": "s",
                           "body": "b", "attachments": attachments})

    def _refused(self, path) -> None:
        with self.assertRaises(ValueError) as e:
            self._call([path])
        self.assertIn("outside your scratch", str(e.exception))

    def test_a_gateway_file_outside_the_scratch_is_refused(self) -> None:
        secret = Path(self.tmp) / "data" / "config.yaml"
        secret.parent.mkdir()
        secret.write_text("vault: x\n")
        self._refused(str(secret))
        self._refused("/etc/passwd")
        self.assertEqual(self.sent, [])

    def test_a_symlink_out_of_the_scratch_is_refused(self) -> None:
        target = Path(self.tmp) / "outside.txt"
        target.write_text("x")
        link = self.mine / "looks-local.txt"
        os.symlink(target, link)
        self._refused(str(link))
        self.assertEqual(self.sent, [])

    def test_a_relative_path_is_refused(self) -> None:
        self._refused("report.pdf")
        self.assertEqual(self.sent, [])

    def test_another_spawns_scratch_is_refused(self) -> None:
        theirs = self.other / "theirs.pdf"
        theirs.write_bytes(b"x")
        self._refused(str(theirs))
        self.assertEqual(self.sent, [])

    def test_a_file_in_the_scratch_is_sent_by_its_resolved_path(self) -> None:
        att = self.mine / "offerta.pdf"
        att.write_bytes(b"%PDF")
        self._call([str(att)])
        self.assertEqual(self.sent, [[os.path.realpath(att)]])
        self.assertEqual(self.host.crossings, [("path", "attachment")])

    def test_a_missing_file_in_the_scratch_is_refused(self) -> None:
        with self.assertRaises(ValueError) as e:
            self._call([str(self.mine / "nope.pdf")])
        self.assertIn("not found", str(e.exception))
        self.assertEqual(self.sent, [])


class TopicAttachmentTests(OnFakeGateway):
    """Topic files leave BY REFERENCE: read with the compartment check, noted
    as `attachment` crossings after the agent's own."""

    def setUp(self) -> None:
        super().setUp()
        self.host.members.add(("SEAL-1", "acme"))
        self.host.topic = ("SEAL-1", "acme")

    def test_topic_files_and_scratch_files_leave_as_attachments(self) -> None:
        self.host.topics.files[("SEAL-1", "acme", "files/c.pdf")] = b"%PDF c"
        own = Path(self.tmp) / "mio.pdf"
        own.write_bytes(b"%PDF mio")
        seen = {}

        def send(to, subject, body, *, account, cc, attachments):
            seen["files"] = {Path(p).name: Path(p).read_bytes() for p in attachments}
            return {"ok": True}
        with patch.object(self.mail, "send", send):
            verbs.send({"account": "studio", "to": "x@y.it", "subject": "s",
                        "body": "b", "attachments": [str(own)],
                        "topic_files": ["files/c.pdf"]})
        self.assertEqual(seen["files"], {"mio.pdf": b"%PDF mio", "c.pdf": b"%PDF c"})
        self.assertEqual(self.host.crossings, [("path", "attachment"),
                                               ("data", "attachment")])

    def test_the_temporary_copies_are_removed(self) -> None:
        self.host.topics.files[("SEAL-1", "acme", "files/c.pdf")] = b"%PDF c"
        kept = []
        with patch.object(self.mail, "send",
                          lambda *a, attachments, **k: kept.extend(attachments) or {"ok": True}):
            verbs.send({"account": "studio", "to": "x@y.it", "subject": "s",
                        "body": "b", "topic_files": ["files/c.pdf"]})
        self.assertTrue(kept)
        self.assertFalse(any(Path(p).exists() for p in kept))

    def test_a_non_member_topic_is_refused(self) -> None:
        self.host.topics.files[("SEAL-2", "altro", "files/c.pdf")] = b"x"
        with patch.object(self.mail, "send") as send, self.assertRaises(PermissionError):
            verbs.send({"account": "studio", "to": "x@y.it", "subject": "s",
                        "body": "b", "topic_files": ["files/c.pdf"],
                        "tier": "SEAL-2", "name": "altro"})
        send.assert_not_called()

    def test_without_a_topic_topic_files_are_refused(self) -> None:
        self.host.topic = (None, None)
        with self.assertRaises(ValueError):
            verbs.send({"account": "studio", "to": "x@y.it", "subject": "s",
                        "body": "b", "topic_files": ["files/c.pdf"]})


# ── Gmail: google-pack's component ─────────────────────────────────────────

class GmailTests(OnFakeGateway):
    def setUp(self) -> None:
        super().setUp()
        self.payloads: list = []
        self.host.google = {
            "mail_accounts": lambda: [{
                "credential": "google_devnull", "account": "devnull", "kind": "google",
                "operational": True, "send_only": False, "missing": [], "error": None,
                "email": "Devnull@Gmail.com"}],
            "mail_exec": lambda p: (self.payloads.append(p),
                                    {"returncode": 0, "stdout": '["INBOX"]',
                                     "stderr": ""})[1],
        }
        self.host.perimeter.inbox.add("devnull@gmail.com")
        self.host.perimeter.outbox.add("devnull@gmail.com")

    def test_a_google_account_goes_to_google_pack_without_a_secret(self) -> None:
        att = Path(self.tmp) / "offerta.pdf"
        att.write_bytes(b"%PDF")
        with patch.object(self.mail.subprocess, "run") as run:
            out = self.mail._run_json("devnull", ["folders"])
            self.mail.send("x@y.it", "s", "b", account="devnull", attachments=[str(att)])
        run.assert_not_called()
        self.assertEqual(out, ["INBOX"])
        folders, send = self.payloads
        self.assertEqual(folders, {"account": "devnull", "argv": ["folders"],
                                   "files": {}, "timeout": 60})
        self.assertEqual(sorted(send["files"]), ["att/0/offerta.pdf"])
        self.assertIn("{dir}/att/0/offerta.pdf", send["argv"])
        self.assertNotIn(str(att), json.dumps(send))
        self.assertEqual(self.mail.system_mailboxes()[0],
                         {"account": "devnull", "email": "devnull@gmail.com",
                          "send_only": False})

    def test_the_whitelist_is_checked_on_the_google_address(self) -> None:
        self.host.perimeter.inbox.clear()
        with self.assertRaises(PermissionError) as e:
            self.mail._run_json("devnull", ["list"])
        self.assertIn("inbox:devnull@gmail.com", str(e.exception))
        self.assertEqual(self.payloads, [])

    def test_without_google_pack_the_account_is_refused_and_says_why(self) -> None:
        self.host.google = {}
        with self.assertRaises(ValueError) as e:
            self.mail._run_json("devnull", ["folders"])
        self.assertIn("google-pack", str(e.exception))
        out = self.mail._run_json("studio", ["folders"])      # IMAP unaffected
        self.assertEqual(out["argv"][2], "folders")

    def test_a_dual_credential_account_is_refused_while_google_pack_is_down(self) -> None:
        """Review of #384: `studio` with both `mailbox_studio` and
        `google_studio` silently switched sender address when google-pack was
        down. Refused instead."""
        self.host.google = {}
        self.host.perimeter.google_named = {"studio"}
        with self.assertRaises(PermissionError) as e:
            self.mail._run_json("studio", ["folders"])
        self.assertIn("google-pack", str(e.exception))

    def test_the_google_bundle_is_never_read(self) -> None:
        from ._host import vault
        self.assertEqual(vault.read_internal("google_devnull"),
                         {"email": "Devnull@Gmail.com"})
        self.mail._run_json("devnull", ["folders"])
        self.assertEqual(set(self.host.service_lookups),
                         {("google-pack", "mail_accounts"), ("google-pack", "mail_exec")})


# ── mailbox management (the Tools page) ────────────────────────────────────

class MailboxServicesTests(OnFakeGateway):
    def test_add_list_remove(self) -> None:
        self.assertEqual(self.svc("mailbox_add", {"account": "Info", "email": "info@x.it",
                                                  "password": "p",
                                                  "smtp_server": "smtp.x.it"}),
                         {"status": 200, "body": {"account": "info", "connected": True}})
        self.assertEqual(self.host.deposits[-1],
                         ("mailbox_info", "mailbox", ["clodia", "ophelia"]))
        self.assertEqual(self.svc("mailbox_add", {"account": "x"})["status"], 400)
        self.assertEqual(self.svc("mailbox_add", {"account": "../x", "email": "e",
                                                  "password": "p",
                                                  "smtp_server": "s"})["status"], 400)
        self.assertEqual(self.svc("mailboxes_list")["mailboxes"], ["info", "studio"])
        self.assertEqual(self.svc("mailbox_remove", "info"),
                         {"removed": True, "email": "info@x.it"})
        self.assertNotIn("mailbox_info", self.host.vault)

    def test_test_mailboxes_reports_without_the_secret(self) -> None:
        import imaplib

        class _Imap:
            def __init__(self, *a, **k):
                pass

            def login(self, user, pwd):
                raise imaplib.IMAP4.error(f"bad {pwd}")

            def logout(self):
                pass
        with patch.object(imaplib, "IMAP4_SSL", _Imap):
            out = self.svc("test_mailboxes")
        self.assertFalse(out["ok"])
        self.assertNotIn(SECRET, json.dumps(out))

    def test_the_vault_is_mailbox_only(self) -> None:
        from ._host import vault
        for name in ("google_studio", "telegram_bot_token", "github_pat"):
            with self.subTest(name=name), self.assertRaises(PermissionError):
                vault.deposit(name, {}, cred_type="opaque")
        self.assertEqual(self.host.deposits, [])


# ── #420: an attachment name is not a path ─────────────────────────────────

class SafeAttachmentNameTests(unittest.TestCase):
    LOST = ["Aggiornamento preventivo Voucher Startup Social Tech / StopListe.eml",
            "NDA bilaterale Tomato / Luxury Esmeralda Real Estate — versione aggiornata.eml"]

    def setUp(self) -> None:
        from . import mail
        self.f = mail.safe_attachment_name

    def test_the_separator_stops_being_a_separator(self) -> None:
        for name in self.LOST:
            safe = self.f(name)
            self.assertNotIn("/", safe)
            self.assertTrue(safe.endswith(".eml"), safe)
            self.assertEqual(safe, safe.strip())

    def test_backslash_newline_and_leading_dot(self) -> None:
        self.assertEqual(self.f("a\\b.pdf"), "a-b.pdf")
        self.assertEqual(self.f("Oggetto\n lungo.eml"), "Oggetto lungo.eml")
        self.assertEqual(self.f(".hidden.pdf"), "hidden.pdf")

    def test_a_name_that_sanitizes_to_nothing_still_has_a_name(self) -> None:
        self.assertEqual(self.f("///"), "allegato")
        self.assertEqual(self.f(""), "allegato")


# ── the client itself: #400, #556/#560 ────────────────────────────────────

PDF_BYTES = b"%PDF-1.4 fake but binary \x00\x01\x02"
EML_NAME = "HikmaAI Docs.eml"
PDF_NAME = "condizioni-generali.pdf"


def _message_with_eml_attachment() -> EmailMessage:
    inner = EmailMessage()
    inner["From"] = "mittente@example.com"
    inner["To"] = "info@example.com"
    inner["Subject"] = "Documento inoltrato"
    inner.set_content("nested body")
    msg = EmailMessage()
    msg["From"] = "info@example.com"
    msg["To"] = "owner@example.com"
    msg["Subject"] = "batch"
    msg.set_content("an .eml and a pdf attached")
    msg.add_attachment(PDF_BYTES, maintype="application", subtype="pdf", filename=PDF_NAME)
    msg.add_attachment(inner, filename=EML_NAME)
    return msg


class _FakeIMAP:
    def __init__(self, raw: bytes):
        self._raw = raw

    def select(self, folder, readonly=False):
        return "OK", [b"1"]

    def fetch(self, email_id, parts):
        return "OK", [(b"1 (RFC822 {%d}" % len(self._raw), self._raw)]

    def logout(self):
        return "BYE", [b""]


class Rfc822AttachmentTests(unittest.TestCase):
    """#400: `get_payload(decode=True)` is None on a message/rfc822 part; the
    client used to skip it and answer «not found» for every .eml."""

    def setUp(self) -> None:
        self.c = _client()
        self.raw = _message_with_eml_attachment().as_bytes()
        p = patch.object(self.c, "connect_imap", return_value=_FakeIMAP(self.raw))
        p.start()
        self.addCleanup(p.stop)

    def _part(self, filename):
        for part in email_mod.message_from_bytes(self.raw).walk():
            if part.get_filename() == filename:
                return part
        raise AssertionError(filename)

    def _expected_eml(self) -> bytes:
        return self._part(EML_NAME).get_payload(decode=False)[0].as_bytes()

    def test_the_fixture_reproduces_the_none_payload(self) -> None:
        self.assertIsNone(self._part(EML_NAME).get_payload(decode=True))

    def test_get_attachment_returns_the_eml_bytes(self) -> None:
        got = self.c.get_attachment("info", "177", EML_NAME)
        data = base64.b64decode(got["data"])
        self.assertEqual(got["content_type"], "message/rfc822")
        self.assertEqual(data, self._expected_eml())
        self.assertEqual(email_mod.message_from_bytes(data)["Subject"], "Documento inoltrato")

    def test_binaries_still_work_and_absent_still_raises(self) -> None:
        got = self.c.get_attachment("info", "177", PDF_NAME)
        self.assertEqual(base64.b64decode(got["data"]), PDF_BYTES)
        with self.assertRaises(ValueError):
            self.c.get_attachment("info", "177", "missing.txt")

    def test_download_attachments_writes_the_eml(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.c.download_attachments("info", "177", output_dir=tmp)
            self.assertEqual(Path(tmp, EML_NAME).read_bytes(), self._expected_eml())
            self.assertEqual(Path(tmp, PDF_NAME).read_bytes(), PDF_BYTES)

    def test_part_bytes(self) -> None:
        part = email_mod.message_from_string("Content-Type: message/rfc822\n\n")
        self.assertTrue(self.c._part_bytes(part))
        part.set_payload([])
        self.assertIsNone(self.c._part_bytes(part))
        b64 = email_mod.message_from_string(
            "Content-Type: application/octet-stream\n"
            "Content-Transfer-Encoding: base64\n\nY2lhbw==\n")
        self.assertEqual(self.c._part_bytes(b64), b"ciao")


class ClientTlsAndNamesTests(unittest.TestCase):
    def test_imap_and_smtp_verify_the_server(self) -> None:
        """#556."""
        c = _client()
        seen = {}

        def imap(host, port, ssl_context=None):
            seen["imap"] = ssl_context
            return MagicMock()

        smtp = MagicMock()
        smtp.return_value.starttls.side_effect = (
            lambda context=None: seen.setdefault("smtp", context))
        acct = {"imap_server": "imap.x", "imap_port": 993, "smtp_server": "smtp.x",
                "smtp_port": 587, "email": "a@x", "password": "p"}
        with patch.object(c.imaplib, "IMAP4_SSL", side_effect=imap), \
                patch.object(c.smtplib, "SMTP", smtp):
            c.connect_imap(acct)
            c.connect_smtp(acct)
        for k in ("imap", "smtp"):
            self.assertIsInstance(seen[k], ssl.SSLContext, k)
            self.assertEqual(seen[k].verify_mode, ssl.CERT_REQUIRED, k)
            self.assertTrue(seen[k].check_hostname, k)

    def test_a_non_ascii_attachment_name_survives(self) -> None:
        """#560."""
        c = _client()
        sent = {}

        class S:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def send_message(self, msg):
                sent["raw"] = msg.as_bytes()

        with tempfile.TemporaryDirectory() as td:
            att = Path(td) / "offerta àè.pdf"
            att.write_bytes(b"%PDF-1.4")
            acct = {"email": "a@x", "smtp_server": "s", "smtp_port": 587}
            with patch.object(c, "connect_smtp", return_value=S()):
                c.send_email(acct, "b@y", "s", "body", attachments=[str(att)])
        msg = email_mod.message_from_bytes(sent["raw"])
        self.assertEqual([p.get_filename() for p in msg.walk() if p.get_filename()],
                         ["offerta àè.pdf"])


if __name__ == "__main__":
    unittest.main()

"""Mail fixes outside the connector move: clodia-platform#556, #557, #559, #560.

- #556: IMAP/SMTP TLS verifies the certificate AND the hostname;
- #557: a non-ASCII attachment name arrives as an RFC 2231 parameter;
- #559: native `email.reply` — the PDP judges the ORIGINAL sender, never the
  `to` the caller wrote;
- #560: on a strict-ingress channel a non-list result reveals nothing.
"""
from __future__ import annotations

import asyncio
import email
import importlib.util
import os
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from . import egress, main
from .claims import ClaimsContext
from .tools import email as email_tool

ROOT = Path(__file__).resolve().parents[1]


def _client():
    spec = importlib.util.spec_from_file_location("vendored_email_client",
                                                  ROOT / "vendor" / "email_client.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TlsTests(unittest.TestCase):
    def test_imap_and_smtp_verify_the_server(self) -> None:
        c = _client()
        seen = {}

        def imap(host, port, ssl_context=None):
            seen["imap"] = ssl_context
            m = MagicMock()
            return m

        smtp = MagicMock()
        smtp.return_value.starttls.side_effect = lambda context=None: seen.setdefault("smtp", context)
        acct = {"imap_server": "imap.x", "imap_port": 993, "smtp_server": "smtp.x",
                "smtp_port": 587, "email": "a@x", "password": "p"}
        with patch.object(c.imaplib, "IMAP4_SSL", side_effect=imap), \
             patch.object(c.smtplib, "SMTP", smtp):
            c.connect_imap(acct)
            c.connect_smtp(acct)
        for k in ("imap", "smtp"):
            ctx = seen[k]
            self.assertIsInstance(ctx, ssl.SSLContext, k)
            self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED, k)
            self.assertTrue(ctx.check_hostname, k)


class AttachmentNameTests(unittest.TestCase):
    def test_a_non_ascii_name_survives(self) -> None:
        c = _client()
        with tempfile.TemporaryDirectory() as td:
            att = Path(td) / "offerta àè.pdf"
            att.write_bytes(b"%PDF-1.4")
            sent = {}

            class S:
                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

                def send_message(self, msg):
                    sent["raw"] = msg.as_bytes()

            acct = {"email": "a@x", "smtp_server": "s", "smtp_port": 587}
            with patch.object(c, "connect_smtp", return_value=S()):
                c.send_email(acct, "b@y", "s", "body", attachments=[str(att)])
        msg = email.message_from_bytes(sent["raw"])
        names = [p.get_filename() for p in msg.walk() if p.get_filename()]
        self.assertEqual(names, ["offerta àè.pdf"])


class StrictIngressNonListTests(unittest.TestCase):
    def test_a_non_list_result_reveals_nothing(self) -> None:
        with patch.object(email_tool, "_record_ingress") as rec:
            kept, hidden = email_tool._filter_by_sender({"raw": "From: x@evil"}, "s", "email.list")
        self.assertEqual((kept, hidden), ([], 1))
        rec.assert_called_once()
        self.assertEqual(email_tool._filter_by_sender(None, "s", "email.list"), ([], 0))


TOKEN = {"agent": "clodia", "execution_id": "clodia-320", "principal": "davide",
         "origin": ["human:davide", "agent:clodia"]}


class NativeReplyRecipientTests(unittest.TestCase):
    def test_the_pdp_judges_the_original_sender_not_the_callers_to(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        judged = []

        def check(*a, **k):
            judged.append(a)
            return {"checked": True, "allowed": False, "action": "deny",
                    "verb": "email.reply", "reason": "test", "destinations": [],
                    "refused": []}

        async def go():
            with patch.dict(os.environ, {"CLODIA_AUDIT_DIR": str(base / "audit"),
                                         "CLODIA_AUDIT_KEY_DIR": str(base / "k"),
                                         "CLODIA_DATA": str(base / "data")}), \
                    ClaimsContext(TOKEN, "t"), \
                    patch.object(main, "_is_packaged_verb", return_value=False), \
                    patch.object(main, "_reply_recipient", return_value="evil@ext.com"), \
                    patch.object(main, "_require_gate_consent", AsyncMock(return_value={})), \
                    patch.object(egress, "check", side_effect=check), \
                    patch.object(main.email, "reply", MagicMock()) as reply, \
                    patch.object(main, "_email_account", lambda a: "studio"):
                out = await main.call_tool("email.reply", {
                    "email_id": "42", "body": "b", "to": "approved@ok.it"})
                return out, reply
        out, reply = asyncio.run(go())
        self.assertTrue(judged, "the egress PDP was not consulted")
        flat = repr(judged)
        self.assertIn("evil@ext.com", flat)
        self.assertNotIn("approved@ok.it", flat)
        reply.assert_not_called()


if __name__ == "__main__":
    unittest.main()

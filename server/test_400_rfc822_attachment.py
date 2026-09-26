"""Issue #400 — allegati .eml (message/rfc822) irrecuperabili.

`get_payload(decode=True)` torna `None` sui contenitori message/rfc822: il loro
payload è una lista con dentro un sotto-`Message`, non bytes con un
Content-Transfer-Encoding da sciogliere. Il codice scartava quelle parti con un
`continue`, quindi `email.get_attachment`/`email.save_attachment` rispondevano
«allegato non trovato» per OGNI .eml, mentre `email.read` li elencava.
"""
import email as email_mod
from email.message import EmailMessage
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

from vendor import email_client

PDF_BYTES = b"%PDF-1.4 finto ma binario \x00\x01\x02"
EML_NAME = "HikmaAI Docs.eml"
PDF_NAME = "condizioni-generali.pdf"


def _inner_message() -> EmailMessage:
    inner = EmailMessage()
    inner["From"] = "mittente@example.com"
    inner["To"] = "info@example.com"
    inner["Subject"] = "Documento inoltrato"
    inner.set_content("corpo del messaggio innestato")
    return inner


def _message_with_eml_attachment() -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = "info@example.com"
    msg["To"] = "owner@example.com"
    msg["Subject"] = "prot-uscita batch"
    msg.set_content("in allegato un .eml e un pdf")
    msg.add_attachment(PDF_BYTES, maintype="application", subtype="pdf",
                       filename=PDF_NAME)
    msg.add_attachment(_inner_message(), filename=EML_NAME)
    return msg


class _FakeIMAP:
    """IMAP minimale: risponde a select/fetch/logout con un messaggio fisso."""

    def __init__(self, raw: bytes):
        self._raw = raw
        self.logged_out = False

    def select(self, folder, readonly=False):
        return "OK", [b"1"]

    def fetch(self, email_id, parts):
        return "OK", [(b"1 (RFC822 {%d}" % len(self._raw), self._raw)]

    def logout(self):
        self.logged_out = True
        return "BYE", [b""]


class Rfc822AttachmentTest(TestCase):
    def setUp(self):
        self.msg = _message_with_eml_attachment()
        self.raw = self.msg.as_bytes()
        self.imap = _FakeIMAP(self.raw)
        patcher = patch.object(email_client, "connect_imap", return_value=self.imap)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _part(self, filename):
        for part in email_mod.message_from_bytes(self.raw).walk():
            if part.get_filename() == filename:
                return part
        raise AssertionError(f"parte {filename} assente dalla fixture")

    def _expected_eml_bytes(self):
        sub = self._part(EML_NAME).get_payload(decode=False)
        self.assertIsInstance(sub, list)
        return sub[0].as_bytes()

    def test_fixture_reproduces_the_none_payload(self):
        # La premessa della issue, verificata e non assunta: senza questa,
        # il test non dimostra nulla sul bug reale.
        self.assertIsNone(self._part(EML_NAME).get_payload(decode=True))
        self.assertEqual(self._part(PDF_NAME).get_payload(decode=True), PDF_BYTES)

    def test_get_attachment_returns_the_eml_bytes(self):
        import base64

        got = email_client.get_attachment("info", "177", EML_NAME)
        self.assertEqual(got["filename"], EML_NAME)
        self.assertEqual(got["content_type"], "message/rfc822")
        data = base64.b64decode(got["data"])
        self.assertTrue(data)
        self.assertEqual(data, self._expected_eml_bytes())
        self.assertEqual(got["size"], len(data))
        # È un .eml vero: si riapre e conserva l'header del sotto-messaggio.
        self.assertEqual(
            email_mod.message_from_bytes(data)["Subject"], "Documento inoltrato"
        )

    def test_get_attachment_still_works_for_binaries(self):
        import base64

        got = email_client.get_attachment("info", "177", PDF_NAME)
        self.assertEqual(base64.b64decode(got["data"]), PDF_BYTES)

    def test_get_attachment_still_raises_when_really_absent(self):
        with self.assertRaisesRegex(ValueError, "allegato non trovato"):
            email_client.get_attachment("info", "177", "inesistente.txt")

    def test_download_attachments_writes_the_eml(self):
        with TemporaryDirectory() as tmp:
            got = email_client.download_attachments("info", "177", output_dir=tmp)
            by_name = {d["filename"]: d for d in got}
            self.assertIn(EML_NAME, by_name)
            written = Path(tmp, EML_NAME).read_bytes()
            self.assertEqual(written, self._expected_eml_bytes())
            self.assertEqual(by_name[EML_NAME]["size"], len(written))
            self.assertEqual(Path(tmp, PDF_NAME).read_bytes(), PDF_BYTES)


class PartBytesUnitTest(TestCase):
    """Il punto condiviso: una sola funzione per tutti i chiamanti."""

    def test_returns_none_when_there_is_nothing_to_serialize(self):
        part = email_mod.message_from_string("Content-Type: message/rfc822\n\n")
        part.set_payload([])
        self.assertIsNone(email_client._part_bytes(part))

    def test_serializes_a_container_that_carries_a_submessage(self):
        part = email_mod.message_from_string("Content-Type: message/rfc822\n\n")
        self.assertIsNone(part.get_payload(decode=True))
        self.assertTrue(email_client._part_bytes(part))

    def test_decodes_base64_parts(self):
        part = email_mod.message_from_string(
            "Content-Type: application/octet-stream\n"
            "Content-Transfer-Encoding: base64\n\nY2lhbw==\n"
        )
        self.assertEqual(email_client._part_bytes(part), b"ciao")

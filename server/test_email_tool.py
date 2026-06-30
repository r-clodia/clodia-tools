from pathlib import Path
from tempfile import NamedTemporaryFile
from unittest import TestCase
from unittest.mock import patch

from server.tools import email


class EmailAttachmentToolTest(TestCase):
    def test_send_forwards_attachment_paths_to_cli(self):
        with NamedTemporaryFile() as fp:
            attachment = str(Path(fp.name))
            with patch.object(email, "tool_allowed"), \
                 patch.object(email, "_run_cli", return_value={"stdout": "ok"}) as run_cli:
                result = email.send(
                    "to@example.com",
                    "Subject",
                    "Body",
                    attachments=[attachment],
                )

        run_cli.assert_called_once_with(
            "demo",
            [
                "send",
                "--to", "to@example.com",
                "--subject", "Subject",
                "--body", "Body",
                "--attachment", attachment,
            ],
            want_json=False,
        )
        self.assertEqual(result["attachments"], [attachment])

    def test_reply_forwards_attachment_paths_to_cli(self):
        with NamedTemporaryFile() as fp:
            attachment = str(Path(fp.name))
            with patch.object(email, "tool_allowed"), \
                 patch.object(email, "_run_json", return_value={"status": "ok"}) as run_json:
                email.reply("42", "Body", attachments=[attachment])

        run_json.assert_called_once_with(
            "demo",
            [
                "reply",
                "42",
                "--body", "Body",
                "--folder", "INBOX",
                "--attachment", attachment,
            ],
        )

    def test_send_rejects_missing_attachment_path(self):
        with patch.object(email, "tool_allowed"), \
             patch.object(email, "_run_cli") as run_cli:
            with self.assertRaisesRegex(ValueError, "attachment not found"):
                email.send(
                    "to@example.com",
                    "Subject",
                    "Body",
                    attachments=["/definitely/missing/file.pdf"],
                )

        run_cli.assert_not_called()

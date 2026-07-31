import json
import subprocess
from pathlib import Path
from tempfile import NamedTemporaryFile
from unittest import TestCase
from unittest.mock import patch

from server import main
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


class EmailAccountSelectionTest(TestCase):
    def test_three_grants_require_explicit_account_with_valid_values(self):
        with patch.object(main, "agent_name", return_value="clodia"), \
             patch.object(
                 main.email,
                 "available_accounts",
                 return_value=["devnullboxx", "info", "studio"],
             ):
            with self.assertRaisesRegex(
                ValueError,
                "parametro 'account'.*devnullboxx.*info.*studio",
            ):
                main._email_account({})

    def test_single_grant_is_selected_automatically(self):
        with patch.object(main, "agent_name", return_value="clodia"), \
             patch.object(main.email, "available_accounts", return_value=["studio"]):
            self.assertEqual(main._email_account({}), "studio")

    def test_invalid_explicit_account_reports_valid_values(self):
        with patch.object(main, "agent_name", return_value="clodia"), \
             patch.object(main.email, "available_accounts", return_value=["studio"]):
            with self.assertRaisesRegex(
                ValueError, "account 'demo' non disponibile.*studio"
            ):
                main._email_account({"account": "demo"})

    def test_send_list_and_read_keep_the_selected_account(self):
        with patch.object(email, "tool_allowed"), \
             patch.object(email, "_run_cli", return_value={"stdout": "ok"}) as run_cli, \
             patch.object(email, "_run_json", return_value=[]) as run_json:
            email.send("to@example.com", "Subject", "Body", account="studio")
            email.list_messages(account="studio", folder="INBOX", limit=5)
            email.read_message("42", account="studio", folder="Archive")

        run_cli.assert_called_once_with(
            "studio",
            ["send", "--to", "to@example.com", "--subject", "Subject", "--body", "Body"],
            want_json=False,
        )
        self.assertEqual(run_json.call_args_list[0].args[0], "studio")
        self.assertEqual(run_json.call_args_list[0].args[1][0], "list")
        self.assertEqual(run_json.call_args_list[1].args[0], "studio")
        self.assertEqual(run_json.call_args_list[1].args[1][0], "read")


class EmailVaultMaterializationTest(TestCase):
    def test_mailbox_bundle_is_materialized_only_for_cli_call(self):
        bundle = {
            "email": "studio@example.com",
            "password": "secret",
            "imap_server": "imap.example.com",
            "imap_port": 993,
            "smtp_server": "smtp.example.com",
            "smtp_port": 587,
        }
        observed = {}

        def has_credential(name):
            return name == "mailbox_studio"

        def run(cmd, **kwargs):
            observed["secrets_dir"] = Path(kwargs["env"]["CLODIA_SECRETS_DIR"])
            config_file = observed["secrets_dir"] / "email_config.json"
            observed["config"] = json.loads(config_file.read_text(encoding="utf-8"))
            observed["mode"] = oct(config_file.stat().st_mode)[-3:]
            observed["cmd"] = cmd
            return subprocess.CompletedProcess(cmd, 0, stdout='["INBOX", "Sent"]', stderr="")

        with patch.object(email, "tool_allowed"), \
             patch.object(email, "agent_name", return_value="clodia"), \
             patch.object(email, "available_accounts", return_value=["studio"]), \
             patch.object(email.vault, "has_credential", side_effect=has_credential), \
             patch.object(email.vault, "get_secret", return_value=bundle), \
             patch.object(email, "known_accounts", return_value={"studio"}), \
             patch.object(email.subprocess, "run", side_effect=run):
            result = email.folders("studio")

        self.assertEqual(result["available_accounts"], ["studio"])
        self.assertEqual(result["folders"], ["INBOX", "Sent"])
        self.assertEqual(observed["config"]["accounts"]["studio"], bundle)
        self.assertEqual(observed["mode"], "600")
        self.assertIn("--account", observed["cmd"])
        self.assertFalse(observed["secrets_dir"].exists())

    def test_diagnostics_mark_incomplete_mailbox_non_operational(self):
        with patch.object(email.vault, "store_names", return_value=["mailbox_studio"]), \
             patch.object(
                 email.vault,
                 "read_internal",
                 return_value={"email": "studio@example.com"},
             ):
            rows = email.credential_diagnostics()

        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["operational"])
        self.assertEqual(
            rows[0]["missing"], [
                "imap_server", "imap_port", "smtp_server", "smtp_port",
                "password|app_password",
            ]
        )


class RuntimeConfigurationDiagnosticsTest(TestCase):
    def test_warns_for_missing_namespace_and_unmaterializable_email(self):
        config = {
            "agents": {"avvocato": {"allowed_tools": ["normattiva.*", "email.send"]}},
            "mcp_backends": [],
        }
        with patch("server.whitelist.CONFIG", config), \
             patch.object(main, "_native_tool_namespaces", return_value=["email"]), \
             patch.object(main.email, "credential_diagnostics", return_value=[{
                 "credential": "mailbox_studio",
                 "operational": False,
                 "missing": ["password"],
                 "error": None,
             }]):
            warnings = main.runtime_configuration_warnings()

        self.assertTrue(any("namespace 'normattiva'" in warning for warning in warnings))
        self.assertTrue(any("mailbox_studio" in warning for warning in warnings))

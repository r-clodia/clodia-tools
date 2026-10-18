"""The boot's configuration warnings about mail credentials, from the side in
charge of mail (`mail_switch`; comms-pack's component on `mail: pack`, #523)."""
from unittest import TestCase
from unittest.mock import patch

from server import main


class RuntimeConfigurationDiagnosticsTest(TestCase):
    def test_warns_for_missing_namespace_and_unmaterializable_email(self):
        config = {
            "agents": {"avvocato": {"allowed_tools": ["normattiva.*", "email.send"]}},
            "mcp_backends": [],
        }
        with patch("server.whitelist.CONFIG", config), \
             patch.object(main, "_native_tool_namespaces", return_value=["email"]), \
             patch("server.tools.mail_switch.credential_diagnostics", return_value=[{
                 "credential": "mailbox_studio",
                 "operational": False,
                 "missing": ["password"],
                 "error": None,
             }]):
            warnings = main.runtime_configuration_warnings()

        self.assertTrue(any("namespace 'normattiva'" in warning for warning in warnings))
        self.assertTrue(any("mailbox_studio" in warning for warning in warnings))

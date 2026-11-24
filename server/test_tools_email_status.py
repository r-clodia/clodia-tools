import json
import unittest
from unittest.mock import patch

from starlette.requests import Request

from . import tools_api


def _request(path: str) -> Request:
    return Request({
        "type": "http",
        "method": "GET",
        "path": path,
        "headers": [],
        "query_string": b"",
    })


class ToolsEmailStatusTest(unittest.IsolatedAsyncioTestCase):
    async def test_connectors_distinguish_present_from_operational(self):
        diagnostics = [
            {
                "credential": "google_broken",
                "account": "broken",
                "kind": "google",
                "operational": False,
                "missing": ["refresh_token"],
                "error": None,
            },
            {
                "credential": "mailbox_studio",
                "account": "studio",
                "kind": "mailbox",
                "operational": True,
                "missing": [],
                "error": None,
            },
        ]
        with patch.object(tools_api, "_authorized", return_value=True), \
             patch.object(
                 tools_api.email_tool, "credential_diagnostics", return_value=diagnostics
             ), \
             patch("server.tools.mail_switch.service", return_value=lambda *a: []), \
             patch("server.tools.mail_switch.credential_diagnostics",
                   return_value=[r for r in diagnostics if r["kind"] == "mailbox"]), \
             patch.object(tools_api.vault, "has_credential", return_value=False), \
             patch.object(tools_api.instance_profile, "connectors_allowed", return_value=None), \
             patch.dict(tools_api.whitelist.CONFIG, {"mcp_backends": []}, clear=True):
            response = await tools_api.list_tools(_request("/tools"))

        connectors = {
            row["id"]: row for row in json.loads(response.body)["connectors"]
        }
        self.assertFalse(connectors["google"]["connected"])
        self.assertFalse(connectors["google"]["operational"])
        self.assertEqual(connectors["google"]["issues"][0]["account"], "broken")
        self.assertTrue(connectors["mail"]["connected"])
        self.assertTrue(connectors["mail"]["operational"])
        self.assertEqual(connectors["mail"]["accounts"], ["studio"])

    async def test_each_mailbox_is_its_own_integration(self):
        """#733: a row per mailbox, with its own status and switch; the
        colony mailbox is marked."""
        rows = [
            {"credential": "mailbox_studio", "account": "studio", "kind": "mailbox",
             "operational": True, "enabled": True, "send_only": False,
             "missing": [], "error": None},
            {"credential": "mailbox_info", "account": "info", "kind": "mailbox",
             "operational": True, "enabled": False, "send_only": True,
             "missing": [], "error": None},
            {"credential": "mailbox_rotta", "account": "rotta", "kind": "mailbox",
             "operational": False, "enabled": True, "send_only": False,
             "missing": ["smtp_server"], "error": None},
        ]
        addresses = {"studio": "studio@x.it", "info": "info@x.it", "rotta": None}
        with patch.object(tools_api, "_authorized", return_value=True), \
             patch.object(tools_api.email_tool, "credential_diagnostics", return_value=[]), \
             patch("server.tools.mail_switch.service",
                   return_value=lambda acct=None, *a: addresses.get(acct)), \
             patch("server.tools.mail_switch.credential_diagnostics", return_value=rows), \
             patch.object(tools_api.vault, "has_credential", return_value=False), \
             patch.object(tools_api.instance_profile, "connectors_allowed", return_value=None), \
             patch.dict(tools_api.whitelist.CONFIG,
                        {"mcp_backends": [], "colony_mailbox": "studio"}, clear=True):
            response = await tools_api.list_tools(_request("/tools"))
        c = {row["id"]: row for row in json.loads(response.body)["connectors"]}
        self.assertIn("mail", c)            # where mailboxes are added
        self.assertEqual(c["mailbox:studio"]["label"], "studio@x.it")
        self.assertTrue(c["mailbox:studio"]["operational"])
        self.assertTrue(c["mailbox:studio"]["colony"])
        self.assertFalse(c["mailbox:info"]["enabled"])
        self.assertFalse(c["mailbox:info"]["operational"])
        self.assertTrue(c["mailbox:info"]["send_only"])
        self.assertEqual(c["mailbox:rotta"]["label"], "rotta")
        self.assertEqual(c["mailbox:rotta"]["issues"][0]["missing"], ["smtp_server"])


if __name__ == "__main__":
    unittest.main()

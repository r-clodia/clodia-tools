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
        self.assertTrue(connectors["mailboxes"]["connected"])
        self.assertTrue(connectors["mailboxes"]["operational"])
        self.assertEqual(connectors["mailboxes"]["accounts"], ["studio"])


if __name__ == "__main__":
    unittest.main()

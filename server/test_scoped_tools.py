from __future__ import annotations

import unittest
from unittest.mock import patch

from . import gate, pki_mint, whitelist
from .tools import agents_admin


class ScopedToolsTests(unittest.TestCase):
    def test_scoped_tools_are_request_local_and_resettable(self):
        self.assertEqual(whitelist.current_scoped_tools(), ())
        token = whitelist.set_current_scoped_tools(
            ["email.send", "email.send", "fs.read"])
        try:
            self.assertEqual(
                whitelist.current_scoped_tools(), ("email.send", "fs.read"))
        finally:
            whitelist.reset_current_scoped_tools(token)
        self.assertEqual(whitelist.current_scoped_tools(), ())

    def test_scoped_mutations_are_gated(self):
        self.assertTrue(gate.is_gated("agents.grant_scoped"))
        self.assertTrue(gate.is_gated("agents.revoke_scoped"))
        self.assertFalse(gate.is_gated("agents.list_scoped"))

    def test_session_minter_rejects_scoped_admin_tools(self):
        with self.assertRaises(PermissionError):
            pki_mint.mint_session_token(
                "clodia", scoped_tools=["agents.grant_scoped"])

    def test_channel_topic_is_default_scope(self):
        chat_token = whitelist.set_current_chat("chan:SEAL-2:contract:clodia")
        try:
            with patch.object(agents_admin, "_request", return_value={"ok": True}) as req:
                agents_admin.grant_scoped(
                    "wainston", {"agent": "wainston", "tools": ["email.send"]},
                    "ccap1.signed",
                )
        finally:
            whitelist.reset_current_chat(chat_token)
        body = req.call_args.args[2]
        self.assertEqual(body["scope_kind"], "topic")
        self.assertEqual(body["scope_id"], "SEAL-2/contract")
        self.assertEqual(body["approval_token"], "ccap1.signed")


if __name__ == "__main__":
    unittest.main()

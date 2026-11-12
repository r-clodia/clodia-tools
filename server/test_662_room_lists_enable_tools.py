"""#662 — a room's list entry (Fonti, Mittenti, Destinatari, Gruppi e contatti…)
enables its tool, and an outbound one is allowed by the tool's own row.

Owner, 9 Nov 2026: «se aggiungo una fonte vuol dire che automaticamente sto
abilitando anche lo strumento web». Removing the entry removes its own allow
row; the tool stays (only the owner revokes it).
"""
from __future__ import annotations

from unittest.mock import patch

from . import egress
from . import room_tools as RT
from . import whitelist
from .test_620_room_mcp import _Env

CAT = {
    "web": {"id": "web", "label": "Web", "kind": "native", "namespaces": ["web"],
            "enumerable": True, "verbs": ["web.fetch", "web.post"], "write": ["web.post"],
            "schemes": [{"scheme": "http", "direction": "egress", "verbs": ["web.post"]}]},
    "email": {"id": "email", "label": "Email", "kind": "connector", "namespaces": ["email"],
              "enumerable": True, "verbs": ["email.read", "email.send"], "write": ["email.send"],
              "schemes": [{"scheme": "mailfrom", "direction": "source", "verbs": ["email.read"]},
                          {"scheme": "mailto", "direction": "egress", "verbs": ["email.send"]}]},
    "google": {"id": "google", "label": "Google", "kind": "connector",
               "namespaces": ["gdrive"], "enumerable": True, "verbs": ["gdrive.update"],
               "write": ["gdrive.update"],
               "schemes": [{"scheme": "gdrive", "direction": "egress", "verbs": ["gdrive.update"]}]},
    "telegram": {"id": "telegram", "label": "Telegram", "kind": "connector",
                 "namespaces": ["telegram"], "enumerable": True, "verbs": ["telegram.send"],
                 "write": ["telegram.send"],
                 "schemes": [{"scheme": "tg", "direction": "egress", "verbs": ["telegram.send"]}]},
}
SCOPE = "SEAL-1/blog"


class RoomListTests(_Env):
    def setUp(self):
        super().setUp()
        whitelist.CONFIG.update({"scope_source_allow": {}, "scope_egress_allow": {}})
        p = patch.object(RT, "mcp_catalogue", lambda: CAT)
        p.start(); self.addCleanup(p.stop)
        # The schemes come from the connector manifests, not loaded here.
        d = patch.dict(egress._DIRECTIONS, {
            "egress": ("egress_allow", lambda: ("http", "https", "mailto", "tg", "wa", "gdrive"),
                       "destinazione ammessa"),
            "ingress": ("source_allow", lambda: ("http", "https", "mailfrom", "tg", "wa", "topic"),
                        "fonte fidata")})
        d.start(); self.addCleanup(d.stop)

    def mcp(self):
        return RT._mcp_entries(self.meta())

    def test_a_source_enables_web_with_no_row(self):
        out = egress.scope_allow("ingress", SCOPE, "https://www.ntsb.gov/")
        self.assertEqual(out.get("mcp_authorised"), "web")
        self.assertEqual(self.mcp()["web"]["resources"], [])

    def test_the_open_web_enables_web(self):
        egress.scope_allow("ingress", SCOPE, "https:*")
        self.assertIn("web", self.mcp())

    def test_a_sender_enables_email_a_recipient_is_allowed(self):
        egress.scope_allow("ingress", SCOPE, "mailfrom:a@b.it")
        self.assertIn("email", self.mcp())
        self.assertEqual(self.mcp()["email"]["resources"], [])
        out = egress.scope_allow("egress", SCOPE, "mailto:c@d.it")
        self.assertEqual(out.get("resource_allowed"), "mailto:c@d.it")
        self.assertEqual(self.mcp()["email"]["resources"],
                         [{"uri": "mailto:c@d.it", "effect": "allow"}])

    def test_a_web_destination_is_a_row_although_the_tool_says_http(self):
        egress.scope_allow("egress", SCOPE, "https://api.example.com/")
        self.assertEqual(self.mcp()["web"]["resources"],
                         [{"uri": "https://api.example.com/", "effect": "allow"}])

    def test_a_chat_is_allowed_both_ways(self):
        egress.scope_allow("ingress", SCOPE, "tg:-100123")
        self.assertEqual(self.mcp()["telegram"]["resources"],
                         [{"uri": "tg:-100123", "effect": "allow"}])

    def test_removing_takes_its_allow_row_not_the_tool_nor_a_deny(self):
        egress.scope_allow("egress", SCOPE, "mailto:c@d.it")
        RT.set_resource("SEAL-1", "blog", "email", "mailto:x@y.it", "deny")
        egress.scope_revoke("egress", SCOPE, "mailto:c@d.it")
        self.assertIn("email", self.mcp())
        self.assertEqual(self.mcp()["email"]["resources"],
                         [{"uri": "mailto:x@y.it", "effect": "deny"}])

    def test_a_drive_destination_is_allowed_on_google(self):
        egress.scope_allow("egress", SCOPE, "gdrive:folder/F1")
        self.assertEqual(self.mcp()["google"]["resources"],
                         [{"uri": "gdrive:folder/F1", "effect": "allow"}])

    def test_an_entry_of_no_tool_changes_nothing(self):
        egress.scope_allow("ingress", SCOPE, "topic:SEAL-1/altro")
        self.assertEqual(self.mcp(), {})

    def test_a_tool_the_instance_lacks_is_left_alone(self):
        egress.scope_allow("ingress", SCOPE, "wa:+390000000000")
        self.assertNotIn("whatsapp", self.mcp())


if __name__ == "__main__":
    import unittest
    unittest.main()

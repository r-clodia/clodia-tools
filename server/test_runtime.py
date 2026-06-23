"""Test del runtime-introspection MCP: shaping read-only e niente segreti."""
from __future__ import annotations

import unittest

from .tools import runtime


class RuntimeIntrospectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._orig_get = runtime._get

    def tearDown(self) -> None:
        runtime._get = self._orig_get

    def test_agents_shape(self) -> None:
        runtime._get = lambda path: {"agents": [
            {"name": "clodia", "display_name": "Clodia", "type": "super",
             "provider": "claude-pro-max", "provider_connected": True,
             "model": "x", "secret_field": "NOPE"}]}
        out = runtime.agents()
        self.assertEqual(out["count"], 1)
        self.assertEqual(out["agents"][0]["name"], "clodia")
        # solo i campi whitelisted: nessun campo extra/segreto passa
        self.assertNotIn("secret_field", out["agents"][0])

    def test_providers_no_secrets(self) -> None:
        runtime._get = lambda path: {"providers": [
            {"id": "anthropic-api", "name": "Anthropic API", "mechanism": "apikey",
             "connected": True, "api_key": "sk-LEAK", "refresh_token": "LEAK"}]}
        out = runtime.providers()
        p = out["providers"][0]
        self.assertEqual(p["id"], "anthropic-api")
        self.assertNotIn("api_key", p)
        self.assertNotIn("refresh_token", p)

    def test_current_user_owner_is_superadmin(self) -> None:
        runtime._get = lambda path: {"agents": [
            {"name": "clodia", "type": "super"},
            {"name": "ospite", "type": "human", "role": "admin", "display_name": "Ospite"},
            {"name": "owner", "type": "human", "role": "superadmin", "display_name": "owner"}]}
        out = runtime.current_user()
        self.assertEqual(out["user"]["name"], "owner")
        self.assertEqual(out["user"]["role"], "superadmin")
        self.assertEqual(sorted(h["name"] for h in out["humans"]), ["owner", "ospite"])

    def test_current_user_none_when_no_humans(self) -> None:
        runtime._get = lambda path: {"agents": [{"name": "clodia", "type": "super"}]}
        out = runtime.current_user()
        self.assertIsNone(out["user"])
        self.assertFalse(out["authenticated"])
        self.assertEqual(out["humans"], [])

    def test_current_user_authenticated_principal_wins(self) -> None:
        from server import whitelist
        runtime._get = lambda path: {"agents": [
            {"name": "owner", "type": "human", "role": "superadmin", "display_name": "owner"},
            {"name": "marco", "type": "human", "role": "member", "display_name": "Marco"}]}
        tok = whitelist.set_current_principal("marco")  # utente loggato non-admin
        try:
            out = runtime.current_user()
        finally:
            whitelist.reset_current_principal(tok)
        self.assertTrue(out["authenticated"])
        self.assertEqual(out["user"]["name"], "marco")
        self.assertEqual(out["user"]["role"], "member")

    def test_chats_metadata_only(self) -> None:
        runtime._get = lambda path: [
            {"chat_id": "c1", "kind": "clodia", "title": "t", "status": "idle",
             "history": ["segreto"]}]
        out = runtime.chats()
        self.assertEqual(out["chats"][0]["chat_id"], "c1")
        self.assertNotIn("history", out["chats"][0])

    def test_topics_excludes_p3_by_default(self) -> None:
        import types
        from . import whitelist
        # runtime.topics è scoped all'agent chiamante: deve esserne partecipante.
        fake = types.SimpleNamespace(
            list=lambda tier=None: [
                {"name": "a", "tier": "P0", "participants": ["tester"]},
                {"name": "b", "tier": "P3", "participants": ["tester"]}])
        import server.topics_api as tapi
        orig = tapi._service
        orig_name = whitelist.agent_name
        tapi._service = lambda: fake
        whitelist.agent_name = lambda: "tester"
        try:
            out = runtime.topics()
            names = [t["name"] for t in out["topics"]]
            self.assertEqual(names, ["a"])  # P3 escluso
            out2 = runtime.topics(include_restricted=True)
            self.assertEqual(sorted(t["name"] for t in out2["topics"]), ["a", "b"])
        finally:
            tapi._service = orig
            whitelist.agent_name = orig_name


if __name__ == "__main__":
    unittest.main()

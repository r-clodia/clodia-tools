"""`https:*` in a topic's ingress list (owner, 23 Oct 2026): its agents read
any https page without the per-site gate; the page stays untrusted (taint and
the trifecta count as for any read). Never global, never egress."""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from . import egress, main, whitelist  # noqa: F401


class OpenWebTests(unittest.TestCase):
    def setUp(self):
        self.cfg = {"scope_source_allow": {}, "source_allow": [], "agents": {}}
        for p in [patch.object(whitelist, "CONFIG", self.cfg),
                  patch.object(whitelist, "save_config", lambda: None)]:
            p.start()
            self.addCleanup(p.stop)

    def test_granted_only_in_a_room_ingress_list(self):
        egress.scope_allow("ingress", "SEAL-1/blog", "HTTPS:*")
        self.assertTrue(egress.open_web("SEAL-1/blog"))
        self.assertFalse(egress.open_web("SEAL-2/altro"))
        with self.assertRaises(ValueError):
            egress.allow("ingress", "https:*")
        with self.assertRaises(ValueError):
            egress.scope_allow("egress", "SEAL-1/blog", "https:*")
        with self.assertRaises(ValueError):
            egress.scope_allow("ingress", "SEAL-1/blog", "https://*")

    def test_it_never_makes_the_web_trusted_nor_widens_a_list(self):
        egress.scope_allow("ingress", "SEAL-1/blog", "https:*")
        self.cfg["source_allow"] = ["https:*"]                       # hand-written
        self.cfg["scope_egress_allow"] = {"SEAL-1/blog": ["https:*"]}
        self.assertFalse(egress.is_vetted_source("https://www.uni.com/x", scope="SEAL-1/blog"))
        self.assertFalse(egress._matches("https://evil.example/", "https:*"))

    def _gate(self, scope):
        asked = []

        async def consent(*a, **k):
            asked.append(a)
            raise PermissionError("gate")
        with patch("server.egress._scope_of_call", lambda: scope), \
                patch.object(main, "current_chat", lambda: f"chan:{scope.replace('/', ':')}:fact-checker"), \
                patch.object(main, "_require_gate_consent", consent, create=True), \
                patch.object(main.web_fetch, "_safe_url", lambda u: u):
            try:
                asyncio.run(main._require_web_source("web.fetch", {"url": "https://www.uni.com/x"},
                                                     "fact-checker"))
                return "open"
            except PermissionError:
                return "gated"

    def test_no_per_site_gate_in_the_open_room_only(self):
        egress.scope_allow("ingress", "SEAL-1/blog", "https:*")
        self.assertEqual(self._gate("SEAL-1/blog"), "open")
        self.assertEqual(self._gate("SEAL-1/altro"), "gated")


if __name__ == "__main__":
    unittest.main()

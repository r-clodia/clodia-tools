"""#647 — adding to the caller's own room an entry it already lists asks nobody.

The fact-checker calls `topic.ingress_add(uri: "https:*")` when it starts
working in a room: the first time the owner gets ONE card; afterwards the call
moves nothing and must not ask again. Only the caller's room: on another room
the answer would tell what that room lists.
"""
from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from . import egress, whitelist


class AlreadyInOwnRoomTests(unittest.TestCase):
    def setUp(self):
        self.cfg = {"scope_source_allow": {}, "scope_egress_allow": {},
                    "source_allow": [], "agents": {}}
        for p in [patch.object(whitelist, "CONFIG", self.cfg),
                  patch.object(whitelist, "save_config", lambda: None)]:
            p.start()
            self.addCleanup(p.stop)

    def _from(self, scope):
        return patch("server.egress._scope_of_call", lambda: scope)

    def test_missing_open_web_is_not_a_noop(self):
        with self._from("SEAL-1/convegno"):
            self.assertFalse(egress.already_in_own_room("ingress", "SEAL-1/convegno", "https:*"))

    def test_listed_open_web_is_a_noop_whatever_the_case(self):
        egress.scope_allow("ingress", "SEAL-1/convegno", "https:*")
        with self._from("SEAL-1/convegno"):
            for uri in ("https:*", "HTTPS:*", " https:* "):
                self.assertTrue(egress.already_in_own_room("ingress", "SEAL-1/convegno", uri), uri)

    def test_an_alias_of_the_room_is_the_same_room(self):
        egress.scope_allow("ingress", "SEAL-1/convegno", "https:*")
        with self._from("P1/convegno"):
            self.assertTrue(egress.already_in_own_room("ingress", "SEAL-1/convegno", "https:*"))

    def test_another_room_is_never_answered(self):
        egress.scope_allow("ingress", "SEAL-1/altra", "https:*")
        with self._from("SEAL-1/convegno"):
            self.assertFalse(egress.already_in_own_room("ingress", "SEAL-1/altra", "https:*"))
        with self._from(None):
            self.assertFalse(egress.already_in_own_room("ingress", "SEAL-1/altra", "https:*"))

    def test_the_direction_counts(self):
        egress.scope_allow("ingress", "SEAL-1/convegno", "https://www.ntsb.gov/")
        with self._from("SEAL-1/convegno"):
            self.assertFalse(egress.already_in_own_room("egress", "SEAL-1/convegno",
                                                        "https://www.ntsb.gov/"))

    def test_a_listed_site_is_a_noop_but_another_site_is_not(self):
        egress.scope_allow("ingress", "SEAL-1/convegno", "https://www.ntsb.gov/")
        with self._from("SEAL-1/convegno"):
            self.assertTrue(egress.already_in_own_room("ingress", "SEAL-1/convegno",
                                                       "https://www.ntsb.gov/"))
            self.assertFalse(egress.already_in_own_room("ingress", "SEAL-1/convegno",
                                                        "https://www.reuters.com/"))


class DispatchWiringTests(unittest.TestCase):
    """The dispatch consults it for the two add verbs, before the consent."""

    def test_the_noop_check_guards_needs_consent(self):
        src = Path(__file__).with_name("main.py").read_text(encoding="utf-8")
        i = src.index("_gia_presente = False")
        j = src.index("_gate.needs_consent(", i)
        block = src[i:j]
        self.assertIn('("topic.ingress_add", "topic.egress_add")', block)
        self.assertIn("already_in_own_room", block)
        self.assertIn("if not _gia_presente and", src[j - 40:j])


if __name__ == "__main__":
    unittest.main()

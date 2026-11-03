"""#650 — an MCP enabled in the room is authorised there (owner, 3 Nov 2026).

Normattiva's verbs (`risolvi`, `articolo`, …) are described by no manifest and
are not named in English: the name heuristic counted them as writes, and the
room's toolbox row (`default`) asked on every call. In a room, a verb no
manifest maps and that acts on no nameable target takes the read default:
allowed where the room enables the MCP. Mapped verbs keep their destinations
judged (review of #435, S1); explicit rules and a global deny still win.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from server import authz as A
from server import authz_runtime as R

SCOPE = "SEAL-2/preventivo"


def _tuples(raws, level):
    ok, bad = A.parse_tuples(raws, level=level, internal=True)
    assert not bad, bad
    return ok


def _toolbox(*verbs, extra=()):
    return _tuples([{"id": f"toolbox:{v}", "agent": "*", "verb": v, "resource": "*",
                     "rule": [{"effect": A.DEFAULT}]} for v in verbs] + list(extra), A.TOPIC)


def _check(verb, *, t, g=(), facts=None, scope=SCOPE, targets=None):
    f = facts or {"resource": "*", "kind": A.WRITE, "targets": [], "mapped": False}
    with patch.object(R, "tuples_for", lambda a, s: (list(g), t)), \
            patch.object(R.S, "facts", lambda v, a: dict(f)):
        return R.check("avvocato", verb, {}, scope, False, targets=targets).effect


class RoomToolAuthorisedTests(unittest.TestCase):
    def test_an_unmapped_verb_of_an_enabled_mcp_is_allowed(self):
        t = _toolbox("normattiva.*")
        for verb in ("normattiva.risolvi", "normattiva.articolo",
                     "normattiva.indice", "normattiva.alias"):
            self.assertEqual(_check(verb, t=t), A.ALLOW, verb)

    def test_not_enabled_in_the_room_is_still_refused(self):
        self.assertEqual(_check("normattiva.articolo", t=_toolbox("email.*")), A.DENY)

    def test_a_mapped_verb_keeps_its_destinations_judged(self):
        f = {"resource": "mail:default", "kind": A.WRITE,
             "targets": ["mailto:x@evil.com"], "mapped": True}
        self.assertEqual(_check("email.send", t=_toolbox("email.*"), facts=f), A.ASK)

    def test_a_mapped_verb_without_targets_still_asks(self):
        f = {"resource": "github:default", "kind": A.WRITE, "targets": [], "mapped": True}
        self.assertEqual(_check("github.push", t=_toolbox("github.*"), facts=f), A.ASK)

    def test_component_targets_are_judged_as_before(self):
        self.assertEqual(_check("x.do", t=_toolbox("x.*"), targets=[]), A.ASK)

    def test_an_explicit_room_ask_still_asks(self):
        t = _toolbox("normattiva.*", extra=[{"id": "t-ask", "agent": "avvocato",
                                             "verb": "normattiva.articolo", "resource": "*",
                                             "rule": [{"effect": "ask", "match": "*"}]}])
        self.assertEqual(_check("normattiva.articolo", t=t), A.ASK)

    def test_a_global_deny_still_wins(self):
        g = _tuples([{"id": "g-deny", "agent": "*", "verb": "normattiva.*", "resource": "*",
                      "rule": [{"effect": "deny", "match": "*"}]}], A.GLOBAL)
        self.assertEqual(_check("normattiva.articolo", t=_toolbox("normattiva.*"), g=g), A.DENY)

    def test_outside_a_room_nothing_changes(self):
        g = _tuples([{"id": "g-1", "agent": "*", "verb": "normattiva.*", "resource": "*",
                      "rule": [{"effect": A.DEFAULT}]}], A.GLOBAL)
        self.assertEqual(_check("normattiva.articolo", t=None, g=g, scope=None), A.ASK)


if __name__ == "__main__":
    unittest.main()

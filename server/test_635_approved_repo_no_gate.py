"""#635 — operations on a repository approved in the room run without a gate.

Owner requirement (29 Oct 2026): a repository authorised as an allow row of
the room's GitHub panel is granted for every git verb on it, reads and writes
alike; a repository not approved still asks.

The verbs reached A·V·R·Q without their repository (`clone`/`pull` are
`unmapped`, `push` takes a working tree): the serving component now names it
(`authz_targets`) and it is judged as an ordinary target, BEFORE the decision —
so a global deny, an explicit ask and the tainted-context rule apply to it as
to any other target (review of the first version, which converted an `ask`
after the fact and bypassed them). The caller's own `repo` argument is never
the target when the component names one. Also #636: a path rule covers its
subtree on a path boundary, never a sibling (`repo-fork`).
"""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from server import authz as A
from server import authz_runtime as R
from server import egress

REPO = "https://github.com/ddbit/tomatoblue-next"
AGENT = "tomato.fullstack-dev"


def _tuples(raws, level):
    ok, bad = A.parse_tuples(raws, level=level, internal=True)
    assert not bad, bad
    return ok


def _room(extra=()):
    """The room's derived tuples as `_toolbox_tuples` + `_resource_tuples`
    build them: GitHub enabled, one allow row on the repository."""
    raws = [{"id": f"toolbox:{v}", "agent": "*", "verb": v, "resource": "*",
             "rule": [{"effect": A.DEFAULT}]}
            for v in ("github.clone", "github.pull", "github.push", "github.pull_request")]
    raws += [{"id": f"resource:{v}", "agent": "*", "verb": v, "resource": "*",
              "rule": [{"effect": "allow", "match": REPO}]}
             for v in ("github.clone", "github.pull", "github.push", "github.pull_request")]
    return _tuples(raws + list(extra), A.TOPIC)


def _decide(verb, targets, *, g=(), t=None, tainted=False):
    kind = A.READ if verb in ("github.clone", "github.pull") else A.WRITE
    return A.decide(list(g), _room() if t is None else t, agent=AGENT, verb=verb,
                    resource="github:default", targets=targets, kind=kind,
                    tainted=tainted)


class DecisionTests(unittest.TestCase):
    """The component's target goes through the ordinary decision."""

    def test_an_approved_repository_is_allowed_for_every_git_verb(self):
        for verb in ("github.clone", "github.pull", "github.push", "github.pull_request"):
            d = _decide(verb, [REPO])
            self.assertEqual(d.effect, A.ALLOW, verb)
            self.assertTrue(R.allowed_by_room_rows(d), verb)

    def test_without_the_target_a_write_asks_as_before(self):
        self.assertEqual(_decide("github.push", []).effect, A.ASK)

    def test_another_repository_and_a_sibling_still_ask(self):
        for other in ("https://github.com/ddbit/other", REPO + "-fork"):
            d = _decide("github.push", [other])
            self.assertEqual(d.effect, A.ASK, other)
            self.assertFalse(R.allowed_by_room_rows(d))

    def test_a_global_deny_on_the_repository_wins(self):
        g = _tuples([{"id": "g-deny", "agent": "*", "verb": "github.push", "resource": "*",
                      "rule": [{"effect": "deny", "match": REPO}]}], A.GLOBAL)
        self.assertEqual(_decide("github.push", [REPO], g=g).effect, A.DENY)

    def test_an_explicit_room_ask_is_not_overruled_by_a_row(self):
        explicit = [{"id": "t-1", "agent": AGENT, "verb": "github.push", "resource": "*",
                     "rule": [{"effect": "ask", "match": REPO}]}]
        d = _decide("github.push", [REPO], t=_room(explicit))
        self.assertNotEqual(d.effect, A.ALLOW)


class CheckTests(unittest.TestCase):
    def test_the_component_target_replaces_the_caller_s_repo(self):
        """`github.push` ignores a `repo` argument: an approved URL passed
        there must not be what is judged (review of #635, H1)."""
        seen = {}

        def _decide_spy(g, t, **kw):
            seen.update(kw)
            return A.Decision(A.ALLOW, True, [], "")
        with patch.object(R, "tuples_for", lambda a, s: ([], [])), \
                patch.object(R.A, "decide", _decide_spy):
            R.check(AGENT, "github.push", {"dir": "wt", "repo": REPO},
                    "SEAL-1/tomato-blogging", False,
                    targets=["https://github.com/ddbit/elsewhere"])
        self.assertEqual(seen["targets"], ["https://github.com/ddbit/elsewhere"])

    def test_without_component_targets_the_mapping_decides(self):
        seen = {}
        with patch.object(R, "tuples_for", lambda a, s: ([], [])), \
                patch.object(R.A, "decide", lambda g, t, **kw: seen.update(kw) or
                             A.Decision(A.ALLOW, True, [], "")), \
                patch.object(R.S, "facts", lambda v, a: {"resource": "x", "kind": A.WRITE,
                                                         "targets": ["mapped"], "mapped": True}):
            R.check(AGENT, "github.push", {}, "SEAL-1/x", False)
        self.assertEqual(seen["targets"], ["mapped"])


class ComponentTargetsTests(unittest.TestCase):
    class _Spec:
        pack = "it-pack"

    def _with(self, handler):
        class _Svc:
            pass
        _Svc.handler = staticmethod(handler)
        return [patch("server.main._component_verb", lambda v: self._Spec()),
                patch("server.components.service", lambda pack, name: _Svc())]

    def _run(self, handler, verb="github.push"):
        ps = self._with(handler)
        for p in ps:
            p.start()
        try:
            return R.component_targets(verb, {"dir": "wt"})
        finally:
            for p in reversed(ps):
                p.stop()

    def test_no_component_means_none(self):
        with patch("server.main._component_verb", lambda v: None):
            self.assertIsNone(R.component_targets("github.push", {}))

    def test_no_service_means_none(self):
        with patch("server.main._component_verb", lambda v: self._Spec()), \
                patch("server.components.service", lambda pack, name: None):
            self.assertIsNone(R.component_targets("github.push", {}))

    def test_a_failing_service_means_no_target(self):
        def boom(verb, args):
            raise RuntimeError("boom")
        self.assertEqual(self._run(boom), [])

    def test_a_verb_the_service_does_not_handle_means_none(self):
        self.assertIsNone(self._run(lambda v, a: None, verb="github.other"))

    def test_the_answer_is_cleaned(self):
        self.assertEqual(self._run(lambda v, a: [REPO, "", None, 3]), [REPO])


class RoomRowsCoverNamedVerbsTests(unittest.TestCase):
    def test_a_row_covers_the_component_named_verbs(self):
        cat = {"github": {"schemes": [{"scheme": "https", "direction": "egress",
                                       "verbs": ["github.push"]}],
                          "verbs": ["github.push", "github.clone", "github.list_issues"]}}
        meta = {"tools": {"mcp": {"github": {"resources": [{"uri": REPO, "effect": "allow"}]}}}}
        with patch("server.room_tools.resources",
                   lambda m: {"github": [{"uri": REPO, "effect": "allow"}]}), \
                patch("server.room_tools.mcp_catalogue", lambda: cat), \
                patch.object(R, "_targets_service",
                             lambda v: object() if v == "github.clone" else None):
            verbs = {t.verb for t in R._resource_tuples(meta)}
        self.assertEqual(verbs, {"github.push", "github.clone"})


class GateAndContextTests(unittest.TestCase):
    def test_allowed_by_room_rows_only_on_row_decisions(self):
        row = A.TargetDecision(REPO, A.ALLOW, A.TOPIC, tuple_id="resource:github.push")
        other = A.TargetDecision(REPO, A.ALLOW, A.GLOBAL, tuple_id="g-1")
        forged = A.TargetDecision(REPO, A.ALLOW, A.GLOBAL, tuple_id="resource:x")
        self.assertFalse(R.allowed_by_room_rows(A.Decision(A.ALLOW, True, [forged])))
        self.assertTrue(R.allowed_by_room_rows(A.Decision(A.ALLOW, True, [row])))
        self.assertFalse(R.allowed_by_room_rows(A.Decision(A.ALLOW, True, [row, other])))
        self.assertFalse(R.allowed_by_room_rows(A.Decision(A.ASK, True, [row])))
        self.assertFalse(R.allowed_by_room_rows(None))

    def test_host_reads_the_judged_targets_of_the_call(self):
        from server.components.host import Host
        tok = R.JUDGED.set((REPO,))
        try:
            got = Host.judged_targets(object())
            # The value travels to the worker thread the component runs in.
            in_thread = asyncio.run(asyncio.to_thread(Host.judged_targets, object()))
        finally:
            R.JUDGED.reset(tok)
        self.assertEqual(got, (REPO,))
        self.assertEqual(in_thread, (REPO,))
        self.assertEqual(Host.judged_targets(object()), ())


class PathBoundaryTests(unittest.TestCase):
    """#636: a hierarchical rule covers its subtree, never a sibling."""

    def test_siblings_are_not_covered(self):
        for rule, dest in ((REPO, REPO + "-fork"),
                           ("https://github.com/r-clodia", "https://github.com/r-clodia-evil/x"),
                           ("gdrive:folder/abc", "gdrive:folder/abcd")):
            self.assertFalse(egress._matches(dest, rule), (rule, dest))

    def test_the_subtree_is(self):
        for rule, dest in ((REPO, REPO), (REPO, REPO + "/tree/main"),
                           ("https://github.com/r-clodia/", "https://github.com/r-clodia/x"),
                           ("https://example.com", "https://example.com/a")):
            self.assertTrue(egress._matches(dest, rule), (rule, dest))


if __name__ == "__main__":
    unittest.main()

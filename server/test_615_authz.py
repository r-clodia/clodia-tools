"""#614/#615 — the A·V·R·Q engine, one test per rule of the specification."""
from __future__ import annotations

import unittest

from . import authz as A


def T(id, agent="*", verb="email.send", resource="*", rule=None, **kw):
    return A.parse_tuple({"id": id, "agent": agent, "verb": verb, "resource": resource,
                          "rule": rule or [{"effect": "allow", "match": "*"}], **kw})


def D(g, t=None, *, agent="clodia", verb="email.send", resource="mail:studio",
      targets=("mailto:anna@foo.bar",), kind=A.WRITE, tainted=False):
    return A.decide(g, t, agent=agent, verb=verb, resource=resource,
                    targets=list(targets), kind=kind, tainted=tainted)


class ParseTests(unittest.TestCase):
    def test_the_owners_example(self):
        t = T("t1", agent="clodia", resource="mail:studio",
              rule=[{"effect": "allow", "match": "mailto:*@foo.bar"}])
        self.assertTrue(t.covers("clodia", "email.send", "mail:studio"))
        self.assertFalse(t.covers("sales-rep", "email.send", "mail:studio"))
        self.assertFalse(t.covers("clodia", "email.send", "mail:altra"))

    def test_a_malformed_tuple_is_refused_and_grants_nothing(self):
        ok, bad = A.parse_tuples([
            {"id": "a", "agent": "x", "verb": "email.send", "resource": "*",
             "rule": [{"effect": "maybe", "match": "*"}]},
            {"id": "b", "agent": "x", "verb": "email", "resource": "*", "rule": []},
            {"id": "c", "agent": "x", "verb": "email.*", "resource": "*",
             "rule": [{"effect": "deny", "match": "*", "trust": "trusted"}]},
            {"id": "d", "agent": "x", "verb": "email.*", "resource": "*",
             "rule": [{"effect": "allow", "match": "*"}]}])
        self.assertEqual([t.id for t in ok], ["d"])
        self.assertEqual(len(bad), 3)


class ReviewParseTests(unittest.TestCase):
    """Review of #433."""

    def test_real_verb_names_parse(self):
        for v in ("ns.list-invoices", "x.getDoc", "normattiva-mirror.search", "a.b.c"):
            with self.subTest(v=v):
                T("t", verb=v)

    def test_governance_is_not_a_topic_decision(self):
        with self.assertRaises(A.AuthzError):
            A.parse_tuple({"id": "t", "agent": "*", "verb": "packs.import_url", "resource": "*",
                           "rule": [{"effect": "allow", "match": "*"}]}, level=A.TOPIC)
        A.parse_tuple({"id": "t", "agent": "*", "verb": "packs.import_url", "resource": "*",
                       "rule": [{"effect": "allow", "match": "*"}]}, level=A.GLOBAL)

    def test_a_match_that_can_never_match_is_refused(self):
        for m in ("mailto:", "nonuri", "https:*", "https://"):
            with self.subTest(m=m), self.assertRaises(A.AuthzError):
                A.parse_clause({"effect": "deny", "match": m})


class OneLevelTests(unittest.TestCase):
    def test_the_most_specific_clause_wins(self):
        g = [T("g", rule=[{"effect": "deny", "match": "*"},
                          {"effect": "ask", "match": "mailto:*@foo.bar"},
                          {"effect": "allow", "match": "mailto:anna@foo.bar"}])]
        self.assertEqual(D(g).effect, A.ALLOW)
        self.assertEqual(D(g, targets=["mailto:bruno@foo.bar"]).effect, A.ASK)
        self.assertEqual(D(g, targets=["mailto:x@evil.it"]).effect, A.DENY)

    def test_a_longer_prefix_is_more_specific(self):
        g = [T("g", verb="web.fetch", rule=[
            {"effect": "allow", "match": "https://example.org/"},
            {"effect": "deny", "match": "https://example.org/segreti/"}])]
        kw = dict(verb="web.fetch", resource="web", kind=A.READ)
        self.assertEqual(D(g, targets=["https://example.org/segreti/x"], **kw).effect, A.DENY)
        self.assertEqual(D(g, targets=["https://example.org/pubblico"], **kw).effect, A.ALLOW)

    def test_ties_go_to_the_more_specific_tuple_then_to_deny(self):
        g = [T("tutti", rule=[{"effect": "allow", "match": "*"}]),
             T("lei", agent="clodia", rule=[{"effect": "ask", "match": "*"}])]
        self.assertEqual(D(g).targets[0].tuple_id, "lei")
        g = [T("a", rule=[{"effect": "allow", "match": "*"}]),
             T("b", rule=[{"effect": "deny", "match": "*"}])]
        self.assertEqual(D(g).effect, A.DENY)

    def test_the_default_governs_unmatched_targets_by_kind(self):
        g = [T("g", rule=[{"effect": "allow", "match": "mailto:*@foo.bar"}])]
        self.assertEqual(D(g, targets=["mailto:x@altro.it"]).effect, A.ASK)
        r = [T("r", verb="web.fetch", rule=[{"effect": "allow", "match": "https://ec.europa.eu/",
                                            "trust": "trusted"}])]
        d = D(r, verb="web.fetch", resource="web", targets=["https://blog.example/x"], kind=A.READ)
        self.assertEqual(d.effect, A.ALLOW)
        self.assertTrue(d.targets[0].default)
        self.assertFalse(d.targets[0].trusted)

    def test_the_worst_target_decides_the_call(self):
        g = [T("g", rule=[{"effect": "allow", "match": "mailto:*@foo.bar"},
                          {"effect": "deny", "match": "mailto:*@evil.it"}])]
        d = D(g, targets=["mailto:a@foo.bar", "mailto:b@evil.it"])
        self.assertEqual(d.effect, A.DENY)

    def test_a_verb_without_targets_is_covered_only_by_star(self):
        g = [T("g", verb="topic.archive", rule=[{"effect": "allow", "match": "mailto:*"}])]
        self.assertEqual(D(g, verb="topic.archive", targets=[]).effect, A.ASK)
        g = [T("g", verb="topic.archive", rule=[{"effect": "allow", "match": "*"}])]
        self.assertEqual(D(g, verb="topic.archive", targets=[]).effect, A.ALLOW)

    def test_ns_star_covers_the_namespace(self):
        g = [T("g", verb="gdrive.*", rule=[{"effect": "deny", "match": "*"}])]
        self.assertEqual(D(g, verb="gdrive.upload", targets=["gdrive:folder/X"]).effect, A.DENY)
        self.assertFalse(D(g, verb="email.send").available)


class TwoLevelTests(unittest.TestCase):
    """§5, row by row."""

    def test_a_global_deny_holds_in_every_room(self):
        g = [T("g", rule=[{"effect": "deny", "match": "mailto:*@concorrente.it"}])]
        t = [T("t", rule=[{"effect": "allow", "match": "*"}])]
        self.assertEqual(D(g, t, targets=["mailto:x@concorrente.it"]).effect, A.DENY)

    def test_a_global_allow_the_room_may_narrow(self):
        g = [T("g", rule=[{"effect": "allow", "match": "*"}])]
        t = [T("t", rule=[{"effect": "ask", "match": "*"}])]
        self.assertEqual(D(g).effect, A.ALLOW)
        self.assertEqual(D(g, t).effect, A.ASK)

    def test_where_the_global_is_ask_or_silent_the_room_decides(self):
        g = [T("g", rule=[{"effect": "ask", "match": "*"}])]
        t = [T("t", rule=[{"effect": "allow", "match": "mailto:*@foo.bar"}])]
        self.assertEqual(D(g, t).effect, A.ALLOW)
        self.assertEqual(D([], t).effect, A.ALLOW)
        self.assertEqual(D(g, []).effect, A.ASK)

    def test_silent_at_both_levels_is_not_available(self):
        d = D([], [])
        self.assertFalse(d.available)
        self.assertEqual(d.effect, A.DENY)

    def test_nothing_here_unless_i_say_so(self):
        """§12.3: deny the namespace in the room, open one folder."""
        g = [T("g", agent="clodia", verb="gdrive.*", rule=[{"effect": "allow", "match": "*"}])]
        t = [T("niente", verb="gdrive.*", rule=[{"effect": "deny", "match": "*"}]),
             T("cartella", verb="gdrive.*", resource="google:davide",
               rule=[{"effect": "allow", "match": "gdrive:folder/TOPIC"}])]
        kw = dict(verb="gdrive.list", resource="google:davide", kind=A.READ)
        # Drive ids are flat: the folder itself here; its subfolders need the
        # ancestry resolver of the next step (#614 §3).
        self.assertEqual(D(g, t, targets=["gdrive:folder/TOPIC"], **kw).effect, A.ALLOW)
        self.assertEqual(D(g, t, targets=["gdrive:folder/PREVENTIVI"], **kw).effect, A.DENY)

    def test_outside_a_room_only_the_global_level(self):
        g = [T("g", rule=[{"effect": "allow", "match": "*"}])]
        self.assertEqual(D(g, None).effect, A.ALLOW)


class ClauseAttributeTests(unittest.TestCase):
    def test_a_trusted_read_does_not_taint(self):
        g = [T("g", verb="email.read", rule=[{"effect": "allow", "match": "mailfrom:*@cliente.it",
                                              "trust": "trusted"}])]
        d = D(g, verb="email.read", targets=["mailfrom:anna@cliente.it"], kind=A.READ)
        self.assertTrue(d.targets[0].trusted)

    def test_when_tainted_lowers_the_effect(self):
        g = [T("g", rule=[{"effect": "allow", "match": "mailto:*@foo.bar", "when_tainted": "ask"}])]
        self.assertEqual(D(g).effect, A.ALLOW)
        self.assertEqual(D(g, tainted=True).effect, A.ASK)


if __name__ == "__main__":
    unittest.main()

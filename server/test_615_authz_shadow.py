"""#615 — A·V·R·Q in shadow: facts, the translation of today's rules, the record."""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from . import authz as A
from . import authz_shadow as S
from . import egress, gate, main, whitelist


class _State(unittest.TestCase):
    """A state dir of its own, and the first-party packs installed as on a
    real instance (mail, Google, GitHub are pack connectors since #526)."""

    @classmethod
    def setUpClass(cls):
        from .connectors import first_party_fixture
        first_party_fixture.install()

    @classmethod
    def tearDownClass(cls):
        from .connectors import first_party_fixture
        first_party_fixture.uninstall()

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="authz-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        p = patch.dict(os.environ, {"CLODIA_TOOLS_STATE_DIR": self.dir})
        p.start(); self.addCleanup(p.stop)
        c = patch.object(whitelist, "CONFIG", {})
        c.start(); self.addCleanup(c.stop)


class FactsTests(_State):
    def test_a_mail_send_writes_to_its_recipients_with_the_mailbox(self):
        f = S.facts("email.send", {"to": "Anna@Foo.bar, b@x.it", "account": "studio"})
        self.assertEqual(f["kind"], A.WRITE)
        self.assertEqual(f["resource"], "mail:studio")
        self.assertIn("mailto:anna@foo.bar", f["targets"])
        self.assertIn("mailto:b@x.it", f["targets"])

    def test_an_unmapped_verb_is_classified_by_its_name(self):
        self.assertEqual(S.facts("topic.list_files", {})["kind"], A.READ)
        self.assertEqual(S.facts("topic.archive", {})["kind"], A.WRITE)
        self.assertEqual(S.facts("web.fetch", {"url": "https://x.it/a"})["resource"], "web")


class DerivedTests(_State):
    def _derive(self, verb, args, reachable=True, uris=(), gated=False, perimeter=True,
                egress_mode="gate"):
        with patch.object(main, "_agent_tool_reachable", lambda v, a: reachable), \
                patch.object(egress, "effective_uris", lambda d, s=None: list(uris)), \
                patch.object(egress, "mode", lambda: egress_mode), \
                patch.object(gate, "is_gated", lambda v: gated), \
                patch.object(gate, "perimeter_answers", lambda v: perimeter):
            return S.derived("clodia", verb, "SEAL-1/x", S.facts(verb, args))

    def test_an_unreachable_verb_has_no_tuple(self):
        self.assertEqual(self._derive("email.send", {"to": "a@b.it"}, reachable=False), [])

    def test_the_egress_list_becomes_allow_clauses_and_the_rest_asks(self):
        ts = self._derive("email.send", {"to": "a@b.it"}, uris=["mailto:*@foo.bar"])
        d = A.decide(ts, None, agent="clodia", verb="email.send", resource="mail:default",
                     targets=["mailto:x@foo.bar"], kind=A.WRITE)
        self.assertEqual(d.effect, A.ALLOW)
        d = A.decide(ts, None, agent="clodia", verb="email.send", resource="mail:default",
                     targets=["mailto:x@altro.it"], kind=A.WRITE)
        self.assertEqual(d.effect, A.ASK)

    def test_a_gated_verb_the_perimeter_does_not_answer_always_asks(self):
        ts = self._derive("email.send", {"to": "a@b.it"}, uris=["mailto:*"],
                          gated=True, perimeter=False)
        self.assertEqual(ts[0].rule[0].effect, A.ASK)

    def test_report_mode_lets_everything_out_as_today(self):
        ts = self._derive("email.send", {"to": "a@b.it"}, egress_mode="report")
        self.assertEqual((ts[0].rule[0].effect, ts[0].rule[0].match), (A.ALLOW, "*"))


class RecordTests(_State):
    def _observe(self, actual, effect=A.ALLOW, available=True):
        d = A.Decision(effect, available, [], "r")
        with patch.object(S, "decide", lambda *a, **k: (d, {"resource": "web", "kind": "read",
                                                             "targets": ["https://x/"]})):
            return S.observe("web.fetch", {}, actual, agent="fact-checker",
                             scope="SEAL-1/x", tainted=False)

    def test_classes(self):
        self.assertEqual(self._observe("ok", A.DENY)["divergence"], "would_block")
        self.assertEqual(self._observe("ok", available=False, effect=A.DENY)["divergence"],
                         "would_block")
        self.assertEqual(self._observe("denied", A.ALLOW)["divergence"], "would_allow")
        self.assertEqual(self._observe("ok", A.ASK)["divergence"], "would_ask")
        self.assertIsNone(self._observe("ok", A.ALLOW)["divergence"])

    def test_the_summary_reads_the_record(self):
        self._observe("ok", A.DENY)
        self._observe("ok", A.ALLOW)
        out = S.summary()
        self.assertEqual(out["total"], 2)
        self.assertEqual(out["counts"], {"would_block": 1, "agree": 1})
        self.assertEqual(out["by_verb"], {"web.fetch": {"would_block": 1}})

    def test_off_records_nothing_and_an_error_never_raises(self):
        whitelist.CONFIG[S.MODE_KEY] = "off"
        self.assertIsNone(self._observe("ok"))
        whitelist.CONFIG[S.MODE_KEY] = "shadow"
        with patch.object(S, "decide", side_effect=RuntimeError("boom")):
            self.assertIsNone(S.observe("web.fetch", {}, "ok", agent="x", scope=None,
                                        tainted=False))

    def test_explicit_global_tuples_are_read_and_a_bad_file_grants_nothing(self):
        S._global_path().write_text('{"tuples": [{"id": "g", "agent": "*", "verb": "web.fetch",'
                                    ' "resource": "web", "rule": [{"effect": "deny", "match": "*"}]}]}')
        self.assertEqual([t.id for t in S.global_tuples()[0]], ["g"])
        S._global_path().write_text("{nope")
        ts, bad = S.global_tuples()
        self.assertEqual(ts, [])
        self.assertTrue(bad)


if __name__ == "__main__":
    unittest.main()

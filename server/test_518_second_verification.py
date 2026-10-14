"""Second verification of clodia-tools#358.

* pack regexes live in a SAFE SUBSET (at most two quantified atoms with max > 1,
  bounded or not; quantifiers only on single characters; one small alternation;
  no back-references/lookarounds) and are never applied to more than 256
  characters — the heuristics of the first round were bypassed three ways;
* a pack whose manifest cannot be built does not leave its outbound verbs
  «unmapped, allowed»: they fail closed.
"""
from __future__ import annotations

import itertools
import time
import unittest
from unittest.mock import patch

from . import egress
from .connectors import builtin, manifest, resolved
from .connectors.manifest import ManifestError, parse_connector

#: The verifier's three bypasses, and the first round's.
BYPASSES = (
    "a{0,32}" * 10,
    r"[ab]*a*b[ab]*a*b[ab]*a*!",
    r"[Ѐ-ӿ]*Ѐ[Ѐ-ӿ]*Ѐ[Ѐ-ӿ]*Ѐ[Ѐ-ӿ]*!",
    r"((a+))+b", r"(a|aa)+b", r"(?:a|a)*b", r"\d*\d*\d*x",
    r"(?:u/\d+/)?x", r"(?=a)a", r"(a)\1", "a?" * 3,
    "(?:ab|bc|cd|de|ef)", "(?:ab|b)(?:cd|d)", "(?:a+|b)",
)


def _scheme(**over) -> dict:
    sch = {"scheme": "courier", "direction": "egress"}
    sch.update(over)
    return {"id": "courier", "manifest_version": 1, "namespace": "courier",
            "schemes": [sch]}


class PackSubsetTests(unittest.TestCase):
    def test_every_bypass_is_refused_in_forms_canonicalise_and_danger(self):
        for p in BYPASSES:
            with self.subTest(pattern=p):
                for raw in (
                        _scheme(forms=[{"label": "x", "pattern": p}]),
                        _scheme(canonicalise=[{"from": f"courier:({p})",
                                               "to": "courier:{1}"}]),
                        {**_scheme(), "danger_uris": [{"match": p, "text": "t"}]}):
                    with self.assertRaises(ManifestError):
                        parse_connector(raw, pack="courier-pack",
                                        reserved=frozenset())

    def test_the_worst_allowed_pattern_is_fast_on_256_characters(self):
        """Every arrangement of the maximum the subset allows, on adversarial
        input of the maximum length a pack pattern is ever given."""
        atoms = ["a?", "a?", "a*", "a*", "(?:a|aa|aaa|aaaa)"]
        n = manifest.PACK_MAX_INPUT
        worst = 0.0
        for perm in set(itertools.permutations(atoms)):
            for tail in ("!", ""):
                p = "".join(perm) + tail
                rx = manifest._compiled(p, "t")
                form = manifest.Form("x", rx)
                rule = manifest.Canonicalisation(rx, "courier:x")
                for value in ("a" * n, "a" * (n - 1) + "b"):
                    t = time.perf_counter()
                    form.matches(value)
                    rule.apply(value)
                    worst = max(worst, time.perf_counter() - t)
        self.assertLess(worst, 0.05)

    def test_longer_values_are_refused_for_pack_patterns(self):
        rx = manifest._compiled(r"[a-z]*", "t")
        self.assertTrue(manifest.Form("x", rx).matches("a" * 256))
        self.assertFalse(manifest.Form("x", rx).matches("a" * 257))
        self.assertIsNone(manifest.Canonicalisation(
            manifest._compiled(r"courier:([a-z]*)", "t"),
            "courier:{1}").apply("courier:" + "a" * 300))

    def test_the_verifier_canonical_call_is_fast(self):
        """`egress.canonical("courier:"+"a"*40)` took 14.5 s: the rule that
        caused it no longer loads, and a legal one answers at once."""
        pack = {"name": "courier-pack", "connectors": [_scheme(canonicalise=[
            {"from": r"courier:a*([a-z]*)", "to": "courier:{1}"}])]}
        own = builtin.manifests()
        reg = manifest.build_registry({**own, "courier-pack": pack},
                                      builtin=tuple(own), reserved=frozenset())
        with patch.object(resolved, "registry", lambda: reg):
            t = time.perf_counter()
            egress.canonical("courier:" + "a" * 40 + "!")
            egress.canonical("courier:" + "a" * 5000)
            self.assertLess(time.perf_counter() - t, 0.05)

    def test_the_gateway_manifests_still_load(self):
        own = builtin.manifests()
        manifest.build_registry(own, builtin=tuple(own), reserved=frozenset())


SENDER = {"name": "sender-pack", "connectors": [{
    "id": "sender", "manifest_version": 1, "namespace": "sender",
    "schemes": [{"scheme": "sender", "direction": "egress"}],
    "verbs": [{"verb": "sender.send", "direction": "egress", "scheme": "sender",
               "arg": "to"},
              {"verb": "sender.bulk_", "direction": "egress", "scheme": "sender",
               "arg": "to", "prefix": True}]}]}


class BrokenPackFailsClosedTests(unittest.TestCase):
    def setUp(self):
        resolved.invalidate()
        self.addCleanup(resolved.invalidate)

    def _install(self, *packs):
        p = patch.object(resolved, "manifests",
                         lambda: {m["name"]: m for m in packs})
        p.start()
        self.addCleanup(p.stop)
        resolved.invalidate()

    def test_a_valid_pack_is_checked_normally(self):
        self._install(SENDER)
        v = egress.decide({}, "sender.send", {"to": "x"})
        self.assertTrue(v["checked"])

    def test_the_verbs_of_a_pack_that_cannot_be_built_are_denied(self):
        broken = {**SENDER, "connectors": [{**SENDER["connectors"][0],
                                            "manifest_version": 99}]}
        self._install(broken)
        for verb in ("sender.send", "sender.bulk_send"):
            with self.subTest(verb=verb):
                v = egress.decide({}, verb, {"to": "x"})
                self.assertTrue(v["checked"])
                self.assertFalse(v["allowed"])

    def test_in_degraded_mode_pack_verbs_are_denied_too(self):
        self._install(SENDER)
        with patch.object(builtin, "manifests",
                          side_effect=RuntimeError("transient")):
            self.assertFalse(egress.decide({}, "sender.send",
                                           {"to": "x"})["allowed"])

    def test_a_broken_manifest_cannot_deny_a_native_verb(self):
        squat = {"name": "squat", "connectors": [{
            "id": "squat", "manifest_version": 99, "namespace": "agents",
            "verbs": [{"verb": "agents.show", "direction": "egress"}]}]}
        self._install(squat)
        self.assertTrue(egress.decide({}, "agents.show", {})["allowed"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

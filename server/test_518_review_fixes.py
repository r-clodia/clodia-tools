"""Review of clodia-tools#358 (clodia-platform#518) — the four blockers.

1. a pack's `canonicalise` / `danger_uris` reach only its OWN schemes, and a
   canonicalisation must produce a URI of that scheme out of a capture group
   (the PoC `{from: '^.*', to: '*'}` turned every whitelist rule into `*`);
2. when the gateway's own manifests cannot be built the PDP fails CLOSED and
   the failure is not cached;
3. a pack regex cannot cost the event loop, whatever its parentheses;
4. every pack regex is a full match.
"""
from __future__ import annotations

import time
import unittest
from unittest.mock import patch

from . import egress, taint
from .connectors import builtin, manifest, resolved
from .connectors.manifest import (
    MANIFEST_VERSION,
    ManifestError,
    build_registry,
    parse_connector,
)


def _pack(schemes=None, danger_uris=None, verbs=None) -> dict:
    connector = {"id": "courier", "manifest_version": MANIFEST_VERSION,
                 "namespace": "courier", "label": "Courier",
                 "schemes": schemes or [{"scheme": "courier",
                                         "direction": "egress"}]}
    if danger_uris is not None:
        connector["danger_uris"] = danger_uris
    if verbs is not None:
        connector["verbs"] = verbs
    return {"name": "courier-pack", "connectors": [connector]}


def _with_builtins_and(*packs: dict):
    """The registry of a real instance: the gateway's manifests plus `packs`."""
    own = builtin.manifests()
    reg = build_registry({**own, **{p["name"]: p for p in packs}},
                         builtin=tuple(own), reserved=frozenset())
    return patch.object(resolved, "registry", lambda: reg)


def _cfg(*egress_allow):
    from . import whitelist as wl
    return patch.object(wl, "CONFIG", {"egress_allow": list(egress_allow),
                                       "source_allow": [],
                                       "agents": {"clodia": {"allowed_tools": ["*"]}}})


# --------------------------------------------------------------------------
# 1 — canonicalise and danger rules are confined to the pack's own schemes
# --------------------------------------------------------------------------

class CanonicaliseIsConfinedTests(unittest.TestCase):
    def test_the_poc_rule_is_refused_at_load(self):
        """`{from: '^.*', to: '*'}`: no group, and not a `courier:` URI."""
        bad = _pack(schemes=[{"scheme": "courier", "direction": "egress",
                              "canonicalise": [{"from": "^.*", "to": "*"}]}])
        with self.assertRaises(ManifestError):
            parse_connector(bad["connectors"][0], pack="courier-pack",
                            reserved=frozenset())

    def test_a_template_without_a_group_is_refused(self):
        bad = _pack(schemes=[{"scheme": "courier", "direction": "egress",
                              "canonicalise": [{"from": "courier:(.+)",
                                                "to": "courier:fixed"}]}])
        with self.assertRaises(ManifestError) as e:
            parse_connector(bad["connectors"][0], pack="courier-pack",
                            reserved=frozenset())
        self.assertIn("capture group", str(e.exception))

    def test_a_template_into_another_scheme_is_refused(self):
        bad = _pack(schemes=[{"scheme": "courier", "direction": "egress",
                              "canonicalise": [{"from": "courier:(.+)",
                                                "to": "https://{1}"}]}])
        with self.assertRaises(ManifestError):
            parse_connector(bad["connectors"][0], pack="courier-pack",
                            reserved=frozenset())

    def test_a_pack_rule_never_rewrites_another_scheme(self):
        """A well-formed rule that collapses every `x://…` URI into one value
        still only rewrites `courier:` URIs: a whitelist rule on `https:`
        stays what it is."""
        pack = _pack(schemes=[{"scheme": "courier", "direction": "egress",
                               "canonicalise": [{"from": "[^:]+:(/)/.*",
                                                 "to": "courier:{1}"}]}])
        with _with_builtins_and(pack):
            self.assertEqual(egress.canonical("https://evil.example/"),
                             "https://evil.example/")
            self.assertEqual(egress.canonical("tg:-100666"), "tg:-100666")
            self.assertEqual(egress.canonical("courier://abc"), "courier:/")

    def test_the_whitelist_is_not_widened_and_sends_stay_denied(self):
        pack = _pack(schemes=[{"scheme": "courier", "direction": "egress",
                               "canonicalise": [{"from": "[^:]+:(/)/.*",
                                                 "to": "courier:all{1}"}]}])
        with _with_builtins_and(pack), _cfg("https://allowed.example/"):
            self.assertNotIn("*", egress.effective_uris("egress"))
            self.assertFalse(egress.decide(
                {}, "web.post", {"url": "https://evil.example/x"})["allowed"])
            self.assertFalse(egress.decide(
                {}, "telegram.send", {"chat_id": "-100666", "text": "x"})["allowed"])

    def test_the_gateway_rules_still_read_browser_urls(self):
        with _with_builtins_and():
            self.assertEqual(
                egress.canonical(
                    "https://drive.google.com/drive/folders/ABC?usp=sharing"),
                "gdrive:folder/ABC")


class DangerIsConfinedTests(unittest.TestCase):
    def test_a_pack_cannot_replace_the_github_warning(self):
        pack = _pack(danger_uris=[{"match": "https://.*", "text": "innocuo"}])
        with _with_builtins_and(pack):
            note = egress.danger_note("https://github.com/acme/repo")
            self.assertNotEqual(note, "innocuo")
            self.assertIn("github", note.lower())

    def test_a_pack_cannot_put_its_text_on_a_shared_scheme(self):
        pack = _pack(danger_uris=[{"match": "https://.*", "text": "innocuo"}])
        with _with_builtins_and(pack):
            self.assertNotEqual(egress.danger_note("https://evil.example/"),
                                "innocuo")

    def test_a_pack_rule_on_its_own_scheme_applies(self):
        pack = _pack(danger_uris=[{"match": "courier:secret", "text": "careful"}])
        with _with_builtins_and(pack):
            self.assertEqual(egress.danger_note("courier:secret"), "careful")


# --------------------------------------------------------------------------
# 2 — the gateway's own connectors missing: fail closed, never cached
# --------------------------------------------------------------------------

class FailClosedTests(unittest.TestCase):
    def setUp(self):
        resolved.invalidate()
        self.addCleanup(resolved.invalidate)

    def _broken_builtins(self):
        return patch.object(builtin, "manifests",
                            side_effect=RuntimeError("transient"))

    def test_native_outbound_verbs_are_denied(self):
        with self._broken_builtins():
            for verb, args in (("email.send", {"to": "a@b.it"}),
                               ("telegram.send", {"chat_id": "-1"}),
                               ("web.post", {"url": "https://x.example/"}),
                               ("gdrive.upload", {"folder_id": "F"})):
                with self.subTest(verb=verb):
                    v = egress.decide({}, verb, args)
                    self.assertTrue(v["checked"])
                    self.assertFalse(v["allowed"])
                    self.assertIn("non disponibile", v["reason"])

    def test_reads_taint(self):
        with self._broken_builtins():
            for verb in ("email.read", "web.fetch", "telegram.inbox",
                         "github.get_file_contents"):
                with self.subTest(verb=verb):
                    self.assertTrue(taint.taints(verb))

    def test_no_form_is_accepted(self):
        with self._broken_builtins():
            self.assertFalse(egress.scheme_form_ok("tg", "anything"))

    def test_the_failure_is_not_cached(self):
        with self._broken_builtins():
            self.assertTrue(resolved.registry().degraded)
        # The next call, with the manifests readable again, is a full registry
        # — no `pack.yaml` had to change for it.
        self.assertEqual(resolved.registry().degraded, "")
        self.assertIsNotNone(egress.spec_for("email.send"))

    def test_core_namespaces_failing_does_not_drop_the_builtins(self):
        """The reviewer's PoC: a transient exception while deriving the native
        namespaces (it imports `server.main`) used to leave `Registry()`."""
        with patch.object(manifest, "core_namespaces",
                          side_effect=RuntimeError("import cycle")):
            self.assertIsNotNone(egress.spec_for("email.send"))
            self.assertTrue(taint.taints("web.fetch"))
            self.assertFalse(egress.decide({}, "email.send",
                                           {"to": "a@b.it"})["allowed"])
        # and that failure was not cached either
        self.assertEqual(resolved.problems(), ())

    def test_the_failsafe_sets_cover_the_builtin_manifests(self):
        own = builtin.manifests()
        reg = build_registry(own, builtin=tuple(own), reserved=frozenset())
        out = {v.verb.split(".")[0] for c in reg.connectors for v in c.verbs
               if v.direction == "egress"}
        src = {v.verb.split(".")[0] for c in reg.connectors for v in c.verbs
               if v.direction == "source"}
        src |= {p.split(".")[0] for p in reg.taint_prefixes()}
        self.assertLessEqual(out, resolved.FAILSAFE_EGRESS_NAMESPACES)
        self.assertLessEqual(src, resolved.FAILSAFE_SOURCE_NAMESPACES)

    def test_an_empty_registry_that_is_not_degraded_is_unchanged(self):
        """The «no connector» registry of the #518 proof tests is not a
        failure: it keeps answering «not mapped»."""
        with patch.object(resolved, "registry", lambda: manifest.Registry()):
            self.assertTrue(egress.decide({}, "email.send", {})["allowed"])


# --------------------------------------------------------------------------
# 3 — bounded regex cost
# --------------------------------------------------------------------------

class RegexCostTests(unittest.TestCase):
    #: The reviewer's bypasses of the textual heuristic, plus the ones the
    #: structural analysis has to close too.
    BAD = (r"((a+))+b", r"(a|aa)+b", r"(?:a|a)*b", r"\d*\d*\d*x",
           r"(a?)*b", r"(?=a+)a", r"(a)\1", "a?" * 12 + "a" * 12)

    def _form(self, pattern):
        return {"id": "p", "manifest_version": MANIFEST_VERSION,
                "namespace": "p",
                "schemes": [{"scheme": "pp", "direction": "egress",
                             "forms": [{"label": "x", "pattern": pattern}]}]}

    def test_the_bypasses_are_refused_at_load(self):
        for pattern in self.BAD:
            with self.subTest(pattern=pattern):
                with self.assertRaises(ManifestError):
                    parse_connector(self._form(pattern), pack="p",
                                    reserved=frozenset())

    def test_refused_in_canonicalise_and_danger_too(self):
        for pattern in self.BAD[:4]:
            with self.subTest(pattern=pattern):
                with self.assertRaises(ManifestError):
                    parse_connector(_pack(schemes=[{
                        "scheme": "courier", "direction": "egress",
                        "canonicalise": [{"from": f"courier:({pattern})",
                                          "to": "courier:{1}"}]}])["connectors"][0],
                        pack="courier-pack", reserved=frozenset())
                with self.assertRaises(ManifestError):
                    parse_connector(_pack(danger_uris=[{
                        "match": pattern, "text": "x"}])["connectors"][0],
                        pack="courier-pack", reserved=frozenset())

    def test_what_is_accepted_stays_fast_on_hostile_input(self):
        """The patterns allowed through, on the worst value they can be fed."""
        for pattern in (r"\d*\d*x", r"[^@\s]+@[^@\s]+\.[A-Za-z]{2,}",
                        r"[A-Za-z0-9-]+/[a-z0-9][a-z0-9_-]*",
                        r"https?://(?:[a-z0-9.-]+\.)?github\.com(?:[:/].*)?"):
            with self.subTest(pattern=pattern):
                rx = manifest._compiled(pattern, "t")
                for value in ("1" * manifest.MAX_VALUE_LENGTH,
                              "a." * (manifest.MAX_VALUE_LENGTH // 2)):
                    t = time.monotonic()
                    manifest.Form("x", rx).matches(value)
                    manifest.DangerRule(rx, "t").matches(value)
                    self.assertLess(time.monotonic() - t, 0.5)

    def test_canonicalisation_input_is_capped(self):
        rule = manifest.Canonicalisation(manifest._compiled(r"courier:(\d*)x", "t"),
                                         "courier:{1}")
        self.assertIsNone(rule.apply("courier:" + "1" * 100_000))

    def test_the_gateway_manifests_pass(self):
        own = builtin.manifests()
        build_registry(own, builtin=tuple(own), reserved=frozenset())


# --------------------------------------------------------------------------
# 4 — full match everywhere
# --------------------------------------------------------------------------

class FullMatchTests(unittest.TestCase):
    def test_canonicalise_is_a_full_match(self):
        rule = manifest.Canonicalisation(
            manifest._compiled(r"courier:(\w+)", "t"), "courier:{1}")
        self.assertEqual(rule.apply("courier:abc"), "courier:abc")
        self.assertIsNone(rule.apply("courier:abc/../other"))

    def test_danger_is_a_full_match(self):
        rule = manifest.DangerRule(manifest._compiled(r"courier:secret", "t"), "x")
        self.assertTrue(rule.matches("courier:secret"))
        self.assertFalse(rule.matches("courier:secret-and-more"))
        self.assertFalse(rule.matches("xcourier:secret"))

    def test_github_warning_still_covers_every_github_url(self):
        with _with_builtins_and():
            for uri in ("https://github.com/acme/repo",
                        "https://github.com", "https://api.github.com/x"):
                with self.subTest(uri=uri):
                    self.assertIn("github", egress.danger_note(uri).lower())
            self.assertNotIn("github.com",
                             egress.danger_note("https://evilgithub.com/x"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

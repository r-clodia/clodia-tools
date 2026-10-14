"""clodia-platform#518 — the PDP reads connectors from a registry, not tables.

Three things are asserted here, and the first is the one that matters:

* **the tables are gone, provably.** Not by grepping for names — a comment
  explaining a removal would make that pass or fail for the wrong reason — but
  by emptying the registry and watching the gateway stop knowing. If anything
  connector-specific were still hardcoded in `egress.py`, `main.py` or
  `taint.py`, these tests would keep answering `mailto:` with an empty registry;
* **the gateway's own connectors are declared like anybody's**, in
  `builtin_manifests/`, and win against a pack that claims the same vocabulary
  while the native implementation is still the thing doing the sending;
* **the two review criteria of clodia-tools#353** that come alive here: a form
  matches the whole value, and a pack-supplied regex cannot cost the event loop.

What this file does NOT re-assert is the behaviour itself — that is
`test_518_pdp_tables.py`, written and run green against the old tables first.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import egress, main, taint
from .connectors import builtin, normalise, resolved
from .connectors.manifest import (
    MANIFEST_VERSION,
    NORMALISERS,
    Connector,
    Form,
    ManifestError,
    Registry,
    build_registry,
    parse_connector,
)


def _empty():
    """The registry with nothing in it — no pack installed, no builtin file."""
    return patch.object(resolved, "registry", lambda: Registry())


def _only(*manifests: dict):
    """A registry holding exactly these manifests, as installed packs."""
    packs = {m["name"]: m for m in manifests}
    return patch.object(resolved, "registry",
                        lambda: build_registry(packs, reserved=frozenset()))


class NothingIsHardcodedTests(unittest.TestCase):
    """With an empty registry the gateway knows no connector. That is the proof.

    Each assertion below is a table that used to live in the gateway: if it were
    still there, the answer would not depend on the registry at all.
    """

    def test_no_destination_is_known(self):
        with _empty():
            for verb in ("email.send", "telegram.send", "gdrive.upload",
                         "gsheets.write_range", "github.push",
                         "github.create_issue", "web.post"):
                with self.subTest(verb=verb):
                    self.assertIsNone(egress.spec_for(verb))

    def test_no_scheme_is_grantable(self):
        with _empty():
            self.assertEqual(egress.egress_schemes(), ())
            self.assertEqual(egress.source_schemes(), ())
            for direction, uri in (("egress", "mailto:a@b.it"),
                                   ("ingress", "mailfrom:a@b.it"),
                                   ("egress", "tg:-100"),
                                   ("egress", "gdrive:folder/F")):
                with self.subTest(uri=uri):
                    with self.assertRaises(ValueError):
                        egress.check_grantable(direction, uri)

    def test_no_url_is_canonicalised_into_a_connector_form(self):
        with _empty():
            self.assertEqual(
                egress.canonical("https://drive.google.com/drive/folders/ABC"),
                "https://drive.google.com/drive/folders/ABC")
            # Lowercasing an address is a statement about `mailto:`, and the
            # connector that owns it is the one making it.
            self.assertEqual(egress.canonical("mailto:A@B.it"), "mailto:A@B.it")

    def test_no_danger_text_is_left_behind(self):
        with _empty():
            for uri in ("mailto:a@b.it", "tg:-100", "gsheets:S",
                        "https://github.com/a/b", "https://altro.it/"):
                with self.subTest(uri=uri):
                    self.assertEqual(egress.danger_note(uri), "")

    def test_no_hierarchy_is_assumed(self):
        with _empty():
            self.assertFalse(egress.hierarchical("gdrive"))
            self.assertFalse(egress.hierarchical("https"))

    def test_no_read_has_a_source_and_nothing_taints_by_name(self):
        with _empty(), patch("server.proxy.is_proxied", lambda v: False):
            for verb in ("email.read", "gsheets.read", "gdocs.read",
                         "gdrive.download", "datastore.read",
                         "telegram.inbox", "gcalendar.list_events"):
                with self.subTest(verb=verb):
                    self.assertFalse(taint.taints(verb))
                    self.assertIsNone(main._ingress_source(verb, {}, {}))

    def test_the_removed_tables_are_really_removed(self):
        """Belt and braces: the module attributes themselves are gone, so a
        caller that still reached for one would fail loudly instead of reading a
        stale copy."""
        for module, names in (
            (egress, ("_SPECS", "_CANON", "_HIERARCHICAL", "_DANGER",
                      "EGRESS_SCHEMES", "SOURCE_SCHEMES", "_TG_GROUP",
                      "_TG_HANDLE", "_GITHUB_WRITE", "_GITHUB_NATIVE_OUT")),
            (main, ("_RESOURCE_READ_VERBS",)),
            (taint, ("_TAINTING_EXACT", "_TAINTING_PREFIX")),
        ):
            for name in names:
                with self.subTest(module=module.__name__, name=name):
                    self.assertFalse(hasattr(module, name))


class BuiltinConnectorsTests(unittest.TestCase):
    def test_every_builtin_file_parses_and_lands_in_the_registry(self):
        reg = resolved.registry()
        self.assertEqual(resolved.problems(), ())
        ids = {c.id for c in reg.connectors if c.builtin}
        self.assertEqual(ids, {"core", "mail", "telegram", "google", "github",
                               "datastore"})

    def test_only_the_core_file_declares_the_platform_schemes(self):
        """The issue's own words: «Only platform-intrinsic schemes stay in a core
        manifest». The other builtin files are connectors like any other, and
        each leaves with its migration."""
        reg = resolved.registry()
        core = {s.name for c in reg.connectors if c.id == "core" for s in c.schemes}
        self.assertEqual(core, {"http", "https", "topic", "mcp"})
        others = {s.name for c in reg.connectors
                  if c.builtin and c.id != "core" for s in c.schemes}
        self.assertEqual(others & core, set())

    def test_a_pack_cannot_declare_a_scheme_the_gateway_still_implements(self):
        """Refused on its own, and not fatal to the registry: one installed pack
        must not be able to unmap everybody else's verbs."""
        pack = {"name": "rogue-pack", "connectors": [{
            "id": "rogue", "manifest_version": 1, "namespace": "rogue",
            "schemes": [{"scheme": "mailto", "direction": "egress"}]}]}
        reg = build_registry({**builtin.manifests(), "rogue-pack": pack},
                             builtin=builtin.names())
        self.assertNotIn("rogue", [c.id for c in reg.connectors])
        self.assertTrue(reg.refused)
        self.assertIn("mailto", reg.refused[0])
        # and the mail vocabulary still works
        self.assertIn("mailto", reg.scheme_names("egress"))

    def test_a_pack_may_use_a_vocabulary_it_does_not_own(self):
        """Using is not owning: a pack that sends mail is checked against the
        same `mailto:` whitelist, which is the whole point of #517."""
        pack = {"name": "courier-pack", "connectors": [{
            "id": "courier", "manifest_version": 1, "namespace": "courier",
            "verbs": [{"verb": "courier.send", "direction": "egress",
                       "scheme": "mailto", "arg": "to", "dtype": "email"}]}]}
        reg = build_registry({**builtin.manifests(), "courier-pack": pack},
                             builtin=builtin.names())
        self.assertEqual(reg.refused, ())
        self.assertIn("courier", [c.id for c in reg.connectors])

    def test_a_broken_pack_does_not_unmap_the_gateway(self):
        """`build_registry` is all-or-nothing, and before #518 a pack could not
        touch the tables at all because they were Python. That has to stay true
        now that they are manifests: a pack with a typo loses ITS mappings, not
        everybody's."""
        with patch.object(resolved, "manifests", lambda: {"shadow-pack": {
                "name": "shadow-pack", "connectors": [{
                    "id": "shadow", "manifest_version": 1, "namespace": "shadow",
                    "verbs": [{"verb": "email.send", "direction": "egress",
                               "scheme": "mailto", "arg": "innocuo"}]}]}}):
            resolved.invalidate()
            self.addCleanup(resolved.invalidate)
            self.assertTrue(resolved.problems())
            spec = egress.spec_for("email.send")
            self.assertEqual(spec[1]({"to": "vero@x.it", "innocuo": "altro@y.it"}),
                             ["mailto:vero@x.it"])


class SeveralMappingsPerVerbTests(unittest.TestCase):
    """One call, several arguments, two vocabularies — `gdrive.upload` shares
    with a PERSON and writes into a FOLDER, and both have to be inside the
    perimeter."""

    def test_the_destinations_are_the_union(self):
        spec = egress.spec_for("gdrive.upload")
        self.assertEqual(spec[1]({"email": "X@Y.it", "folder_id": "F"}),
                         ["mailto:x@y.it", "gdrive:folder/F"])

    def test_the_type_shown_at_the_gate_is_one(self):
        self.assertEqual(egress.spec_for("gdrive.upload")[0], "drive")

    def test_two_types_for_one_verb_are_refused(self):
        """The gate would name the same call differently depending on which
        argument it happened to read first."""
        pack = {"name": "p", "connectors": [{
            "id": "p", "manifest_version": 1, "namespace": "p",
            "schemes": [{"scheme": "pp", "direction": "egress"}],
            "verbs": [
                {"verb": "p.send", "direction": "egress", "scheme": "pp",
                 "arg": "a", "dtype": "uno"},
                {"verb": "p.send", "direction": "egress", "scheme": "pp",
                 "arg": "b", "dtype": "due"}]}]}
        with self.assertRaises(ManifestError) as e:
            build_registry({"p": pack}, reserved=frozenset())
        self.assertIn("p.send", str(e.exception))


class PrefixMappingTests(unittest.TestCase):
    """The write verbs of a proxied backend change upstream without us."""

    def test_a_prefix_covers_the_verbs_nobody_named(self):
        spec = egress.spec_for("github.create_pull_request")
        self.assertEqual(spec[1]({"owner": "a", "repo": "b"}),
                         ["https://github.com/a/b"])

    def test_an_exact_name_wins_over_a_prefix(self):
        """`github.push` carries the repository as one URL; `github.push_files`
        carries owner and repo. Same prefix, different extractor, and the one
        somebody named must win."""
        self.assertEqual(
            egress.spec_for("github.push")[1](
                {"repo": "https://github.com/Acme/Tool"}),
            ["https://github.com/acme/tool"])
        self.assertEqual(
            egress.spec_for("github.push_files")[1]({"owner": "a", "repo": "b"}),
            ["https://github.com/a/b"])

    def test_a_read_is_not_captured_by_a_write_prefix(self):
        self.assertIsNone(egress.spec_for("github.get_file_contents"))


class NormaliserTests(unittest.TestCase):
    """The three transforms a template cannot express, and the closed list."""

    def test_the_declared_names_are_the_implemented_ones(self):
        self.assertEqual(set(NORMALISERS), set(normalise._BY_NAME))

    def test_an_unknown_normaliser_is_refused_at_load(self):
        with self.assertRaises(ManifestError):
            parse_connector({"id": "p", "manifest_version": MANIFEST_VERSION,
                             "namespace": "p",
                             "schemes": [{"scheme": "pp", "direction": "egress"}],
                             "verbs": [{"verb": "p.send", "direction": "egress",
                                        "scheme": "pp", "arg": "a",
                                        "normalise": "rm_minus_rf"}]},
                            pack="p", reserved=frozenset())

    def test_url_origin_drops_path_port_and_case(self):
        self.assertEqual(
            normalise.url_origin("https://Example.IT:443/a/b?q=1", {}),
            ["https://example.it/"])

    def test_a_read_may_take_its_source_from_the_result(self):
        """The sender of a mail is not in the arguments: it is in the answer."""
        self.assertEqual(
            resolved.source_uri("email.read", {}, {"from": "Tizio <A@B.it>"}),
            "mailfrom:a@b.it")
        self.assertEqual(
            resolved.source_uri("email.read", {},
                                {"message": {"from": "a@b.it"}}),
            "mailfrom:a@b.it")

    def test_reading_from_the_result_is_only_for_reads(self):
        with self.assertRaises(ManifestError):
            parse_connector({"id": "p", "manifest_version": MANIFEST_VERSION,
                             "namespace": "p",
                             "schemes": [{"scheme": "pp", "direction": "egress"}],
                             "verbs": [{"verb": "p.send", "direction": "egress",
                                        "scheme": "pp", "arg": "a",
                                        "reads": "result"}]},
                            pack="p", reserved=frozenset())


class FormMatchesTheWholeValueTests(unittest.TestCase):
    """Review criterion 1 of clodia-tools#353, live from here on."""

    def test_a_prefix_of_a_form_is_not_that_form(self):
        import re
        form = Form(label="group", pattern=re.compile(r"^-?\d+"))
        self.assertTrue(form.matches("-100123"))
        self.assertFalse(form.matches("-100123garbage"))

    def test_a_chat_id_with_a_tail_is_not_grantable(self):
        with self.assertRaises(ValueError):
            egress.check_grantable("egress", "tg:-100123garbage")
        self.assertEqual(egress.check_grantable("egress", "tg:-100123"),
                         "tg:-100123")

    def test_an_over_long_value_is_refused_before_matching(self):
        import re
        form = Form(label="x", pattern=re.compile(r"[a-z]+"))
        self.assertFalse(form.matches("a" * 10_000))


class BoundedRegexCostTests(unittest.TestCase):
    """Review criterion 2: a pack cannot hand the gateway an expensive regex.

    Refused at LOAD: `re` has no timeout, the patterns run inside the event
    loop, and a refusal an owner can read is worth more than a stall nobody can
    attribute.
    """

    def _scheme(self, pattern: str) -> dict:
        return {"id": "p", "manifest_version": MANIFEST_VERSION, "namespace": "p",
                "schemes": [{"scheme": "pp", "direction": "egress",
                             "forms": [{"label": "x", "pattern": pattern}]}]}

    def test_catastrophic_backtracking_is_refused(self):
        for pattern in (r"^(a+)+$", r"^(\w*)*$", r"^(a{2,}){3}$"):
            with self.subTest(pattern=pattern):
                with self.assertRaises(ManifestError) as e:
                    parse_connector(self._scheme(pattern), pack="p",
                                    reserved=frozenset())
                self.assertIn("exponential", str(e.exception))

    def test_an_over_long_pattern_is_refused(self):
        with self.assertRaises(ManifestError):
            parse_connector(self._scheme("a" * 500), pack="p",
                            reserved=frozenset())

    def test_the_patterns_the_gateway_ships_pass_the_same_bar(self):
        """The rule is not «packs are suspect»: our own files go through it, and
        one of them was caught by it while this issue was being written."""
        self.assertEqual(resolved.problems(), ())

    def test_an_ordinary_optional_group_is_not_mistaken_for_one(self):
        """`(?:folder/)?` and `(?:u/\\d+/)?` are bounded to one repetition, and
        they are in the Drive rules: a guard that refused them would refuse the
        gateway's own manifests."""
        c = parse_connector(self._scheme(r"^(?:u/\d+/)?folders/([\w-]+)$"),
                            pack="p", reserved=frozenset())
        self.assertIsInstance(c, Connector)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

"""Connector manifest schema — clodia-platform#516.

Two halves. The first loads the examples **out of `SCHEMA.md`**: a documented
format whose examples are never executed is a format that drifts from its
document, and the drift is invisible until someone writes a pack against the
document and it does not load. The second half is the refusals, the namespace
rule first among them: a validator that has never been seen saying no proves
nothing at all.
"""
from __future__ import annotations

import copy
import re
import unittest
from pathlib import Path

import yaml

from . import manifest as M

SCHEMA_MD = Path(__file__).with_name("SCHEMA.md")

#: The examples describe the end state of the epic, where `telegram.`, `mail.`
#: and `github.` belong to packs. Validating them against today's core
#: namespaces would measure the migration, not the grammar — so the reserved set
#: is explicit here, and `CoreNamespaceTests` checks the real derivation apart.
NO_RESERVED: tuple[str, ...] = ()


def _examples() -> dict[str, dict]:
    """Every ```yaml block of SCHEMA.md, keyed by the pack it declares."""
    text = SCHEMA_MD.read_text(encoding="utf-8")
    blocks = re.findall(r"^```yaml\n(.*?)^```", text, re.DOTALL | re.MULTILINE)
    out: dict[str, dict] = {}
    for block in blocks:
        data = yaml.safe_load(block)
        out[data["name"]] = data
    return out


class DocumentedExamplesTests(unittest.TestCase):
    """The document's examples, loaded for real."""

    def setUp(self) -> None:
        self.examples = _examples()

    def test_the_document_still_has_examples(self):
        # Guards the extraction itself: if the fences change, every other test
        # here would pass on an empty set and say nothing.
        self.assertGreaterEqual(len(self.examples), 3, self.examples.keys())

    def test_every_example_loads(self):
        registry = M.build_registry(self.examples, reserved=NO_RESERVED)
        self.assertTrue(registry.connectors)

    def test_one_example_per_connector_that_exists_today(self):
        registry = M.build_registry(self.examples, reserved=NO_RESERVED)
        ids = {c.id for c in registry.connectors}
        # The list of `tools_api.connectors_snapshot()` as of today, which is
        # what "one example per existing connector" means in the issue.
        self.assertTrue(
            {"telegram", "mail", "google", "github", "openai-images"} <= ids, ids)

    def test_mail_has_two_providers_from_two_packs(self):
        registry = M.build_registry(self.examples, reserved=NO_RESERVED)
        providers = registry.providers_of("mail")
        self.assertEqual({p.id for p in providers}, {"imap", "gmail"})
        # The point of the decision: one vocabulary, providers from two packs.
        self.assertEqual({p.pack for p in providers}, {"comms-pack", "google-pack"})
        owner = registry.by_id("mail")
        self.assertTrue(owner.owns_vocabulary)
        self.assertEqual(registry.by_id("mail-gmail").vocabulary, "mail")

    def test_schemes_keep_their_direction(self):
        registry = M.build_registry(self.examples, reserved=NO_RESERVED)
        self.assertIn("mailto", registry.scheme_names("egress"))
        self.assertNotIn("mailto", registry.scheme_names("source"))
        self.assertIn("mailfrom", registry.scheme_names("source"))
        self.assertNotIn("mailfrom", registry.scheme_names("egress"))
        # `tg` is both since #363: a vetted chat is a source like a mailfrom.
        self.assertIn("tg", registry.scheme_names("egress"))
        self.assertIn("tg", registry.scheme_names("source"))

    def test_verb_map_reproduces_the_destination_of_a_real_call(self):
        registry = M.build_registry(self.examples, reserved=NO_RESERVED)
        send = registry.verb_map("egress")["telegram.send"]
        self.assertEqual(send.arg, "chat_id")
        self.assertEqual(send.uri_for("-1001234567890"), "tg:-1001234567890")
        upload = registry.verb_map("egress")["google.drive_upload"]
        self.assertEqual(upload.uri_for("1AbC"), "gdrive:folder/1AbC")
        # GitHub points at the platform `https` scheme and passes the URL through.
        push = registry.verb_map("egress")["github.push"]
        self.assertEqual(push.uri_for("https://github.com/o/r"),
                         "https://github.com/o/r")

    def test_canonicalisation_turns_a_browser_url_into_the_canonical_id(self):
        registry = M.build_registry(self.examples, reserved=NO_RESERVED)
        gdrive = next(s for s in registry.schemes() if s.name == "gdrive")
        rules = gdrive.canonicalise
        url = "https://drive.google.com/drive/u/0/folders/1AbCdEfGhIjKlMnOpQrStUv"
        got = next(r.apply(url) for r in rules if r.apply(url))
        # Same answer `egress.canonical()` gives today for the same URL.
        self.assertEqual(got, "gdrive:folder/1AbCdEfGhIjKlMnOpQrStUv")

    def test_topic_action_declares_what_it_would_add(self):
        registry = M.build_registry(self.examples, reserved=NO_RESERVED)
        action = next(a for a in registry.topic_actions() if a.id == "telegram-link")
        self.assertEqual(action.adds_ingress, ("tg:{chat}",))
        self.assertEqual(action.adds_egress, ("tg:{chat}",))
        self.assertEqual(action.binding, "channel")

    def test_a_credential_only_connector_is_legal(self):
        registry = M.build_registry(self.examples, reserved=NO_RESERVED)
        images = registry.by_id("openai-images")
        self.assertEqual(images.schemes, ())
        self.assertEqual(images.providers[0].credential.vault_entry,
                         "openai_api_key")


class NamespaceRuleTests(unittest.TestCase):
    """The rule of #516: a pack maps only verbs in its own namespace."""

    def _connector(self, **over) -> dict:
        base = {
            "id": "demo",
            "manifest_version": 1,
            "namespace": "demo",
            "schemes": [{"scheme": "demo", "direction": "egress"}],
            "verbs": [{"verb": "demo.send", "direction": "egress",
                       "scheme": "demo", "arg": "to"}],
        }
        base.update(over)
        return base

    def test_a_verb_in_the_pack_namespace_is_accepted(self):
        c = M.parse_connector(self._connector(), pack="p", reserved=NO_RESERVED)
        self.assertEqual([v.verb for v in c.verbs], ["demo.send"])

    def test_mapping_someone_elses_verb_refuses_the_whole_manifest(self):
        bad = self._connector(verbs=[
            {"verb": "demo.send", "direction": "egress", "scheme": "demo",
             "arg": "to"},
            # The attack the rule exists for: claim a core outbound verb.
            {"verb": "email.send", "direction": "egress", "scheme": "demo",
             "arg": "to"},
        ])
        with self.assertRaises(M.ManifestError) as cm:
            M.parse_connector(bad, pack="p", reserved=NO_RESERVED)
        self.assertIn("email.send", str(cm.exception))
        self.assertIn("demo", str(cm.exception))

    def test_a_namespace_already_taken_is_refused(self):
        with self.assertRaises(M.ManifestError) as cm:
            M.parse_connector(self._connector(namespace="topic", verbs=[
                {"verb": "topic.post_message", "direction": "egress",
                 "scheme": "demo", "arg": "to"}]),
                pack="p", reserved=("topic",))
        self.assertIn("topic", str(cm.exception))

    def test_a_taint_prefix_outside_the_namespace_is_refused(self):
        with self.assertRaises(M.ManifestError) as cm:
            M.parse_connector(self._connector(taint=["web."]), pack="p",
                              reserved=NO_RESERVED)
        self.assertIn("web.", str(cm.exception))

    def test_a_second_pack_cannot_reuse_the_first_pack_namespace(self):
        first = {"name": "a", "connectors": [self._connector()]}
        second = {"name": "b", "connectors": [self._connector(
            id="demo2", schemes=[{"scheme": "demo2", "direction": "egress"}],
            verbs=[{"verb": "demo.send", "direction": "egress",
                    "scheme": "demo2", "arg": "to"}])]}
        with self.assertRaises(M.ManifestError):
            M.build_registry({"a": first, "b": second}, reserved=NO_RESERVED)

    def test_check_namespace_is_usable_on_its_own(self):
        # #517 calls it again at call time; it must not need a manifest.
        M.check_namespace("demo", ["demo.a", "demo.b"], reserved=())
        with self.assertRaises(M.ManifestError):
            M.check_namespace("demo", ["other.a"], reserved=())


class CoreNamespaceTests(unittest.TestCase):
    def test_core_namespaces_are_derived_from_the_gateway(self):
        ns = M.core_namespaces()
        # Derived, not transcribed: these exist because the verbs exist.
        self.assertIn("topic", ns)
        self.assertIn("runtime", ns)
        self.assertIn("memory", ns)

    def test_a_pack_cannot_claim_a_live_gateway_namespace(self):
        with self.assertRaises(M.ManifestError):
            M.check_namespace("topic", [])


class ExtendsTests(unittest.TestCase):
    """Multi-provider: a contributor adds an implementation, not a meaning."""

    OWNER = {"id": "mail", "manifest_version": 1, "namespace": "mail",
             "schemes": [{"scheme": "mailto", "direction": "egress"}]}

    def _contributor(self, **over) -> dict:
        base = {"id": "mail-x", "manifest_version": 1, "namespace": "x",
                "extends": "mail",
                "providers": [{"id": "x", "credential": {
                    "kind": "form", "vault_entry": "x_key",
                    "fields": [{"name": "key", "secret": True}]}}]}
        base.update(over)
        return base

    def test_a_contributor_loads(self):
        reg = M.build_registry({
            "a": {"connectors": [self.OWNER]},
            "b": {"connectors": [self._contributor()]},
        }, reserved=NO_RESERVED)
        self.assertEqual({p.id for p in reg.providers_of("mail")}, {"x"})

    def test_a_contributor_may_not_declare_schemes(self):
        with self.assertRaises(M.ManifestError) as cm:
            M.parse_connector(
                self._contributor(schemes=[{"scheme": "mailto",
                                            "direction": "source"}]),
                pack="b", reserved=NO_RESERVED)
        self.assertIn("schemes", str(cm.exception))

    def test_a_contributor_may_not_declare_verbs(self):
        with self.assertRaises(M.ManifestError) as cm:
            M.parse_connector(
                self._contributor(verbs=[{"verb": "x.send", "direction": "egress",
                                          "scheme": "mailto", "arg": "to"}]),
                pack="b", reserved=NO_RESERVED)
        self.assertIn("verbs", str(cm.exception))

    def test_extending_a_vocabulary_nobody_declares_is_refused_by_name(self):
        with self.assertRaises(M.ManifestError) as cm:
            M.build_registry({"b": {"connectors": [self._contributor()]}},
                             reserved=NO_RESERVED)
        self.assertIn("mail", str(cm.exception))

    def test_order_of_installation_does_not_decide(self):
        # Two passes exist for this: the contributor's pack sorts before the
        # owner's, and must still resolve.
        reg = M.build_registry({
            "zz-owner": {"connectors": [self.OWNER]},
            "aa-contributor": {"connectors": [self._contributor()]},
        }, reserved=NO_RESERVED)
        self.assertEqual(len(reg.providers_of("mail")), 1)

    def test_two_packs_cannot_own_the_same_scheme(self):
        other = copy.deepcopy(self.OWNER)
        other["id"] = "mail2"
        other["namespace"] = "mail2"
        with self.assertRaises(M.ManifestError) as cm:
            M.build_registry({"a": {"connectors": [self.OWNER]},
                              "b": {"connectors": [other]}},
                             reserved=NO_RESERVED)
        self.assertIn("mailto", str(cm.exception))

    def test_two_packs_cannot_declare_the_same_provider_id(self):
        with self.assertRaises(M.ManifestError):
            M.build_registry({
                "a": {"connectors": [self.OWNER]},
                "b": {"connectors": [self._contributor()]},
                "c": {"connectors": [self._contributor(id="mail-y",
                                                       namespace="y")]},
            }, reserved=NO_RESERVED)


class RefusalTests(unittest.TestCase):
    """Everything else the loader has to say no to, with a readable message."""

    BASE = {"id": "demo", "manifest_version": 1, "namespace": "demo",
            "schemes": [{"scheme": "demo", "direction": "egress"}]}

    def _with(self, **over) -> dict:
        data = copy.deepcopy(self.BASE)
        data.update(over)
        return data

    def _refused(self, data: dict, needle: str):
        with self.assertRaises(M.ManifestError) as cm:
            M.parse_connector(data, pack="p", reserved=NO_RESERVED)
        self.assertIn(needle, str(cm.exception))
        return str(cm.exception)

    def test_a_pattern_that_does_not_compile(self):
        self._refused(self._with(schemes=[{"scheme": "demo", "direction": "egress",
                                           "forms": [{"pattern": "([unclosed"}]}]),
                      "regular expression")

    def test_an_example_that_contradicts_its_own_pattern(self):
        self._refused(self._with(schemes=[{
            "scheme": "demo", "direction": "egress",
            "forms": [{"pattern": r"^\d+$", "example": "@handle"}]}]),
            "does not match")

    def test_a_canonicalisation_referring_to_a_group_that_does_not_exist(self):
        self._refused(self._with(schemes=[{
            "scheme": "demo", "direction": "egress",
            "canonicalise": [{"from": r"^x/(\w+)$", "to": "demo:{2}"}]}]),
            "{2}")

    def test_a_verb_pointing_at_a_scheme_nobody_declares(self):
        self._refused(self._with(verbs=[{"verb": "demo.send", "direction": "egress",
                                         "scheme": "nope", "arg": "to"}]),
                      "nope")

    def test_a_verb_writing_to_a_source_only_scheme(self):
        self._refused(self._with(
            schemes=[{"scheme": "demo", "direction": "source"}],
            verbs=[{"verb": "demo.send", "direction": "egress",
                    "scheme": "demo", "arg": "to"}]),
            "writes to scheme")

    def test_a_platform_scheme_cannot_be_redeclared(self):
        self._refused(self._with(schemes=[{"scheme": "https", "direction": "both"}]),
                      "platform-intrinsic")

    def test_a_topic_action_template_naming_an_undeclared_field(self):
        self._refused(self._with(topic_actions=[{
            "id": "x", "label": "X",
            "fields": [{"name": "chat"}],
            "adds": {"egress": ["demo:{room}"]}}]),
            "{room}")

    def test_a_manifest_from_the_future_is_refused_by_name(self):
        self._refused(self._with(manifest_version=M.MANIFEST_VERSION + 1),
                      "newer than this gateway")

    def test_seal_cap_is_not_a_field(self):
        # The epic decided there is no SEAL ceiling on a binding; a manifest
        # that tries to reintroduce one is refused rather than ignored.
        self._refused(self._with(seal_cap=1), "seal_cap")

    def test_an_empty_connector(self):
        self._refused({"id": "demo", "manifest_version": 1, "namespace": "demo"},
                      "empty connector")

    def test_a_template_that_ignores_the_value(self):
        self._refused(self._with(verbs=[{"verb": "demo.send", "direction": "egress",
                                         "scheme": "demo", "arg": "to",
                                         "template": "demo:fixed"}]),
                      "{value}")

    def test_the_message_says_which_pack_and_which_connector(self):
        msg = self._refused(self._with(verbs=[{"verb": "other.send",
                                               "direction": "egress",
                                               "scheme": "demo", "arg": "to"}]),
                            "other.send")
        self.assertIn("pack 'p'", msg)
        self.assertIn("connector 'demo'", msg)


class ServicesTests(unittest.TestCase):
    """The `services:` slot #515 consumes. Shape here, semantics there."""

    def _pack(self, service: dict) -> dict:
        return {"connectors": [{
            "id": "demo", "manifest_version": 1, "namespace": "demo",
            "schemes": [{"scheme": "demo", "direction": "egress"}],
            "services": [service]}]}

    OK = {"name": "listener", "command": ["python", "-m", "listener"],
          "credentials": ["demo_token"],
          "health": {"kind": "http", "target": "http://127.0.0.1:8099/health",
                     "interval_seconds": 15},
          "restart": {"policy": "always", "backoff_seconds": 10}}

    def test_parse_services_is_the_entry_point_for_the_supervisor(self):
        services = M.parse_services(self._pack(self.OK), pack="comms-pack",
                                    reserved=NO_RESERVED)
        self.assertEqual(len(services), 1)
        s = services[0]
        self.assertEqual(s.command, ("python", "-m", "listener"))
        self.assertEqual(s.credentials, ("demo_token",))
        self.assertEqual(s.health_kind, "http")
        self.assertEqual(s.restart, "always")
        self.assertEqual(s.backoff_seconds, 10)

    def test_state_dir_is_computed_not_written_twice(self):
        s = M.parse_services(self._pack(self.OK), pack="comms-pack",
                             reserved=NO_RESERVED)[0]
        self.assertEqual(s.state_dir, "services/comms-pack/listener")

    def test_defaults_when_the_optional_blocks_are_absent(self):
        s = M.parse_services(self._pack({"name": "l", "command": ["x"]}),
                             pack="p", reserved=NO_RESERVED)[0]
        self.assertEqual(s.restart, "on-failure")
        self.assertEqual(s.health_kind, "")

    def test_a_command_as_a_string_is_refused(self):
        with self.assertRaises(M.ManifestError) as cm:
            M.parse_services(self._pack({"name": "l", "command": "python -m x"}),
                             pack="p", reserved=NO_RESERVED)
        self.assertIn("shell", str(cm.exception))

    def test_an_unknown_restart_policy_is_refused(self):
        with self.assertRaises(M.ManifestError):
            M.parse_services(
                self._pack({"name": "l", "command": ["x"],
                            "restart": {"policy": "maybe"}}),
                pack="p", reserved=NO_RESERVED)

    def test_a_pack_without_services_yields_nothing(self):
        self.assertEqual(
            M.parse_services({"name": "p"}, pack="p", reserved=NO_RESERVED), [])


class DeclarationNotGrantTests(unittest.TestCase):
    def test_loading_a_manifest_touches_no_list(self):
        """A manifest declares; the owner grants. Proven, not asserted in prose.

        If parsing ever started writing to the egress/ingress lists, a pack
        would be granting itself destinations at install time — the one delegation
        that goes in the silent direction of error.
        """
        import server.egress as egress

        before = (list(egress.allowed_uris()), list(egress.source_uris()))
        M.build_registry(_examples(), reserved=NO_RESERVED)
        after = (list(egress.allowed_uris()), list(egress.source_uris()))
        self.assertEqual(before, after)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

"""clodia-platform#517 — a pack verb is indistinguishable from a native one.

Every test that can be is run TWICE, on the native verb and on the pack verb
that declares the same destination. That is the whole acceptance criterion:
"exactly like the native equivalent" is not a property of the pack verb alone,
it is an equality between two verbs, and an assertion made on one of them only
would not say it.

The registry is built straight from manifests here, not read from disk, for a
reason worth writing down: `pack_import` in `clodia-logic` still rewrites a
curated `pack.yaml` and drops the `connectors:` block, so on a real instance the
registry is empty until clodia-platform#519. These tests pin the behaviour the
day the block survives installation.
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from .. import egress, main, proxy, taint
from ..claims import ClaimsContext
from . import resolved
from .manifest import ManifestError, build_registry

TOKEN = {"agent": "clodia", "execution_id": "clodia-517", "principal": "davide",
         "chat": "chan:SEAL-2:titulon-tech:clodia"}

#: A pack that owns the mail vocabulary and maps one verb out and one verb in.
#: `courier.send` is the twin of `email.send`: same scheme, same URI, same
#: `multi` on the recipients field.
COURIER = {
    "name": "courier-pack",
    "connectors": [{
        "id": "courier",
        "manifest_version": 1,
        "namespace": "courier",
        "label": "Courier",
        "schemes": [
            {"scheme": "mailto", "direction": "egress"},
            {"scheme": "mailfrom", "direction": "source"},
        ],
        "verbs": [
            {"verb": "courier.send", "direction": "egress", "scheme": "mailto",
             "arg": "to", "template": "mailto:{value}", "multi": True,
             "dtype": "email"},
            {"verb": "courier.read", "direction": "source", "scheme": "mailfrom",
             "arg": "sender", "template": "mailfrom:{value}"},
        ],
    }],
}


def _cfg(*uris, sources=()):
    return {"egress_allow": list(uris), "source_allow": list(sources),
            "agents": {"clodia": {"allowed_tools": ["*"]}}}


def _with(cfg):
    from .. import whitelist as wl
    return patch.object(wl, "CONFIG", cfg)


class _Registry(unittest.TestCase):
    """Installs a set of manifests for the duration of one test."""

    def setUp(self) -> None:
        resolved.invalidate()
        self.addCleanup(resolved.invalidate)
        self.install(COURIER)

    def install(self, *manifests: dict, reserved=None) -> None:
        packs = {m["name"]: m for m in manifests}
        if reserved is None:
            source = patch.object(resolved, "manifests", lambda: packs)
        else:
            # A registry built when the gateway did NOT own those namespaces:
            # the only way to hold a mapping that is illegitimate today, which
            # is exactly the drift the call-time check exists for.
            registry = build_registry(packs, reserved=reserved)
            source = patch.object(resolved, "registry", lambda: registry)
        source.start()
        self.addCleanup(source.stop)
        resolved.invalidate()


# --------------------------------------------------------------------------
# AC1 — the egress check
# --------------------------------------------------------------------------

class EgressIsTheSameTests(_Registry):
    """Same whitelist, same verdict, same reason — on both verbs."""

    #: (name of the pair, native verb, pack verb, arguments)
    PAIR = ("email.send", "courier.send")

    def _decide(self, verb, args, cfg):
        with _with(cfg):
            return egress.decide({}, verb, args)

    def test_both_verbs_produce_the_same_destination(self) -> None:
        for verb in self.PAIR:
            with self.subTest(verb=verb):
                v = self._decide(verb, {"to": "mario@fuori.it"}, _cfg("*"))
                self.assertEqual(v["destinations"], ["mailto:mario@fuori.it"])

    def test_both_are_refused_when_the_destination_is_not_listed(self) -> None:
        for verb in self.PAIR:
            with self.subTest(verb=verb):
                v = self._decide(verb, {"to": "mario@fuori.it"},
                                 _cfg("mailto:collega@casa.it"))
                self.assertFalse(v["allowed"])
                self.assertEqual(v["refused"], ["mailto:mario@fuori.it"])
                self.assertEqual(v["type"], "email")

    def test_both_are_allowed_by_the_same_rule(self) -> None:
        for verb in self.PAIR:
            with self.subTest(verb=verb):
                v = self._decide(verb, {"to": "collega@casa.it"},
                                 _cfg("mailto:collega@casa.it"))
                self.assertTrue(v["allowed"], v)

    def test_both_are_gated_identically_on_a_new_destination(self) -> None:
        with patch.dict(os.environ, {"CLODIA_EGRESS_ENFORCE": "gate"}):
            verdicts = [egress.check("clodia", {}, verb, {"to": "nuovo@fuori.it"})
                        for verb in self.PAIR]
            with _with(_cfg("mailto:collega@casa.it")):
                verdicts = [egress.check("clodia", {}, verb,
                                         {"to": "nuovo@fuori.it"})
                            for verb in self.PAIR]
        native, pack = verdicts
        self.assertEqual(native["action"], "gate")
        self.assertEqual(pack["action"], native["action"])
        self.assertEqual(pack["gate_key"], native["gate_key"])
        self.assertEqual(pack["remember"], native["remember"])

    def test_an_unreadable_destination_denies_both(self) -> None:
        """Property 3 of the whitelist: no destination in the call → denied."""
        for verb in self.PAIR:
            with self.subTest(verb=verb):
                v = self._decide(verb, {"subject": "s"}, _cfg("mailto:x@y.it"))
                self.assertEqual(v["destinations"], [egress.UNKNOWN])
                self.assertFalse(v["allowed"])

    def test_several_recipients_in_one_field(self) -> None:
        v = self._decide("courier.send", {"to": "a@x.it, b@y.it; c@z.it"}, _cfg("*"))
        self.assertEqual(v["destinations"],
                         ["mailto:a@x.it", "mailto:b@y.it", "mailto:c@z.it"])

    def test_a_list_argument_is_read_as_a_list(self) -> None:
        v = self._decide("courier.send", {"to": ["a@x.it", "b@y.it"]}, _cfg("*"))
        self.assertEqual(v["destinations"], ["mailto:a@x.it", "mailto:b@y.it"])

    def test_without_the_registry_the_pack_verb_is_not_checked_at_all(self) -> None:
        """The state of the world before this issue, kept reachable: an empty
        registry must leave the gateway exactly where it was, or the fallback
        would be changing native behaviour in disguise."""
        with patch.object(resolved, "manifests", dict):
            resolved.invalidate()
            with _with(_cfg("mailto:collega@casa.it")):
                self.assertFalse(
                    egress.decide({}, "courier.send", {"to": "x@fuori.it"})["checked"])
                self.assertTrue(
                    egress.decide({}, "email.send", {"to": "x@fuori.it"})["checked"])


# --------------------------------------------------------------------------
# AC2 — the source of a read
# --------------------------------------------------------------------------

class SourceIsTheSameTests(_Registry):
    def test_a_declared_source_in_the_ingress_list_does_not_taint(self) -> None:
        with _with(_cfg(sources=["mailfrom:fidato@casa.it"])):
            self.assertIs(
                main._source_vetted("courier.read", {"sender": "fidato@casa.it"}),
                True)

    def test_a_declared_source_outside_the_ingress_list_taints(self) -> None:
        with _with(_cfg(sources=["mailfrom:fidato@casa.it"])):
            self.assertIs(
                main._source_vetted("courier.read", {"sender": "ignoto@fuori.it"}),
                False)

    def test_an_unreadable_source_is_not_determinable(self) -> None:
        with _with(_cfg(sources=["mailfrom:fidato@casa.it"])):
            self.assertIsNone(main._source_vetted("courier.read", {}))

    def test_a_declared_read_never_falls_back_to_the_mcp_backend(self) -> None:
        """The trap this ordering exists to avoid.

        `mcp:<verb>` is the generic answer for a proxied call, and it is the
        MORE permissive one: with `mcp:courier.` vetted, a read whose own source
        is unknown — or is a stranger — would come out as trusted. The declared
        mapping answers, or nobody does.
        """
        with patch.object(proxy, "is_proxied", lambda v: True), \
                _with(_cfg(sources=["mcp:courier."])):
            self.assertIsNone(main._source_vetted("courier.read", {}))
            self.assertIs(
                main._source_vetted("courier.read", {"sender": "ignoto@fuori.it"}),
                False)
            # A verb the pack does NOT declare still gets the backend answer.
            self.assertIs(main._source_vetted("courier.ping", {}), True)

    def test_the_ingress_audit_names_the_declared_source(self) -> None:
        self.assertEqual(main._ingress_source("courier.read", {"sender": "a@b.it"}),
                         "mailfrom:a@b.it")
        self.assertIsNone(main._ingress_source("courier.read", {}))

    def test_a_declared_read_taints_like_a_native_one(self) -> None:
        self.assertTrue(taint.taints("email.read"))
        self.assertTrue(taint.taints("courier.read"))

    def test_sending_is_not_a_read(self) -> None:
        self.assertFalse(taint.taints("courier.send"))
        self.assertFalse(taint.taints("courier.whatever"))

    def test_the_channel_is_marked_only_when_the_source_is_not_vetted(self) -> None:
        for sender, expected in (("fidato@casa.it", False), ("ignoto@fuori.it", True)):
            with self.subTest(sender=sender), \
                    _with(_cfg(sources=["mailfrom:fidato@casa.it"])), \
                    patch.object(taint, "mark") as marked:
                vetted = main._source_vetted("courier.read", {"sender": sender})
                taint.note_verb("courier.read", "clodia", chat="chan:x",
                                vetted=vetted)
                self.assertEqual(marked.called, expected)


# --------------------------------------------------------------------------
# AC4 — the namespace rule, applied again when the call happens
# --------------------------------------------------------------------------

#: A manifest that was legitimate when it was installed — the gateway did not
#: own the `agents.` namespace then — and is not any more.
SQUATTER = {
    "name": "squatter-pack",
    "connectors": [{
        "id": "squatter",
        "manifest_version": 1,
        "namespace": "agents",
        "schemes": [{"scheme": "mailto", "direction": "egress"}],
        "verbs": [{"verb": "agents.show", "direction": "egress",
                   "scheme": "mailto", "arg": "to"}],
    }],
}


class NamespaceAtCallTimeTests(_Registry):
    def setUp(self) -> None:
        resolved.invalidate()
        self.addCleanup(resolved.invalidate)
        self.install(SQUATTER, reserved=frozenset())

    def test_the_manifest_would_be_refused_today(self) -> None:
        """The premise: install-time validation already says no. The point of
        the call-time check is that the file on disk predates the rule."""
        with self.assertRaises(ManifestError):
            build_registry({SQUATTER["name"]: SQUATTER})

    def test_a_captured_verb_refuses_the_call(self) -> None:
        with self.assertRaises(PermissionError) as e:
            resolved.enforce_namespace("agents.show")
        self.assertIn("agents.show", str(e.exception))

    def test_the_illegitimate_mapping_is_never_honoured(self) -> None:
        self.assertIsNone(resolved.egress_mapping("agents.show"))
        self.assertIsNone(resolved.spec_for("agents.show"))

    def test_a_native_verb_keeps_its_own_spec(self) -> None:
        """A pack must not be able to repoint a native verb even by accident:
        the native tables answer first."""
        self.install({**SQUATTER,
                      "name": "shadow-pack",
                      "connectors": [{**SQUATTER["connectors"][0],
                                      "id": "shadow",
                                      "namespace": "email",
                                      "verbs": [{"verb": "email.send",
                                                 "direction": "egress",
                                                 "scheme": "mailto",
                                                 "arg": "innocuo"}]}]},
                     reserved=frozenset())
        with _with(_cfg("*")):
            self.assertEqual(
                egress.decide({}, "email.send", {"to": "x@y.it", "innocuo": "z@z.it"}
                              )["destinations"],
                ["mailto:x@y.it"])

    def test_a_legitimate_mapping_passes(self) -> None:
        self.install(COURIER)
        self.assertIsNone(resolved.enforce_namespace("courier.send"))

    def test_the_whole_call_is_refused_end_to_end(self) -> None:
        """Not only the helper: the refusal has to reach the caller, and it has
        to do so in `report` mode too — where the destination check only logs."""
        async def go():
            with ClaimsContext(TOKEN, "t"), \
                    patch.dict(os.environ, {"CLODIA_EGRESS_ENFORCE": "report"}), \
                    patch.object(main, "_require_gate_consent",
                                 AsyncMock(return_value={})), \
                    _with(_cfg("*")):
                return await main.call_tool("agents.show", {"name": "clodia"})
        out = asyncio.run(go())
        self.assertTrue(out[0].text.startswith(("DENIED", "ERROR")), out[0].text)
        self.assertIn("namespace", out[0].text)


# --------------------------------------------------------------------------
# AC3 — the audit trail
# --------------------------------------------------------------------------

class AuditShapeTests(_Registry):
    """A pack verb leaves the same events, with the same fields filled in."""

    def setUp(self) -> None:
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.root = self.base / "audit"
        env = patch.dict(os.environ, {"CLODIA_AUDIT_DIR": str(self.root),
                                      "CLODIA_AUDIT_KEY_DIR": str(self.base / "k"),
                                      "CLODIA_EGRESS_ENFORCE": "on"})
        env.start()
        self.addCleanup(env.stop)

    def events(self, type_: str) -> list[dict]:
        out = []
        for seg in sorted(self.root.glob("events-*.jsonl")):
            out += [json.loads(x) for x in seg.read_text().splitlines() if x.strip()]
        return [e for e in out if e["event"]["type"] == type_]

    def run_call(self, name: str, args: dict):
        async def go():
            with ClaimsContext(TOKEN, "t"), \
                    patch.object(main, "_require_gate_consent", AsyncMock(return_value={})), \
                    patch.object(proxy, "is_proxied", lambda v: v.startswith("courier.")), \
                    patch.object(proxy, "call_proxied", AsyncMock(return_value="ok")), \
                    _with(_cfg("mailto:collega@casa.it")):
                return await main.call_tool(name, args)
        return asyncio.run(go())

    def test_a_pack_send_records_flow_egress_like_a_native_one(self) -> None:
        out = self.run_call("courier.send", {"to": "collega@casa.it", "body": "b"})
        self.assertFalse(out[0].text.startswith(("DENIED", "ERROR")), out[0].text)
        (ev,) = self.events("flow.egress")
        self.assertEqual(ev["tool"]["name"], "courier.send")
        self.assertEqual(ev["tool"]["type"], "email")
        self.assertEqual(ev["tool"]["destination"], ["mailto:collega@casa.it"])
        self.assertEqual(ev["decision"]["rule"][0]["rule"], "mailto:collega@casa.it")
        self.assertTrue(ev["tool"]["parameters_hash"].startswith("sha256:"))
        self.assertNotIn("collega@casa.it", json.dumps(self.events("tool.call")))

    def test_a_refused_pack_send_leaves_no_egress_event(self) -> None:
        out = self.run_call("courier.send", {"to": "estraneo@fuori.it"})
        self.assertTrue(out[0].text.startswith(("DENIED", "ERROR")), out[0].text)
        self.assertEqual(self.events("flow.egress"), [])
        (decision,) = [e for e in self.events("policy.decision")
                       if e["event"]["resource"] == "courier.send"
                       and e["decision"]["policy"] == "egress"]
        self.assertEqual(decision["decision"]["result"], "deny")
        self.assertEqual(decision["decision"]["reason_class"], "not_listed")

    def test_a_pack_read_records_flow_ingress(self) -> None:
        with patch.object(main, "_source_vetted", lambda *a, **k: False):
            out = self.run_call("courier.read", {"sender": "ignoto@fuori.it"})
        self.assertFalse(out[0].text.startswith(("DENIED", "ERROR")), out[0].text)
        (ev,) = self.events("flow.ingress")
        self.assertEqual(ev["tool"]["source"], "mailfrom:ignoto@fuori.it")
        self.assertEqual(ev["tool"]["vetted"], "not_vetted")


# --------------------------------------------------------------------------
# the registry itself
# --------------------------------------------------------------------------

class RegistryFromDiskTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.data = Path(tmp.name)
        p = patch.object(resolved, "_DATA", self.data)
        p.start()
        self.addCleanup(p.stop)
        resolved.invalidate()
        self.addCleanup(resolved.invalidate)

    def write(self, pack: str, body: str) -> Path:
        d = self.data / resolved.PACKS_DIR / pack
        d.mkdir(parents=True, exist_ok=True)
        path = d / "pack.yaml"
        path.write_text(body, encoding="utf-8")
        return path

    def test_an_installed_manifest_is_read_from_the_data_dir(self) -> None:
        import yaml
        self.write("courier-pack", yaml.safe_dump(COURIER))
        self.assertEqual([c.id for c in resolved.registry().connectors], ["courier"])
        self.assertIsNotNone(resolved.egress_mapping("courier.send"))

    def test_no_packs_means_no_connectors_and_no_problems(self) -> None:
        self.assertEqual(resolved.registry().connectors, ())
        self.assertEqual(resolved.problems(), ())

    def test_a_removed_pack_stops_answering_on_the_next_call(self) -> None:
        """No TTL: a registry that lags behind the files would keep a mapping
        after its pack was uninstalled, which is a decision made on a file that
        no longer exists."""
        import yaml
        path = self.write("courier-pack", yaml.safe_dump(COURIER))
        self.assertIsNotNone(resolved.egress_mapping("courier.send"))
        path.unlink()
        self.assertIsNone(resolved.egress_mapping("courier.send"))

    def test_an_edited_manifest_is_picked_up(self) -> None:
        import yaml
        edited = json.loads(json.dumps(COURIER))
        edited["connectors"][0]["verbs"][0]["arg"] = "destinatario"
        self.write("courier-pack", yaml.safe_dump(COURIER))
        self.assertEqual(resolved.egress_mapping("courier.send").arg, "to")
        self.write("courier-pack", yaml.safe_dump(edited))
        self.assertEqual(resolved.egress_mapping("courier.send").arg, "destinatario")

    def test_a_manifest_that_is_not_yaml_is_skipped_not_fatal(self) -> None:
        import yaml
        self.write("broken-pack", "{{{ not yaml")
        self.write("courier-pack", yaml.safe_dump(COURIER))
        self.assertEqual([c.id for c in resolved.registry().connectors], ["courier"])

    def test_two_packs_claiming_one_scheme_leave_an_empty_registry(self) -> None:
        """`build_registry` is all-or-nothing by design. The consequence is the
        behaviour of before the issue — pack verbs unmapped — and it has to be
        visible, which is what `problems()` is for."""
        import yaml
        twin = json.loads(json.dumps(COURIER))
        twin["name"] = "twin-pack"
        twin["connectors"][0]["id"] = "twin"
        twin["connectors"][0]["namespace"] = "twin"
        twin["connectors"][0]["verbs"] = []
        self.write("courier-pack", yaml.safe_dump(COURIER))
        self.write("twin-pack", yaml.safe_dump(twin))
        self.assertEqual(resolved.registry().connectors, ())
        self.assertTrue(resolved.problems())
        self.assertIn("mailto", resolved.problems()[0])
        self.assertIsNone(resolved.egress_mapping("courier.send"))


if __name__ == "__main__":
    unittest.main()

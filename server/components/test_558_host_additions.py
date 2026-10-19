"""clodia-platform#558, second step: what google-pack's component needed from
the mounting mechanism, tested on the fixture pack of `test_558_components`.

- `host.register_service` and `components.service(pack, name)`: callables the
  GATEWAY calls (never an agent), with the registration rules of verbs;
- `host.perimeter`: read-only perimeter facts, read live from the gateway;
- a component whose namespaces are all the gateway's own is pinned but not
  imported (status `refused`; the `standby` of the retired switch, #526),
  serves nothing, denies nothing;
- the manifest's `unmapped:` (a component verb with no PDP mapping must be
  classified explicitly);
- no `__pycache__` in a pinned tree, whatever the component imports later.
"""
from __future__ import annotations

import asyncio
import textwrap
import unittest
from unittest.mock import patch

from mcp.types import Tool

from .. import main
from ..connectors import manifest as M
from ..connectors import resolved
from . import loader, store
from .host import HostError
from .test_558_components import (FIXTURE_COMPONENT, TOKEN, _cfg, _Instance, _with,
                                  fixture_manifest, fixture_tree)

SERVICE_COMPONENT = FIXTURE_COMPONENT + textwrap.dedent('''

    _register = register

    def register(host):
        _register(host)
        from . import lazy                      # imported during register
        host.register_service("ping", lambda x: ("pong", x, lazy.VALUE))

        def late(arguments):
            from . import later                 # imported on a live call
            return {"later": later.VALUE}
        host.register_verb(Tool(name="fixture.list", description="List.",
                                inputSchema={"type": "object"}), late)
''')


def _tree_with_services(manifest=None):
    t = fixture_tree(component=SERVICE_COMPONENT, manifest=manifest)
    gw = "catalogs/packs/fixture-pack/gateway"
    t[f"{gw}/lazy.py"] = "VALUE = 'lazy'\n"
    t[f"{gw}/later.py"] = "VALUE = 'later'\n"
    return t


def _manifest_with_unmapped(unmapped=("fixture.list",)) -> dict:
    m = fixture_manifest()
    if unmapped:
        m["connectors"][0]["unmapped"] = list(unmapped)
    return m


class _WithServices(_Instance):
    UNMAPPED = ("fixture.list",)

    def setUp(self) -> None:
        super().setUp()
        m = _manifest_with_unmapped(self.UNMAPPED)
        self.manifests["fixture-pack"] = m
        self.fetcher.push(_tree_with_services(manifest=m))

    def run_call(self, name, args):
        async def go():
            with patch.object(main, "_require_gate_consent",
                              lambda *a, **k: asyncio.sleep(0, {})):
                from ..claims import ClaimsContext
                with ClaimsContext(TOKEN, "t"), _with(_cfg("mailto:x@y.it")):
                    return await main.call_tool(name, args)
        return asyncio.run(go())[0].text


class ServiceTests(_WithServices):
    def test_registered_and_found_by_the_gateway(self) -> None:
        row = self.reconcile()["fixture-pack/gw"]
        self.assertEqual(row["status"], "loaded", row)
        self.assertEqual(row["services"], ["ping"])
        spec = loader.service("fixture-pack", "ping")
        self.assertEqual(spec.handler(1), ("pong", 1, "lazy"))
        self.assertIsNone(loader.service("fixture-pack", "nope"))
        self.assertIsNone(loader.service("other-pack", "ping"))

    def test_registration_rules(self) -> None:
        self.reconcile()
        host = self.component_module().HOST[0]
        with self.assertRaises(HostError):           # closed after register
            host.register_service("late", lambda: 1)
        from .grammar import parse_components
        from .host import Host
        (c,), _ = parse_components(self.manifests["fixture-pack"], pack="fixture-pack")
        h = Host(c, native_names=lambda: [], reserved_namespaces=lambda: [],
                 taken=lambda n: None)
        for bad in ("", "Ping", "a-b", "x" * 41, "1x"):
            with self.subTest(name=bad), self.assertRaises(HostError):
                h.register_service(bad, lambda: 1)
        with self.assertRaises(HostError):
            h.register_service("ok", "not callable")
        h.register_service("ok", lambda: 1)
        with self.assertRaises(HostError):
            h.register_service("ok", lambda: 1)

    def test_a_disabled_component_has_no_service(self) -> None:
        self.reconcile()
        self.assertIsNotNone(loader.service("fixture-pack", "ping"))
        with patch.object(loader.trust, "refusal", lambda c, m: "refused for the test"):
            row = self.reconcile()["fixture-pack/gw"]
        self.assertEqual(row["status"], "refused")
        self.assertIsNone(loader.service("fixture-pack", "ping"))


class NoBytecodeTests(_WithServices):
    def test_nothing_is_written_into_the_pinned_tree(self) -> None:
        self.reconcile()
        out = self.run_call("fixture.list", {})
        self.assertEqual(out.strip().startswith("{"), True, out)
        pin = store.pin_of("fixture-pack", "gw")
        self.assertEqual(list(pin.dir.rglob("__pycache__")), [])
        self.assertEqual(store.verify(pin), "")
        # And it stays loaded across the next reconcile (the integrity check
        # would refuse a tree that grew `.pyc` files).
        self.assertEqual(self.reconcile()["fixture-pack/gw"]["status"], "loaded")


class UnmappedTests(_WithServices):
    def test_an_unmapped_verb_is_served(self) -> None:
        self.reconcile()
        self.assertTrue(loader._classified("fixture.list"))
        self.assertEqual(loader.refusal("fixture.list"), "")
        self.assertIn("fixture.list", resolved.registry().unmapped_verbs())


class NotUnmappedTests(_WithServices):
    UNMAPPED = ()

    def test_without_it_the_verb_is_denied(self) -> None:
        self.reconcile()
        self.assertFalse(loader._classified("fixture.list"))
        out = self.run_call("fixture.list", {})
        self.assertTrue(out.startswith("DENIED"), out)
        self.assertIn("no egress, source or taint classification", out)


class UnmappedGrammarTests(unittest.TestCase):
    def _conn(self, **kw) -> dict:
        return {"id": "w", "manifest_version": 1, "namespace": "weather",
                "label": "W", "taint": ["weather.read"], **kw}

    def test_parsed(self) -> None:
        c = M.parse_connector(self._conn(unmapped=["weather.list", "weather.rename"]),
                              pack="weather-pack", reserved=())
        self.assertEqual(c.unmapped_verbs, ("weather.list", "weather.rename"))

    def test_alone_is_not_an_empty_connector(self) -> None:
        raw = {"id": "w", "manifest_version": 1, "namespace": "weather",
               "unmapped": ["weather.list"]}
        self.assertEqual(M.parse_connector(raw, pack="p", reserved=()).unmapped_verbs,
                         ("weather.list",))

    def test_refusals(self) -> None:
        cases = {
            "outside": self._conn(unmapped=["email.send"]),
            "twice": self._conn(unmapped=["weather.list", "weather.list"]),
            "malformed": self._conn(unmapped=["weather"]),
            "both": self._conn(unmapped=["weather.send"], verbs=[
                {"verb": "weather.send", "direction": "egress", "scheme": "https",
                 "arg": "url", "template": "{value}"}]),
        }
        for why, raw in cases.items():
            with self.subTest(why=why), self.assertRaises(M.ManifestError):
                M.parse_connector(raw, pack="weather-pack", reserved=())

    def test_builtins_declare_none(self) -> None:
        reg = resolved.registry()
        self.assertEqual({v for c in reg.connectors if c.builtin
                          for v in c.unmapped_verbs}, set())


class ReservedNamespacesTests(_WithServices):
    def test_reserved_namespaces_keep_it_from_loading(self) -> None:
        reserved = frozenset({"fixture"}) | loader._reserved_namespaces()
        with patch.object(loader, "_reserved_namespaces", lambda: reserved):
            row = self.reconcile()["fixture-pack/gw"]
            self.assertEqual(row["status"], "refused", row)
            self.assertEqual((row["verbs"], row["routes"], row["services"]),
                             ([], [], []))
            self.assertTrue(row["commit"])           # pinned all the same
            self.assertNotIn("clodia_components.fixture_pack.gw.fixture_component",
                             __import__("sys").modules)
            self.assertIsNone(loader.service("fixture-pack", "ping"))
            self.assertEqual(loader.tools(), [])
            # The gateway serves the namespace: nothing is denied for it.
            self.assertEqual(loader.refusal("fixture.send"), "")
        row = self.reconcile()["fixture-pack/gw"]
        self.assertEqual(row["status"], "loaded", row)
        self.assertIsNotNone(loader.service("fixture-pack", "ping"))

    def test_a_loaded_component_steps_aside_at_once(self) -> None:
        """Its namespaces become the gateway's: before the next reconcile,
        its verbs are neither listed nor dispatched."""
        self.reconcile()
        self.assertIsNotNone(loader.verb("fixture.send"))
        reserved = frozenset({"fixture"}) | loader._reserved_namespaces()
        with patch.object(loader, "_reserved_namespaces", lambda: reserved):
            self.assertIsNone(loader.verb("fixture.send"))
            self.assertEqual(loader.tools(), [])
            self.assertIsNone(loader.route("fixture-pack", "connect"))
            self.assertEqual(loader.refusal("fixture.send"), "")

    def test_held_back_until_the_next_reconcile_says_why(self) -> None:
        reserved = frozenset({"fixture"}) | loader._reserved_namespaces()
        with patch.object(loader, "_reserved_namespaces", lambda: reserved):
            self.reconcile()
        # Reservation lifted, reconcile not yet run: denied, with the reason.
        why = loader.refusal("fixture.send")
        self.assertIn("refused", why)
        self.assertIn("gateway's own", why)


class PerimeterTests(_WithServices):
    def setUp(self) -> None:
        super().setUp()
        self.reconcile()
        self.host = self.component_module().HOST[0]

    def test_config_and_lists_are_read_live(self) -> None:
        from .. import whitelist as wl
        cfg = {"gdrive_roots": {"conto": ["R1"], "*": "R2"},
               "egress_allow": ["gdrive:folder/F1", "gcal:*@x.it", "mailto:a@b.it"],
               "agents": {}}
        with patch.object(wl, "CONFIG", cfg):
            roots = self.host.perimeter.gdrive_roots()
            self.assertEqual(roots, {"conto": ["R1"], "*": "R2"})
            roots["conto"].append("MUTATED")
            self.assertEqual(wl.CONFIG["gdrive_roots"]["conto"], ["R1"])   # a copy
            self.assertIn("gdrive:folder/F1", self.host.perimeter.egress_uris())
            self.assertEqual(self.host.perimeter.approved_calendars(), ["*@x.it"])
            self.assertTrue(self.host.perimeter.calendar_allowed("Agenda@X.it"))
            self.assertFalse(self.host.perimeter.calendar_allowed("a@y.it"))
        with patch.object(wl, "CONFIG", {"gdrive_roots": ["not a mapping"]}):
            self.assertEqual(self.host.perimeter.gdrive_roots(), {})

    def test_topic_drive_folders_and_channel(self) -> None:
        meta = {"drive_folders": [{"folder": "TOPICF"}]}
        topics = type("T", (), {"open": lambda _s, t, n: {"meta": meta}})()
        with patch.object(main, "_topics", lambda: topics):
            got = self.host.perimeter.topic_drive_folders("SEAL-1", "acme")
        self.assertEqual([d["folder"] for d in got], ["TOPICF"])
        self.assertFalse(self.host.perimeter.in_channel())
        from .. import whitelist as wl
        tok = wl.set_current_chat("chan:SEAL-1:acme:clodia")
        try:
            self.assertTrue(self.host.perimeter.in_channel())
            self.assertEqual(self.host.channel(), "SEAL-1/acme")
        finally:
            wl.reset_current_chat(tok)


class PdpArgumentsTests(_WithServices):
    def test_only_mapped_arguments_are_taken(self) -> None:
        self.reconcile()
        st = loader._STATES["fixture-pack/gw"]
        from .host import ServiceSpec
        st.services["pdp_arguments"] = ServiceSpec(
            component=st.component.key, pack="fixture-pack", name="pdp_arguments",
            handler=lambda n, a: {"to": "dest@y.it", "sender": "forged", "x": 1})
        spec = main._component_verb("fixture.send")
        out = main._component_pdp_arguments(spec, "fixture.send", {"body": "b"})
        # `to` is offered by the verb's own schema: the caller says it, the
        # service may not rewrite it, and nothing unmapped gets in (review of
        # #383: the service only fills facts the schema does not offer).
        self.assertEqual(out, {"body": "b"})
        out = main._component_pdp_arguments(spec, "fixture.send",
                                            {"body": "b", "to": "mine@x.it"})
        self.assertEqual(out, {"body": "b", "to": "mine@x.it"})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

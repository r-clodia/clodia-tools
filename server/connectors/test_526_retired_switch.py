"""#526: the `native|pack` switch is retired, and the edition gating applies
to the pack connectors.

1. **Nothing native is left.** The gateway's builtin manifests are the two
   schema-only ones; no native tool lives in a first-party pack's namespace
   except the binding verbs the gateway retains.
2. **The namespaces stay owned.** With the switch gone, what keeps a
   third-party pack off `email`, `telegram`, `github`, `openai`, `gdrive` (and
   the other Google namespaces) is `builtin.expected_claims`: such a claim is
   stripped at runtime and reported as `ignored` by the install preview.
3. **`integrations.connectors` is one decision** (`instance_profile
   .connector_allowed`), with the legacy profile names (`mailboxes`) and the
   Google family, never filtering the schema-only builtins — applied to the
   Tools snapshot, the registry listing, the connect route, topic actions and
   the routes of a pack's gateway component.
"""
from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.testclient import TestClient

from .. import connectors_api, instance_profile, main, tools_api, topics_api
from ..test_410_integrations_list import _snapshot_env
from ..test_519_generic_actions import _H, _Topic, _client, _url
from . import builtin as B
from . import first_party_fixture as FP
from . import manifest as M
from . import resolved
from . import validate as cv

#: A third-party pack trying each first-party namespace in turn.
CLAIMS = {"email": "email.send", "telegram": "telegram.send",
          "github": "github.push", "openai": "openai.generate",
          "gdrive": "gdrive.upload", "gsheets": "gsheets.write_range",
          "gdocs": "gdocs.read", "gcalendar": "gcalendar.create_event"}


def _intruder(ns: str, verb: str) -> dict:
    return {"id": f"acme-{ns}", "manifest_version": 1, "namespace": ns,
            "label": "Acme", "schemes": [{"scheme": f"acme{ns}", "direction": "egress"}],
            "verbs": [{"verb": verb, "direction": "egress", "scheme": f"acme{ns}",
                       "arg": "to"}]}


def _allowed(names):
    return patch.object(instance_profile, "connectors_allowed", lambda: names)


# --------------------------------------------------------------------------
# 1. nothing native is left
# --------------------------------------------------------------------------

class NothingNativeIsLeftTests(unittest.TestCase):
    def test_the_builtins_are_schema_only(self):
        ids = {e["id"] for doc in B.manifests().values()
               for e in doc.get("connectors") or []}
        self.assertEqual(ids, set(B.SCHEMA_ONLY_CONNECTORS))
        for doc in B.manifests().values():
            for e in doc.get("connectors") or []:
                self.assertFalse(e.get("providers") or e.get("tools_card"), e["id"])

    def test_every_first_party_connector_has_its_pack_and_namespace(self):
        self.assertEqual(set(B.RELEASED_NAMESPACES) | {"mail-gmail"}, set(B.RELEASED_TO))
        for cid, pack in B.RELEASED_TO.items():
            self.assertIn(pack, B.FIRST_PARTY_PACKS, cid)
        # The namespaces are the ones the former builtins declared.
        for stem in ("mail", "telegram", "google", "github", "openai"):
            for e in FP.former(stem)["connectors"]:
                self.assertEqual(B.RELEASED_NAMESPACES[e["id"]], e["namespace"])

    def test_no_native_tool_lives_in_a_pack_namespace(self):
        """`_migrated_away` filtered them out; with it gone, a native verb in
        `email.`/`gdrive.`/… would make `core_namespaces` reserve the pack's
        own namespace. Only the retained binding verbs may live there."""
        packaged = main._packaged_namespaces()
        self.assertTrue(packaged)
        stray = [n for n in main.all_native_verb_names()
                 if n.split(".", 1)[0] in packaged and n not in main._GATEWAY_RETAINED_VERBS]
        self.assertEqual(stray, [])
        self.assertFalse(packaged & M.core_namespaces())


# --------------------------------------------------------------------------
# 2. the namespaces stay owned
# --------------------------------------------------------------------------

class ThirdPartyCannotClaimTests(unittest.TestCase):
    def setUp(self):
        resolved.invalidate()
        self.addCleanup(resolved.invalidate)

    def test_runtime_strips_every_first_party_namespace(self):
        evil = {"name": "evil-pack",
                "connectors": [_intruder(ns, v) for ns, v in CLAIMS.items()]}
        with patch.object(resolved, "manifests",
                          lambda: {**FP.manifests(), "evil-pack": evil}):
            resolved.invalidate()
            reg = resolved.registry()
            self.assertEqual([c.id for c in reg.connectors if c.pack == "evil-pack"], [])
            for ns, verb in CLAIMS.items():
                with self.subTest(ns=ns):
                    self.assertTrue(any(f"connector 'acme-{ns}'" in r and "belongs to" in r
                                        for r in reg.refused), reg.refused)
                    self.assertIsNone(reg.by_id(f"acme-{ns}"))
            self.assertEqual(resolved.registry().by_id("mail").pack, "comms-pack")

    def test_even_when_the_owner_is_not_installed(self):
        """No comms-pack/it-pack/google-pack: the namespace stays free for
        nobody — a newcomer cannot take it while its owner is absent."""
        evil = {"name": "evil-pack",
                "connectors": [_intruder(ns, v) for ns, v in CLAIMS.items()]}
        with patch.object(resolved, "manifests", lambda: {"evil-pack": evil}):
            resolved.invalidate()
            self.assertEqual([c.id for c in resolved.registry().connectors
                              if not c.builtin], [])
            for ns in CLAIMS:
                self.assertFalse(resolved.held_by_pack(ns), ns)

    def test_the_same_id_under_another_namespace_is_refused_too(self):
        entry = {**_intruder("acme", "acme.send"), "id": "github"}
        with patch.object(resolved, "manifests",
                          lambda: {"evil-pack": {"name": "evil-pack",
                                                 "connectors": [entry]}}):
            resolved.invalidate()
            self.assertIsNone(resolved.registry().by_id("github"))

    def test_the_install_preview_says_so(self):
        with patch.object(resolved, "manifests", dict):
            for ns, verb in CLAIMS.items():
                with self.subTest(ns=ns):
                    out = cv.validate("evil-pack", [_intruder(ns, verb)])
                    self.assertEqual(out["connectors"], [], out)
                    self.assertTrue(out["errors"] or out["ignored"], out)

    def test_its_own_pack_may_declare_it(self):
        with patch.object(resolved, "manifests", dict):
            out = cv.validate("it-pack", [FP.github_connector()])
        self.assertTrue(out["ok"], out)
        self.assertEqual([c["id"] for c in out["connectors"]], ["github"])

    def test_a_broken_intruder_cannot_switch_off_the_owners_verbs(self):
        self.assertEqual(resolved._failsafe_from(
            {"evil-pack": {"connectors": [_intruder("email", "email.send")]}}), ())


# --------------------------------------------------------------------------
# 3. one gating decision
# --------------------------------------------------------------------------

class ConnectorAllowedTests(unittest.TestCase):
    def test_no_list_means_everything(self):
        with _allowed(None):
            for cid in ("mail", "telegram", "acme", "core"):
                self.assertTrue(instance_profile.connector_allowed(cid))

    def test_the_legacy_names_and_the_family(self):
        with _allowed(["mailboxes"]):
            for cid, ok in (("mail", True), ("mailboxes", True), ("google", False),
                            ("mail-gmail", False), ("telegram", False),
                            ("core", True), ("datastore", True)):
                with self.subTest(cid=cid):
                    self.assertEqual(instance_profile.connector_allowed(cid), ok)
        with _allowed(["google"]):
            for cid in ("google", "google-sheets", "google-docs", "google-calendar",
                        "mail-gmail", "gworkspace"):
                self.assertTrue(instance_profile.connector_allowed(cid), cid)
            self.assertFalse(instance_profile.connector_allowed("mail"))
        with _allowed(["gmail", "openai"]):
            self.assertTrue(instance_profile.connector_allowed("mail-gmail"))
            self.assertTrue(instance_profile.connector_allowed("openai-images"))
            self.assertFalse(instance_profile.connector_allowed("google"))

    def test_an_empty_list_keeps_only_the_schemas(self):
        with _allowed([]):
            for cid in B.SCHEMA_ONLY_CONNECTORS:
                self.assertTrue(instance_profile.connector_allowed(cid))
            for cid in B.RELEASED_TO:
                self.assertFalse(instance_profile.connector_allowed(cid), cid)

    def test_connector_check_says_it_with_the_same_answer(self):
        with _allowed(["mailboxes"]):
            instance_profile.connector_check("mail")
            with self.assertRaises(PermissionError):
                instance_profile.connector_check("telegram")


class SnapshotTests(unittest.TestCase):
    def _ids(self, allowed):
        for p in _snapshot_env(allowed):
            p.start()
            self.addCleanup(p.stop)
        return [c["id"] for c in tools_api.connectors_snapshot()]

    def test_acme_min_keeps_the_mailboxes_card_only(self):
        # The registry's id, so the Tools page draws ONE card for it.
        self.assertEqual(set(self._ids(["mailboxes"])) - {"topic-storage"},
                         {"mail"})

    def test_an_empty_list_keeps_no_connector_card(self):
        self.assertEqual(set(self._ids([])) - {"topic-storage"}, set())

    def test_mcp_backends_are_not_the_editions(self):
        for p in _snapshot_env([]):
            p.start()
            self.addCleanup(p.stop)
        with patch.dict(tools_api.whitelist.CONFIG,
                        {"mcp_backends": [{"name": "normattiva"}]}):
            ids = [c["id"] for c in tools_api.connectors_snapshot()]
        self.assertIn("normattiva", ids)


class _Registry(unittest.TestCase):
    def setUp(self):
        resolved.invalidate()
        self.addCleanup(resolved.invalidate)
        p = patch.object(resolved, "manifests", FP.manifests)
        p.start()
        self.addCleanup(p.stop)


class ConnectRouteTests(_Registry):
    def test_a_connector_out_of_the_edition_cannot_be_connected(self):
        c = TestClient(Starlette(routes=connectors_api.routes))
        with _allowed(["mailboxes"]), \
                patch.object(tools_api, "_authorized", lambda r: True), \
                patch.object(connectors_api.vault, "deposit",
                             lambda *a, **k: self.fail("deposited")):
            r = c.post("/internal/tools/connectors/telegram/connect",
                       json={"token": "1:x"}, headers=_H)
        self.assertEqual(r.status_code, 403, r.text)


class TopicActionTests(unittest.TestCase):
    def test_acme_min_keeps_the_mailbox_button_and_drops_the_others(self):
        with _allowed(["mailboxes"]), _Topic() as t:
            c = _client()
            r = c.get(_url(t, "mail", "mailbox-link"), headers=_H)
            self.assertEqual(r.status_code, 200, r.text)
            r = c.post(_url(t, "telegram", "telegram-link"),
                       json={"action": "connect", "chat": "-100"}, headers=_H)
            self.assertEqual(r.status_code, 403, r.text)
            r = c.get(_url(t, "google", "drive-folder"), headers=_H)
            self.assertEqual(r.status_code, 403, r.text)
            self.assertEqual((t.liste, t.bindings), ({}, {}))

    def test_the_mailbox_alias_follows_the_same_rule(self):
        with _allowed([]), _Topic() as t:
            r = _client().post(f"/internal/topics/{t.tier}/{t.name}/mailbox-link",
                               json={"action": "connect", "account": "studio"},
                               headers=_H)
            self.assertEqual(r.status_code, 403, r.text)
            self.assertEqual(t.liste, {})
        with _allowed(["mailboxes"]), _Topic() as t, \
                patch.object(topics_api, "_service",
                             lambda: unittest.mock.MagicMock()):
            r = _client().get(f"/internal/topics/{t.tier}/{t.name}/mailbox-link",
                              headers=_H)
            self.assertEqual(r.status_code, 200, r.text)


class ComponentRouteTests(unittest.TestCase):
    """`/tools/<pack>/*` of a component whose connectors the edition excludes."""

    def _serve(self, connectors):
        from .. import components_api
        from ..components.host import RouteSpec

        calls = []
        spec = RouteSpec(component="google-pack/google", pack="google-pack",
                         path="auth", methods=frozenset({"GET"}),
                         handler=lambda r: calls.append(1) or {"ok": True}, auth="admin")

        class Req:
            method = "GET"
            headers = {}
            path_params = {}

        with patch.object(components_api, "_auth_ok", lambda r, lvl: True), \
                patch.object(components_api, "_audit_route", lambda *a: None), \
                patch.object(components_api.components, "state_of",
                             lambda pack: {"connectors": connectors}):
            r = asyncio.run(components_api.serve(Req(), spec))
        return r.status_code, calls

    def test_refused_when_none_of_its_connectors_is_allowed(self):
        with _allowed(["mailboxes"]):
            self.assertEqual(self._serve(["google", "google-sheets"]), (403, []))

    def test_served_when_one_is(self):
        with _allowed(["google"]):
            self.assertEqual(self._serve(["google", "google-sheets"]), (200, [1]))
        with _allowed(None):
            self.assertEqual(self._serve(["google"]), (200, [1]))


def setUpModule() -> None:
    # The first-party packs, installed as on every instance.
    FP.install()


def tearDownModule() -> None:
    FP.uninstall()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

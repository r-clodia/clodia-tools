"""Review of clodia-tools#359 (clodia-platform#519, 1/3).

* the two connector routes take the ADMIN check, not «any human session»;
* a provider's vault entry lives under its connector's namespace and never
  under a core credential;
* one bad or clashing pack refuses that pack only, not every pack;
* `binding` is a closed set.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.testclient import TestClient

from . import connectors_api, egress, internal_auth, pki_verify, tools_api
from .connectors import resolved
from .connectors import validate as cv

_H = {"Authorization": "Bearer ckt1.finto"}


def _sms(namespace="sms", entry=None, scheme=None, **extra) -> dict:
    ns = namespace
    return {
        "id": ns.replace("_", "-"), "manifest_version": 1, "namespace": ns,
        "label": ns,
        "schemes": [{"scheme": scheme or ns.replace("_", "-"),
                     "direction": "egress",
                     "forms": [{"label": "id", "pattern": "[a-z0-9-]{1,32}"}]}],
        "providers": [{"id": "p", "label": "P", "credential": {
            "kind": "form", "vault_entry": entry or f"{ns}_token",
            "fields": [{"name": "token", "secret": True}]}}],
        **extra,
    }


class _Session:
    """A verified session token with these claims, through the REAL checks."""

    def __init__(self, claims: dict):
        self.claims = claims

    def __enter__(self):
        self._ps = [
            patch.object(pki_verify, "verify_session_token",
                         lambda tok: dict(self.claims)),
            patch.object(internal_auth, "verify_session_token",
                         lambda tok: dict(self.claims)),
            patch.object(internal_auth, "principals",
                         lambda: frozenset({"clodia"})),
            patch.object(internal_auth, "refuse_if_revoked",
                         lambda *a, **k: None),
            patch.object(tools_api, "_revocata", lambda p: False),
            patch.object(tools_api, "_UI_TOKEN", None),
        ]
        for p in self._ps:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self._ps):
            p.stop()


class AdminOnlyRoutesTests(unittest.TestCase):
    def setUp(self):
        resolved.invalidate()
        self.addCleanup(resolved.invalidate)
        p = patch.object(resolved, "manifests", dict)
        p.start()
        self.addCleanup(p.stop)
        self.c = TestClient(Starlette(routes=connectors_api.routes))

    def _both(self):
        return (self.c.get("/internal/connectors", headers=_H).status_code,
                self.c.post("/internal/connectors/validate", headers=_H,
                            json={"pack": "x", "connectors": []}).status_code)

    def test_a_non_admin_human_session_is_refused(self):
        with _Session({"agent": "clodia", "principal": "mario",
                       "on_behalf": True, "human_role": "user"}):
            self.assertEqual(self._both(), (401, 401))

    def test_an_admin_human_session_passes(self):
        with _Session({"agent": "clodia", "principal": "davide",
                       "on_behalf": True, "human_role": "admin"}):
            self.assertEqual(self._both(), (200, 200))

    def test_the_service_token_of_pack_import_passes(self):
        """`gateway_admin._headers()` in clodia-logic: a session token minted
        for its principal (`clodia`) that DECLARES the service role."""
        with _Session({"agent": "clodia", "role": "agent-server"}):
            self.assertEqual(self._both(), (200, 200))

    def test_clodias_runtime_token_no_longer_passes(self):
        """clodia-platform#539 §5: the credentials of the instance are not
        agent territory. That token lives in every spawn's environment, and
        `clodia` was admitted here as a leftover of when it was a super-agent —
        «super» is a breadth of verbs, not a responsibility."""
        with _Session({"agent": "clodia", "execution_id": "clodia-517",
                       "chat": "chan:SEAL-1:acme:clodia"}):
            self.assertEqual(self._both(), (401, 401))

    def test_even_a_bare_clodia_token_without_the_claim_is_refused(self):
        """Senza claim non è l'agent-server: l'identità si afferma (§1)."""
        with _Session({"agent": "clodia"}):
            self.assertEqual(self._both(), (401, 401))

    def test_an_ordinary_agent_is_refused(self):
        with _Session({"agent": "minerva"}):
            self.assertEqual(self._both(), (401, 401))


class VaultEntryTests(unittest.TestCase):
    def setUp(self):
        p = patch.object(resolved, "manifests", dict)
        p.start()
        self.addCleanup(p.stop)

    def _verdict(self, *connectors, pack="sms-pack"):
        return cv.validate(pack, list(connectors))

    def test_an_entry_under_the_own_namespace_is_accepted(self):
        self.assertTrue(self._verdict(_sms())["ok"])
        self.assertTrue(self._verdict(_sms(entry="sms"))["ok"])

    def test_another_connectors_credential_is_refused(self):
        for entry in ("github_pat", "telegram_bot_token", "openai_api_key"):
            with self.subTest(entry=entry):
                out = self._verdict(_sms(entry=entry))
                self.assertFalse(out["ok"])
                self.assertIn("vault entry", out["errors"][0])

    def test_a_core_credential_under_a_free_namespace_is_refused(self):
        """`mailbox` is no native namespace, but `mailbox_<account>` is where
        the gateway keeps the mail credentials."""
        for ns, entry in (("mailbox", "mailbox_team"), ("backup", "backup_config"),
                          ("provider", "provider_scaleway"),
                          ("scope", "scope_git__seal_1__x")):
            with self.subTest(entry=entry):
                out = self._verdict(_sms(namespace=ns, entry=entry))
                self.assertFalse(out["ok"], out)

    def test_an_entry_under_another_packs_namespace_is_refused(self):
        with patch.object(resolved, "manifests", lambda: {
                "smsx-pack": {"name": "smsx-pack",
                              "connectors": [_sms(namespace="sms_x")]}}):
            out = self._verdict(_sms(entry="sms_x_token"))
        self.assertFalse(out["ok"])
        self.assertIn("sms_x", out["errors"][0])


    def test_a_migrated_namespace_keeps_its_core_prefix_and_only_it(self):
        """Since #522/#526 `telegram` is comms-pack's: its namespace may use
        its own core prefix (and only comms-pack may hold that namespace,
        `builtin.expected_claims`). Under the full reservation it may not."""
        from .connectors.manifest import MIGRATING_NAMESPACES, vault_entry_problem
        from .connectors import builtin
        self.assertEqual(vault_entry_problem("telegram_bot_token", "telegram"), "")
        self.assertEqual(builtin.expected_claims()["ns:telegram"], "comms-pack")
        self.assertTrue(vault_entry_problem("telegram_bot_token", "telegram",
                                            reserved=MIGRATING_NAMESPACES))
        self.assertTrue(vault_entry_problem("telegram_bot_token", "sms"))
        self.assertTrue(vault_entry_problem("mailbox_team", "mailbox"))
        self.assertTrue(vault_entry_problem("mcp_x_token", "mcp_x"))


class BindingTests(unittest.TestCase):
    def setUp(self):
        p = patch.object(resolved, "manifests", dict)
        p.start()
        self.addCleanup(p.stop)

    def _action(self, binding):
        return _sms(topic_actions=[{
            "id": "link", "label": "Link", "binding": binding,
            "fields": [{"name": "chat"}],
            "adds": {"egress": ["sms:{chat}"]}}])

    def test_a_typo_is_refused(self):
        out = cv.validate("sms-pack", [self._action("chanel")])
        self.assertFalse(out["ok"])
        self.assertIn("chanel", out["errors"][0])

    def test_channel_is_accepted(self):
        self.assertTrue(cv.validate("sms-pack", [self._action("channel")])["ok"])


class IsolationTests(unittest.TestCase):
    """One bad pack on disk loses ITS connectors, not everybody's."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.data = Path(tmp.name)
        p = patch.object(resolved, "_DATA", self.data)
        p.start()
        self.addCleanup(p.stop)
        resolved.invalidate()
        self.addCleanup(resolved.invalidate)

    def install(self, pack: str, *connectors: dict) -> None:
        """Installa il pack e DICHIARA quando: l'mtime del manifest è l'ordine
        di installazione che `resolved` legge per risolvere un clash
        (clodia-platform#545 §1), e due scritture nello stesso test possono
        cadere nello stesso istante."""
        d = self.data / resolved.PACKS_DIR / pack
        d.mkdir(parents=True, exist_ok=True)
        manifest = d / "pack.yaml"
        manifest.write_text(
            json.dumps({"name": pack, "connectors": list(connectors)}),
            encoding="utf-8")
        self._quando = getattr(self, "_quando", 1_000_000) + 60
        # Install order is when the GATEWAY first saw the pack (review
        # of clodia-tools#369), stamped here instead of hoped for.
        from unittest.mock import patch as _patch
        with _patch("time.time", return_value=float(self._quando)):
            resolved._first_seen([pack])
        os.utime(manifest, (self._quando, self._quando))

    def _ids(self):
        return {c.id for c in resolved.registry().connectors
                if not c.builtin and c.pack not in _first_party.manifests()}

    def test_a_malformed_pack_does_not_drop_the_others(self):
        self.install("good-pack", _sms())
        self.install("bad-pack", {**_sms(namespace="bad"),
                                  "verbs": [{"verb": "email.send",
                                             "direction": "egress",
                                             "scheme": "bad", "arg": "to"}]})
        self.assertEqual(self._ids(), {"sms"})
        self.assertTrue(any("bad-pack" in p for p in resolved.problems()))
        self.assertIsNotNone(egress.spec_for("email.send"))

    def test_a_clash_costs_the_newcomer_its_connectors_not_the_incumbent(self):
        """clodia-platform#545 §1. `aaa-pack` è installato prima e tiene lo
        schema conteso; `zzz-pack` arriva dopo e lo perde. Prima li perdevano
        entrambi, cioè installare un pack qualsiasi era un modo per spegnere
        un pack che funzionava. Nota che il perdente sorta PRIMA in ordine
        alfabetico: è così che si distingue «chi c'era prima» da «chi sorta
        per primo»."""
        self.install("good-pack", _sms())
        self.install("aaa-pack", _sms(namespace="aaa", scheme="contested"))
        self.install("zzz-pack", _sms(namespace="zzz", scheme="contested"))
        self.assertEqual(self._ids(), {"sms", "aaa"})
        problems = " ".join(resolved.problems())
        self.assertIn("zzz-pack", problems)
        self.assertNotIn("pack 'aaa-pack' refused", problems)

    def test_a_pack_extending_a_refused_pack_goes_too(self):
        self.install("good-pack", _sms())
        self.install("owner-pack", {**_sms(namespace="owner"),
                                    "manifest_version": 99})
        self.install("ext-pack", {"id": "ext", "manifest_version": 1,
                                  "namespace": "ext", "extends": "owner",
                                  "providers": [{"id": "x", "label": "X"}]})
        self.assertEqual(self._ids(), {"sms"})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


from .connectors import first_party_fixture as _first_party


def setUpModule() -> None:
    # The first-party packs, installed as on every instance: since the switch
    # was retired (#526) the tables pinned here are theirs, not the gateway's.
    _first_party.install()


def tearDownModule() -> None:
    _first_party.uninstall()

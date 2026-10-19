"""Review of clodia-tools#360 (clodia-platform#519, 3/3).

1. the generic connect route is ADMIN-only and touches only the connector's
   own vault entry — never one written by someone else;
2. a built-in connector with a dedicated handler (GitHub) goes through that
   handler: same vault shape, MCP backend, guards, disconnect;
3. a topic action writes only addresses of its connector's own schemes, in a
   form the scheme accepts — checked before anything is written;
plus the parity drifts of the old routes kept as aliases, and the SEAL tier
in the state of every action.
"""
from __future__ import annotations

import dataclasses
import unittest
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.testclient import TestClient

from . import connectors_api, egress, instance_profile, proxy, tools_api, \
    topics_api, vault, whitelist
from .connectors import actions as ca
from .connectors import resolved
from .connectors.manifest import ManifestError, build_registry
from .test_519_generic_actions import SMS_PACK, _H, _Topic, _client, _url
from .test_519_review_fixes import _Session
from .topics.service import TopicError


def _connect_client():
    return TestClient(Starlette(routes=connectors_api.routes))


class _Vault:
    """Vault in memory: `{entry: (bundle, type)}`."""

    def __init__(self, **existing):
        self.store = dict(existing)

    def __enter__(self):
        self._p = [
            patch.object(vault, "deposit", self._deposit),
            patch.object(vault, "remove", lambda e: self.store.pop(e, None)),
            # `create=True`: the red-before run of this file is against a
            # vault without the helper.
            patch.object(vault, "credential_type",
                         lambda e: self.store[e][1] if e in self.store else None,
                         create=True),
            patch.object(vault, "has_credential", lambda e: e in self.store),
        ]
        for p in self._p:
            p.start()
        return self

    def _deposit(self, entry, bundle, *, cred_type="opaque", grant_agents=None,
                 actions=None):
        self.store[entry] = (bundle, cred_type)

    def __exit__(self, *exc):
        for p in self._p:
            p.stop()


# --------------------------------------------------------------------------
# 1 — admin only, own vault entry only
# --------------------------------------------------------------------------

class ConnectAuthAndOwnershipTests(unittest.TestCase):
    def setUp(self):
        resolved.invalidate()
        self.addCleanup(resolved.invalidate)
        p = patch.object(resolved, "manifests", lambda: {"sms-pack": SMS_PACK})
        p.start()
        self.addCleanup(p.stop)

    def test_a_non_admin_session_cannot_write_or_remove(self):
        with _Session({"agent": "clodia", "principal": "mario",
                       "on_behalf": True, "human_role": "user"}), \
                _Vault(github_pat=({"value": "old"}, "mcp_secret")) as v:
            c = _connect_client()
            for cid, body in (("github", {"token": "ghp_x"}), ("github", {}),
                              ("sms", {"token": "x"})):
                with self.subTest(cid=cid, body=body):
                    r = c.post(f"/internal/tools/connectors/{cid}/connect",
                               json=body, headers=_H)
                    self.assertEqual(r.status_code, 401)
            self.assertEqual(v.store, {"github_pat": ({"value": "old"},
                                                      "mcp_secret")})

    def test_an_entry_written_by_someone_else_is_neither_removed_nor_overwritten(self):
        with patch.object(tools_api, "_authorized", lambda r: True), \
                _Vault(sms_twilio=({"x": "core"}, "mcp_secret")) as v:
            c = _connect_client()
            for body in ({"token": ""}, {"token": "new"}):
                with self.subTest(body=body):
                    r = c.post("/internal/tools/connectors/sms/connect",
                               json=body, headers=_H)
                    self.assertEqual(r.status_code, 409)
            self.assertEqual(v.store["sms_twilio"], ({"x": "core"}, "mcp_secret"))

    def test_its_own_entry_is_rewritten_and_removed(self):
        with patch.object(tools_api, "_authorized", lambda r: True), \
                _Vault() as v:
            c = _connect_client()
            c.post("/internal/tools/connectors/sms/connect",
                   json={"token": "a"}, headers=_H)
            self.assertEqual(v.store["sms_twilio"][1], "connector:sms")
            c.post("/internal/tools/connectors/sms/connect",
                   json={"token": "b"}, headers=_H)
            self.assertEqual(v.store["sms_twilio"][0], {"token": "b"})
            c.post("/internal/tools/connectors/sms/connect",
                   json={"token": ""}, headers=_H)
            self.assertNotIn("sms_twilio", v.store)

    def test_a_foreign_entry_in_a_manifest_that_slipped_through_is_refused(self):
        """Defence in depth: the load-time rule refuses `github_pat` under the
        `sms` namespace; the route re-checks what it is about to touch."""
        reg = resolved.registry()
        sms = reg.by_id("sms")
        cred = dataclasses.replace(sms.providers[0].credential,
                                   vault_entry="github_pat")
        prov = dataclasses.replace(sms.providers[0], credential=cred)
        rogue = dataclasses.replace(sms, providers=(prov,))
        fake = dataclasses.replace(
            reg, connectors=tuple(rogue if c.id == "sms" else c
                                  for c in reg.connectors))
        with patch.object(tools_api, "_authorized", lambda r: True), \
                patch.object(resolved, "registry", lambda: fake), \
                _Vault(github_pat=({"value": "old"}, "mcp_secret")) as v:
            r = _connect_client().post("/internal/tools/connectors/sms/connect",
                                       json={"token": ""}, headers=_H)
            self.assertEqual(r.status_code, 409)
            self.assertIn("github_pat", v.store)


# --------------------------------------------------------------------------
# 2 — GitHub through the generic route = the GitHub route
# --------------------------------------------------------------------------

class GithubParityTests(unittest.TestCase):
    def setUp(self):
        resolved.invalidate()
        self.addCleanup(resolved.invalidate)
        self.cfg = {"mcp_backends": [], "agents": {}}
        for p in (patch.object(tools_api, "_authorized", lambda r: True),
                  patch.object(whitelist, "CONFIG", self.cfg),
                  patch.object(whitelist, "save_config", lambda: None),
                  patch.object(whitelist, "reload_config", lambda: None),
                  patch.object(proxy, "clear_cache", lambda: None),
                  patch.object(tools_api, "_connector_guard", lambda cid: None),
                  patch.object(instance_profile, "integrations_check",
                               lambda name: None)):
            p.start()
            self.addCleanup(p.stop)

    def _post(self, body):
        return _connect_client().post("/internal/tools/connectors/github/connect",
                                      json=body, headers=_H)

    def test_the_pat_is_stored_as_the_proxy_reads_it_and_nothing_mounted(self):
        """The backend is it-pack's own mount (#525/#526): the route deposits
        the PAT in the shape the pack's mount reads, and mounts nothing."""
        with _Vault() as v:
            r = self._post({"token": "ghp_x"})
            self.assertEqual(r.status_code, 200, r.text)
            self.assertNotIn("ghp_x", r.text)
            self.assertEqual(v.store["github_pat"], ({"value": "ghp_x"},
                                                     "mcp_secret"))
        self.assertEqual(self.cfg["mcp_backends"], [])
        self.assertTrue(r.json()["connected"])
        self.assertEqual(r.json()["vault_entry"], "github_pat")

    def test_disconnect_unmounts_the_backend(self):
        with _Vault() as v:
            self._post({"token": "ghp_x"})
            r = self._post({"token": ""})
            self.assertFalse(r.json()["connected"])
            self.assertNotIn("github_pat", v.store)
        self.assertEqual(self.cfg["mcp_backends"], [])

    def test_the_guards_apply(self):
        with _Vault() as v, patch.object(
                tools_api, "_connector_guard",
                lambda cid: JSONResponse({"error": "no"}, status_code=403)):
            self.assertEqual(self._post({"token": "ghp_x"}).status_code, 403)
            self.assertEqual(v.store, {})
        def _no(name):
            raise PermissionError("integrations off")
        with _Vault() as v, patch.object(instance_profile,
                                         "integrations_check", _no):
            self.assertEqual(self._post({"token": "ghp_x"}).status_code, 403)
            self.assertEqual(v.store, {})


# --------------------------------------------------------------------------
# 3 — topic actions write only their own schemes, in a valid form
# --------------------------------------------------------------------------

def _action_pack(template: str) -> dict:
    return {"name": "evil-pack", "connectors": [{
        "id": "evil", "manifest_version": 1, "namespace": "evil",
        "schemes": [{"scheme": "evil", "direction": "egress"}],
        "topic_actions": [{"id": "open", "label": "Open",
                           "fields": [{"name": "url"}],
                           "adds": {"egress": [template]}}]}]}


class ActionSchemeTests(unittest.TestCase):
    def test_a_template_without_its_own_scheme_is_refused_at_load(self):
        for tpl in ("{url}", "https://{url}/", "tg:{url}", "{url}:x"):
            with self.subTest(tpl=tpl):
                with self.assertRaises(ManifestError):
                    build_registry({"evil-pack": _action_pack(tpl)},
                                   reserved=frozenset())

    def test_a_template_that_slipped_through_is_refused_at_run_time(self):
        """`adds.egress: ['{url}']` with `url=https://evil.example/*`: the
        reviewer's PoC, on a registry that bypassed the load-time check."""
        reg = resolved.registry()
        tg = reg.by_id("telegram")
        act = dataclasses.replace(tg.topic_actions[0], adds_egress=("{chat}",),
                                  adds_ingress=())
        fake = dataclasses.replace(reg, connectors=tuple(
            dataclasses.replace(c, topic_actions=(act,)) if c.id == "telegram"
            else c for c in reg.connectors))
        with _Topic() as t, patch.object(resolved, "registry", lambda: fake):
            r = _client().post(_url(t, "telegram", "telegram-link"),
                               json={"action": "connect",
                                     "chat": "https://evil.example/*"},
                               headers=_H)
            self.assertEqual(r.status_code, 400)
            self.assertEqual(t.liste, {})
            self.assertEqual(t.bindings, {})

    def test_a_free_text_value_must_have_the_scheme_form(self):
        for chat in ("pippo", "-100123garbage", "*", "-1 tg:*"):
            with self.subTest(chat=chat), _Topic() as t:
                r = _client().post(_url(t, "telegram", "telegram-link"),
                                   json={"action": "connect", "chat": chat},
                                   headers=_H)
                self.assertEqual(r.status_code, 400, r.text)
                self.assertEqual(t.liste, {})
                self.assertEqual(t.bindings, {})

    def test_every_action_shows_the_topic_tier(self):
        with _Topic(tier="SEAL-2") as t:
            st = _client().get(_url(t, "mail", "mailbox-link"),
                               headers=_H).json()
            self.assertEqual(st["seal"]["tier"], "SEAL-2")
            self.assertEqual(st["tier"], "SEAL-2")


# --------------------------------------------------------------------------
# the Telegram button through the generic route (the `telegram-link` alias
# was removed with #526: the webui calls the generic route only)
# --------------------------------------------------------------------------

class TelegramActionTests(unittest.TestCase):
    def _tg(self, t, body):
        return _client().post(_url(t, "telegram", "telegram-link"),
                              json=body, headers=_H)

    def _missing(self, t):
        return patch.object(topics_api, "_service", lambda: _MissingSvc())

    def test_telegram_connect_on_a_missing_topic_writes_nothing(self):
        with _Topic() as t, self._missing(t):
            r = self._tg(t, {"action": "connect", "chat": "-100123"})
            self.assertIn(r.status_code, (400, 404), r.text)
            self.assertEqual((t.liste, t.bindings), ({}, {}))

    def test_the_missing_field_is_named(self):
        with _Topic() as t:
            r = self._tg(t, {"action": "connect"})
            self.assertEqual(r.status_code, 400)
            self.assertIn("chat", r.json()["error"])

    def test_mailbox_value_error_is_400(self):
        def _boom(direction, scope, uri):
            raise ValueError("schema non ammesso")
        with _Topic() as t, patch.object(egress, "scope_allow", _boom):
            r = _client().post(f"/internal/topics/{t.tier}/{t.name}/mailbox-link",
                               json={"action": "connect", "account": "studio"},
                               headers=_H)
            self.assertEqual(r.status_code, 400, r.text)

    def test_a_whitelist_failure_leaves_no_orphan_binding(self):
        def _boom(direction, scope, uri):
            raise ValueError("config non scrivibile")
        with _Topic() as t, patch.object(egress, "scope_allow", _boom):
            r = self._tg(t, {"action": "connect", "chat": "-100123"})
            self.assertEqual(r.status_code, 400, r.text)
            self.assertEqual(t.bindings, {})


class _MissingSvc:
    def open(self, tier, name):
        raise TopicError(f"topic {tier}/{name} non trovato")

    def revoke_channel_cap_ack(self, tier, name):
        raise TopicError("non trovato")

    def accept_channel_cap(self, *a, **k):
        raise TopicError("non trovato")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


from .connectors import first_party_fixture as _first_party


def setUpModule() -> None:
    # The first-party packs, installed as on every instance: since the switch
    # was retired (#526) the tables pinned here are theirs, not the gateway's.
    _first_party.install()


def tearDownModule() -> None:
    _first_party.uninstall()

"""Second verification of clodia-tools#360.

* a topic's connectors (`…/connectors/{id}/{action}` and the aliases
  `telegram-link`, `mailbox-link`, `drive-folder`) are changed only by the
  topic's owner or an admin, on-behalf — or by the agent-server's own session
  (no execution, no chat), which checks owner/admin before forwarding. An
  agent's runtime token (`CLODIA_TOOLS_TOKEN`) and a non-owner get 403;
* a pack's topic action may write only into a scheme that declares `forms`.
"""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from . import topics_api
from .connectors.manifest import ManifestError, build_registry
from .test_519_generic_actions import _H, _Topic, _client, _url

AGENT_RUNTIME = {"agent": "clodia", "execution_id": "clodia-517",
                 "chat": "chan:SEAL-1:acme:clodia"}
# topics_client._headers(): dal #539 §1 il runner si dichiara con un claim
# FIRMATO invece di farsi riconoscere da ciò che il suo token non porta.
SYSTEM = {"agent": "clodia", "role": "agent-server"}
#: Lo stesso principal SENZA il claim: prima passava per assenza di
#: `execution_id` e `chat`, adesso è un token come un altro.
SYSTEM_SENZA_CLAIM = {"agent": "clodia"}
OWNER = {"agent": "clodia", "principal": "davide", "on_behalf": True,
         "human_role": "user"}
STRANGER = {**OWNER, "principal": "mario"}
ADMIN = {**STRANGER, "human_role": "admin"}


class _As:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        svc = MagicMock()
        svc.open.return_value = {"meta": {"tier": "SEAL-1", "owner": "davide"}}
        svc.drive_folder_add.return_value = {"ok": True}
        svc.drive_folder_remove.return_value = {"ok": True}
        self._p = [patch.object(topics_api.internal_auth, "authorize",
                                lambda *a, **k: (dict(self.payload), None)),
                   patch.object(topics_api, "_service", lambda: svc)]
        for p in self._p:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self._p):
            p.stop()


def _calls(t):
    base = f"/internal/topics/{t.tier}/{t.name}"
    return [
        (_url(t, "telegram", "telegram-link"),
         {"action": "connect", "chat": "-100777"}),
        (f"{base}/telegram-link", {"action": "connect", "chat_id": "-100777"}),
        (f"{base}/mailbox-link", {"action": "connect", "account": "studio"}),
        (f"{base}/drive-folder", {"action": "add", "folder": "F"}),
    ]


class TopicOwnerOnlyTests(unittest.TestCase):
    def _run(self, payload):
        out = []
        with _Topic() as t, _As(payload):
            for url, body in _calls(t):
                out.append(_client().post(url, json=body, headers=_H).status_code)
            written = (dict(t.liste), dict(t.bindings))
        return out, written

    def test_an_agent_runtime_token_is_refused_everywhere(self):
        codes, (liste, bindings) = self._run(AGENT_RUNTIME)
        self.assertEqual(codes, [403, 403, 403, 403])
        self.assertEqual((liste, bindings), ({}, {}))

    def test_a_non_owner_human_is_refused_everywhere(self):
        codes, (liste, bindings) = self._run(STRANGER)
        self.assertEqual(codes, [403, 403, 403, 403])
        self.assertEqual((liste, bindings), ({}, {}))

    def test_the_owner_admin_and_the_agent_server_pass(self):
        for who in (OWNER, ADMIN, SYSTEM):
            with self.subTest(who=who):
                codes, (liste, bindings) = self._run(who)
                self.assertEqual(codes, [200, 200, 200, 200])
                self.assertIn("-100777", bindings)

    def test_without_the_service_claim_it_does_not_pass_by_absence(self):
        """#539 §1: riconoscere il runner dall'ASSENZA di claim reggeva per
        caso — `_execution_id` torna `""` finché lo spawn non ha il workspace."""
        codes, (liste, bindings) = self._run(SYSTEM_SENZA_CLAIM)
        self.assertEqual(codes, [403, 403, 403, 403])
        self.assertEqual((liste, bindings), ({}, {}))

    def test_the_state_read_follows_the_same_rule(self):
        with _Topic() as t, _As(AGENT_RUNTIME):
            r = _client().get(_url(t, "telegram", "telegram-link"), headers=_H)
            self.assertEqual(r.status_code, 403)


def _pack(forms):
    sch = {"scheme": "courier", "direction": "egress"}
    if forms:
        sch["forms"] = [{"label": "id", "pattern": "[a-z]{1,16}"}]
    return {"name": "courier-pack", "connectors": [{
        "id": "courier", "manifest_version": 1, "namespace": "courier",
        "schemes": [sch],
        "topic_actions": [{"id": "link", "label": "Link",
                           "fields": [{"name": "who"}],
                           "adds": {"egress": ["courier:{who}"]}}]}]}


class ActionSchemeNeedsFormsTests(unittest.TestCase):
    def test_a_scheme_without_forms_cannot_be_written_by_an_action(self):
        with self.assertRaises(ManifestError) as e:
            build_registry({"courier-pack": _pack(False)}, reserved=frozenset())
        self.assertIn("forms", str(e.exception))

    def test_with_forms_it_loads(self):
        build_registry({"courier-pack": _pack(True)}, reserved=frozenset())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

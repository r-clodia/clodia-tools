"""Second verification of clodia-tools#360.

* a topic's connectors (`…/connectors/{id}/{action}` and the aliases
  `telegram-link`, `mailbox-link`, `drive-folder`) are changed only by the
  topic's owner or an admin, on-behalf — or by the agent-server's own session,
  which SAYS SO (signed claim `role: agent-server`, clodia-platform#539 §1) and
  checks owner/admin before forwarding. An agent's runtime token
  (`CLODIA_TOOLS_TOKEN`), a bare token without the claim, and a non-owner
  get 403;
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
SYSTEM = {"agent": "clodia", "role": "agent-server"}   # topics_client._headers()
#: Un token nudo: nessun `execution_id`, nessun `chat`, e nessuna affermazione.
#: Era indistinguibile dall'agent-server, perché il riconoscimento avveniva per
#: ASSENZA (clodia-platform#539 §1). `_execution_id(spawn)` torna "" quando il
#: workspace dello spawn non è stato creato: non è un caso di laboratorio.
BARE = {"agent": "clodia"}
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

    def test_a_token_without_the_claim_is_not_the_agent_server(self):
        """Il cuore della #539 §1: l'identità si afferma, non si deduce da ciò
        che manca. Prima bastava un token senza `execution_id` e senza `chat`
        per scrivere i muri di una stanza qualunque."""
        codes, (liste, bindings) = self._run(BARE)
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

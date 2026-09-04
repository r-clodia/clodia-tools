"""`/internal/authorize` decideva su `_is_super`, non sui grant dell'agente.

L'endpoint è la DECISIONE che l'agent-server chiede per le azioni che esegue
localmente. Per una chiamata on-behalf guardava il ruolo umano — corretto — ma
per un AGENTE rispondeva `_is_super(agent)`: da quando `_SUPER_AGENTS` è vuoto
(#104) quella risposta è False per qualunque agente, con qualunque grant. La
matrice del principal — seed, ancestry, archseed, più gli scoped e i connettori
— non veniva consultata proprio dall'endpoint che serve a consultarla.

L'effetto visibile era un 403 indistinguibile da un permesso mancante:
`sysadmin`, che ha `packs.*`, chiamava `packs.setup_done` e riceveva «azione
riservata agli admin» (clodia-platform#297).

Qui si misura che la decisione sia la STESSA di `call_tool`: la matrice concede,
la deny-list per-agente sottrae, e sul ramo umano il tetto `scoped_tools` vale
anche qui — `/internal/tool` lo applica a valle, `/internal/authorize` non
eseguendo nulla non aveva nessun «a valle» che lo applicasse.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.testclient import TestClient

from . import human_mcp, main, tool_api, whitelist

_H = {"Authorization": "Bearer ckt1.finto"}

#: Il token che `platform_ops` inoltra: quello dell'agente, nudo (nessun
#: `on_behalf`, nessun ruolo umano).
_SYSADMIN = {"agent": "sysadmin"}

#: Una sessione umana della webui, come la conia `gateway_pdp._token`.
_UMANO_ADMIN = {"agent": "clodia", "principal": "davide", "on_behalf": True,
                "human_role": "admin"}


def _client() -> TestClient:
    return TestClient(Starlette(routes=tool_api.routes))


class _Agente:
    """L'agente `sysadmin` con `packs.*` dichiarato e nessun deny."""

    def __init__(self, dichiarati=("packs.*",), denies=()):
        self._dichiarati, self._denies = set(dichiarati), set(denies)
        self._payload = _SYSADMIN

    def __enter__(self):
        self._p = [
            patch.object(tool_api, "verify_session_token", lambda _t: self._payload),
            patch.object(tool_api.whitelist, "agent_name", lambda: "sysadmin"),
            patch.object(main, "_is_super", lambda _n: False),
            patch.object(main, "_declared_tools", lambda _ag: set(self._dichiarati)),
            patch.object(main, "_vault_grants", lambda _ag: set()),
            patch.object(whitelist, "agent_denies",
                         lambda verb, name=None: verb in self._denies),
        ]
        for p in self._p:
            p.start()
        return self

    def __exit__(self, *a):
        for p in self._p:
            p.stop()
        return False

    def decisione(self, tool: str, payload: dict | None = None) -> dict:
        self._payload = payload or _SYSADMIN
        r = _client().post("/internal/authorize", headers=_H, json={"tool": tool})
        assert r.status_code == 200, f"{r.status_code}: {r.text}"
        return r.json()


class AGrantIsTheDecisionTests(unittest.TestCase):

    def test_a_declared_namespace_authorizes_the_verb(self):
        """`packs.*` copre `packs.setup_done`: è il caso della #297."""
        with _Agente() as a:
            self.assertTrue(a.decisione("packs.setup_done")["allowed"])

    def test_a_verb_outside_the_matrix_is_still_refused(self):
        with _Agente() as a:
            self.assertFalse(a.decisione("shell.exec")["allowed"])

    def test_the_deny_list_still_subtracts(self):
        """La deny-list per-agente è una sottrazione da `*`: un allow non la
        sovrascrive, o non toglierebbe nulla."""
        with _Agente(denies=("packs.setup_done",)) as a:
            self.assertFalse(a.decisione("packs.setup_done")["allowed"])

    def test_an_unknown_agent_is_a_refusal_not_a_crash(self):
        """`agent_name()` solleva per un agente non dichiarato: senza guardia
        l'endpoint rispondeva 500, e il chiamante traduce ogni non-200 in
        «negato» — un guasto travestito da rifiuto."""
        def _boom():
            raise PermissionError("agent 'ignoto' not declared in config.yaml")

        with _Agente() as a, patch.object(tool_api.whitelist, "agent_name", _boom):
            self.assertFalse(a.decisione("packs.setup_done")["allowed"])


class TheHumanBranchKeepsItsCeilingTests(unittest.TestCase):
    """Il ramo umano non cambia decisione sul RUOLO; cambia che il tetto
    `scoped_tools` lo legge anche questo endpoint."""

    def _decisione(self, tool: str, payload: dict) -> dict:
        with patch.object(tool_api, "verify_session_token", lambda _t: payload):
            r = _client().post("/internal/authorize", headers=_H, json={"tool": tool})
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def test_an_admin_session_still_decides_on_the_role(self):
        self.assertTrue(self._decisione("packs.import_url", _UMANO_ADMIN)["allowed"])

    def test_a_scoped_token_does_not_reach_outside_its_ceiling(self):
        scoped = {**_UMANO_ADMIN, "scoped_tools": list(human_mcp.PROXY_VERBS)}
        self.assertFalse(self._decisione("packs.import_url", scoped)["allowed"])

    def test_a_scoped_token_keeps_the_verbs_it_was_minted_for(self):
        scoped = {**_UMANO_ADMIN, "scoped_tools": ["topic.messages"]}
        self.assertTrue(self._decisione("topic.messages", scoped)["allowed"])


if __name__ == "__main__":
    unittest.main()

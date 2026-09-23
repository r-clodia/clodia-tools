"""Il grant `crosstopic`: default-deny cross-topic per ogni spawn, unica
eccezione clodia/sysadmin tramite un consenso M-gate scoped ALLO SPAWN che
l'ha chiesto (decisione di Davide, 23 set 2026 — in risposta al leak
strutturale su `tomato-blogging`: `runtime.topics()` esponeva a clodia
contenuti di altri topic che finivano ripostati altrove senza che i
destinatari ne avessero titolo).

Tre proprietà, testate qui perché non le copre `test_topic_access.py`:

1. il grant NON si eredita fra spawn dello stesso seed — `clodia-1` approvato
   non abilita `clodia-2`;
2. il tetto di clearance resta attivo SOPRA il grant — un grant valido non
   assolve un tier oltre la clearance dello spawn;
3. un agente non eleggibile viene negato SENZA mai interrogare il gate — non
   esiste una card che nessuno potrà mai approvare per lui.
"""
from __future__ import annotations

import types
import unittest
from unittest.mock import patch

from . import gate, main


def _service(meta: dict):
    return types.SimpleNamespace(open=lambda _tier, _name: {"meta": meta})


META = {"tier": "SEAL-1", "owner": "davide", "participants": ["davide"]}


class SpawnScopingTests(unittest.TestCase):
    def test_grant_does_not_carry_over_to_a_different_spawn(self):
        """Il consenso vive per (agent, instance, verb): un'attivazione keyed
        su 'clodia-1' non deve rispondere vero per 'clodia-2'."""
        def active_only_for_clodia_1(agent, instance, verb):
            return agent == "clodia" and instance == "clodia-1" and verb == "crosstopic"

        with patch.object(main, "agent_name", return_value="clodia"), \
                patch.object(main, "current_clearance", return_value="SEAL-3"), \
                patch.object(gate, "active", side_effect=active_only_for_clodia_1):
            with patch("server.whitelist.current_spawn", return_value="clodia-1"):
                main._require_topic_member(_service(META), "SEAL-1", "acme")  # non solleva
            with patch("server.whitelist.current_spawn", return_value="clodia-2"):
                with self.assertRaises(PermissionError):
                    main._require_topic_member(_service(META), "SEAL-1", "acme")

    def test_clearance_cap_applies_above_an_active_grant(self):
        """Il grant apre il compartimento, non il livello: un consenso attivo
        non assolve una clearance insufficiente per il tier del bersaglio."""
        with patch.object(main, "agent_name", return_value="clodia"), \
                patch.object(main, "current_clearance", return_value="SEAL-0"), \
                patch("server.whitelist.current_spawn", return_value="clodia-1"), \
                patch.object(gate, "active", return_value=True):
            with self.assertRaises(PermissionError) as ctx:
                main._require_topic_member(_service(META), "SEAL-1", "acme")
        self.assertIn("livello", str(ctx.exception))


class EligibilityGateTests(unittest.TestCase):
    def test_ineligible_agent_never_queries_the_gate(self):
        """Nessuna card per un agente che non potrà mai ottenerla: il rifiuto
        avviene prima di chiedere qualunque cosa a `gate`."""
        chiamato = []
        with patch.object(main, "_topics", return_value=_service(META)), \
                patch.object(gate, "active", side_effect=lambda *a: chiamato.append(a) or True):
            with self.assertRaises(PermissionError):
                main._cross_topic_gate_key(
                    "topic.read_file", {"tier": "SEAL-1", "name": "acme"},
                    "articolista")
        self.assertFalse(chiamato, "il gate non va interrogato per un agente non eleggibile")


if __name__ == "__main__":
    unittest.main()

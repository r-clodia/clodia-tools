from __future__ import annotations

import types
import unittest
from unittest.mock import patch

from . import gate, main


def _service(meta: dict):
    return types.SimpleNamespace(open=lambda _tier, _name: {"meta": meta})


class CrossTopicGateTests(unittest.TestCase):
    def setUp(self) -> None:
        # "clodia" NON è participant per default qui: i test di questa classe
        # vogliono verificare il percorso CROSS-topic (non-membro), e un
        # participant salterebbe quel ramo indipendentemente dal grant —
        # falsando l'esito.
        self.meta = {
            "tier": "SEAL-2",
            "owner": "davide",
            "participants": ["davide"],
        }

    def test_human_membership_no_longer_skips_gate_request(self) -> None:
        """Eleggibile (clodia): niente esenzione per la membership umana, ma
        la chiave è ora il grant unico 'crosstopic' (23 set 2026), non più
        per-target."""
        with patch.object(main, "_topics", return_value=_service(self.meta)), \
                patch.object(main, "current_principal", return_value="davide"):
            key = main._cross_topic_gate_key(
                "topic.read_document",
                {"tier": "SEAL-2", "name": "confidential"},
                "clodia",
            )
        self.assertEqual(key, "crosstopic")

    def test_ineligible_agent_is_denied_outright_no_gate_offered(self) -> None:
        """Solo clodia/sysadmin possono anche solo CHIEDERE il grant: per
        chiunque altro non esiste una card da approvare, è un rifiuto subito."""
        with patch.object(main, "_topics", return_value=_service(self.meta)), \
                patch.object(main, "current_principal", return_value="davide"):
            with self.assertRaises(PermissionError):
                main._cross_topic_gate_key(
                    "topic.read_document",
                    {"tier": "SEAL-2", "name": "confidential"},
                    "esperto-bandi",
                )

    def test_agent_membership_needs_no_gate(self) -> None:
        """Fuori da una stanza la membership decide ancora: non c'è una platea
        in cui riversare, e gatare qui chiederebbe una card per ogni verbo
        `topic.*` di ogni chat normale (clodia-platform#382, `RoomlessSession
        Tests` in `test_spawn_compartment.py`)."""
        self.meta["participants"].append("esperto-bandi")
        with patch.object(main, "_topics", return_value=_service(self.meta)):
            key = main._cross_topic_gate_key(
                "topic.read_document",
                {"tier": "SEAL-2", "name": "confidential"},
                "esperto-bandi",
            )
        self.assertIsNone(key)

    def test_agent_membership_inside_another_room_no_longer_waives(self) -> None:
        """Dentro una stanza sì: è il caso di clodia-platform#382 — leggere un
        topic stando in un altro, dove la platea della stanza non ha titolo. Per
        un agente non eleggibile al grant `crosstopic` il rifiuto è immediato:
        per lui non esiste nemmeno una card da approvare."""
        from . import whitelist as w
        self.meta["participants"].append("esperto-bandi")
        tok = w.set_current_chat("chan:SEAL-1:un-altro-topic:esperto-bandi")
        try:
            with patch.object(main, "_topics", return_value=_service(self.meta)):
                with self.assertRaises(PermissionError):
                    main._cross_topic_gate_key(
                        "topic.read_document",
                        {"tier": "SEAL-2", "name": "confidential"},
                        "esperto-bandi",
                    )
        finally:
            w.reset_current_chat(tok)

    def test_inside_its_own_room_an_agent_needs_no_gate(self) -> None:
        """Ciò che resta libero dopo #382: la propria stanza — presa dal claim
        `chat` firmato, non dalla lista participants."""
        from . import whitelist as w
        self.meta["participants"].append("esperto-bandi")
        tok = w.set_current_chat("chan:SEAL-2:confidential:esperto-bandi")
        try:
            with patch.object(main, "_topics", return_value=_service(self.meta)):
                key = main._cross_topic_gate_key(
                    "topic.read_document",
                    {"tier": "SEAL-2", "name": "confidential"},
                    "esperto-bandi",
                )
        finally:
            w.reset_current_chat(tok)
        self.assertIsNone(key)

    def test_dispatch_denies_ineligible_agent_even_with_an_active_consent(self) -> None:
        """Difesa in profondità: anche se qualcosa nel gate risultasse attivo,
        un agente fuori da clodia/sysadmin resta negato — l'eleggibilità non
        passa dal gate, è un axis a monte."""
        with patch.object(main, "agent_name", return_value="esperto-bandi"), \
                patch.object(main, "current_principal", return_value="davide"), \
                patch.object(main, "current_clearance", return_value="SEAL-3"), \
                patch("server.whitelist.current_spawn", return_value="esperto-bandi-1"), \
                patch.object(gate, "active", return_value=True):
            with self.assertRaises(PermissionError):
                main._require_topic_member(
                    _service(self.meta), "SEAL-2", "confidential")

    def test_dispatch_denies_eligible_agent_without_consent(self) -> None:
        with patch.object(main, "agent_name", return_value="clodia"), \
                patch.object(main, "current_principal", return_value="davide"), \
                patch.object(main, "current_clearance", return_value="SEAL-3"), \
                patch("server.whitelist.current_spawn", return_value="clodia-1"), \
                patch.object(gate, "active", return_value=False):
            with self.assertRaises(PermissionError):
                main._require_topic_member(
                    _service(self.meta), "SEAL-2", "confidential")

    def test_dispatch_accepts_explicit_crosstopic_consent_for_this_spawn(self) -> None:
        with patch.object(main, "agent_name", return_value="clodia"), \
                patch.object(main, "current_principal", return_value="davide"), \
                patch.object(main, "current_clearance", return_value="SEAL-3"), \
                patch("server.whitelist.current_spawn", return_value="clodia-1"), \
                patch.object(gate, "active", return_value=True):
            main._require_topic_member(
                _service(self.meta), "SEAL-2", "confidential")

    def test_dispatch_denies_without_a_signed_spawn_identity(self) -> None:
        """Fail-closed: un consenso non scopabile per spawn (token senza
        execution_id) non abilita mai il cross-topic, anche per clodia."""
        with patch.object(main, "agent_name", return_value="clodia"), \
                patch.object(main, "current_principal", return_value="davide"), \
                patch.object(main, "current_clearance", return_value="SEAL-3"), \
                patch("server.whitelist.current_spawn", return_value=None), \
                patch.object(gate, "active", return_value=True):
            with self.assertRaises(PermissionError):
                main._require_topic_member(
                    _service(self.meta), "SEAL-2", "confidential")

    def test_topic_list_does_not_expand_to_human_memberships(self) -> None:
        rows = [
            {**self.meta, "name": "human-only"},
            {"name": "agent-topic", "owner": "davide",
             "participants": ["davide", "esperto-bandi"]},
        ]
        with patch.object(main, "current_principal", return_value="davide"):
            visible = main._filter_member_rows(rows, "esperto-bandi")
        self.assertEqual([row["name"] for row in visible], ["agent-topic"])


if __name__ == "__main__":
    unittest.main()

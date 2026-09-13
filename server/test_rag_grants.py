from __future__ import annotations

import unittest
from unittest.mock import patch

from . import main


class RagGrantEnforcementTests(unittest.TestCase):
    def _base_patches(self):
        return (
            patch.object(main, "agent_name", return_value="esperto-bandi"),
            patch.object(main, "_is_super", return_value=False),
            patch.object(main, "current_clearance", return_value="SEAL-2"),
            patch.object(main.instance_profile, "rag_check_collection"),
            patch.object(main.eu_corpus, "collection_tier", return_value="SEAL-1"),
        )

    def test_read_grant_authorizes_search(self) -> None:
        patches = self._base_patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patch.object(main.runtime, "rag_grants", return_value={
                    "rag_read": {"eu-normativa"}, "rag_write": set(),
                }):
            main._rag_authorize("eu-normativa", write=False)

    def test_write_grant_implies_read_but_read_does_not_imply_write(self) -> None:
        patches = self._base_patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patch.object(main.runtime, "rag_grants", return_value={
                    "rag_read": set(), "rag_write": {"eu-normativa"},
                }):
            main._rag_authorize("eu-normativa", write=False)
            main._rag_authorize("eu-normativa", write=True)

        patches = self._base_patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patch.object(main.runtime, "rag_grants", return_value={
                    "rag_read": {"eu-normativa"}, "rag_write": set(),
                }):
            with self.assertRaises(PermissionError):
                main._rag_authorize("eu-normativa", write=True)

    def test_core_failure_denies_access(self) -> None:
        patches = self._base_patches()
        with patches[0], patches[1], patches[2], patches[3], patches[4], \
                patch.object(main.runtime, "rag_grants",
                             side_effect=RuntimeError("core unavailable")):
            with self.assertRaises(PermissionError):
                main._rag_authorize("eu-normativa", write=False)

    def test_sysadmin_provisioner_can_write_within_clearance(self) -> None:
        with patch.object(main, "agent_name", return_value="sysadmin"), \
                patch.object(main, "_is_super", return_value=False), \
                patch.object(main, "current_clearance", return_value="SEAL-1"), \
                patch.object(main.instance_profile, "rag_check_collection"), \
                patch.object(main.eu_corpus, "collection_tier", return_value="SEAL-1"), \
                patch.object(main.runtime, "rag_grants",
                             side_effect=AssertionError("grant lookup should be bypassed")):
            main._rag_authorize("pack-kb", write=True)

    def test_sysadmin_provisioner_still_respects_clearance(self) -> None:
        with patch.object(main, "agent_name", return_value="sysadmin"), \
                patch.object(main, "_is_super", return_value=False), \
                patch.object(main, "current_clearance", return_value="SEAL-1"), \
                patch.object(main.instance_profile, "rag_check_collection"), \
                patch.object(main.eu_corpus, "collection_tier", return_value="SEAL-2"):
            with self.assertRaises(PermissionError):
                main._rag_authorize("confidential-kb", write=True)

    def test_collections_are_filtered_with_live_core_grants(self) -> None:
        with patch.object(main, "agent_name", return_value="esperto-bandi"), \
                patch.object(main, "_is_super", return_value=False), \
                patch.object(main.instance_profile, "rag_enabled", return_value=True), \
                patch.object(main.instance_profile, "rag_mode", return_value="multi"), \
                patch.object(main.runtime, "rag_grants", return_value={
                    "rag_read": {"eu-normativa"}, "rag_write": set(),
                }), \
                patch.object(main.eu_corpus, "collections", return_value={
                    "collections": [
                        {"collection": "eu-normativa"},
                        {"collection": "segreta"},
                    ],
                }):
            result = main._dispatch_rag("rag.collections", {})
        self.assertEqual(
            [row["collection"] for row in result["collections"]],
            ["eu-normativa"],
        )

    def test_collections_for_provisioner_are_filtered_by_clearance(self) -> None:
        with patch.object(main, "agent_name", return_value="sysadmin"), \
                patch.object(main, "_is_super", return_value=False), \
                patch.object(main, "current_clearance", return_value="SEAL-1"), \
                patch.object(main.instance_profile, "rag_enabled", return_value=True), \
                patch.object(main.instance_profile, "rag_mode", return_value="multi"), \
                patch.object(main.eu_corpus, "collections", return_value={
                    "collections": [
                        {"collection": "public-kb", "tier": "SEAL-1"},
                        {"collection": "client-kb", "tier": "SEAL-2"},
                    ],
                }):
            result = main._dispatch_rag("rag.collections", {})
        self.assertEqual(
            [row["collection"] for row in result["collections"]],
            ["public-kb"],
        )


class RagWildcardGrantTests(unittest.TestCase):
    """`*` sull'asse RAG concede TUTTE le collection (clodia-platform#354).

    Prima era letterale: `rag_read: ["*"]` cercava una collection di nome `*`,
    quindi la configurazione che sembra concedere tutto concedeva zero. Il
    tiering resta a valle e invariato — la wildcard non alza la clearance.
    """

    def _gate(self, *, read=frozenset(), write=frozenset(),
              clearance="SEAL-2", tier="SEAL-1"):
        return (
            patch.object(main, "agent_name", return_value="esperto-bandi"),
            patch.object(main, "_is_super", return_value=False),
            patch.object(main, "current_clearance", return_value=clearance),
            patch.object(main.instance_profile, "rag_check_collection"),
            patch.object(main.eu_corpus, "collection_tier", return_value=tier),
            patch.object(main.runtime, "rag_grants", return_value={
                "rag_read": set(read), "rag_write": set(write),
            }),
        )

    def test_wildcard_read_grant_authorizes_a_collection_never_named(self) -> None:
        a, b, c, d, e, f = self._gate(read={"*"})
        with a, b, c, d, e, f:
            main._rag_authorize("collection-mai-nominata", write=False)

    def test_wildcard_read_does_not_grant_write(self) -> None:
        a, b, c, d, e, f = self._gate(read={"*"})
        with a, b, c, d, e, f:
            with self.assertRaises(PermissionError):
                main._rag_authorize("collection-mai-nominata", write=True)

    def test_wildcard_write_grant_authorizes_write(self) -> None:
        a, b, c, d, e, f = self._gate(write={"*"})
        with a, b, c, d, e, f:
            main._rag_authorize("collection-mai-nominata", write=True)

    def test_wildcard_does_not_raise_the_clearance(self) -> None:
        """L'asse livello è l'altro, e resta: `*` allarga l'appartenenza, non
        la clearance."""
        a, b, c, d, e, f = self._gate(read={"*"}, clearance="SEAL-1", tier="SEAL-3")
        with a, b, c, d, e, f:
            with self.assertRaises(PermissionError):
                main._rag_authorize("collection-riservata", write=False)

    def test_listed_collections_are_exactly_those_the_gate_allows(self) -> None:
        """Secondo criterio dell'issue: la lista mostrata coincide col gate.

        Con `*` l'elenco non può più essere «tutto ciò che esiste»: le
        collection di tier superiore restano fuori, perché `_rag_authorize` le
        rifiuta comunque e un elenco che le mostra promette un accesso che non
        c'è."""
        righe = [
            {"collection": "public-kb", "tier": "SEAL-1"},
            {"collection": "team-kb", "tier": "SEAL-2"},
            {"collection": "client-kb", "tier": "SEAL-3"},
        ]
        tiers = {r["collection"]: r["tier"] for r in righe}
        with patch.object(main, "agent_name", return_value="esperto-bandi"), \
                patch.object(main, "_is_super", return_value=False), \
                patch.object(main, "current_clearance", return_value="SEAL-2"), \
                patch.object(main.instance_profile, "rag_enabled", return_value=True), \
                patch.object(main.instance_profile, "rag_mode", return_value="multi"), \
                patch.object(main.instance_profile, "rag_check_collection"), \
                patch.object(main.eu_corpus, "collection_tier",
                             side_effect=lambda c: tiers[c]), \
                patch.object(main.runtime, "rag_grants", return_value={
                    "rag_read": {"*"}, "rag_write": set(),
                }), \
                patch.object(main.eu_corpus, "collections",
                             return_value={"collections": list(righe)}):
            elencate = [r["collection"]
                        for r in main._dispatch_rag("rag.collections", {})["collections"]]
            self.assertEqual(elencate, ["public-kb", "team-kb"])
            for nome in elencate:          # ogni riga mostrata è davvero aperta
                main._rag_authorize(nome, write=False)
            with self.assertRaises(PermissionError):   # e la nascosta è chiusa
                main._rag_authorize("client-kb", write=False)


if __name__ == "__main__":
    unittest.main()

"""Member list dichiarata di una collection RAG (`clodia-platform#343`).

Il gate delle collection aveva un asse solo che guardasse la COLLECTION — il
tier — e uno che guardava il SEED (i grant `rag_read`/`rag_write`). Chi entra
in una collection era quindi scritto solo dalla parte del seed: una collection
non poteva dire di sé «questi, e nessun altro».

Qui si misura l'aggiunta, e soprattutto il suo confine: `seeds` dichiarati
RESTRINGONO (servono grant E appartenenza), `seeds` non dichiarati lasciano il
regime di prima. Un fail-closed sull'assenza avrebbe negato ogni collection
viva, perché nessun manifest dichiara ancora il campo.
"""
from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from . import main, rag_collections


def _write_manifest(root: Path, pack: str, collections: list[dict]) -> None:
    import yaml
    pdir = root / "plugins" / pack
    pdir.mkdir(parents=True, exist_ok=True)
    (pdir / "plugin.yaml").write_text(
        yaml.safe_dump({"name": pack, "rag_collections": collections}),
        encoding="utf-8")


class DeclaredTests(unittest.TestCase):
    def test_declared_seeds_round_trip(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root, "contabilita", [
                {"name": "prassi-fiscale", "tier": "SEAL-1",
                 "seeds": ["aitiero", "archivista"]},
            ])
            with patch.object(rag_collections, "DATADIR", str(root)):
                entry = rag_collections.find("prassi-fiscale")
        self.assertEqual(entry["pack"], "contabilita")
        self.assertEqual(entry["seeds"], ["aitiero", "archivista"])

    def test_collection_without_declared_seeds_has_no_member_list(self) -> None:
        """`seeds` assente ≠ `seeds` vuoto: il primo dice «il manifest non si è
        pronunciato», il secondo direbbe «nessuno entra». Il gate si comporta in
        modo opposto nei due casi, quindi non possono collassare qui."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root, "contabilita", [{"name": "prassi-fiscale"}])
            with patch.object(rag_collections, "DATADIR", str(root)):
                entry = rag_collections.find("prassi-fiscale")
        self.assertIsNone(entry["seeds"])

    def test_unknown_collection_is_not_declared(self) -> None:
        """Una collection orfana (pack disinstallato) o creata a mano non ha
        manifest: non è un errore, è il caso normale di oggi."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root, "contabilita", [{"name": "prassi-fiscale"}])
            with patch.object(rag_collections, "DATADIR", str(root)):
                self.assertIsNone(rag_collections.find("eu-normativa"))

    def test_malformed_seeds_are_not_a_member_list(self) -> None:
        """Un `seeds: aitiero` (stringa) non deve diventare una lista di
        caratteri né una lista di uno: il sanitizer a monte lo scarta, e qui si
        scarta di nuovo — questo modulo legge il manifest sul disco, che un
        umano può aver scritto a mano."""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root, "contabilita", [
                {"name": "prassi-fiscale", "seeds": "aitiero"},
            ])
            with patch.object(rag_collections, "DATADIR", str(root)):
                entry = rag_collections.find("prassi-fiscale")
        self.assertIsNone(entry["seeds"])


class RagAuthorizeMemberListTests(unittest.TestCase):
    """`_rag_authorize` con la member list dichiarata."""

    def _patches(self, agent: str, grants: dict, declared):
        return (
            patch.object(main, "agent_name", return_value=agent),
            patch.object(main, "_is_super", return_value=False),
            patch.object(main, "current_clearance", return_value="SEAL-2"),
            patch.object(main.instance_profile, "rag_check_collection"),
            patch.object(main.eu_corpus, "collection_tier", return_value="SEAL-1"),
            patch.object(main.runtime, "rag_grants", return_value=grants),
            patch.object(main.rag_collections, "find", return_value=declared),
        )

    def test_seed_with_grant_but_outside_the_member_list_is_denied(self) -> None:
        """Il criterio 3 dell'issue nella sua forma forte: il grant da solo non
        basta più, se la collection ha detto chi sono i suoi membri."""
        p = self._patches(
            "esperto-bandi",
            {"rag_read": {"prassi-fiscale"}, "rag_write": set()},
            {"pack": "contabilita", "name": "prassi-fiscale", "seeds": ["aitiero"]})
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6]:
            with self.assertRaises(PermissionError):
                main._rag_authorize("prassi-fiscale", write=False)

    def test_seed_in_the_member_list_with_grant_is_authorized(self) -> None:
        p = self._patches(
            "aitiero",
            {"rag_read": {"prassi-fiscale"}, "rag_write": set()},
            {"pack": "contabilita", "name": "prassi-fiscale", "seeds": ["aitiero"]})
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6]:
            main._rag_authorize("prassi-fiscale", write=False)

    def test_member_list_does_not_replace_the_grant(self) -> None:
        """I due assi sono congiuntivi: stare nella lista non concede ciò che il
        grant non concede (qui: lettura sì, scrittura no)."""
        p = self._patches(
            "aitiero",
            {"rag_read": {"prassi-fiscale"}, "rag_write": set()},
            {"pack": "contabilita", "name": "prassi-fiscale", "seeds": ["aitiero"]})
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6]:
            with self.assertRaises(PermissionError):
                main._rag_authorize("prassi-fiscale", write=True)

    def test_collection_without_declared_seeds_keeps_the_grant_regime(self) -> None:
        """La deviazione dichiarata dal criterio 2 dell'issue, misurata: campo
        assente → si decide sui soli grant, come prima di questo cambio. È ciò
        che evita di spegnere il RAG di ogni agente al deploy."""
        p = self._patches(
            "esperto-bandi",
            {"rag_read": {"prassi-fiscale"}, "rag_write": set()},
            {"pack": "contabilita", "name": "prassi-fiscale", "seeds": None})
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6]:
            main._rag_authorize("prassi-fiscale", write=False)

    def test_undeclared_collection_keeps_the_grant_regime(self) -> None:
        p = self._patches(
            "esperto-bandi",
            {"rag_read": {"eu-normativa"}, "rag_write": set()},
            None)
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6]:
            main._rag_authorize("eu-normativa", write=False)

    def test_unreadable_manifest_denies_a_granted_collection(self) -> None:
        """Fail-closed sull'INFRASTRUTTURA, che è un caso diverso dal campo
        assente: se non riesco a sapere se una member list esiste, non posso
        concludere che non esista — stessa scelta già fatta per i grant
        (`_rag_grants`: backend giù = accesso negato)."""
        p = self._patches(
            "esperto-bandi",
            {"rag_read": {"prassi-fiscale"}, "rag_write": set()},
            None)
        with p[0], p[1], p[2], p[3], p[4], p[5], \
                patch.object(main.rag_collections, "find",
                             side_effect=OSError("datadir non leggibile")):
            with self.assertRaises(PermissionError):
                main._rag_authorize("prassi-fiscale", write=False)


if __name__ == "__main__":
    unittest.main()

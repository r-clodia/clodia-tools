"""Appartenenza graduata: owner, contributor, reader.

Fino al 7 ago 2026 era BINARIA — dieci endpoint, una guardia sola, owner e
partecipante trattati allo stesso modo. Un invitato poteva azzerare la memoria
conversazionale del canale e caricare l'`AGENTS.md` iniettato nel contesto di
ogni agente a ogni turno.

Tre ruoli, insieme chiuso. Non una lista di verbi per persona per scope: sarebbe
l'argomento della #128 moltiplicato — là quattordici agenti e lo stesso indirizzo
chiesto quattordici volte, qui 156 topic per N persone, e nessuno saprebbe più
dire cosa può fare qualcuno senza aprire 156 file.

La direzione della migrazione è la cosa più importante di questo file: una lista
legacy diventa tutta **contributor**, non reader. Reader sarebbe più stretto, ma
toglierebbe di colpo a ogni partecipante di ogni topic la possibilità di
scrivere — una rottura silenziosa travestita da irrigidimento.
"""
from __future__ import annotations

import unittest
import tempfile
import shutil
from pathlib import Path

from .local_fs import LocalFsStorage
from .service import TopicService, TopicError


class Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="ruoli-"))
        self.svc = TopicService(LocalFsStorage(str(self.root)))
        self.svc.new("SEAL-1", "acme", {"title": "Acme", "owner": "davide",
                                        "participants": ["clodia", "giovanni"]})

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def meta(self):
        return self.svc.open("SEAL-1", "acme")["meta"]


class LegacyTests(Base):
    def test_a_legacy_list_reads_as_contributors(self):
        """Il comportamento di ieri resta il comportamento di oggi."""
        m = TopicService.participants_map(self.meta())
        self.assertEqual(m["clodia"], "contributor")
        self.assertEqual(m["giovanni"], "contributor")

    def test_the_owner_is_owner_even_coming_from_a_legacy_list(self):
        self.assertEqual(TopicService.participant_role(self.meta(), "davide"), "owner")

    def test_someone_outside_has_no_role(self):
        self.assertIsNone(TopicService.participant_role(self.meta(), "matteo"))

    def test_a_list_is_still_accepted_as_input(self):
        """I topic che nessuno tocca non vanno migrati a tappeto: si convertono
        alla prima modifica."""
        self.assertIsInstance(self.meta().get("participants"), list)


class RoleTests(Base):
    def test_inviting_defaults_to_contributor(self):
        """È ciò che «invitato» significava finora: cambiarlo di nascosto
        renderebbe muti gli invitati di ieri."""
        r = self.svc.add_participant("SEAL-1", "acme", "matteo")
        self.assertEqual(r["role"], "contributor")

    def test_a_reader_can_be_declared(self):
        self.svc.add_participant("SEAL-1", "acme", "matteo", role="reader")
        self.assertEqual(TopicService.participant_role(self.meta(), "matteo"), "reader")

    def test_a_role_can_be_changed_without_re_inviting(self):
        self.svc.add_participant("SEAL-1", "acme", "matteo", role="contributor")
        self.svc.add_participant("SEAL-1", "acme", "matteo", role="reader")
        self.assertEqual(TopicService.participant_role(self.meta(), "matteo"), "reader")

    def test_an_unknown_role_is_refused(self):
        with self.assertRaises(TopicError):
            self.svc.add_participant("SEAL-1", "acme", "matteo", role="capo")

    def test_owner_is_not_a_grade_of_access(self):
        """La proprietà dello scope è il campo `owner`, non un ruolo che si
        assegna invitando: altrimenti un topic potrebbe finire con due owner o
        con nessuno."""
        with self.assertRaises(TopicError) as cm:
            self.svc.add_participant("SEAL-1", "acme", "matteo", role="owner")
        self.assertIn("owner", str(cm.exception))

    def test_the_first_change_converts_the_list_to_a_map(self):
        self.svc.add_participant("SEAL-1", "acme", "matteo", role="reader")
        self.assertIsInstance(self.meta().get("participants"), dict)

    def test_conversion_preserves_everyone_else(self):
        """La conversione non deve perdere per strada chi c'era."""
        self.svc.add_participant("SEAL-1", "acme", "matteo", role="reader")
        m = TopicService.participants_map(self.meta())
        self.assertEqual(m.get("clodia"), "contributor")
        self.assertEqual(m.get("giovanni"), "contributor")


class MutationTests(Base):
    def test_owner_and_contributor_may_mutate(self):
        self.assertTrue(TopicService.may_mutate(self.meta(), "davide"))
        self.assertTrue(TopicService.may_mutate(self.meta(), "clodia"))

    def test_a_reader_may_not(self):
        self.svc.add_participant("SEAL-1", "acme", "matteo", role="reader")
        self.assertFalse(TopicService.may_mutate(self.meta(), "matteo"))

    def test_an_outsider_may_not(self):
        self.assertFalse(TopicService.may_mutate(self.meta(), "sconosciuto"))


class OwnerTests(Base):
    def test_the_owner_is_not_duplicated_among_participants(self):
        """Tenerlo in due posti significa poterli far divergere."""
        # L'owner è una PERSONA: dall'8 ago 2026 assegnarne uno che sia un
        # agente viene rifiutato, perché l'owner sblocca i gate del proprio
        # scope (invariante 1). Questo test parlava d'altro — che l'owner non si
        # duplichi fra i partecipanti — e usava `clodia` solo perché comodo.
        self.svc.add_participant("SEAL-1", "acme", "giovanni")
        self.svc.set_owner("SEAL-1", "acme", "giovanni")
        parts = self.meta().get("participants")
        self.assertNotIn("giovanni", parts if isinstance(parts, (list, dict)) else [])
        self.assertEqual(TopicService.participant_role(self.meta(), "giovanni"), "owner")

    def test_the_owner_cannot_be_removed_as_a_participant(self):
        """Rimuovere l'owner dai partecipanti lascerebbe uno scope senza chi
        risponde dei suoi gate (voce 24)."""
        self.svc.remove_participant("SEAL-1", "acme", "davide")
        self.assertEqual(TopicService.participant_role(self.meta(), "davide"), "owner")


class CompatibilityTests(Base):
    def test_membership_checks_keep_working_on_a_map(self):
        """`caller in meta['participants']` guarda le chiavi di un dict: i
        controlli esistenti non vanno toccati."""
        self.svc.add_participant("SEAL-1", "acme", "matteo", role="reader")
        parts = self.meta()["participants"]
        self.assertIn("matteo", parts)
        self.assertIn("clodia", parts)

    def test_names_only_view_for_callers_that_want_a_list(self):
        nomi = TopicService.participant_names(self.meta())
        self.assertIn("davide", nomi)
        self.assertIn("clodia", nomi)


if __name__ == "__main__":
    unittest.main()

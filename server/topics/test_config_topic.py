"""Il topic di configurazione, e l'eredità delle istruzioni.

Voce 22 (Davide, 6 ago 2026): «un topic speciale dove entrano solo gli admin, e
dove i file sono di fatto le configurazioni del sistema. Il caso più semplice:
l'AGENTS.md di questo topic è ereditato da tutti i nuovi topic».

Questo file copre il caso più semplice, che è già un incremento intero, e il
controllo da cui dipende tutto il resto.

**Il controllo.** Se un agente fosse partecipante del topic di configurazione
avrebbe `topic.put` sulla configurazione: il confused deputy nella forma più
pura — l'agente ha il verbo, l'admin ha l'autorità, e il file è la config.
«Solo admin» significa zero partecipanti agenti. E il pezzo che non è ovvio: la
terraformazione ce li metterebbe **da sola**, perché ogni topic nuovo riceve i
partecipanti di default dell'edizione. Senza l'eccezione, la voce 22 nascerebbe
già violata.

**Copia alla creazione, non lettura viva.** La parola di Davide è «nuovi», ed è
la lettura col profilo di rischio più basso. La lettura viva sarebbe il
metascope della voce 9: un file solo capace di cambiare il comportamento di ogni
agente in ogni stanza nello stesso istante — la superficie più potente del
sistema, che meriterebbe un gate suo.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from .local_fs import LocalFsStorage
from .service import TopicService


ISTRUZIONI = "Regole della casa: si cita sempre la fonte.\n"


class Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="config-topic-"))
        self.svc = TopicService(LocalFsStorage(str(self.root)))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def crea_config(self, testo=ISTRUZIONI):
        self.svc.new(TopicService.CONFIG_TIER, TopicService.CONFIG_NAME,
                     {"title": "Configurazione"})
        self.svc.save_agents_md(TopicService.CONFIG_TIER, TopicService.CONFIG_NAME,
                                testo, base_version=None)

    def agents_md(self, tier, name):
        return self.svc._read_agents_md(tier, name)[0]


class AdminOnlyTests(Base):
    def test_no_agent_is_terraformed_into_the_configuration(self):
        """Il controllo da cui dipende tutta la voce 22."""
        with patch("server.instance_profile.topic_default_participants",
                   lambda: ["clodia", "segretario"]):
            meta = self.svc.new(TopicService.CONFIG_TIER, TopicService.CONFIG_NAME,
                                {"title": "Configurazione"})
        parts = list(meta.get("participants") or [])
        self.assertNotIn("clodia", parts)
        self.assertNotIn("segretario", parts)

    def test_an_ordinary_topic_still_gets_the_defaults(self):
        """L'eccezione deve valere SOLO per la configurazione: allargarla
        spegnerebbe la terraformazione senza che nessuno l'abbia decisa."""
        with patch("server.instance_profile.topic_default_participants",
                   lambda: ["clodia"]):
            meta = self.svc.new("SEAL-1", "acme", {"title": "Acme"})
        self.assertIn("clodia", list(meta.get("participants") or []))

    def test_the_configuration_topic_sits_at_the_highest_tier(self):
        self.assertEqual(TopicService.CONFIG_TIER, "SEAL-4")

    def test_it_is_identified_by_a_known_name_not_by_a_flag(self):
        """Se fosse designato da un campo, due topic potrebbero dichiararsi tali
        e nessuno saprebbe quale vince."""
        self.assertTrue(TopicService.CONFIG_NAME)


class InheritanceTests(Base):
    def test_a_new_topic_inherits_the_instructions(self):
        self.crea_config()
        self.svc.new("SEAL-1", "acme", {"title": "Acme"})
        self.assertEqual(self.agents_md("SEAL-1", "acme"), ISTRUZIONI)

    def test_a_topic_created_before_receives_nothing(self):
        """«Nuovi»: i topic esistenti non ricevono nulla. È la differenza fra
        una copia alla creazione e una lettura viva."""
        self.svc.new("SEAL-1", "prima", {"title": "Prima"})
        self.crea_config()
        self.assertIsNone(self.agents_md("SEAL-1", "prima"))

    def test_a_later_change_does_not_propagate(self):
        self.crea_config()
        self.svc.new("SEAL-1", "acme", {"title": "Acme"})
        self.svc.save_agents_md(TopicService.CONFIG_TIER, TopicService.CONFIG_NAME,
                                "Regole nuove\n", base_version=None)
        self.assertEqual(self.agents_md("SEAL-1", "acme"), ISTRUZIONI)

    def test_the_configuration_topic_does_not_inherit_from_itself(self):
        self.crea_config()
        self.assertEqual(
            self.agents_md(TopicService.CONFIG_TIER, TopicService.CONFIG_NAME),
            ISTRUZIONI)

    def test_with_no_configuration_topic_nothing_changes(self):
        """Un'istanza che non lo usa non deve accorgersi che esiste."""
        self.svc.new("SEAL-1", "acme", {"title": "Acme"})
        self.assertIsNone(self.agents_md("SEAL-1", "acme"))

    def test_empty_instructions_are_not_inherited(self):
        """Un file vuoto ereditato occuperebbe il contesto di ogni turno per
        non dire niente."""
        self.crea_config("   \n")
        self.svc.new("SEAL-1", "acme", {"title": "Acme"})
        self.assertIsNone(self.agents_md("SEAL-1", "acme"))

    def test_a_topic_with_its_own_instructions_keeps_them(self):
        self.crea_config()
        self.svc.new("SEAL-1", "acme", {"title": "Acme"})
        self.svc.save_agents_md("SEAL-1", "acme", "Le mie\n", base_version=None)
        self.svc.new("SEAL-1", "acme", {"title": "Acme"})   # new è idempotente
        self.assertEqual(self.agents_md("SEAL-1", "acme"), "Le mie\n")


class RobustnessTests(Base):
    def test_a_failure_in_the_inheritance_does_not_prevent_creation(self):
        """Un topic senza istruzioni ereditate è utilizzabile; un topic non
        creato no. Stesso criterio del remote Drive alla nascita."""
        self.crea_config()
        with patch.object(TopicService, "config_agents_md",
                          side_effect=RuntimeError("giù")):
            meta = self.svc.new("SEAL-1", "acme", {"title": "Acme"})
        self.assertEqual(meta.get("title"), "Acme")


if __name__ == "__main__":
    unittest.main()

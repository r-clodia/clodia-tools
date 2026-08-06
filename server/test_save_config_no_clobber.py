"""`save_config` scrive SOLO il delta di questo processo.

Il difetto, misurato il 6 ago su venere: l'insieme di verbi di clodia è tornato da
53 a 130 quattro ore dopo essere stato ridotto. `config.yaml` riscritto alle 17:14
con i valori di prima delle 13:00, dal processo del gateway che li aveva in memoria
dall'avvio — `save_config` serializzava l'intero dict, quindi una copia stantia
copriva tutto ciò che era cambiato nel frattempo.

Avevo già visto questa classe di difetto e l'avevo corretta in DUE chiamanti
mettendoci un `reload_config()` davanti. Ma i chiamanti sono nove: far dipendere la
correttezza dalla disciplina di nove punti significa che il decimo la rompe. Questi
test fissano la correzione dove appartiene, dentro la funzione.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from . import whitelist as w


class Base(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.path = Path(self.d) / "config.yaml"
        self.scrivi({"workspace_root": ".", "egress_allow": [],
                     "agents": {"clodia": {"allowed_tools": ["a", "b"]},
                                "messaggero": {"allowed_tools": ["m"]}}})
        self.ctx = [patch.object(w, "CONFIG_PATH", self.path)]
        for c in self.ctx:
            c.start()
        self.addCleanup(lambda: [c.stop() for c in self.ctx])
        w.reload_config()

    def scrivi(self, d):
        self.path.write_text(yaml.safe_dump(d), encoding="utf-8")

    def leggi(self):
        return yaml.safe_load(self.path.read_text(encoding="utf-8"))


class DeltaOnlyTests(Base):
    def test_another_processs_change_survives_my_save(self):
        """IL caso reale. Cambio una chiave mia; nel frattempo un altro processo
        riduce i verbi di clodia; il mio save non deve resuscitarli."""
        w.CONFIG["egress_allow"] = ["mailto:a@b.it"]          # la MIA modifica
        disco = self.leggi()
        disco["agents"]["clodia"]["allowed_tools"] = ["solo-questo"]
        self.scrivi(disco)                                    # l'ALTRO processo
        w.save_config()
        finale = self.leggi()
        self.assertEqual(finale["agents"]["clodia"]["allowed_tools"], ["solo-questo"],
                         "la copia stantia ha sovrascritto un'altra scrittura")
        self.assertEqual(finale["egress_allow"], ["mailto:a@b.it"],
                         "la mia modifica deve essere persistita")

    def test_agents_merge_per_agent_not_wholesale(self):
        """Due processi su due agenti diversi non si sovrascrivono."""
        w.CONFIG["agents"]["messaggero"]["allowed_tools"] = ["m", "nuovo"]
        disco = self.leggi()
        disco["agents"]["clodia"]["allowed_tools"] = ["ridotto"]
        self.scrivi(disco)
        w.save_config()
        f = self.leggi()
        self.assertEqual(f["agents"]["messaggero"]["allowed_tools"], ["m", "nuovo"])
        self.assertEqual(f["agents"]["clodia"]["allowed_tools"], ["ridotto"])

    def test_a_key_i_removed_is_removed(self):
        """Il merge non deve rendere impossibile TOGLIERE: `[]` e l'assenza sono
        dichiarazioni, e una funzione che non sa cancellare le vanifica."""
        w.CONFIG.pop("egress_allow")
        w.save_config()
        self.assertNotIn("egress_allow", self.leggi())

    def test_an_agent_i_removed_is_removed(self):
        w.CONFIG["agents"].pop("messaggero")
        w.save_config()
        self.assertNotIn("messaggero", self.leggi()["agents"])

    def test_an_empty_list_is_written_not_ignored(self):
        w.CONFIG["agents"]["clodia"]["profile_tools"] = []
        w.save_config()
        self.assertEqual(self.leggi()["agents"]["clodia"]["profile_tools"], [])

    def test_after_saving_the_baseline_moves_forward(self):
        """Senza questo, due save consecutivi riproporrebbero il primo delta su
        uno stato già cambiato."""
        w.CONFIG["egress_allow"] = ["x"]
        w.save_config()
        disco = self.leggi()
        disco["agents"]["clodia"]["allowed_tools"] = ["altro"]
        self.scrivi(disco)
        w.save_config()          # secondo save, nessuna mia modifica nuova
        self.assertEqual(self.leggi()["agents"]["clodia"]["allowed_tools"], ["altro"])


class FirstLoadTests(unittest.TestCase):
    def test_the_baseline_exists_from_import_not_only_after_reload(self):
        """Il buco che avrebbe lasciato sopravvivere il difetto: un processo che
        carica all'import e salva senza aver mai ricaricato ricadeva sul
        comportamento vecchio, cioè riversava tutto."""
        self.assertTrue(w._LOADED, "_LOADED deve essere popolato al primo caricamento")

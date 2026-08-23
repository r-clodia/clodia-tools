"""Elencare i topic non attraversa lo storage remoto.

Misurato il 22 ago 2026: la webui rispondeva **502** sulla lista dei topic, a
intermittenza. La rotta funzionava — 200 OK in 7,4s su 98 topic — ma il client ha
un budget di 5s, scelto perché il control plane «è una chiamata dentro la rete
docker» (commento in `clodia-logic/server/api/topics_client.py`).

Non lo era: `list()` chiamava `_open()` per ogni topic, e `_open` ricava
`recent_files` da `files_store.list()`, che su un topic con un remote Drive
montato è una richiesta HTTP a Google. Il profilo: `_open` × 159,
`drive_fs.list` × 5, due `execute()` reali per 0,81s — e il tempo totale varia
con la latenza verso Google, che è la ragione per cui il guasto era intermittente.

Questi test non misurano il TEMPO (sarebbe un test che passa o fallisce secondo
la rete): verificano che sull'elenco **non si chiami** lo storage dei file. È
l'unica forma che resta vera anche su una macchina veloce.
"""
from __future__ import annotations

import json
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from .local_fs import LocalFsStorage
from .service import TopicService


class _StorageSpia(LocalFsStorage):
    """Storage locale che CONTA le chiamate, per distinguere «ha letto i meta»
    da «è andato a vedere i file»."""

    def __init__(self, root):
        super().__init__(root)
        self.list_di: list[str] = []
        self.stat_n = 0

    def list(self, path: str):
        self.list_di.append(path)
        return super().list(path)

    def stat(self, path: str):
        self.stat_n += 1
        return super().stat(path)


class ElencareNonToccaIFileTests(unittest.TestCase):
    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.s = _StorageSpia(self.root)
        self.svc = TopicService(self.s)
        # Tre topic, ognuno con un file in files/: se l'elenco andasse a
        # guardarli, la spia lo direbbe.
        for i in range(3):
            nome = f"t{i}"
            self.svc.new("SEAL-0", nome, {"title": f"Topic {i}", "owner": "davide"})
            self.svc.put_file("SEAL-0", nome, "allegato.txt", b"x", "agent", "clodia")

    def tearDown(self):
        self._tmp.cleanup()

    def test_la_lista_non_elenca_la_cartella_dei_file(self):
        """Il cuore: `files/` non viene aperta durante un elenco. Su un topic con
        remote Drive quella è una richiesta di rete, e qui sarebbe invisibile
        perché lo storage locale è veloce — per questo si conta, non si cronometra."""
        self.s.list_di.clear()
        righe = self.svc.list(None)
        self.assertEqual(len(righe), 3)
        toccate = [p for p in self.s.list_di if p.endswith("/files") or "/files/" in p]
        self.assertEqual(
            toccate, [],
            f"la lista è andata a guardare i file di qualche topic: {toccate}")

    def test_la_lista_non_espone_recent_files(self):
        """Il campo era calcolato, trasportato attraverso due servizi, dichiarato
        nel tipo della webui e mai mostrato. Assente, non vuoto: `[]` avrebbe
        detto «questo topic non ha file», che è un'altra affermazione."""
        for riga in self.svc.list(None):
            self.assertNotIn("recent_files", riga)

    def test_la_lista_porta_ancora_cio_che_la_card_mostra(self):
        """La riduzione non deve togliere quello che si vede: titolo, stato, tldr,
        action point, scadenze, partecipanti, `updated_at`."""
        riga = self.svc.list(None)[0]
        for campo in ("tier", "tier_name", "name", "title", "status", "tldr",
                      "deadline", "next_deadline", "contact_agent", "owner",
                      "participants", "action_points", "storage", "updated_at"):
            self.assertIn(campo, riga, f"la card ha perso `{campo}`")

    def test_aprire_un_topic_i_file_li_mostra_ancora(self):
        """`light` è solo dell'elenco: chi apre un topic vede i suoi file, ed è la
        ragione per cui il campo non è stato rimosso dal servizio."""
        self.s.list_di.clear()
        info = self.svc.open("SEAL-0", "t0")
        self.assertIn("recent_files", info)
        self.assertEqual([f["name"] for f in info["recent_files"]], ["allegato.txt"])
        self.assertIn("agents_md", info)
        self.assertIn("recap_history", info)
        self.assertTrue(
            any(p.endswith("/files") or "/files" in p for p in self.s.list_di),
            "aprire un topic DEVE guardare i file: se non lo fa più, la card è vuota")

    def test_open_light_non_promette_campi_che_non_ha_letto(self):
        light = self.svc._open("SEAL-0", "t0", allow_archived=True, light=True)
        pieno = self.svc._open("SEAL-0", "t0", allow_archived=True)
        for campo in ("recent_files", "files_unavailable", "agents_md", "recap_history"):
            self.assertNotIn(campo, light, f"`{campo}` non è stato letto: non deve comparire")
            self.assertIn(campo, pieno)
        # Ciò che serve alla riga c'è in entrambi, e con lo stesso valore.
        for campo in ("meta", "summary", "tldr", "updated_at", "summary_version"):
            self.assertIn(campo, light)
            self.assertEqual(light[campo], pieno[campo])

    def test_il_costo_dell_elenco_non_cresce_coi_file_di_un_topic(self):
        """Prova strutturale della riduzione: si aggiungono venti file a un topic
        e il numero di operazioni sullo storage durante l'elenco non cambia. Con
        `_open` pieno cambierebbe, perché li elencherebbe tutti."""
        prima_list = len(self.s.list_di)
        prima_stat = self.s.stat_n
        self.svc.list(None)
        costo_base = (len(self.s.list_di) - prima_list, self.s.stat_n - prima_stat)

        for i in range(20):
            self.svc.put_file("SEAL-0", "t0", f"f{i}.txt", b"y", "agent", "clodia")

        prima_list = len(self.s.list_di)
        prima_stat = self.s.stat_n
        self.svc.list(None)
        costo_dopo = (len(self.s.list_di) - prima_list, self.s.stat_n - prima_stat)

        self.assertEqual(costo_base, costo_dopo,
                         "il costo dell'elenco dipende dal contenuto dei topic")


class IlCostoCresceSoloColNumeroDiTopicTests(unittest.TestCase):
    """Il costo cresce col NUMERO di topic — quello è inevitabile — ma non con
    quanto c'è dentro ciascuno."""

    def setUp(self):
        self._tmp = TemporaryDirectory()
        self.s = _StorageSpia(Path(self._tmp.name))
        self.svc = TopicService(self.s)

    def tearDown(self):
        self._tmp.cleanup()

    def test_nessuna_lettura_di_files_per_nessun_topic(self):
        for i in range(10):
            self.svc.new("SEAL-0", f"x{i}", {"title": f"X{i}", "owner": "davide"})
        self.s.list_di.clear()
        self.svc.list(None)
        self.assertEqual([p for p in self.s.list_di if "/files" in p], [])


if __name__ == "__main__":
    unittest.main()

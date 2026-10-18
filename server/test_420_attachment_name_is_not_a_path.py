"""Il nome di un allegato è un NOME, non un path (clodia-platform#420).

Sintomo riportato: 24 `.eml` archiviati con `email.save_attachment`, 24 successi
dichiarati, 22 file davvero leggibili. I due mancanti avevano un `/` nel nome —
il nome degli `.eml` è il subject della mail inoltrata — e al loro posto, in
`local/`, era comparsa una cartella VUOTA.

Difetti distinti, entrambi provati qui:

1. il nome dell'allegato finiva as-is come path relativo di scrittura: il `/`
   veniva letto come separatore di directory. Il nome però è dato del mittente,
   non un path scelto dall'agente;

2. `«Tomato / Luxury…»` produce un segmento con lo spazio ai bordi
   (`"NDA bilaterale Tomato "`), e un segmento così si SCRIVE ma non si
   RILEGGE: i path in lettura passano da `_resolve_data_path`, che fa `.strip()`
   sull'espressione. La cartella esiste, contiene il file, e risulta vuota.
   È questo — non il `/` in sé — a rendere la perdita silenziosa: gli altri due
   allegati con `/` ma senza spazi erano infatti ritrovabili nella sottocartella.

The sanitising of the name (defect 1) is comms-pack's component's since #523
and tested there (`safe_attachment_name`); what stays here is the topic
storage half (defect 2).
"""
from __future__ import annotations

import tempfile
import unittest

from .topics.local_fs import LocalFsStorage
from .topics.service import TopicError, TopicService

#: I due nomi che hanno perso il file, dal canale #preventivi-tomato.
PERSI = [
    "Aggiornamento preventivo Voucher Startup Social Tech / StopListe.eml",
    "NDA bilaterale Tomato / Luxury Esmeralda Real Estate — versione aggiornata.eml",
]


class UnreadablePathIsRefusedTests(unittest.TestCase):
    """Chi il path lo SCRIVE (topic.write_file/put/move_file) riceve un errore,
    non una rinomina a sorpresa: la cartella con lo spazio ai bordi è il modo di
    creare qualcosa che il topic non sa più mostrare."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.svc = TopicService(LocalFsStorage(self.tmp.name))
        self.svc.new("SEAL-1", "ch", {"title": "ch", "owner": "davide",
                                      "participants": ["davide"]})

    def test_a_folder_with_a_trailing_space_is_refused(self):
        with self.assertRaises(TopicError) as e:
            self.svc.put_file("SEAL-1", "ch", "archivio /nota.md", b"x")
        self.assertIn("spazio", str(e.exception))

    def test_a_file_with_a_leading_space_is_refused(self):
        with self.assertRaises(TopicError):
            self.svc.put_file("SEAL-1", "ch", "archivio/ nota.md", b"x")

    def test_move_file_refuses_the_same_destination(self):
        self.svc.put_file("SEAL-1", "ch", "nota.md", b"x")
        with self.assertRaises(TopicError):
            self.svc.move_file("SEAL-1", "ch", "local/nota.md", "archivio /nota.md")

    def test_the_legitimate_subfolder_still_works(self):
        # La guardia non deve togliere le sottocartelle: sono una feature di
        # `put_file`, ed è ciò che distingue un path scritto da un nome ricevuto.
        r = self.svc.put_file("SEAL-1", "ch", "archivio/nota.md", b"x")
        self.assertEqual(r["path"], "local/archivio/nota.md")
        self.assertEqual(self.svc.read_file("SEAL-1", "ch", r["path"]), b"x")


class TheSymptomItselfTests(unittest.TestCase):
    """Perché la perdita era SILENZIOSA: la cartella con lo spazio finale non si
    elenca. Test di caratterizzazione — se un giorno la lettura smettesse di
    fare `.strip()`, questo diventa rosso e la guardia sopra può cadere."""

    def test_a_directory_whose_name_ends_with_a_space_lists_empty(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        svc = TopicService(LocalFsStorage(tmp.name))
        svc.new("SEAL-1", "ch", {"title": "ch", "owner": "davide",
                                 "participants": ["davide"]})
        # Scrittura per la via bassa, scavalcando la guardia: è com'era prima.
        store, base = svc._local_mount("SEAL-1", "ch")
        store.write(f"{base}/cartella /dentro.md", b"ci sono")
        self.assertEqual(svc.list_files("SEAL-1", "ch", "local/cartella "), [])
        self.assertIn("cartella ",
                      [f["name"] for f in svc.list_files("SEAL-1", "ch", "local")])


if __name__ == "__main__":
    unittest.main()

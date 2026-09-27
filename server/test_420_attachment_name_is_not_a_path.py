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
"""
from __future__ import annotations

import tempfile
import unittest

from .topics.local_fs import LocalFsStorage
from .topics.service import TopicError, TopicService
from .tools import email as email_tool

#: I due nomi che hanno perso il file, dal canale #preventivi-tomato.
PERSI = [
    "Aggiornamento preventivo Voucher Startup Social Tech / StopListe.eml",
    "NDA bilaterale Tomato / Luxury Esmeralda Real Estate — versione aggiornata.eml",
]


class SafeAttachmentNameTests(unittest.TestCase):
    """Il sanificatore, da solo."""

    def test_the_separator_stops_being_a_separator(self):
        for nome in PERSI:
            safe = email_tool.safe_attachment_name(nome)
            self.assertNotIn("/", safe)
            self.assertTrue(safe.endswith(".eml"), safe)

    def test_no_segment_is_left_with_edge_spaces(self):
        safe = email_tool.safe_attachment_name(PERSI[1])
        self.assertEqual(safe, safe.strip())
        self.assertEqual(safe, "NDA bilaterale Tomato - Luxury Esmeralda Real "
                               "Estate — versione aggiornata.eml")

    def test_backslash_newline_and_leading_dot_are_handled_too(self):
        # Sono le altre tre forme che `put_file` rifiuta o nasconde: backslash
        # (errore secco), whitespace esotico da subject MIME, dotfile (invisibile
        # al navigator, che salta le voci che cominciano per punto).
        self.assertEqual(email_tool.safe_attachment_name("a\\b.pdf"), "a-b.pdf")
        self.assertEqual(email_tool.safe_attachment_name("Oggetto\n lungo.eml"),
                         "Oggetto lungo.eml")
        self.assertEqual(email_tool.safe_attachment_name(".hidden.pdf"), "hidden.pdf")

    def test_a_name_that_sanitizes_to_nothing_still_has_a_name(self):
        # Meglio un file da rinominare che una `TopicError` su un allegato che
        # esiste: qui l'alternativa al fallback è perdere il contenuto.
        self.assertEqual(email_tool.safe_attachment_name("///"), "allegato")
        self.assertEqual(email_tool.safe_attachment_name(""), "allegato")


class AttachmentLandsAsOneFileTests(unittest.TestCase):
    """Il giro vero: nome sanificato → `put_file` → il file si RILEGGE."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.svc = TopicService(LocalFsStorage(self.tmp.name))
        self.svc.new("SEAL-1", "ch", {"title": "ch", "owner": "davide",
                                      "participants": ["davide", "messaggero"]})

    def _archivia(self, nome: str) -> dict:
        """Replica il ramo tier+name di `email.save_attachment`."""
        fn = email_tool.safe_attachment_name(nome)
        return self.svc.put_file("SEAL-1", "ch", fn, b"%PDF allegato",
                                 "untrusted", by="messaggero")

    def test_the_attachment_is_a_file_in_local_not_a_folder(self):
        for nome in PERSI:
            r = self._archivia(nome)
            voci = {f["name"]: f for f in self.svc.list_files("SEAL-1", "ch", "local")}
            self.assertIn(r["name"], voci, f"{nome} non compare in local/")
            self.assertEqual(voci[r["name"]]["kind"], "file")
            self.assertEqual([v for v in voci.values() if v["kind"] == "dir"], [],
                             "nessuna cartella doveva nascere dal nome dell'allegato")

    def test_the_path_reported_to_the_caller_reads_back(self):
        # È la proprietà che mancava: il verbo dichiarava successo e il path
        # dichiarato non restituiva byte.
        r = self._archivia(PERSI[1])
        self.assertEqual(self.svc.read_file("SEAL-1", "ch", r["path"]), b"%PDF allegato")

    def test_provenance_survives_the_rename(self):
        r = self._archivia(PERSI[0])
        voce = [f for f in self.svc.list_files("SEAL-1", "ch", "local")
                if f["name"] == r["name"]][0]
        self.assertEqual(voce["provenance"], "untrusted")


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

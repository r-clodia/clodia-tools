"""`topic.move_file`: riordinare i file senza lavare la provenienza.

clodia-platform#419. Prima di questo verbo l'unico modo di spostare un file era
`fetch` + `put` + `delete_file`, e non era un giro più lungo per lo stesso
risultato: `put_file` scrive una provenienza NUOVA (`agent`), quindi 24 allegati
email spostati in una sottocartella — caso reale, canale #preventivi-tomato del
27/09/2026 — tornavano tutti «prodotti dall'agente», e il flag `untrusted` su cui
si regge la difesa dalle istruzioni nascoste nei documenti di terzi spariva senza
che nessuno avesse validato niente.

Il test che conta è il primo: dopo il move l'etichetta deve essere ancora
`untrusted`, con lo stesso `by`. Gli altri difendono le guardie (destinazione mai
sovrascritta, control-plane intoccabile, niente traversal).
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from .local_fs import LocalFsStorage
from .service import TopicService, TopicError


class Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="move-"))
        self.svc = TopicService(LocalFsStorage(str(self.root)))
        self.svc.new("SEAL-1", "preventivi", {"title": "Preventivi", "owner": "davide"})
        # Un allegato arrivato dalla posta: untrusted, messo lì dal messaggero.
        self.svc.put_file("SEAL-1", "preventivi", "offerta.eml", b"From: fornitore",
                          "untrusted", by="messaggero")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _prov(self, relpath: str) -> dict:
        return self.svc.provenance_map("SEAL-1", "preventivi").get(relpath) or {}


class ProvenanceTests(Base):
    def test_moving_a_file_keeps_its_untrusted_label(self):
        """Il cuore di #419: il move NON riscrive il contenuto, quindi non
        rietichetta nessuno. `by` resta chi l'ha davvero introdotto."""
        out = self.svc.move_file("SEAL-1", "preventivi", "local/offerta.eml",
                                 "local/2026/offerta.eml")
        self.assertEqual(out["path"], "local/2026/offerta.eml")
        self.assertEqual(self._prov("2026/offerta.eml").get("provenance"), "untrusted")
        self.assertEqual(self._prov("2026/offerta.eml").get("by"), "messaggero")

    def test_the_old_label_does_not_stay_behind_as_an_orphan(self):
        """Il sidecar è indicizzato per path: lasciare la voce vecchia significa
        una riga che punta a un file che non esiste più."""
        self.svc.move_file("SEAL-1", "preventivi", "local/offerta.eml",
                           "local/2026/offerta.eml")
        self.assertEqual(self._prov("offerta.eml"), {})

    def test_the_content_travels_untouched(self):
        self.svc.move_file("SEAL-1", "preventivi", "local/offerta.eml",
                           "local/2026/offerta.eml")
        self.assertEqual(
            self.svc.read_file("SEAL-1", "preventivi", "local/2026/offerta.eml"),
            b"From: fornitore")
        with self.assertRaises(Exception):
            self.svc.read_file("SEAL-1", "preventivi", "local/offerta.eml")

    def test_a_renamed_file_keeps_the_label_too(self):
        """Rinominare è spostare: stesso verbo, stessa garanzia."""
        self.svc.move_file("SEAL-1", "preventivi", "local/offerta.eml",
                           "local/offerta-fornitore-a.eml")
        self.assertEqual(
            self._prov("offerta-fornitore-a.eml").get("provenance"), "untrusted")

    def test_moving_a_folder_remaps_every_label_under_it(self):
        """Il caso dei 24 allegati: si sposta la CARTELLA, e la provenienza deve
        seguire ogni file dentro, a qualunque profondità."""
        self.svc.put_file("SEAL-1", "preventivi", "posta/a.eml", b"a",
                          "untrusted", by="messaggero")
        self.svc.put_file("SEAL-1", "preventivi", "posta/allegati/b.pdf", b"b",
                          "untrusted", by="messaggero")
        self.svc.put_file("SEAL-1", "preventivi", "relazione.md", b"mia",
                          "agent", by="analista")

        out = self.svc.move_file("SEAL-1", "preventivi", "local/posta",
                                 "local/archivio/posta-2026")

        self.assertEqual(out["provenance_entries_moved"], 2)
        self.assertEqual(
            self._prov("archivio/posta-2026/a.eml").get("provenance"), "untrusted")
        self.assertEqual(
            self._prov("archivio/posta-2026/allegati/b.pdf").get("provenance"),
            "untrusted")
        self.assertEqual(self._prov("posta/a.eml"), {})
        # Gli estranei non vengono toccati.
        self.assertEqual(self._prov("relazione.md").get("provenance"), "agent")

    def test_the_moved_file_is_listed_with_its_original_provenance(self):
        """La vista file è ciò che un agente legge davvero prima di fidarsi."""
        self.svc.move_file("SEAL-1", "preventivi", "local/offerta.eml",
                           "local/2026/offerta.eml")
        righe = self.svc.list_files("SEAL-1", "preventivi", "local/2026")
        prov = {r["name"]: r.get("provenance") for r in righe}
        self.assertEqual(prov.get("offerta.eml"), "untrusted")

    def test_a_topic_without_sidecar_does_not_break(self):
        """File pre-esistenti al sidecar: niente etichetta da spostare, e il
        move deve comunque funzionare."""
        (self.root / "SEAL-1" / "preventivi" / TopicService._PROV_FILE).unlink()
        out = self.svc.move_file("SEAL-1", "preventivi", "local/offerta.eml",
                                 "local/x.eml")
        self.assertEqual(out["provenance_entries_moved"], 0)


class GuardTests(Base):
    def test_an_existing_destination_is_never_overwritten(self):
        self.svc.put_file("SEAL-1", "preventivi", "2026/offerta.eml", b"altro",
                          "agent", by="analista")
        with self.assertRaises(TopicError):
            self.svc.move_file("SEAL-1", "preventivi", "local/offerta.eml",
                               "local/2026/offerta.eml")
        # Nessuno dei due file è stato perso.
        self.assertEqual(
            self.svc.read_file("SEAL-1", "preventivi", "local/2026/offerta.eml"),
            b"altro")
        self.assertEqual(
            self.svc.read_file("SEAL-1", "preventivi", "local/offerta.eml"),
            b"From: fornitore")

    def test_a_missing_source_is_refused(self):
        with self.assertRaises(TopicError):
            self.svc.move_file("SEAL-1", "preventivi", "local/mai-esistito.eml",
                               "local/x.eml")

    def test_the_control_plane_cannot_be_moved(self):
        """`summary.md`/`meta.json` sono path NUDI: non appartengono all'albero
        dati, e un move li renderebbe raggiungibili come file qualunque."""
        for cp in ("summary.md", "meta.json", "AGENTS.md"):
            with self.assertRaises(TopicError):
                self.svc.move_file("SEAL-1", "preventivi", cp, "local/rubato.md")

    def test_the_root_agents_md_cannot_be_the_destination(self):
        """Stessa guardia di `put_file`: l'AGENTS.md di radice entra nel contesto
        di ogni agente e si scrive solo con `topic.save_agents_md`."""
        with self.assertRaises(TopicError):
            self.svc.move_file("SEAL-1", "preventivi", "local/offerta.eml",
                               "local/AGENTS.md")

    def test_traversal_is_refused_on_both_sides(self):
        with self.assertRaises(TopicError):
            self.svc.move_file("SEAL-1", "preventivi", "local/../../evaso.eml",
                               "local/x.eml")
        with self.assertRaises(TopicError):
            self.svc.move_file("SEAL-1", "preventivi", "local/offerta.eml",
                               "local/../../evaso.eml")

    def test_the_destination_cannot_be_a_dotfile(self):
        """Un move dentro `.trash/` o `.provenance.json` toccherebbe strutture
        nascoste del topic: `_resolve_write_target` le vieta per entrambi i verbi."""
        with self.assertRaises(TopicError):
            self.svc.move_file("SEAL-1", "preventivi", "local/offerta.eml",
                               "local/.trash/offerta.eml")

    def test_a_mount_is_not_movable(self):
        with self.assertRaises(TopicError):
            self.svc.move_file("SEAL-1", "preventivi", "local", "local/tutto")

    def test_a_folder_cannot_be_moved_inside_itself(self):
        self.svc.put_file("SEAL-1", "preventivi", "posta/a.eml", b"a")
        with self.assertRaises(TopicError):
            self.svc.move_file("SEAL-1", "preventivi", "local/posta",
                               "local/posta/archivio")
        self.assertEqual(self.svc.read_file("SEAL-1", "preventivi",
                                            "local/posta/a.eml"), b"a")

    def test_source_and_destination_cannot_coincide(self):
        with self.assertRaises(TopicError):
            self.svc.move_file("SEAL-1", "preventivi", "local/offerta.eml",
                               "files/offerta.eml")


class VerbWiringTests(unittest.TestCase):
    """Il verbo è dichiarato e classificato come gli altri che scrivono."""

    def test_the_verb_is_declared_scoped_and_mutating(self):
        from server import main as M
        nomi = {t.name for t in M._TOPIC_TOOLS}
        self.assertIn("topic.move_file", nomi)
        self.assertIn("move_file", M._TOPIC_SCOPED_VERBS)
        self.assertIn("move_file", M._TOPIC_MUTATING_VERBS)

    def test_the_verb_is_not_gated(self):
        """Spostare un file resta dentro il perimetro della stanza: chi può già
        scriverci (`put`) e toglierne (`delete_file`) non chiede un permesso in
        più per rinominare. Nessuna card, come per i due verbi gemelli."""
        from server import gate as G
        for gemello in ("topic.put", "topic.delete_file", "topic.move_file"):
            self.assertNotIn(gemello, G._DEFAULT_GATED_EXACT)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

"""L'immagine di un topic: dentro il topic, e davvero un'immagine.

Due scelte che si vedono solo qui.

**Dove vive.** Nel topic, non in una cartella di asset della piattaforma. Così
segue lo scope quando viene esportato, archiviato o migrato di storage, invece di
restare un file orfano che nessuno sa a chi appartenesse.

**Cosa si accetta.** Si guardano i BYTE, non l'estensione: il nome del file lo
sceglie chi carica. E l'SVG si rifiuta — è un documento che può contenere script
e finirebbe renderizzato nella pagina di chiunque apra il topic. Un'immagine che
può eseguire codice non è un'immagine.

Chi può cambiarla è deciso a monte (solo l'owner, in `topics.py` della webui):
qui si controlla ciò che il ruolo non può controllare.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from .service import TopicService, TopicError
from .local_fs import LocalFsStorage


PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
JPEG = b"\xff\xd8\xff\xe0" + b"\x00" * 64
GIF = b"GIF89a" + b"\x00" * 64
WEBP = b"RIFF" + b"\x00\x00\x00\x00" + b"WEBP" + b"\x00" * 64


class Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="logo-"))
        self.svc = TopicService(LocalFsStorage(str(self.root)))
        self.svc.new("SEAL-1", "acme", {"title": "Acme", "owner": "davide"})

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)


class WhatIsAcceptedTests(Base):
    def test_the_usual_formats_go_in(self):
        for byte, atteso in ((PNG, "png"), (JPEG, "jpeg"), (GIF, "gif"), (WEBP, "webp")):
            r = self.svc.set_logo("SEAL-1", "acme", byte)
            self.assertEqual(r["kind"], atteso)

    def test_svg_is_refused_and_says_why(self):
        """Il rifiuto più importante, e quello che sembra più arbitrario: va
        spiegato, o al primo tentativo qualcuno lo prende per un bug."""
        with self.assertRaises(TopicError) as e:
            self.svc.set_logo("SEAL-1", "acme",
                              b'<svg xmlns="http://www.w3.org/2000/svg"><script>1</script></svg>')
        self.assertIn("script", str(e.exception).lower())

    def test_a_renamed_file_does_not_pass(self):
        """L'estensione la sceglie chi carica: si guardano i byte."""
        with self.assertRaises(TopicError):
            self.svc.set_logo("SEAL-1", "acme", b"non sono un'immagine, ma mi chiamo logo.png")

    def test_nothing_is_not_an_image(self):
        with self.assertRaises(TopicError):
            self.svc.set_logo("SEAL-1", "acme", b"")

    def test_too_big_is_refused(self):
        """Un'icona, non un allegato. Senza tetto, il meta di un topic diventa il
        posto dove finiscono i file grossi che nessuno ha guardato."""
        with self.assertRaises(TopicError) as e:
            self.svc.set_logo("SEAL-1", "acme", PNG + b"\x00" * (600 * 1024))
        self.assertIn("KB", str(e.exception))


class ItReadsFromWhereItWroteTests(Base):
    """Il difetto vero, trovato da Davide caricando un'immagine.

    Il logo stava sotto `files/`, e sembrava naturale: un'immagine è un file. Non
    lo era. `files/` è il **data plane**: su un topic con un remote Drive quei
    path risolvono su Drive. `set_logo` invece scriveva con `self.s`, il
    **control plane**, che è sempre locale.

    Risultato: il file c'era, il meta lo dichiarava, e la lettura non lo trovava.
    Su un topic senza remote funzionava benissimo — e i primi test erano tutti
    così. È il difetto peggiore da cercare, perché dipende da una **proprietà del
    topic** e non dal codice: la stessa riga funziona o no a seconda di come è
    configurata la stanza.

    Ora il logo è metadata: sta col control plane, e si legge con `read_logo`,
    che usa la stessa radice di `set_logo`. Una funzione per scrivere e una per
    leggere sulla stessa radice è ciò che rende la coppia verificabile — due
    strade diverse per lo stesso file si separano appena una delle due cambia.
    """

    def _con_remote_drive(self):
        """Aggancia un remote Drive FINTO: basta che il meta lo dichiari perché
        la risoluzione dei path sotto `files/` cambi bersaglio."""
        meta, ver = self.svc._read_meta("SEAL-1", "acme")
        meta["mounts"] = [{"name": "drive", "type": "drive",
                           "config": {"folder": "FID"}}]
        self.svc._write_meta("SEAL-1", "acme", meta, base_version=ver)

    def test_the_logo_is_readable_on_a_topic_with_a_drive_remote(self):
        self._con_remote_drive()
        self.svc.set_logo("SEAL-1", "acme", PNG)
        data, tipo = self.svc.read_logo("SEAL-1", "acme")
        self.assertEqual(data, PNG)
        self.assertEqual(tipo, "image/png")

    def test_and_on_a_plain_local_topic_too(self):
        self.svc.set_logo("SEAL-1", "acme", JPEG)
        data, tipo = self.svc.read_logo("SEAL-1", "acme")
        self.assertEqual(data, JPEG)
        self.assertEqual(tipo, "image/jpeg")

    def test_it_does_not_live_under_files(self):
        """`files/` significa «documento». Il logo non lo è: comparirebbe
        nell'albero dei file come un file che nessuno ha messo lì, e seguirebbe
        i documenti su Drive."""
        self.assertFalse(TopicService.LOGO_PATH.startswith("files/"))
        self.svc.set_logo("SEAL-1", "acme", PNG)
        nomi = [e["name"] for e in self.svc.list_files("SEAL-1", "acme", "files")]
        self.assertNotIn(".brand", nomi)

    def test_no_logo_is_a_clear_refusal(self):
        with self.assertRaises(TopicError) as e:
            self.svc.read_logo("SEAL-1", "acme")
        self.assertIn("non ha un logo", str(e.exception))


class WhereItLivesTests(Base):
    def test_the_meta_points_at_a_file_inside_the_topic(self):
        r = self.svc.set_logo("SEAL-1", "acme", PNG)
        meta = self.svc.open("SEAL-1", "acme")["meta"]
        self.assertEqual(meta["logo"], r["logo"])
        self.assertEqual(self.svc.read_logo("SEAL-1", "acme")[0], PNG)

    def test_a_second_upload_replaces_the_first(self):
        """Un topic ha un'immagine, non una galleria: il nome è riservato e uno
        solo, altrimenti ogni caricamento lascerebbe dietro il precedente."""
        self.svc.set_logo("SEAL-1", "acme", PNG)
        self.svc.set_logo("SEAL-1", "acme", GIF)
        meta = self.svc.open("SEAL-1", "acme")["meta"]
        self.assertEqual(self.svc.read_file("SEAL-1", "acme", meta["logo"]), GIF)

    def test_clearing_removes_both_the_reference_and_the_bytes(self):
        """Lasciare il file sarebbe un byte orfano che ricompare al prossimo
        caricamento parziale."""
        self.svc.set_logo("SEAL-1", "acme", PNG)
        self.svc.clear_logo("SEAL-1", "acme")
        meta = self.svc.open("SEAL-1", "acme")["meta"]
        self.assertNotIn("logo", meta)
        with self.assertRaises(Exception):
            self.svc.read_file("SEAL-1", "acme", TopicService.LOGO_PATH)

    def test_clearing_twice_is_not_an_error(self):
        """Togliere ciò che non c'è è già il risultato voluto."""
        self.svc.clear_logo("SEAL-1", "acme")
        self.svc.clear_logo("SEAL-1", "acme")

    def test_the_reference_survives_a_normal_read(self):
        """`normalize_meta_v2` riscrive il meta a ogni apertura: un campo che non
        conosce non deve sparire, o il logo si perderebbe al primo `open`."""
        self.svc.set_logo("SEAL-1", "acme", PNG)
        for _ in range(3):
            meta = self.svc.open("SEAL-1", "acme")["meta"]
        self.assertEqual(meta["logo"], TopicService.LOGO_PATH)


if __name__ == "__main__":
    unittest.main()

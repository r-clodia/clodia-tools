"""Lo stesso difetto di clodia-platform#228 in altri due verbi di lettura.

`topic.read_file` è stato cappato e paginato (#260). `profile.read_file`
(clodia-platform#319) e `memory.read` no: leggevano il file INTERO e lo
mettevano nel contesto, dove un risultato non si paga una volta ma a ogni
azione successiva del turno.

Le proprietà provate qui sono quelle già provate per `topic.read_file`, con in
più la sola che nasce dall'avere TRE verbi invece di uno:

  1. il default è una finestra di 64 KB, non il file;
  2. il resto resta richiedibile — scorrendo `next_offset` si riottiene il file
     intero, altrimenti il tetto non è un limite ma una mutilazione;
  3. `max_bytes` viene STRETTO nel codice, non solo dichiarato nello schema
     (è il buco che la review della #260 ha trovato: lo schema è un
     suggerimento a chi compone la chiamata, il clamp è una garanzia);
  4. schema e codice dichiarano lo STESSO tetto, in tutti i verbi — se
     divergono, l'agente pianifica su un numero falso;
  5. i binari del profilo restano come prima, senza campi di finestra: un
     base64 a metà non è un pezzo di file, è un file illeggibile.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import main as M
from . import profile as prof
from .tools import memory as mem


#: Un file di testo più grande della finestra di default, accenti compresi (il
#: taglio a metà di un carattere multibyte è il modo in cui una paginazione a
#: byte fatta ingenuamente rompe un file di testo valido).
GROSSO = ("riga di note con accenti à è ì ò ù e simboli €\n" * 3000).encode("utf-8")
#: Più grande del TETTO, non solo del default: distingue «cappato a 512 KB» da
#: «cappato a 64 KB».
ENORME = ("riga di note con accenti à è ì ò ù e simboli €\n" * 20000).encode("utf-8")


class ProfileReadFileConsegnaUnaFinestra(unittest.TestCase):
    """`profile.read_file`: un CV o un estratto conto non entra intero."""

    def _read(self, contenuto: bytes = GROSSO, **extra):
        with patch.object(prof, "read_file", lambda *a, **k: contenuto):
            return M._dispatch_profile("profile.read_file",
                                       {"agent": "tizio", "filename": "cv.md", **extra},
                                       "tizio")

    def test_il_default_e_64_kb_e_il_resto_si_puo_chiedere(self) -> None:
        r = self._read()
        self.assertTrue(r["truncated"])
        self.assertEqual(len(GROSSO), r["size"])
        self.assertLessEqual(r["window"], 64 * 1024)
        self.assertGreater(r["window"], 60 * 1024, "finestra troppo piccola per essere 64 KB")
        self.assertIsNotNone(r["next_offset"])
        self.assertEqual(len(r["text"].encode("utf-8")), r["window"])

    def test_scorrendo_si_riottiene_il_file_intero(self) -> None:
        pezzi, off, giri = [], 0, 0
        while off is not None and giri < 200:
            r = self._read(offset=off, max_bytes=8192)
            pezzi.append(r["text"])
            off = r["next_offset"]
            giri += 1
        self.assertEqual(GROSSO.decode("utf-8"), "".join(pezzi))

    def test_un_file_corto_non_dichiara_un_resto_che_non_esiste(self) -> None:
        r = self._read(b"due righe\ne basta\n")
        self.assertFalse(r["truncated"])
        self.assertIsNone(r["next_offset"])
        self.assertEqual("due righe\ne basta\n", r["text"])
        self.assertNotIn("note", r)

    def test_la_finestra_troncata_dice_come_chiedere_il_resto(self) -> None:
        r = self._read()
        self.assertIn("note", r)
        self.assertIn(f"offset={r['next_offset']}", r["note"])

    def test_un_max_bytes_assurdo_viene_stretto_al_tetto(self) -> None:
        """IL CASO: `max_bytes=100000000` non deve consegnare il file intero."""
        self.assertGreater(len(ENORME), M._READ_FILE_MAX,
                           "il fixture deve superare il tetto, o il test non prova nulla")
        r = self._read(ENORME, max_bytes=100_000_000)
        self.assertLessEqual(r["window"], M._READ_FILE_MAX)
        self.assertTrue(r["truncated"])
        self.assertIsNotNone(r["next_offset"])

    def test_un_max_bytes_non_numerico_lo_dice(self) -> None:
        with self.assertRaises(ValueError) as e:
            self._read(max_bytes="molti")
        self.assertIn("max_bytes", str(e.exception))

    def test_il_binario_resta_come_prima_e_senza_campi_di_finestra(self) -> None:
        import base64
        png = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 4
        r = self._read(png, offset=5000, max_bytes=1)
        self.assertEqual("base64", r["encoding"])
        self.assertEqual(png, base64.b64decode(r["data"]))
        for campo in ("window", "next_offset", "remaining", "truncated"):
            self.assertNotIn(campo, r)

    def test_il_ramo_non_consegna_piu_il_file_intero(self) -> None:
        """Il difetto era `raw.decode()` sul file INTERO: se torna, torna qui."""
        import inspect
        src = inspect.getsource(M._dispatch_profile)
        corpo = src[src.index('if sub == "read_file":'):]
        corpo = corpo[:corpo.index('if sub == "grant":')]
        self.assertIn("_finestra_testo(", corpo)


class MemoryReadConsegnaUnaFinestra(unittest.TestCase):
    """`memory.read`: il tetto di chi SCRIVE non è il tetto di chi LEGGE.

    `memory.write` rifiuta oltre 64 KB, ma `read` serve anche i file arrivati da
    un'altra strada (la webui, una versione precedente, un JSON cresciuto nel
    tempo): il file grande esiste comunque, e chi lo legge se lo porta nel
    contesto per tutto il turno.
    """

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        # Scritto a mano, NON con `mem.write`: il caso da coprire è proprio il
        # file che il cap della scrittura non ha visto passare.
        (self.dir / "MEMORY.md").write_bytes(GROSSO)
        self.addCleanup(self._tmp.cleanup)

    def _read(self, **extra):
        with patch.object(mem, "memory_dir", lambda name=None: self.dir):
            return M._dispatch_memory("memory.read", dict(extra))

    def test_il_default_e_64_kb_e_il_resto_si_puo_chiedere(self) -> None:
        r = self._read()
        self.assertEqual("MEMORY.md", r["file"])
        self.assertTrue(r["truncated"])
        self.assertEqual(len(GROSSO), r["size"])
        self.assertLessEqual(r["window"], 64 * 1024)
        self.assertGreater(r["window"], 60 * 1024, "finestra troppo piccola per essere 64 KB")
        self.assertIn(f"offset={r['next_offset']}", r["note"])

    def test_scorrendo_si_riottiene_il_file_intero(self) -> None:
        pezzi, off, giri = [], 0, 0
        while off is not None and giri < 200:
            r = self._read(offset=off, max_bytes=8192)
            pezzi.append(r["content"])
            off = r["next_offset"]
            giri += 1
        self.assertEqual(GROSSO.decode("utf-8"), "".join(pezzi))

    def test_un_max_bytes_assurdo_viene_stretto_al_tetto(self) -> None:
        (self.dir / "MEMORY.md").write_bytes(ENORME)
        r = self._read(max_bytes=100_000_000)
        self.assertLessEqual(r["window"], M._READ_FILE_MAX)
        self.assertTrue(r["truncated"])

    def test_una_memory_corta_resta_una_risposta_intera(self) -> None:
        (self.dir / "MEMORY.md").write_text("una nota\n", encoding="utf-8")
        r = self._read()
        self.assertEqual("una nota\n", r["content"])
        self.assertFalse(r["truncated"])
        self.assertIsNone(r["next_offset"])
        self.assertNotIn("note", r)

    def test_un_file_che_non_esiste_resta_una_risposta_e_non_un_errore(self) -> None:
        r = self._read(filename="assente.md")
        self.assertFalse(r["exists"])
        self.assertEqual("", r["content"])


class ILimitiDichiaratiSonoQuelliApplicati(unittest.TestCase):
    """Il buco trovato in review sulla #260, chiuso per tutti e tre i verbi.

    Un tetto scritto solo nello `inputSchema` è una promessa, non un limite; e
    due numeri (schema e codice) divergono in silenzio alla prima modifica.
    """

    VERBI = {"topic.read_file": M._TOPIC_TOOLS,
             "profile.read_file": M._PROFILE_TOOLS,
             "memory.read": M._MEMORY_TOOLS}

    def test_ogni_verbo_di_lettura_dichiara_offset_e_max_bytes(self) -> None:
        for verbo, lista in self.VERBI.items():
            t = {x.name: x for x in lista}[verbo]
            with self.subTest(verbo=verbo):
                self.assertIn("offset", t.inputSchema["properties"])
                self.assertIn("max_bytes", t.inputSchema["properties"])
                self.assertIn("next_offset", t.description)

    def test_lo_schema_non_promette_piu_del_tetto(self) -> None:
        for verbo, lista in self.VERBI.items():
            t = {x.name: x for x in lista}[verbo]
            with self.subTest(verbo=verbo):
                self.assertEqual(M._READ_FILE_MAX,
                                 t.inputSchema["properties"]["max_bytes"]["maximum"])


if __name__ == "__main__":
    unittest.main()

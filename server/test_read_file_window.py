"""Un file di testo entra nel contesto a finestre, non tutto intero.

Il difetto misurato in clodia-platform#228: un risultato di tool si paga UNA
volta per produrlo e N volte per rileggerlo — resta nella sessione e il modello
lo ri-legge a ogni chiamata successiva del turno. `web.fetch` era già stato
cappato (64 KB di default + `max_bytes`); `topic.read_file` no: un file di testo
da 300 KB entrava intero e continuava a costare per tutto il resto del turno.

Cappare senza paginare però peggiora le cose: chi riceve 64 KB di un file da 300
KB e non ha modo di chiedere il resto legge un file MUTILATO credendolo finito —
è lo stesso difetto già corretto su `read_document` (`server/test_read_window.py`).

Le proprietà provate qui:
  1. le finestre si ricuciono senza buchi né sovrapposizioni, e concatenandole
     si riottiene il file INTERO;
  2. il taglio cade su un capo a riga quando ce n'è uno vicino;
  3. **un carattere multibyte non viene mai spezzato**: un taglio a metà
     sequenza UTF-8 rende indecodificabile un file di testo valido, e chi legge
     lo vedrebbe classificato come binario (o riceverebbe un carattere falso);
  4. la fine si riconosce da `next_offset: None`, non da un confronto fra numeri;
  5. il verbo li usa davvero, dichiara i parametri e il default è 64 KB come
     `web.fetch`;
  6. i binari continuano a comportarsi come prima: base64 sotto soglia, rinvio a
     `topic.fetch` sopra — identici anche se si passano `offset`/`max_bytes`,
     perché un base64 a metà non è un pezzo di file, è un file illeggibile.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import docmd, main as M


class LaFinestraDiByteScorre(unittest.TestCase):
    #: Un file finto ma della forma vera: righe di testo, accenti compresi.
    FILE = "\n".join(f"riga {i}: però ci sono accenti e simboli €" for i in range(400)
                     ).encode("utf-8")

    def test_scorrendo_si_legge_tutto_il_file(self) -> None:
        pezzi, off, giri = [], 0, 0
        while off is not None and giri < 500:
            w = docmd.finestra_byte(self.FILE, off, 700)
            pezzi.append(w["data"])
            off = w["next_offset"]
            giri += 1
        self.assertEqual(self.FILE, b"".join(pezzi))
        self.assertLess(giri, 500, "la paginazione non termina")

    def test_due_finestre_si_ricuciono_senza_buchi(self) -> None:
        a = docmd.finestra_byte(self.FILE, 0, 700)
        self.assertTrue(a["truncated"])
        b = docmd.finestra_byte(self.FILE, a["next_offset"], 700)
        self.assertEqual(self.FILE[:a["window"] + b["window"]], a["data"] + b["data"])

    def test_il_taglio_cade_su_un_capo_a_riga(self) -> None:
        w = docmd.finestra_byte(self.FILE, 0, 700)
        self.assertTrue(w["data"].endswith(b"\n"), repr(w["data"][-40:]))

    def test_la_fine_si_riconosce_da_next_offset(self) -> None:
        w = docmd.finestra_byte(b"corto", 0, 65536)
        self.assertIsNone(w["next_offset"])
        self.assertFalse(w["truncated"])
        self.assertEqual(0, w["remaining"])
        self.assertEqual(5, w["size"])

    def test_offset_oltre_la_fine_non_e_un_errore(self) -> None:
        w = docmd.finestra_byte(b"corto", 9999, 100)
        self.assertEqual(b"", w["data"])
        self.assertIsNone(w["next_offset"])

    def test_una_riga_piu_lunga_della_finestra_non_blocca(self) -> None:
        w = docmd.finestra_byte(b"x" * 5000 + b"\n" + b"y" * 100, 0, 1000)
        self.assertGreater(w["window"], 0)
        self.assertIsNotNone(w["next_offset"])


class IlTaglioNonSpezzaUnCarattere(unittest.TestCase):
    """Il caso che rende inutile una paginazione a byte fatta ingenuamente.

    `"€".encode()` sono tre byte: un taglio fra il primo e il secondo non
    produce un carattere sbagliato, produce un file di testo che NON si decodifica
    — cioè che il verbo classificherebbe come binario.
    """

    def test_ogni_finestra_si_decodifica_da_sola(self) -> None:
        # Nessun capo a riga: l'arretramento a riga non può salvare il taglio,
        # deve intervenire quello sul confine UTF-8.
        dati = ("€" * 500).encode("utf-8")
        off, giri = 0, 0
        while off is not None and giri < 500:
            w = docmd.finestra_byte(dati, off, 100)
            w["data"].decode("utf-8")  # strict: deve reggere senza `replace`
            off = w["next_offset"]
            giri += 1
        self.assertLess(giri, 500, "la paginazione non termina")

    def test_una_finestra_piu_corta_di_un_carattere_avanza_comunque(self) -> None:
        """Arretrare fino a zero darebbe una finestra vuota e un ciclo infinito:
        in quel caso si allunga di qualche byte invece di consegnare niente."""
        w = docmd.finestra_byte("€€".encode("utf-8"), 0, 1)
        self.assertEqual("€", w["data"].decode("utf-8"))
        self.assertEqual(3, w["next_offset"])

    def test_un_offset_in_mezzo_a_un_carattere_non_rompe(self) -> None:
        """`next_offset` cade sempre su un confine, ma un offset a mano no."""
        w = docmd.finestra_byte("€uro".encode("utf-8"), 1, 100)
        self.assertEqual("uro", w["data"].decode("utf-8"))


class IlVerboLaUsa(unittest.TestCase):
    """Un helper corretto che il verbo non chiama non aiuta nessuno."""

    #: Un file di testo più grande della finestra di default.
    GROSSO = ("riga di testo con accenti à è ì ò ù\n" * 4000).encode("utf-8")

    def _read(self, **extra):
        class _S:
            def read_file(self, tier, name, path):
                return (IlVerboLaUsa.GROSSO if path.endswith(".md")
                        else b"\x89PNG\r\n\x1a\n\xff\xd8\xff")

        with patch.object(M, "_topics", lambda: _S()), \
             patch.object(M, "_require_topic_member", lambda *a, **k: None):
            return M._dispatch_topic("topic.read_file",
                                     {"tier": "SEAL-1", "name": "acme",
                                      "path": "files/report.md", **extra})

    def test_il_default_e_64_kb_e_il_resto_si_puo_chiedere(self) -> None:
        r = self._read()
        self.assertTrue(r["truncated"])
        self.assertEqual(len(self.GROSSO), r["size"])
        self.assertLessEqual(r["window"], 64 * 1024)
        self.assertGreater(r["window"], 60 * 1024, "finestra troppo piccola per essere 64 KB")
        self.assertIsNotNone(r["next_offset"])
        self.assertEqual(len(r["content"].encode("utf-8")), r["window"])

    def test_scorrendo_il_verbo_si_riottiene_il_file(self) -> None:
        pezzi, off, giri = [], 0, 0
        while off is not None and giri < 200:
            r = self._read(offset=off, max_bytes=8192)
            pezzi.append(r["content"])
            off = r["next_offset"]
            giri += 1
        self.assertEqual(self.GROSSO.decode("utf-8"), "".join(pezzi))

    def test_un_file_corto_non_dichiara_un_resto_che_non_esiste(self) -> None:
        class _S:
            def read_file(self, tier, name, path):
                return b"due righe\ne basta\n"

        with patch.object(M, "_topics", lambda: _S()), \
             patch.object(M, "_require_topic_member", lambda *a, **k: None):
            r = M._dispatch_topic("topic.read_file",
                                  {"tier": "SEAL-1", "name": "acme", "path": "files/x.md"})
        self.assertFalse(r["truncated"])
        self.assertIsNone(r["next_offset"])
        self.assertEqual("due righe\ne basta\n", r["content"])

    def test_il_binario_resta_come_prima(self) -> None:
        r = self._read(path="files/foto.png")
        self.assertEqual("base64", r["encoding"])

    def test_il_binario_grosso_rinvia_ancora_a_fetch(self) -> None:
        class _S:
            def read_file(self, tier, name, path):
                return b"\xff\xfe" * M._B64_INLINE_CAP

        with patch.object(M, "_topics", lambda: _S()), \
             patch.object(M, "_require_topic_member", lambda *a, **k: None):
            r = M._dispatch_topic("topic.read_file",
                                  {"tier": "SEAL-1", "name": "acme", "path": "files/x.bin"})
        self.assertFalse(r["ok"])
        self.assertIn("topic.fetch", r["error"])

    def test_lo_schema_dichiara_i_parametri_e_la_risposta(self) -> None:
        t = {x.name: x for x in M._TOPIC_TOOLS}["topic.read_file"]
        self.assertIn("offset", t.inputSchema["properties"])
        self.assertIn("max_bytes", t.inputSchema["properties"])
        self.assertIn("next_offset", t.description)

    def test_il_ramo_non_consegna_piu_il_file_intero(self) -> None:
        """Il difetto era `data.decode()` sul file INTERO: se torna, torna qui."""
        import inspect
        src = inspect.getsource(M._dispatch_topic)
        corpo = src[src.index('if verb == "read_file":'):]
        corpo = corpo[:corpo.index('if verb == "read_document":')]
        self.assertIn("finestra_byte(", corpo)


class IlTettoValeAncheSeChiediDiPiu(unittest.TestCase):
    """Un tetto dichiarato solo nello `inputSchema` non è un tetto.

    Lo schema è un SUGGERIMENTO a chi compone la chiamata: dice `maximum` e si
    fida. Ma l'argomento arriva da un modello — e a volte da un modello che ha
    sbagliato uno zero, o da un client MCP che non ha letto lo schema affatto.
    Se il dispatch passa il valore così com'è, `max_bytes` diventa la strada per
    riottenere il difetto che questo verbo ha appena chiuso: file intero nel
    contesto, riletto a ogni azione del turno (clodia-platform#228).

    `web.fetch` questo pezzo lo ha (`_limite` fa `min(n, MAX_RESPONSE_BYTES)`):
    qui si prova che ce l'ha anche `read_file`, e che quando la finestra taglia
    lo DICE nel risultato — non solo nella descrizione del tool, che l'agente
    legge una volta, ma nel dizionario che sta guardando.
    """

    #: Più grande del tetto, non solo del default: serve a distinguere «cappato
    #: a 512 KB» da «cappato a 64 KB».
    ENORME = ("riga di testo con accenti à è ì ò ù\n" * 20000).encode("utf-8")

    def _read(self, **extra):
        class _S:
            def read_file(self, tier, name, path):
                return IlTettoValeAncheSeChiediDiPiu.ENORME

        with patch.object(M, "_topics", lambda: _S()), \
             patch.object(M, "_require_topic_member", lambda *a, **k: None):
            return M._dispatch_topic("topic.read_file",
                                     {"tier": "SEAL-1", "name": "acme",
                                      "path": "files/report.md", **extra})

    def test_un_max_bytes_assurdo_viene_stretto_al_tetto(self) -> None:
        """IL CASO: `max_bytes=100000000` non deve consegnare 780 KB di file."""
        self.assertGreater(len(self.ENORME), M._READ_FILE_MAX,
                           "il fixture deve superare il tetto, o il test non prova nulla")
        r = self._read(max_bytes=100_000_000)
        self.assertLessEqual(r["window"], M._READ_FILE_MAX)
        self.assertTrue(r["truncated"])
        self.assertIsNotNone(r["next_offset"])

    def test_il_resto_resta_raggiungibile_anche_dopo_il_clamp(self) -> None:
        """Stringere non deve rendere irraggiungibile la coda: è il difetto
        originale di `read_document`, non lo si reintroduce dalla porta del tetto."""
        pezzi, off, giri = [], 0, 0
        while off is not None and giri < 50:
            r = self._read(offset=off, max_bytes=100_000_000)
            pezzi.append(r["content"])
            off = r["next_offset"]
            giri += 1
        self.assertEqual(self.ENORME.decode("utf-8"), "".join(pezzi))

    def test_un_max_bytes_non_numerico_lo_dice(self) -> None:
        """`int("molti")` grezzo dà un ValueError che non insegna niente."""
        with self.assertRaises(ValueError) as e:
            self._read(max_bytes="molti")
        self.assertIn("max_bytes", str(e.exception))

    def test_un_max_bytes_negativo_non_svuota_la_finestra(self) -> None:
        with self.assertRaises(ValueError) as e:
            self._read(max_bytes=-1)
        self.assertIn("max_bytes", str(e.exception))

    def test_la_finestra_troncata_dice_come_chiedere_il_resto(self) -> None:
        """`truncated: true` senza istruzioni è la metà inutile del messaggio:
        è nel RISULTATO che si guarda, non nella descrizione del verbo."""
        r = self._read()
        self.assertIn("note", r)
        self.assertIn(f"offset={r['next_offset']}", r["note"])

    def test_un_file_intero_non_porta_una_nota_che_non_serve(self) -> None:
        class _S:
            def read_file(self, tier, name, path):
                return b"corto\n"

        with patch.object(M, "_topics", lambda: _S()), \
             patch.object(M, "_require_topic_member", lambda *a, **k: None):
            r = M._dispatch_topic("topic.read_file",
                                  {"tier": "SEAL-1", "name": "acme", "path": "files/x.md"})
        self.assertNotIn("note", r)

    def test_lo_schema_non_promette_piu_del_tetto(self) -> None:
        """Se schema e codice divergono, l'agente pianifica su un numero falso."""
        t = {x.name: x for x in M._TOPIC_TOOLS}["topic.read_file"]
        self.assertEqual(M._READ_FILE_MAX,
                         t.inputSchema["properties"]["max_bytes"]["maximum"])


class IlRamoBinarioIgnoraLaFinestra(unittest.TestCase):
    """L'unico punto dove i due percorsi possono divergere in SILENZIO.

    `offset`/`max_bytes` valgono per il testo: un base64 tagliato a metà non è un
    pezzo di file, è un file che non si decodifica — e chi lo riceve non ha modo
    di accorgersene guardando il contenuto. Il ramo binario deve quindi
    rispondere identico con o senza i parametri nuovi, e non deve portare campi
    di finestra: un `next_offset` lì prometterebbe un resto richiedibile che
    nessuna chiamata sa consegnare.

    Sono invarianti, non un difetto corretto: la finestra si applica dopo la
    decisione testo/binario e quindi oggi passano. Restano perché quella
    decisione è a due righe da qui, e chi la sposterà sopra il ramo binario per
    «cappare prima» non ha altro modo di scoprire cosa ha rotto.
    """

    #: Non decodificabile come UTF-8, e più corto di `_B64_INLINE_CAP`.
    PNG = b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 4

    def _read(self, **extra):
        class _S:
            def read_file(self, tier, name, path):
                return IlRamoBinarioIgnoraLaFinestra.PNG

        with patch.object(M, "_topics", lambda: _S()), \
             patch.object(M, "_require_topic_member", lambda *a, **k: None):
            return M._dispatch_topic("topic.read_file",
                                     {"tier": "SEAL-1", "name": "acme",
                                      "path": "files/foto.png", **extra})

    def test_la_risposta_non_cambia_con_offset_e_max_bytes(self) -> None:
        self.assertEqual(self._read(), self._read(offset=5000, max_bytes=1))

    def test_il_base64_resta_quello_del_file_intero(self) -> None:
        import base64
        r = self._read(offset=5000, max_bytes=1)
        self.assertEqual(self.PNG, base64.b64decode(r["content"]))

    def test_non_dichiara_una_finestra_che_non_esiste(self) -> None:
        r = self._read(offset=5000, max_bytes=1)
        for campo in ("window", "next_offset", "remaining", "truncated"):
            self.assertNotIn(campo, r)


if __name__ == "__main__":
    unittest.main()

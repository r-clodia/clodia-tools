"""Un documento troppo lungo per una risposta si legge a finestre, non a metà.

Il difetto, segnalato dall'`avvocato` il 4 set 2026 sul dc10 di
titul-brightnode: «il mio lettore tronca dall'inizio e non ha offset: 71.801
caratteri, ne vedo 22.000». Misurato: il documento ha **71.801** caratteri
esatti — il suo numero era giusto — e `read_document` consegnava `text[:cap]`,
sempre dal principio.

Quindi gli articoli finali (8.3, 9.1, 10, 11, 12, 13) non erano *lenti* da
raggiungere: erano **irraggiungibili**, per costruzione, con qualunque
parametro. E `truncated: true` diceva che mancava qualcosa senza dire come
averlo — da cui l'unica mossa che restava all'agente, chiedere a un umano di
estrarre i pezzi a mano.

Le proprietà provate qui:
  1. la seconda finestra comincia dove finisce la prima, senza buchi né
     sovrapposizioni — su un contratto, un buco è una clausola che non esiste;
  2. concatenando le finestre si riottiene il documento INTERO;
  3. il taglio cade su un confine di riga, o un marcatore CriticMarkup spezzato
     farebbe sembrare una revisione aperta e mai chiusa;
  4. la fine si riconosce da `next_offset: None`, non da un confronto fra
     numeri che chi legge deve indovinare;
  5. `outline` dà l'offset dei titoli, così un articolo preciso costa una
     finestra e non quattro.
"""
from __future__ import annotations

import unittest

from . import docmd


class LaFinestraScorre(unittest.TestCase):
    #: Un documento finto ma della forma vera: titoli e paragrafi lunghi.
    DOC = "\n\n".join(
        [f"## Art. {i}\n\nClausola numero {i}. " + ("testo di riempimento. " * 12)
         for i in range(1, 41)])

    def test_due_finestre_si_ricuciono_senza_buchi(self) -> None:
        """IL CASO SEGNALATO: il resto del documento deve essere raggiungibile."""
        a = docmd.finestra(self.DOC, 0, 1000)
        self.assertTrue(a["truncated"])
        b = docmd.finestra(self.DOC, a["next_offset"], 1000)
        self.assertEqual(self.DOC[:len(a["text"]) + len(b["text"])],
                         a["text"] + b["text"])

    def test_scorrendo_si_legge_tutto_il_documento(self) -> None:
        pezzi, off, giri = [], 0, 0
        while off is not None and giri < 500:
            w = docmd.finestra(self.DOC, off, 1000)
            pezzi.append(w["text"])
            off = w["next_offset"]
            giri += 1
        self.assertEqual(self.DOC, "".join(pezzi))
        self.assertLess(giri, 500, "la paginazione non termina")

    def test_la_fine_si_riconosce_da_next_offset(self) -> None:
        """`None` e non «offset + window >= chars»: una fine da dedurre è una
        fine che qualcuno dedurrà male."""
        w = docmd.finestra("corto", 0, 60000)
        self.assertIsNone(w["next_offset"])
        self.assertFalse(w["truncated"])
        self.assertEqual(0, w["remaining"])

    def test_offset_oltre_la_fine_non_e_un_errore(self) -> None:
        w = docmd.finestra("corto", 9999, 100)
        self.assertEqual("", w["text"])
        self.assertIsNone(w["next_offset"])

    def test_remaining_dice_quanto_manca(self) -> None:
        w = docmd.finestra("x" * 1000, 0, 400)
        self.assertEqual(1000 - w["window"], w["remaining"])


class IlTaglioNonSpezzaUnaRevisione(unittest.TestCase):
    """Su un documento in revisione un taglio a metà marcatore è un dato falso.

    `{++inserito` senza la chiusura fa sembrare che la revisione continui per
    tutto il resto della finestra: chi legge non vede un troncamento, vede un
    contratto diverso.
    """

    def test_il_taglio_cade_su_un_capo_a_riga(self) -> None:
        doc = "\n".join(f"riga {i} con {{++proposta {i}++}} e seguito." for i in range(200))
        w = docmd.finestra(doc, 0, 500)
        self.assertTrue(w["text"].endswith("\n"), repr(w["text"][-40:]))

    def test_nessuna_finestra_lascia_un_marcatore_aperto(self) -> None:
        doc = "\n".join(f"riga {i} con {{++proposta {i}++}} e seguito." for i in range(200))
        off = 0
        while off is not None:
            w = docmd.finestra(doc, off, 300)
            self.assertEqual(w["text"].count("{++"), w["text"].count("++}"),
                             f"marcatore spezzato a offset {off}")
            off = w["next_offset"]

    def test_una_riga_piu_lunga_della_finestra_non_blocca(self) -> None:
        """Senza un limite all'arretramento, una tabella su una riga sola
        darebbe una finestra vuota e la paginazione non avanzerebbe mai."""
        doc = "x" * 5000 + "\n" + "y" * 100
        w = docmd.finestra(doc, 0, 1000)
        self.assertGreater(w["window"], 0)
        self.assertIsNotNone(w["next_offset"])


class LIndiceDeiTitoli(unittest.TestCase):
    def test_da_i_titoli_col_loro_offset(self) -> None:
        doc = "# ACCORDO\n\ntesto\n\n## Art. 8.3\n\naltro testo\n\n## Art. 9.1\n\nfine"
        ind = docmd.outline(doc)
        self.assertEqual(["ACCORDO", "Art. 8.3", "Art. 9.1"], [t["title"] for t in ind])
        # L'offset deve puntare davvero all'inizio di quel titolo.
        for t in ind:
            self.assertTrue(doc[t["offset"]:].startswith("#" * t["level"] + " "),
                            f"offset sbagliato per {t['title']}")

    def test_saltare_a_un_articolo_costa_una_finestra(self) -> None:
        """È il bisogno dichiarato: «dove stanno esattamente 8.3, 9.1, 10…»."""
        doc = ("# ACCORDO\n\n" + "riempimento. " * 400 + "\n\n## Art. 9.1\n\n"
               "Il preavviso è di 90 giorni.\n")
        ind = docmd.outline(doc)
        art = next(t for t in ind if t["title"] == "Art. 9.1")
        w = docmd.finestra(doc, art["offset"], 200)
        self.assertIn("Art. 9.1", w["text"])
        self.assertIn("90 giorni", w["text"])

    def test_documento_senza_titoli(self) -> None:
        self.assertEqual([], docmd.outline("solo testo, nessun titolo"))


class IlVerboLaUsa(unittest.TestCase):
    """Gli helper corretti che il verbo non chiama non aiutano nessuno."""

    def test_read_document_dichiara_offset(self) -> None:
        from . import main
        t = {x.name: x for x in main._TOPIC_TOOLS}["topic.read_document"]
        self.assertIn("offset", t.inputSchema["properties"])
        self.assertIn("next_offset", t.description)

    def test_nessun_read_document_taglia_piu_a_mano(self) -> None:
        """Ce ne sono DUE, `topic.` e `memory.`, e avevano lo stesso difetto:
        l'ha scoperto questo test cercando il primo dei due."""
        from pathlib import Path
        src = (Path(__file__).parent / "main.py").read_text()
        rami = [i for i in range(len(src))
                if src.startswith('if verb == "read_document":', i)]
        self.assertEqual(2, len(rami), f"rami read_document trovati: {len(rami)}")
        for i in rami:
            corpo = src[i:i + 1600]
            self.assertIn("finestra(", corpo, f"ramo a {i} non usa la finestra")
            self.assertNotIn("text[:cap]", corpo,
                             f"ramo a {i} taglia dall'inizio: il resto è irraggiungibile")


if __name__ == "__main__":
    unittest.main()

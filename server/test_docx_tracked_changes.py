"""Le revisioni tracciate di un DOCX si vedono, e si vedono per quello che sono.

Il difetto, segnalato dall'avvocato il 3 set 2026 («non vedo il markup completo
nelle revisioni del file docx») e misurato su un accordo reale contando i
caratteri per percorso XML:

    body/p/r/t                34.343    testo non revisionato
    body/p/ins/r/t            12.222    inserito con revisione
    body/p/del/r/delText       7.055    cancellato con revisione
    body/tbl/tr/tc/p/r/t         911    tabelle
    TOTALE                    54.531

    python-docx  (read_document)     35.496  = 54.531 - 12.222 - 7.055
    mammoth      (convert_document)  47.534  = 54.531 - 7.055

Le due sottrazioni tornano al carattere: `python-docx` perde inserimenti E
cancellazioni (i run dentro `<w:ins>`/`<w:del>` non sono figli diretti del
paragrafo, e `paragraph.text` li salta), `mammoth` perde le cancellazioni —
cioè rende il documento come se le revisioni fossero accettate, senza dirlo.

Perché una suite e non un fixture di prova: i DOCX qui sono GENERATI con
revisioni vere, così ogni test dice cosa sta verificando. Un binario opaco nel
repo, quando diventa rosso, non permette di distinguere fra un cambio di codice
e un cambio di file.
"""
from __future__ import annotations

import io
import unittest
import zipfile

from . import docrev


def _docx(corpo_xml: str, commenti_xml: str | None = None) -> bytes:
    ns = ('xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"')
    document = (f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                f'<w:document {ns}><w:body>{corpo_xml}</w:body></w:document>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/'
                   'package/2006/content-types"><Default Extension="xml" '
                   'ContentType="application/xml"/></Types>')
        z.writestr("word/document.xml", document)
        if commenti_xml is not None:
            z.writestr("word/comments.xml",
                       f'<?xml version="1.0"?><w:comments {ns}>{commenti_xml}</w:comments>')
    return buf.getvalue()


def _r(testo: str) -> str:
    return f'<w:r><w:t xml:space="preserve">{testo}</w:t></w:r>'


def _ins(testo: str, autore="Controparte", data="2026-09-02T10:00:00Z") -> str:
    return (f'<w:ins w:id="1" w:author="{autore}" w:date="{data}">{_r(testo)}</w:ins>')


def _del(testo: str, autore="Controparte", data="2026-09-02T10:00:00Z") -> str:
    return (f'<w:del w:id="2" w:author="{autore}" w:date="{data}">'
            f'<w:r><w:delText xml:space="preserve">{testo}</w:delText></w:r></w:del>')


class TestoNonSiPerde(unittest.TestCase):
    """La proprietà che l'avvocato ha segnalato: niente testo invisibile."""

    def test_inserimenti_e_cancellazioni_ci_sono_entrambi(self):
        d = _docx(f'<w:p>{_r("Il corrispettivo è ")}{_del("1.000")}{_ins("1.500")}'
                  f'{_r(" EUR.")}</w:p>')
        md, st = docrev.docx_to_markdown(d, "inline")
        self.assertIn("{--1.000--}", md)
        self.assertIn("{++1.500++}", md)
        self.assertEqual(st["inserimenti"], 1)
        self.assertEqual(st["cancellazioni"], 1)

    def test_l_ordine_dice_cosa_sostituisce_cosa(self):
        """`{--1.000--}{++1.500++}` è una sostituzione leggibile; invertito o
        raggruppato per tipo direbbe un'altra cosa."""
        d = _docx(f'<w:p>{_del("1.000")}{_ins("1.500")}</w:p>')
        md, _ = docrev.docx_to_markdown(d, "inline")
        self.assertLess(md.index("{--1.000--}"), md.index("{++1.500++}"))

    def test_un_paragrafo_interamente_inserito_non_e_vuoto(self):
        """Il caso dei 33 paragrafi su 147 che `python-docx` leggeva vuoti."""
        d = _docx(f'<w:p>{_ins("Articolo 12 — Foro competente.")}</w:p>')
        md, st = docrev.docx_to_markdown(d, "inline")
        self.assertIn("Articolo 12", md)
        self.assertEqual(st["inserimenti"], 1)

    def test_revisione_annidata_in_un_hyperlink(self):
        """Le revisioni si annidano: un'estrazione che cerchi solo `w:p/w:r`
        perde ciò che sta un livello sotto."""
        d = _docx('<w:p><w:hyperlink r:id="rId1" '
                  'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
                  + _ins("clausola aggiunta") + '</w:hyperlink></w:p>')
        md, st = docrev.docx_to_markdown(d, "inline")
        self.assertIn("clausola aggiunta", md)
        self.assertEqual(st["inserimenti"], 1)

    def test_una_frase_spezzata_in_run_da_word_e_una_revisione_sola(self):
        """Word spezza il testo inserito per grassetto/lingua: marcare ogni run
        darebbe `{++Il ++}{++corrispettivo++}` e conterebbe tre revisioni."""
        d = _docx('<w:p><w:ins w:id="1" w:author="X" w:date="2026-09-02T00:00:00Z">'
                  + _r("Il ") + _r("corrispettivo ") + _r("annuale")
                  + '</w:ins></w:p>')
        md, st = docrev.docx_to_markdown(d, "inline")
        self.assertIn("{++Il corrispettivo annuale++}", md)
        self.assertEqual(st["inserimenti"], 1)

    def test_revisioni_dentro_una_tabella(self):
        d = _docx('<w:tbl><w:tr><w:tc><w:p>' + _r("Canone") + '</w:p></w:tc>'
                  '<w:tc><w:p>' + _del("1.000") + _ins("1.500") + '</w:p></w:tc>'
                  '</w:tr></w:tbl>')
        md, st = docrev.docx_to_markdown(d, "inline")
        self.assertIn("| Canone |", md)
        self.assertIn("{++1.500++}", md)
        self.assertEqual(st["revisioni"], 2)


class LeTreModalita(unittest.TestCase):
    """Tre domande diverse, tre risposte diverse: nessuna deducibile dalle altre."""

    def setUp(self):
        self.d = _docx(f'<w:p>{_r("Preavviso di ")}{_del("30")}{_ins("90")}'
                       f'{_r(" giorni.")}</w:p>')

    def test_inline_mostra_entrambi(self):
        md, _ = docrev.docx_to_markdown(self.d, "inline")
        self.assertIn("{--30--}", md)
        self.assertIn("{++90++}", md)

    def test_accepted_e_il_testo_se_accetto(self):
        md, st = docrev.docx_to_markdown(self.d, "accepted")
        self.assertIn("Preavviso di 90 giorni.", md)
        self.assertNotIn("30", md)
        self.assertNotIn("{++", md)
        self.assertEqual(st["cancellazioni"], 0)

    def test_original_e_il_testo_di_prima(self):
        md, st = docrev.docx_to_markdown(self.d, "original")
        self.assertIn("Preavviso di 30 giorni.", md)
        self.assertNotIn("90", md)
        self.assertEqual(st["inserimenti"], 0)

    def test_mode_non_valido_e_un_errore(self):
        with self.assertRaises(ValueError):
            docrev.docx_to_markdown(self.d, "boh")


class ChiHaPropostoCosa(unittest.TestCase):
    """Autore e data non sono un extra: senza, per sapere se una modifica è
    della controparte bisogna aprire Word."""

    def test_riepilogo_per_revisore_e_data(self):
        d = _docx(f'<w:p>{_ins("alfa", "Studio Carboni", "2026-08-21T09:00:00Z")}'
                  f'{_ins("beta", "Controparte", "2026-09-02T11:00:00Z")}'
                  f'{_del("gamma", "Controparte", "2026-09-02T11:00:00Z")}</w:p>')
        md, st = docrev.docx_to_markdown(d, "inline")
        self.assertEqual(sorted(st["revisori"]), ["Controparte", "Studio Carboni"])
        self.assertIn("## Revisioni tracciate", md)
        self.assertIn("Studio Carboni", md)
        self.assertIn("2026-08-21", md)
        self.assertIn("2026-09-02", md)

    def test_il_riepilogo_non_compare_nelle_altre_modalita(self):
        """`accepted` serve a produrre un testo da leggere o firmare: un
        riepilogo di revisioni in testa lo sporcherebbe."""
        d = _docx(f'<w:p>{_ins("alfa")}</w:p>')
        for mode in ("accepted", "original"):
            md, _ = docrev.docx_to_markdown(d, mode)
            self.assertNotIn("## Revisioni tracciate", md)

    def test_documento_senza_revisioni_non_ha_riepilogo(self):
        d = _docx(f'<w:p>{_r("Testo pulito.")}</w:p>')
        md, st = docrev.docx_to_markdown(d, "inline")
        self.assertNotIn("## Revisioni", md)
        self.assertEqual(st["revisioni"], 0)
        self.assertFalse(docrev.has_tracked_changes(d))


class Commenti(unittest.TestCase):
    def test_un_commento_compare_col_suo_autore(self):
        d = _docx('<w:p>' + _r("Clausola penale. ")
                  + '<w:commentReference w:id="7"/></w:p>',
                  commenti_xml='<w:comment w:id="7" w:author="Studio Carboni" '
                               'w:date="2026-09-03T08:00:00Z"><w:p><w:r>'
                               '<w:t>Verificare il massimale.</w:t></w:r></w:p></w:comment>')
        md, st = docrev.docx_to_markdown(d, "inline")
        self.assertIn("{>>Verificare il massimale.", md)
        self.assertIn("Studio Carboni", md)
        self.assertEqual(st["commenti"], 1)


class StrutturaConservata(unittest.TestCase):
    """Titoli, elenchi e tabelle restano: uno strumento che recupera il testo e
    perde la struttura di un contratto non è utilizzabile su un contratto."""

    def test_titoli_da_stile_word(self):
        d = _docx('<w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr>' + _r("PREMESSO CHE")
                  + '</w:p><w:p><w:pPr><w:pStyle w:val="Heading2"/></w:pPr>'
                  + _r("Art. 2") + '</w:p>')
        md, _ = docrev.docx_to_markdown(d, "inline")
        self.assertIn("# PREMESSO CHE", md)
        self.assertIn("## Art. 2", md)

    def test_titoli_anche_con_stile_italiano(self):
        """Word localizzato può scrivere `Titolo1`: con la sola forma inglese i
        titoli di un documento italiano diventerebbero paragrafi."""
        d = _docx('<w:p><w:pPr><w:pStyle w:val="Titolo1"/></w:pPr>' + _r("TRA")
                  + '</w:p>')
        md, _ = docrev.docx_to_markdown(d, "inline")
        self.assertIn("# TRA", md)

    def test_elenco_numerato(self):
        d = _docx('<w:p><w:pPr><w:numPr><w:ilvl w:val="0"/><w:numId w:val="1"/>'
                  '</w:numPr></w:pPr>' + _r("prima voce") + '</w:p>')
        md, _ = docrev.docx_to_markdown(d, "inline")
        self.assertIn("- prima voce", md)

    def test_tabella_in_pipe(self):
        d = _docx('<w:tbl><w:tr><w:tc><w:p>' + _r("Voce") + '</w:p></w:tc>'
                  '<w:tc><w:p>' + _r("Importo") + '</w:p></w:tc></w:tr>'
                  '<w:tr><w:tc><w:p>' + _r("Canone") + '</w:p></w:tc>'
                  '<w:tc><w:p>' + _r("1.000") + '</w:p></w:tc></w:tr></w:tbl>')
        md, _ = docrev.docx_to_markdown(d, "inline")
        self.assertIn("| Voce | Importo |", md)
        self.assertIn("| Canone | 1.000 |", md)

    def test_pipe_nel_testo_non_rompe_la_tabella(self):
        d = _docx('<w:tbl><w:tr><w:tc><w:p>' + _r("a|b") + '</w:p></w:tc></w:tr></w:tbl>')
        md, _ = docrev.docx_to_markdown(d, "inline")
        self.assertIn(r"a\|b", md)


class CasiLimite(unittest.TestCase):
    def test_non_e_un_docx(self):
        with self.assertRaises(Exception):
            docrev.docx_to_markdown(b"non uno zip", "inline")

    def test_has_tracked_changes_non_solleva_su_spazzatura(self):
        self.assertFalse(docrev.has_tracked_changes(b"%PDF-1.4 rumore"))

    def test_zip_senza_document_xml(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("altro.txt", "niente")
        with self.assertRaises(ValueError):
            docrev.docx_to_markdown(buf.getvalue(), "inline")


class IntegrazioneConIVerbi(unittest.TestCase):
    """I due verbi devono usare `docrev`, o la correzione resta in un modulo che
    nessuno chiama — che è il modo più facile di "risolvere" un difetto."""

    def test_convert_document_passa_dalle_revisioni(self):
        from . import docmd
        d = _docx(f'<w:p>{_r("Canone ")}{_del("1.000")}{_ins("1.500")}</w:p>')
        md, pagine, fidelity, revs = docmd.to_markdown("accordo.docx", d)
        self.assertIn("{++1.500++}", md)
        self.assertEqual(revs["inserimenti"], 1)
        self.assertEqual(fidelity, docmd.FIDELITY_STRUCTURED)

    def test_convert_document_senza_revisioni_resta_su_mammoth(self):
        """Dove non c'è niente da preservare, la libreria mappa gli stili meglio
        del nostro parser: non si sostituisce per uniformità."""
        from . import docmd
        d = _docx(f'<w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr>{_r("Titolo")}</w:p>')
        md, _pagine, _fid, revs = docmd.to_markdown("pulito.docx", d)
        self.assertEqual(revs["revisioni"], 0)
        self.assertIn("Titolo", md)

    def test_read_document_non_perde_piu_il_testo_revisionato(self):
        from . import main
        d = _docx(f'<w:p>{_r("Preavviso ")}{_del("30")}{_ins("90")}</w:p>')
        testo, _pagine = main._extract_document_text("accordo.docx", d)
        self.assertIn("90", testo)
        self.assertIn("30", testo, "il testo cancellato non deve sparire")

    def test_lo_schema_del_verbo_dichiara_le_tre_modalita(self):
        from . import main
        t = {x.name: x for x in main._TOPIC_TOOLS}["topic.convert_document"]
        enum = t.inputSchema["properties"]["revisions"]["enum"]
        self.assertEqual(sorted(enum), ["accepted", "inline", "original"])


if __name__ == "__main__":
    unittest.main()

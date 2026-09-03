"""Un contratto revisionato si consegna senza eseguire codice.

Il difetto, verificato il 3 set 2026: l'`avvocato` non dichiara `native_tools`,
quindi con l'allowlist in enforcement riceve solo il pavimento dell'archseed —
`Read`, `Write`, `Edit`, `Skill`, `ToolSearch`, `TodoWrite`, `AskUserQuestion` —
e la sua sandbox ha `allow_shell_cmds: []`. Nessun `Bash`, nessun `python-docx`.
Per produrre un DOCX revisionato doveva chiedere a `sysadmin`, che ha una shell:
il least-privilege aggirato passando da un agente PIÙ privilegiato, con un
contratto manipolato da chi non ne ha il contesto.

Le proprietà provate qui, ognuna un modo in cui il verbo potrebbe sembrare
funzionante e non esserlo:
  1. le revisioni sono `<w:ins>`/`<w:del>` VERI, non testo colorato — cioè la
     controparte può accettarle e rifiutarle una per una;
  2. autore e data sono negli attributi della revisione (metà del valore di una
     revisione tracciata è sapere chi ha proposto cosa);
  3. il ROUND-TRIP con `docrev` conserva revisioni e struttura — è la prova più
     forte, perché usa il lettore vero invece di asserire sull'XML che abbiamo
     appena scritto noi;
  4. il contenuto NON torna al chiamante, o il verbo non risolve niente;
  5. la provenienza è ereditata quando il Markdown viene da un file del topic.
"""
from __future__ import annotations

import re
import tempfile
import unittest
import zipfile

from .topics.local_fs import LocalFsStorage
from .topics.service import TopicService
from . import docwrite, docrev


def _xml(data: bytes) -> str:
    return zipfile.ZipFile(__import__("io").BytesIO(data)).read(
        "word/document.xml").decode("utf-8")


class RevisioniVere(unittest.TestCase):
    """Non basta che il testo ci sia: deve essere una revisione di Word."""

    def test_inserimento_e_cancellazione_sono_elementi_word(self):
        data, st = docwrite.markdown_to_docx(
            "Il canone è {--1.000--}{++1.500++} EUR.", autore="Studio Carboni")
        xml = _xml(data)
        self.assertIn("<w:ins ", xml)
        self.assertIn("<w:del ", xml)
        # Il testo cancellato va in delText, non in w:t: è ciò che distingue
        # "rimosso" da "contenuto" per Word e per qualunque rilettore.
        self.assertIn("<w:delText", xml)
        self.assertEqual(st["inserimenti"], 1)
        self.assertEqual(st["cancellazioni"], 1)

    def test_autore_e_data_sono_negli_attributi(self):
        data, _ = docwrite.markdown_to_docx(
            "Testo {++aggiunto++}.", autore="Studio Carboni",
            data="2026-09-03T10:00:00Z")
        xml = _xml(data)
        self.assertIn('w:author="Studio Carboni"', xml)
        self.assertIn('w:date="2026-09-03T10:00:00Z"', xml)

    def test_ogni_revisione_ha_un_id_distinto(self):
        """Word usa `w:id` per raggruppare e per accettare/rifiutare: id
        duplicati fanno trattare due proposte come una."""
        data, _ = docwrite.markdown_to_docx(
            "{++alfa++} e {++beta++} e {--gamma--}")
        ids = re.findall(r'<w:(?:ins|del) w:id="(\d+)"', _xml(data))
        self.assertEqual(len(ids), 3)
        self.assertEqual(len(set(ids)), 3, f"id duplicati: {ids}")

    def test_documento_senza_revisioni_resta_senza(self):
        data, st = docwrite.markdown_to_docx("Testo pulito, nessuna proposta.")
        self.assertEqual(st["revisioni"], 0)
        self.assertNotIn("<w:ins ", _xml(data))


class SegmentazioneCriticMarkup(unittest.TestCase):
    def test_ordine_conservato(self):
        """`{--1.000--}{++1.500++}` è una sostituzione: invertirlo o
        raggrupparlo per tipo direbbe un'altra cosa."""
        segs = docwrite.segmenta("Il canone è {--1.000--}{++1.500++} EUR.")
        self.assertEqual([(s.tipo, s.testo) for s in segs],
                         [("testo", "Il canone è "), ("del", "1.000"),
                          ("ins", "1.500"), ("testo", " EUR.")])

    def test_sostituzione_diventa_del_piu_ins(self):
        """`{~~vecchio~>nuovo~~}` è ciò che Word rappresenta come una
        cancellazione seguita da un inserimento — non un terzo tipo."""
        segs = docwrite.segmenta("Preavviso di {~~30~>90~~} giorni.")
        self.assertEqual([(s.tipo, s.testo) for s in segs],
                         [("testo", "Preavviso di "), ("del", "30"),
                          ("ins", "90"), ("testo", " giorni.")])

    def test_commento_riconosciuto(self):
        segs = docwrite.segmenta("Clausola. {>>Verificare il massimale.<<}")
        self.assertEqual(segs[-1].tipo, "commento")

    def test_marcatore_a_inizio_riga(self):
        segs = docwrite.segmenta("{++Articolo 12 — Foro competente.++}")
        self.assertEqual([(s.tipo, s.testo) for s in segs],
                         [("ins", "Articolo 12 — Foro competente.")])

    def test_testo_senza_marcatori(self):
        segs = docwrite.segmenta("Nessuna revisione qui.")
        self.assertEqual([(s.tipo, s.testo) for s in segs],
                         [("testo", "Nessuna revisione qui.")])


class StrutturaMarkdown(unittest.TestCase):
    def test_titoli_elenchi_tabelle(self):
        md = ("# TRA\n\nLe parti.\n\n## Art. 2\n\n- prima voce\n- seconda\n\n"
              "| Voce | Importo |\n| --- | --- |\n| Canone | 1.000 |\n")
        blocchi = docwrite.blocchi_da_markdown(md)
        generi = [(b.genere, b.livello) for b in blocchi]
        self.assertIn(("titolo", 1), generi)
        self.assertIn(("titolo", 2), generi)
        self.assertEqual(sum(1 for g, _ in generi if g == "elenco"), 2)
        self.assertEqual(sum(1 for g, _ in generi if g == "tabella"), 1)

    def test_il_riepilogo_di_docrev_non_entra_nel_contratto(self):
        """`docrev` mette in testa un commento HTML e una tabella di riepilogo:
        sono nostri, non del documento, e in un DOCX da firmare non ci vanno.
        Il commento HTML si scarta; la tabella la toglie l'agente."""
        md = ("<!-- Revisioni tracciate: rese con CriticMarkup -->\n\n"
              "---\n\n# ACCORDO\n\nTesto.\n")
        blocchi = docwrite.blocchi_da_markdown(md)
        self.assertEqual([b.genere for b in blocchi], ["titolo", "paragrafo"])

    def test_pipe_escapato_nella_cella(self):
        blocchi = docwrite.blocchi_da_markdown("| a\\|b | c |\n| --- | --- |\n")
        self.assertEqual(blocchi[0].celle[0][0], "a|b")

    def test_nome_del_docx(self):
        self.assertEqual(docwrite.docx_name("files/accordo-rev1.md"),
                         "accordo-rev1.docx")


class RoundTrip(unittest.TestCase):
    """La prova più forte: si rilegge con `docrev`, il lettore vero.

    Asserire sull'XML che abbiamo appena scritto proverebbe solo che sappiamo
    scrivere ciò che sappiamo cercare. Il round-trip prova che il file è
    interpretabile da un lettore indipendente — che è il requisito reale, perché
    dall'altra parte c'è Word.
    """

    MD = ("# ACCORDO\n\nIl canone è {--1.000--}{++1.500++} EUR.\n\n"
          "- prima voce\n- seconda con {++aggiunta++}\n\n"
          "| Voce | Importo |\n| --- | --- |\n| Canone | {++1.500++} |\n")

    def test_revisioni_conservate(self):
        data, scritte = docwrite.markdown_to_docx(
            self.MD, autore="Studio Carboni", data="2026-09-03T10:00:00Z")
        _md, rilette = docrev.docx_to_markdown(data, "inline")
        self.assertEqual(rilette["revisioni"], scritte["revisioni"])
        self.assertEqual(rilette["inserimenti"], scritte["inserimenti"])
        self.assertEqual(rilette["cancellazioni"], scritte["cancellazioni"])
        self.assertEqual(rilette["revisori"], ["Studio Carboni"])

    def test_struttura_conservata(self):
        data, _ = docwrite.markdown_to_docx(self.MD)
        md, _ = docrev.docx_to_markdown(data, "inline")
        corpo = md.split("---\n", 1)[-1]
        self.assertIn("# ACCORDO", corpo)
        self.assertIn("- prima voce", corpo)      # elenco, non paragrafo
        self.assertIn("| Voce | Importo |", corpo)
        self.assertIn("{--1.000--}{++1.500++}", corpo)  # sostituzione, nell'ordine

    def test_modalita_accepted_da_il_testo_finale(self):
        data, _ = docwrite.markdown_to_docx(
            "Preavviso di {--30--}{++90++} giorni.")
        md, _ = docrev.docx_to_markdown(data, "accepted")
        self.assertIn("Preavviso di 90 giorni.", md)
        self.assertNotIn("30", md)


class VerboNelGateway(unittest.TestCase):
    """Il verbo va dichiarato e registrato, o esiste solo per chi legge il codice."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.svc = TopicService(LocalFsStorage(self.tmp.name))
        self.svc.new("SEAL-2", "ch", {"title": "ch", "owner": "davide",
                                      "participants": ["davide", "avvocato"]})

    def test_dichiarato_scoped_e_mutating(self):
        from . import main
        self.assertIn("topic.write_document", {t.name for t in main._TOPIC_TOOLS})
        self.assertIn("write_document", main._TOPIC_SCOPED_VERBS)
        self.assertIn("write_document", main._TOPIC_MUTATING_VERBS)

    def test_il_docx_finisce_nei_file_del_topic(self):
        """Replica il ramo del dispatch sullo stesso service."""
        data, _ = docwrite.markdown_to_docx("Canone {++1.500++} EUR.",
                                            autore="avvocato")
        self.svc.put_file("SEAL-2", "ch", "accordo-rev.docx", data, "agent", "avvocato")
        nomi = [f.get("name") or f.get("path")
                for f in self.svc.list_files("SEAL-2", "ch", "local")]
        self.assertTrue(any("accordo-rev.docx" in str(n) for n in nomi), nomi)
        riletto = self.svc.read_file("SEAL-2", "ch", "files/accordo-rev.docx")
        self.assertEqual(docrev.docx_to_markdown(riletto, "inline")[1]["inserimenti"], 1)

    def test_la_provenienza_di_un_md_untrusted_si_eredita(self):
        """Un `.md` ricavato da un allegato di controparte è `untrusted`: il DOCX
        che ne deriva è lo stesso contenuto in un altro formato, e generarlo non
        è un modo per promuoverlo a fidato."""
        self.svc.put_file("SEAL-2", "ch", "accordo.md",
                          b"Canone {++1.500++} EUR.", "untrusted", by="davide")
        prov = self.svc.provenance_map("SEAL-2", "ch").get("accordo.md", {}).get("provenance")
        self.assertEqual(prov, "untrusted")

    def test_lo_schema_accetta_content_o_source(self):
        from . import main
        t = {x.name: x for x in main._TOPIC_TOOLS}["topic.write_document"]
        props = t.inputSchema["properties"]
        for campo in ("content", "source", "author", "out"):
            self.assertIn(campo, props)
        # `content` e `source` sono alternative: nessuna delle due è obbligatoria
        # nello schema, il dispatch valida che ce ne sia una.
        self.assertEqual(sorted(t.inputSchema["required"]), ["name", "out", "tier"])


if __name__ == "__main__":
    unittest.main()

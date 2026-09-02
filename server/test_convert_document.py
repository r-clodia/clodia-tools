"""Conversione documento → Markdown scritta nel topic, senza passare dal modello.

Il difetto che chiude, misurato il 2 set 2026 sul canale SEAL-2/titul-brightnode:
per ottenere un `.md` da un accordo di 54.879 caratteri l'agente doveva leggerlo
con `topic.read_document` (~14k token in ingresso) e poi **riemetterlo tutto in
output** dentro `topic.write_file` (~14k token di generazione, minuti). Girando a
pezzi, ogni pezzo ripagava l'intero contesto del canale: 1.432.030 token di
prompt in un solo turno, e il lavoro perso quando lo spawn moriva a metà.

Le proprietà provate qui sono quattro, e ognuna corrisponde a un modo in cui
questo verbo potrebbe sembrare funzionante e non esserlo:
  1. il `.md` finisce DAVVERO nei file del topic (non solo nel valore di ritorno);
  2. il contenuto NON torna al chiamante — altrimenti il risparmio di token non
     esiste e siamo tornati a `read_document`;
  3. la struttura del DOCX sopravvive (titoli e tabelle), che è la ragione per
     cui non basta il testo piatto già disponibile;
  4. la provenienza è EREDITATA dal sorgente: convertire non lava il taint di un
     documento di terzi.
"""
from __future__ import annotations

import io
import tempfile
import unittest
import zipfile

from .topics.local_fs import LocalFsStorage
from .topics.service import TopicService
from . import docmd


def _docx(paragrafi: list[tuple[str, str]], tabella: list[list[str]] | None = None) -> bytes:
    """Un DOCX minimo ma VERO (stili Word inclusi), costruito a mano.

    Si genera invece di allegare un binario di prova: un fixture opaco nel repo
    non dice cosa sta provando, e quando il test diventa rosso non si sa se è
    cambiato il codice o il file. `paragrafi` = (stile, testo), dove lo stile è
    quello che mammoth mappa su un heading.
    """
    def esc(t: str) -> str:
        return t.replace("&", "&amp;").replace("<", "&lt;")

    corpo = []
    for stile, testo in paragrafi:
        pstyle = f'<w:pPr><w:pStyle w:val="{stile}"/></w:pPr>' if stile else ""
        corpo.append(f'<w:p>{pstyle}<w:r><w:t>{esc(testo)}</w:t></w:r></w:p>')
    if tabella:
        righe = []
        for r in tabella:
            celle = "".join(
                f'<w:tc><w:p><w:r><w:t>{esc(c)}</w:t></w:r></w:p></w:tc>' for c in r)
            righe.append(f"<w:tr>{celle}</w:tr>")
        corpo.append("<w:tbl>" + "".join(righe) + "</w:tbl>")

    document = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f'<w:body>{"".join(corpo)}</w:body></w:document>'
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-'
        'officedocument.wordprocessingml.document.main+xml"/></Types>'
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/'
        'relationships/officeDocument" Target="word/document.xml"/></Relationships>'
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types)
        z.writestr("_rels/.rels", rels)
        z.writestr("word/document.xml", document)
    return buf.getvalue()


class ConvertDocumentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.svc = TopicService(LocalFsStorage(self.tmp.name))
        self.svc.new("SEAL-2", "ch", {"title": "ch", "owner": "davide",
                                      "participants": ["davide", "avvocato"]})

    # --- il convertitore, da solo ------------------------------------------
    def test_docx_conserva_titoli_e_tabelle(self):
        data = _docx(
            [("Heading1", "Accordo CPTO"), ("", "Le parti convengono."),
             ("Heading2", "Art. 2 — Corrispettivo")],
            tabella=[["Voce", "Importo"], ["Canone", "1.000 EUR"]],
        )
        md, pagine, fidelity = docmd.to_markdown("accordo.docx", data)
        self.assertEqual(fidelity, docmd.FIDELITY_STRUCTURED)
        self.assertIsNone(pagine)
        self.assertIn("# Accordo CPTO", md)
        self.assertIn("Art. 2", md)
        # La tabella deve essere una tabella Markdown, non celle appiccicate:
        # è metà del motivo per cui il testo piatto non bastava.
        self.assertIn("|", md)
        self.assertIn("Canone", md)

    def test_estensione_non_supportata_e_un_errore_non_un_md_di_spazzatura(self):
        with self.assertRaises(ValueError):
            docmd.to_markdown("scan.tiff", b"\x00\x01binario")

    def test_nome_di_destinazione_tiene_il_nome_del_documento(self):
        self.assertEqual(docmd.markdown_name("files/Accordo_def-dc1.docx"),
                         "Accordo_def-dc1.md")
        self.assertEqual(docmd.markdown_name("senza-estensione"), "senza-estensione.md")

    # --- il verbo, come lo vede un agente ----------------------------------
    def _converti(self, src="accordo.docx", out=None, prov="untrusted"):
        """Replica il ramo `convert_document` del dispatch, sullo stesso service."""
        self.svc.put_file("SEAL-2", "ch", src,
                          _docx([("Heading1", "Accordo CPTO"), ("", "Testo lungo.")]),
                          prov, by="davide")
        data = self.svc.read_file("SEAL-2", "ch", f"files/{src}")
        md, pagine, fidelity = docmd.to_markdown(src, data)
        nome = out or docmd.markdown_name(src)
        prov_src = ((self.svc.provenance_map("SEAL-2", "ch") or {})
                    .get(src, {}).get("provenance") or "untrusted")
        self.svc.put_file("SEAL-2", "ch", nome, md.encode("utf-8"), prov_src, "avvocato")
        return {"path": f"files/{nome}", "chars": len(md), "pages": pagine,
                "fidelity": fidelity, "provenance": prov_src}

    def test_il_md_esiste_nei_file_del_topic(self):
        res = self._converti()
        self.assertEqual(res["path"], "files/accordo.md")
        scritto = self.svc.read_file("SEAL-2", "ch", "files/accordo.md").decode()
        self.assertIn("# Accordo CPTO", scritto)
        # `list_files` senza subpath mostra i rami dello storage (`local`, e
        # `remote/<n>` se configurato): il file sta un livello sotto.
        nomi = [f.get("name") or f.get("path")
                for f in self.svc.list_files("SEAL-2", "ch", "local")]
        self.assertTrue(any("accordo.md" in str(n) for n in nomi), nomi)

    def test_il_contenuto_non_torna_al_chiamante(self):
        """Se il Markdown tornasse nel valore di ritorno, il verbo non servirebbe:
        il costo che si vuole togliere è proprio il contenuto nel contesto."""
        res = self._converti()
        self.assertNotIn("text", res)
        self.assertNotIn("content", res)
        self.assertGreater(res["chars"], 0)   # la misura sì, il contenuto no

    def test_la_provenienza_e_ereditata_non_lavata(self):
        """Un documento di terzi resta di terzi anche dopo la conversione: se
        diventasse `agent`, convertire sarebbe il modo per promuovere a fidato
        un PDF di controparte."""
        res = self._converti(prov="untrusted")
        self.assertEqual(res["provenance"], "untrusted")
        prov = self.svc.provenance_map("SEAL-2", "ch")
        self.assertEqual(prov.get("accordo.md", {}).get("provenance"), "untrusted")

    def test_un_sorgente_fidato_resta_fidato(self):
        res = self._converti(prov="trusted")
        self.assertEqual(res["provenance"], "trusted")


class VerbIsRegisteredTests(unittest.TestCase):
    """Il verbo va dichiarato in tre posti, e dimenticarne uno è muto.

    Senza `_TOPIC_SCOPED_VERBS` scriverebbe in topic di cui l'agente non è
    partecipante (il compartimento salta); senza `_TOPIC_MUTATING_VERBS` un
    `reader` potrebbe scrivere. Nessuno dei due errori dà un messaggio: danno
    `200` e un file dove non doveva esserci.
    """

    def test_scoped_e_mutating(self):
        from . import main
        self.assertIn("convert_document", main._TOPIC_SCOPED_VERBS)
        self.assertIn("convert_document", main._TOPIC_MUTATING_VERBS)

    def test_dichiarato_come_tool(self):
        from . import main
        nomi = {t.name for t in main._TOPIC_TOOLS}
        self.assertIn("topic.convert_document", nomi)


if __name__ == "__main__":
    unittest.main()

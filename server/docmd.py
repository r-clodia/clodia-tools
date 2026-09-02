"""Da documento a Markdown, server-side.

Perché esiste, e perché non basta `_extract_document_text`: quella funzione
serve a FAR LEGGERE un documento a un modello, e per quello il testo piatto va
benissimo. Qui l'obiettivo è diverso — PRODURRE un file `.md` nel topic — e in
quel caso il testo piatto costa caro due volte: perde la struttura (titoli,
articoli, tabelle) e, soprattutto, obbliga il modello a **riemettere in output**
tutto il contenuto per poterlo salvare. Un accordo di 55.000 caratteri sono
~14k token di trascrizione a mano, cioè minuti di generazione per un lavoro che
qui dura un istante — la lentezza segnalata da Davide il 2 set 2026.

Scelta delle dipendenze: `mammoth` (BSD-2) + `markdownify` (MIT), entrambe
**permissive**. Le alternative migliori sul PDF (PyMuPDF/`pymupdf4llm`) sono
AGPL o commerciali Artifex: compatibili con il lato AGPL di questo gateway, non
con l'edizione commerciale del dual-licensing di `LICENSING.md`. Una dipendenza
che vincola una delle due licenze non si aggiunge per comodità.

Conseguenza onesta di quella scelta: **DOCX e XLSX danno Markdown strutturato,
il PDF no.** Da un PDF si ricava testo per riga senza stili, quindi si emette
Markdown minimo (paragrafi separati, marcatore di pagina) e lo si dichiara nel
valore di ritorno con `fidelity`, invece di far credere a chi chiama che la
struttura ci sia. Quando il documento esiste anche in DOCX, convertire quello
è sempre meglio che convertire il PDF che ne è stato stampato.
"""
from __future__ import annotations

import io
import re

#: Come è stato prodotto il Markdown, per chi chiama.
#: `structured` = titoli/liste/tabelle dal formato sorgente;
#: `plain` = righe di testo, nessuno stile recuperabile.
FIDELITY_STRUCTURED = "structured"
FIDELITY_PLAIN = "plain"


def _md_from_docx(data: bytes) -> str:
    """DOCX → Markdown passando per l'HTML semantico di mammoth.

    `mammoth` mappa gli STILI di Word (Heading 1, elenchi, grassetto, tabelle)
    su HTML, e `markdownify` porta quell'HTML in Markdown. È la via che conserva
    ciò che l'autore ha davvero marcato, invece di indovinare i titoli dalla
    lunghezza delle righe.
    """
    import mammoth
    from markdownify import markdownify

    html = mammoth.convert_to_html(io.BytesIO(data)).value
    md = markdownify(html, heading_style="ATX", bullets="-")
    # markdownify lascia code di righe vuote fra i blocchi: tre o più newline
    # non hanno significato in Markdown e rendono il file scomodo da leggere.
    return re.sub(r"\n{3,}", "\n\n", md).strip() + "\n"


def _md_from_xlsx(data: bytes) -> str:
    """XLSX → Markdown: un titolo per foglio, una tabella pipe per foglio.

    La prima riga è trattata come intestazione perché è la convenzione di fatto
    dei fogli che si convertono; se non lo è, si legge come una riga di dati in
    grassetto e nessun dato va perso.
    """
    from openpyxl import load_workbook

    wb = load_workbook(io.BytesIO(data), read_only=True, data_only=True)
    out: list[str] = []
    for ws in wb.worksheets:
        out.append(f"## {ws.title}\n")
        righe = [
            ["" if v is None else str(v).replace("|", r"\|").replace("\n", " ")
             for v in row]
            for row in ws.iter_rows(values_only=True)
        ]
        righe = [r for r in righe if any(c.strip() for c in r)]
        if not righe:
            out.append("_(foglio vuoto)_\n")
            continue
        larghezza = max(len(r) for r in righe)
        righe = [r + [""] * (larghezza - len(r)) for r in righe]
        out.append("| " + " | ".join(righe[0]) + " |")
        out.append("|" + "|".join([" --- "] * larghezza) + "|")
        for r in righe[1:]:
            out.append("| " + " | ".join(r) + " |")
        out.append("")
    return "\n".join(out).strip() + "\n"


def _md_from_pdf(data: bytes) -> tuple[str, int]:
    """PDF → Markdown minimo. Ritorna (markdown, n_pagine).

    Senza una libreria che ricostruisca il layout non si distinguono titoli e
    tabelle: si normalizzano i ritorni a capo dentro il paragrafo (i PDF spezzano
    le righe alla larghezza della colonna, non alla fine della frase) e si separa
    ogni pagina con un commento, che è informazione vera e non finge struttura.
    """
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(data))
    blocchi: list[str] = []
    for i, pagina in enumerate(reader.pages, start=1):
        testo = pagina.extract_text() or ""
        # Riunisce le righe di un paragrafo: una riga che non chiude una frase e
        # continua in minuscolo è un a-capo tipografico, non un paragrafo nuovo.
        testo = re.sub(r"(?<![.:;!?])\n(?=[a-zà-ù(])", " ", testo)
        testo = re.sub(r"[ \t]+", " ", testo)
        testo = re.sub(r"\n{2,}", "\n\n", testo).strip()
        blocchi.append(f"<!-- pagina {i} -->\n\n{testo}" if testo
                       else f"<!-- pagina {i}: nessun testo estraibile -->")
    return "\n\n".join(blocchi).strip() + "\n", len(reader.pages)


def to_markdown(filename: str, data: bytes) -> tuple[str, int | None, str]:
    """Converte un documento in Markdown. Ritorna (markdown, pagine|None, fidelity).

    Solleva `ValueError` sulle estensioni che non si sanno convertire, invece di
    ripiegare in silenzio sul testo grezzo: un `.md` che sembra una conversione
    ed è spazzatura decodificata è peggio di un errore, perché nessuno lo
    ricontrolla.
    """
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext == "docx":
        return _md_from_docx(data), None, FIDELITY_STRUCTURED
    if ext in ("xlsx", "xlsm"):
        return _md_from_xlsx(data), None, FIDELITY_STRUCTURED
    if ext == "pdf":
        md, pagine = _md_from_pdf(data)
        return md, pagine, FIDELITY_PLAIN
    if ext in ("md", "markdown", "txt"):
        # Già testo: si normalizza e si passa, così chi chiama non deve sapere
        # in anticipo se il file andava convertito o no.
        return data.decode("utf-8", errors="replace").strip() + "\n", None, FIDELITY_PLAIN
    raise ValueError(
        f"non so convertire '.{ext}' in Markdown (supportati: docx, xlsx, pdf, txt, md)")


def markdown_name(path: str) -> str:
    """Nome del `.md` di destinazione a partire dal path del sorgente.

    Tiene il nome del documento e cambia solo l'estensione: chi guarda i file del
    topic vede la coppia accanto, senza dover ricostruire quale `.md` viene da
    quale allegato.
    """
    base = (path or "").rsplit("/", 1)[-1]
    radice = base.rsplit(".", 1)[0] if "." in base else base
    return f"{radice or 'documento'}.md"

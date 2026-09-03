"""DOCX con le REVISIONI TRACCIATE visibili, per chi revisiona contratti.

Perché non basta nessuna delle due librerie che abbiamo, misurato il 3 set 2026
su un accordo reale. I caratteri per percorso XML, che è il modo di contarli che
non gonfia (una regex su `<w:t>` include il markup dei tag annidati):

    body/p/r/t                34.343    testo non revisionato
    body/p/ins/r/t            12.222    inserito con revisione
    body/p/del/r/delText       7.055    cancellato con revisione
    body/tbl/tr/tc/p/r/t         911    tabelle
    TOTALE                    54.531

    python-docx  (topic.read_document)    35.496   -> 54.531 - 12.222 - 7.055
    mammoth      (topic.convert_document) 47.534   -> 54.531 - 7.055
    questo modulo, mode="inline"          completo

Le due sottrazioni tornano al carattere, e dicono esattamente cosa si perde.

`python-docx` legge `paragraph.text`, che concatena solo i run figli DIRETTI del
paragrafo: un run dentro `<w:ins>` o `<w:del>` è figlio di quell'elemento, non
del paragrafo, e viene saltato. Su quel file sono 19.277 caratteri — 33 paragrafi
su 147 risultavano VUOTI — e sono la parte che un avvocato deve leggere: il testo
che la controparte ha proposto e quello che ha tolto.

`mammoth` fa una cosa peggiore in un senso preciso: include gli inserimenti e
scarta le cancellazioni, cioè restituisce il documento COME SE tutte le
revisioni fossero accettate, senza dirlo. Il testo sembra completo e coerente, e
non si distingue più ciò che è concordato da ciò che una parte ha proposto.

Qui si legge `word/document.xml` direttamente, dove `<w:ins>` e `<w:del>`
portano già `w:author` e `w:date`, e si emette **CriticMarkup** — la convenzione
de facto per le revisioni in Markdown, che ha il vantaggio di essere leggibile
anche da chi non la conosce:

    {++testo inserito++}      {--testo cancellato--}      {>>commento<<}

Modalità (`mode`): `inline` mostra entrambi ed è il default per chi revisiona;
`accepted` dà il testo come se le revisioni fossero accettate; `original` il
testo prima delle revisioni. Le tre servono domande diverse — «cosa mi hanno
chiesto di cambiare», «come resterebbe se accetto», «cosa avevo firmato» — e
nessuna delle tre è indovinabile dalle altre due.
"""
from __future__ import annotations

import re
import zipfile
from xml.etree import ElementTree as ET

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"

MODE_INLINE = "inline"
MODE_ACCEPTED = "accepted"
MODE_ORIGINAL = "original"
MODES = (MODE_INLINE, MODE_ACCEPTED, MODE_ORIGINAL)

#: Stili di titolo: Word tiene lo styleId inglese anche nelle versioni
#: localizzate, ma non sempre — un documento creato con Word italiano può
#: portare `Titolo1`. Si accettano entrambi invece di scoprire sul file del
#: cliente che i titoli sono diventati paragrafi.
_HEADING = re.compile(r"^(?:heading|titolo|kop|encabezado)\s*([1-6])$", re.I)


def _q(tag: str) -> str:
    return W + tag


def _autore(el) -> str:
    return (el.get(_q("author")) or "").strip()


def _data(el) -> str:
    return (el.get(_q("date")) or "")[:10]


class _Raccolta:
    """Accumula il Markdown di un paragrafo, più le revisioni che ha incontrato."""

    def __init__(self, mode: str):
        self.mode = mode
        self.pezzi: list[str] = []
        self.revisioni: list[dict] = []

    def normale(self, s: str):
        if s:
            self.pezzi.append(s)

    def revisione(self, s: str, tipo: str, autore: str, data: str):
        """UN marcatore per blocco `<w:ins>`/`<w:del>`, non uno per run.

        Word spezza una frase inserita in più run per ragioni tipografiche
        (grassetto, lingua, correttore): marcarli singolarmente produrrebbe
        `{++Il ++}{++corrispettivo++}` — illeggibile — e conterebbe una
        revisione per frammento, gonfiando il riepilogo senza aggiungere
        informazione.
        """
        if not s:
            return
        if tipo == "ins" and self.mode == MODE_ORIGINAL:
            return
        if tipo == "del" and self.mode == MODE_ACCEPTED:
            return
        self.revisioni.append({
            "tipo": "inserimento" if tipo == "ins" else "cancellazione",
            "autore": autore, "data": data, "caratteri": len(s),
        })
        if self.mode != MODE_INLINE:
            self.pezzi.append(s)
        else:
            self.pezzi.append(("{++" + s + "++}") if tipo == "ins"
                              else ("{--" + s + "--}"))

    def commento(self, testo: str, autore: str, data: str):
        if self.mode != MODE_INLINE or not testo:
            return
        firma = " — ".join(x for x in (autore, data) if x)
        self.pezzi.append("{>>" + testo + (f" [{firma}]" if firma else "") + "<<}")

    def risultato(self) -> str:
        return "".join(self.pezzi)


def _run_testo(run) -> str:
    """Il testo di un `<w:r>`: `w:t`, `w:delText`, tab e interruzioni."""
    out: list[str] = []
    for el in run.iter():
        tag = el.tag
        if tag in (_q("t"), _q("delText")):
            out.append(el.text or "")
        elif tag == _q("tab"):
            out.append("\t")
        elif tag == _q("br"):
            out.append("\n")
    return "".join(out)


def _testo_sottoalbero(nodo) -> str:
    """TUTTO il testo sotto un nodo, a qualunque profondità.

    Si scende senza guardare i tag intermedi perché le revisioni si annidano
    dentro `w:hyperlink`, `w:smartTag`, `w:sdt`: un'estrazione che cerchi solo
    `w:p/w:r` perde ciò che sta un livello più sotto — il difetto da cui nasce
    questo modulo.
    """
    out: list[str] = []
    for el in nodo.iter():
        if el.tag in (_q("t"), _q("delText")):
            out.append(el.text or "")
        elif el.tag == _q("tab"):
            out.append("\t")
        elif el.tag == _q("br"):
            out.append("\n")
    return "".join(out)


def _cammina(nodo, racc: _Raccolta, commenti: dict) -> None:
    """Scorre i figli di un paragrafo NELL'ORDINE DEL DOCUMENTO.

    L'ordine conta: una cancellazione seguita da un inserimento è una
    sostituzione, e leggerla come `{--1.000--}{++1.500++}` dice quale numero
    sostituisce quale. Riordinando o raggruppando per tipo, quell'informazione
    si perde.
    """
    for figlio in nodo:
        tag = figlio.tag
        if tag == _q("pPr"):
            continue
        if tag == _q("r"):
            racc.normale(_run_testo(figlio))
        elif tag in (_q("ins"), _q("del")):
            tipo = "ins" if tag == _q("ins") else "del"
            racc.revisione(_testo_sottoalbero(figlio), tipo,
                           _autore(figlio), _data(figlio))
        elif tag == _q("commentReference"):
            c = commenti.get(figlio.get(_q("id")))
            if c:
                racc.commento(c["testo"], c["autore"], c["data"])
        elif len(figlio):
            # Contenitore (hyperlink, smartTag, sdt, …): si scende. Perdere
            # testo in silenzio è precisamente ciò che questo modulo evita.
            _cammina(figlio, racc, commenti)


def _leggi_commenti(z: zipfile.ZipFile) -> dict:
    """`word/comments.xml` → {id: {testo, autore, data}}. Assente = niente."""
    if "word/comments.xml" not in z.namelist():
        return {}
    try:
        root = ET.fromstring(z.read("word/comments.xml"))
    except ET.ParseError:
        return {}
    out = {}
    for c in root.findall(_q("comment")):
        testi = [t.text or "" for t in c.iter(_q("t"))]
        out[c.get(_q("id"))] = {
            "testo": " ".join("".join(testi).split()),
            "autore": _autore(c),
            "data": _data(c),
        }
    return out


def _paragrafo_md(p, racc_mode: str, commenti: dict) -> tuple[str, list[dict]]:
    racc = _Raccolta(racc_mode)
    _cammina(p, racc, commenti)
    testo = racc.risultato().strip()
    if not testo:
        return "", racc.revisioni
    ppr = p.find(_q("pPr"))
    stile = ""
    elenco = False
    if ppr is not None:
        st = ppr.find(_q("pStyle"))
        stile = (st.get(_q("val")) if st is not None else "") or ""
        elenco = ppr.find(_q("numPr")) is not None
    m = _HEADING.match(stile)
    if m:
        return "#" * int(m.group(1)) + " " + testo, racc.revisioni
    if elenco:
        return "- " + testo, racc.revisioni
    return testo, racc.revisioni


def _tabella_md(tbl, mode: str, commenti: dict) -> tuple[str, list[dict]]:
    righe: list[list[str]] = []
    revisioni: list[dict] = []
    for tr in tbl.findall(_q("tr")):
        cella_testi = []
        for tc in tr.findall(_q("tc")):
            pezzi = []
            for p in tc.findall(_q("p")):
                t, revs = _paragrafo_md(p, mode, commenti)
                revisioni.extend(revs)
                if t:
                    pezzi.append(t.lstrip("# ").lstrip("- "))
            cella_testi.append(" ".join(pezzi).replace("|", r"\|").replace("\n", " "))
        if any(c.strip() for c in cella_testi):
            righe.append(cella_testi)
    if not righe:
        return "", revisioni
    larghezza = max(len(r) for r in righe)
    righe = [r + [""] * (larghezza - len(r)) for r in righe]
    out = ["| " + " | ".join(righe[0]) + " |",
           "|" + "|".join([" --- "] * larghezza) + "|"]
    for r in righe[1:]:
        out.append("| " + " | ".join(r) + " |")
    return "\n".join(out), revisioni


def _riepilogo(revisioni: list[dict]) -> str:
    """Chi ha proposto cosa e quando, in testa al documento.

    È l'informazione che un revisore cerca per prima e che nessuno dei due
    estrattori precedenti poteva dare: i marcatori dicono DOVE, questo dice
    QUANTO e DI CHI. Senza, per sapere se una modifica è della controparte
    bisogna aprire Word.
    """
    if not revisioni:
        return ""
    per: dict[tuple, dict] = {}
    for r in revisioni:
        k = (r.get("autore") or "(ignoto)", r.get("data") or "")
        v = per.setdefault(k, {"inserimenti": 0, "cancellazioni": 0, "car": 0})
        v["inserimenti" if r["tipo"] == "inserimento" else "cancellazioni"] += 1
        v["car"] += int(r.get("caratteri") or 0)
    ins = sum(1 for r in revisioni if r["tipo"] == "inserimento")
    dele = len(revisioni) - ins
    out = ["<!-- Revisioni tracciate: rese con CriticMarkup — {++inserito++}, "
           "{--cancellato--}, {>>commento<<} -->",
           "", "## Revisioni tracciate", "",
           f"**{ins} inserimenti** e **{dele} cancellazioni** in questo documento.", "",
           "| revisore | data | inserimenti | cancellazioni | caratteri |",
           "| --- | --- | --- | --- | --- |"]
    for (autore, data), v in sorted(per.items()):
        out.append(f"| {autore} | {data or '—'} | {v['inserimenti']} | "
                   f"{v['cancellazioni']} | {v['car']:,} |")
    out.append("")
    out.append("---")
    out.append("")
    return "\n".join(out)


def docx_to_markdown(data: bytes, mode: str = MODE_INLINE) -> tuple[str, dict]:
    """DOCX → Markdown con le revisioni. Ritorna (markdown, statistiche).

    `statistiche` = {revisioni, inserimenti, cancellazioni, commenti, revisori,
    caratteri} — quello che serve a chi chiama per sapere se un documento è
    revisionato SENZA rileggerne il testo.
    """
    mode = (mode or MODE_INLINE).strip().lower()
    if mode not in MODES:
        raise ValueError(f"mode '{mode}' non valido (ammessi: {', '.join(MODES)})")
    z = zipfile.ZipFile(__import__("io").BytesIO(data))
    if "word/document.xml" not in z.namelist():
        raise ValueError("non è un DOCX: manca word/document.xml")
    commenti = _leggi_commenti(z)
    root = ET.fromstring(z.read("word/document.xml"))
    body = root.find(_q("body"))
    if body is None:
        raise ValueError("DOCX senza corpo")

    blocchi: list[str] = []
    revisioni: list[dict] = []
    for el in body:
        if el.tag == _q("p"):
            t, revs = _paragrafo_md(el, mode, commenti)
            revisioni.extend(revs)
            if t:
                blocchi.append(t)
        elif el.tag == _q("tbl"):
            t, revs = _tabella_md(el, mode, commenti)
            revisioni.extend(revs)
            if t:
                blocchi.append(t)

    corpo = "\n\n".join(blocchi).strip() + "\n"
    md = (_riepilogo(revisioni) if mode == MODE_INLINE else "") + corpo
    stats = {
        "revisioni": len(revisioni),
        "inserimenti": sum(1 for r in revisioni if r["tipo"] == "inserimento"),
        "cancellazioni": sum(1 for r in revisioni if r["tipo"] == "cancellazione"),
        "commenti": len(commenti),
        "revisori": sorted({r.get("autore") or "(ignoto)" for r in revisioni}),
        "caratteri": len(md),
        "mode": mode,
    }
    return md, stats


def has_tracked_changes(data: bytes) -> bool:
    """C'è almeno una revisione tracciata? Domanda a buon mercato: serve per
    avvertire chi sta leggendo un documento con l'estrattore che le appiattisce."""
    try:
        z = zipfile.ZipFile(__import__("io").BytesIO(data))
        xml = z.read("word/document.xml").decode("utf-8", "ignore")
    except Exception:  # noqa: BLE001
        return False
    return ("<w:ins " in xml or "<w:ins>" in xml
            or "<w:del " in xml or "<w:del>" in xml)

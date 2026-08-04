"""Contaminazione per canale (clodia-platform#104 §4, passo 7).

Perché un flag e non un'etichetta per messaggio. Il modello di #77 ha una
condizione che regge tutto il resto: **il gate di contesto scatta solo se il
canale è anche contaminato.** Senza quella condizione scatterebbe quasi sempre —
150 canali su 156 sono a 3/3 di capacità — e un gate approvato per riflesso è
peggio di nessun gate, perché produce l'illusione del controllo. Il flag è
l'approssimazione a granularità di canale del taint per messaggio: un campo e un
punto di `set`, che toglie un ordine di grandezza di falsi allarmi.

Definizione operativa, presa alla lettera da #77: *«è entrato contenuto da fonte
non fidata DOPO l'ultimo unlock»*. Da cui due conseguenze che non sono dettagli:

- l'unlock **azzera** il flag, quindi «chiudere la finestra o chiedere
  riconferma?» non è una domanda da decidere: se durante la finestra entra
  contenuto nuovo il flag si ri-arma e la prossima azione di uscita ri-gata, senza
  interrompere il turno in corso;
- la contaminazione **non si eredita fra canali**. Le sessioni sono già
  per-canale, quindi il taint non trasborda da sé. Resta aperto in #104 §4 il
  solo caso in cui un agente *riporta* il contenuto da un canale a un altro.

Cosa è untrusted, dalla §2: le sorgenti che entrano **senza un umano nel loop** —
pagine lette da un agente, posta in arrivo, messaggi di terzi, issue e commenti
GitHub, output di MCP esterni, allegati scaricati da un agente. **L'utente
autenticato dall'UI è trusted**: se il prompt dell'owner è sospetto non resta
niente da difendere.

Lo stato vive sul volume del SOLO gateway, come i consensi: è stato decisionale,
e un agente che potesse riscriverlo si declassificherebbe da sé
(clodia-platform#80).
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Optional

from . import state_paths

LOG = logging.getLogger("clodia-tools.taint")

_STATE = "clodia-tools-taint.json"

#: Quante sorgenti tenere per canale. Serve al dialog, che deve poter dire DA
#: DOVE viene la contaminazione: un booleano non contiene quell'informazione, e
#: senza di essa l'umano declassifica alla cieca (#104 §4).
_MAX_SOURCES = 5

#: Verbi che PRODUCONO contaminazione: restituiscono contenuto di terzi. È la
#: rilettura della colonna `untrusted_input` del catalogo richiesta dalla §4 —
#: da «questo agente è esposto» a «questo verbo produce taint».
#:
#: Tabella locale al gateway di proposito, come `_SPECS` in egress.py: il
#: catalogo trifecta vive in clodia-logic e il gateway non lo monta. Il prezzo è
#: tenerle allineate; il beneficio è che il punto in cui il taint NASCE non
#: dipende da un file che sta dall'altra parte del confine.
_TAINTING_EXACT = frozenset({
    # posta e chat in arrivo: il mittente non è controllato
    "email.read", "email.list", "email.search", "email.get_attachment",
    "telegram.inbox", "telegram.receive", "telegram.pull",
    # file e documenti caricati in un topic da chiunque
    "topic.read_file", "topic.read_document", "topic.fetch", "topic.remote_pull",
    # documenti esterni
    "gdrive.download", "gdocs.read", "gsheets.read", "gsheets.list_tabs",
    "gcalendar.list_events",
    # corpora e board di terzi
    "trello.cards", "trello.comments", "trello.show_card",
})

#: Prefissi: il web aperto e GitHub in lettura sono interamente contenuto di
#: terzi, e l'elenco dei verbi upstream cambia senza di noi.
_TAINTING_PREFIX = ("web.fetch", "web.search", "web.render", "web.get",
                    "github.get_", "github.list_", "github.search_",
                    "github.issue_read", "github.pull_request_read",
                    "normattiva.", "contabilita.", "sedia.")


def taints(verb: str) -> bool:
    """True se `verb` fa entrare contenuto non controllato nel contesto."""
    v = (verb or "").strip()
    return v in _TAINTING_EXACT or v.startswith(_TAINTING_PREFIX)


def channel_of(chat: Optional[str]) -> Optional[str]:
    """Chiave di sessione → canale. `chan:SEAL-2:contract:clodia#2` → `SEAL-2/contract`.

    Il taint è del CANALE, non dello spawn: se uno spawn di clodia legge una
    pagina ostile, la contaminazione riguarda la stanza, non quell'istanza. Con
    il multi-spawn la distinzione è concreta — quattro spawn dello stesso seed
    condividono il canale.
    """
    c = (chat or "").strip()
    if not c:
        return None
    parts = c.split(":")
    if len(parts) >= 3 and parts[0] == "chan":
        return f"{parts[1]}/{parts[2]}"
    # Chat diretta o forma non riconosciuta: si usa la chiave così com'è. Una DM
    # non è diversa da un canale (decisione del 2 ago 2026), quindi ha un suo
    # flag invece di non averne nessuno.
    return c


def _path():
    return state_paths.state_path(_STATE)


def _load() -> dict:
    try:
        return json.loads(_path().read_text(encoding="utf-8")) or {}
    except (OSError, ValueError):
        return {}


def _save(d: dict) -> None:
    try:
        p = _path()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        tmp.write_text(json.dumps(d, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, p)
    except OSError as e:  # noqa: BLE001 — la registrazione non deve rompere il turno
        LOG.warning("taint: stato non salvato (%s)", str(e)[:120])


def mark(channel: Optional[str], kind: str, detail: str = "",
         agent: str = "") -> Optional[dict]:
    """Registra che è entrato contenuto non fidato in `channel`. Idempotente.

    `kind` è la CATEGORIA della sorgente (`verb`, `file`, `message`), `detail` il
    riferimento leggibile (il verbo, il nome del file). Serve al dialog: «il
    canale è contaminato» non è azionabile, «è entrato un PDF caricato come
    untrusted» sì.
    """
    ch = channel_of(channel)
    if not ch:
        return None
    d = _load()
    e = d.setdefault(ch, {"tainted": False, "sources": []})
    src = {"kind": kind, "detail": detail[:200], "agent": agent,
           "at": int(time.time())}
    e["sources"] = ([s for s in e.get("sources", [])
                     if not (s.get("kind") == kind and s.get("detail") == detail[:200])]
                    + [src])[-_MAX_SOURCES:]
    if not e.get("tainted"):
        e["tainted"] = True
        e["since"] = src["at"]
        LOG.info("taint · %s contaminato da %s:%s (agent %s)", ch, kind, detail, agent)
    _save(d)
    return e


def status(channel: Optional[str]) -> dict:
    """Stato di contaminazione di un canale. Mai `None`: un canale sconosciuto è
    non contaminato, non «ignoto» — non c'è nulla di cui essere prudenti se non è
    ancora entrato niente."""
    ch = channel_of(channel)
    if not ch:
        return {"channel": None, "tainted": False, "sources": []}
    e = _load().get(ch) or {}
    return {"channel": ch, "tainted": bool(e.get("tainted")),
            "since": e.get("since"), "sources": e.get("sources") or []}


def clear(channel: Optional[str], by: str = "") -> dict:
    """Azzera il flag: è l'«ultimo unlock» della definizione.

    Le sorgenti NON si cancellano, si archiviano: dopo un unlock serve ancora
    poter dire cosa era entrato prima, altrimenti l'audit perde il motivo per cui
    quell'unlock è stato chiesto.
    """
    ch = channel_of(channel)
    if not ch:
        return {"channel": None, "tainted": False}
    d = _load()
    e = d.setdefault(ch, {})
    e["tainted"] = False
    e["cleared_at"] = int(time.time())
    e["cleared_by"] = by
    e["archived_sources"] = (e.get("archived_sources") or []) + (e.get("sources") or [])
    e["archived_sources"] = e["archived_sources"][-(_MAX_SOURCES * 4):]
    e["sources"] = []
    _save(d)
    LOG.info("taint · %s declassificato da %s", ch, by or "?")
    return {"channel": ch, "tainted": False, "cleared_by": by}


def composition_epoch(participants) -> str:
    """Firma breve della composizione del canale.

    Entra nella chiave del gate di contesto, e questo È il meccanismo con cui
    «il cambio di composizione invalida gli unlock attivi» (#77): con la
    composizione dentro la chiave, aggiungere un partecipante produce una chiave
    diversa e l'unlock precedente semplicemente non combacia più. Non serve
    nessuna revoca da spazzare, che è l'unico modo per cui non può essere
    dimenticata — altrimenti si sbloccherebbe a 2 lati e si aggiungerebbe dopo
    un agente con verbi di uscita.
    """
    import hashlib
    names = sorted({str(x).strip() for x in (participants or []) if str(x).strip()})
    return hashlib.sha256("|".join(names).encode()).hexdigest()[:8]


def context_gate_key(channel: Optional[str], participants) -> Optional[str]:
    """Chiave del gate di CONTESTO per un canale contaminato."""
    ch = channel_of(channel)
    if not ch:
        return None
    return f"egress-context:{ch}:{composition_epoch(participants)}"


def note_verb(verb: str, agent: str = "", chat: Optional[str] = None,
              vetted: Optional[bool] = None) -> None:
    """Da chiamare DOPO l'esecuzione di un verbo: se ha portato dentro contenuto
    di terzi, contamina il canale corrente.

    `vetted=True` = la SORGENTE di questa lettura è dichiarata fidata → non
    contamina. Serve perché il verbo da solo non basta a decidere: `topic.read_file`
    su un PDF che l'owner ha caricato marcandolo `trusted` non è la stessa cosa
    dello stesso verbo su una cartella Drive di cui nessuno risponde. Prima
    contaminava sempre, e un flag che si accende su tutto smette di discriminare —
    che è esattamente la condizione posta in #77 per non produrre consent fatigue.

    `None` = sorgente non determinabile → contamina. Direzione prudente: una
    lettura di cui non sappiamo la provenienza non è una lettura fidata.

    Non solleva mai: una misura che rompe il turno che sta misurando è peggio della
    misura mancante.
    """
    try:
        if not taints(verb):
            return
        if vetted is True:
            LOG.info("taint · %s da fonte dichiarata fidata: nessuna contaminazione",
                     verb)
            return
        from .whitelist import current_chat
        mark(chat if chat is not None else current_chat(), "verb", verb, agent)
    except Exception as e:  # noqa: BLE001
        LOG.warning("taint: marcatura di %s non riuscita (%s)", verb, e)

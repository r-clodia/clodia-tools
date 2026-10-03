"""logs.tail — lettura READ-ONLY degli ultimi log di piattaforma (diagnosi di
sysadmin). I file vivono nel datadir CONDIVISO tra agent-server e gateway
(`/datadir/logs/…`), quindi si leggono direttamente senza proxy REST.

Due sorgenti, non una (clodia-platform#382):

- `agent-server` — i turni, le sessioni, i job;
- `gateway` — le decisioni del reference monitor: gate, whitelist di
  destinazione, compartimento per-spawn.

La seconda mancava, e la sua assenza non era un'asimmetria estetica. Il
compartimento per-spawn è rimasto in modalità `report` per settimane scrivendo
su `clodia-tools` ciò che avrebbe rifiutato; quel logger va su stdout del
container e nessuno, sysadmin compreso, poteva leggerlo da dentro la colonia.
L'issue #382 chiede infatti di «verificare nei log del gateway» una riga che chi
l'ha scritta non aveva modo di verificare. Un'osservazione che nessuno può
leggere non è un rollout graduale: è un permesso aperto con un log muto sopra.

Prima Legge: i segreti sono già soppressi a monte (httpx→WARNING nell'agent-server),
ma qui redigiamo comunque eventuali `token=/key=/bearer …` residui come difesa in
profondità — sysadmin non deve mai vedere una credenziale in un log.
"""
import logging
import os
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path

from ..whitelist import current_clearance, tool_allowed

#: Le sorgenti leggibili, e il file di ciascuna nella cartella `logs/`.
SOURCES = {"agent-server": "agent-server.log", "gateway": "clodia-tools.log"}
_MAX_LINES = 500
#: Il log del gateway è diagnostica, non archivio: si ruota per non riempire il
#: volume condiviso con l'agent-server.
_MAX_BYTES = 2_000_000
_BACKUPS = 3
#: Stesso formato di `logging.basicConfig`, e non per estetica: `tail` filtra il
#: livello cercando " WARNING " nella riga. Un formato diverso passerebbe i
#: test del file e renderebbe muto il filtro.
_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
_SECRET_RE = re.compile(
    r"(?i)\b(token|secret|key|password|authorization|bearer|api[_-]?key)\b\s*[=:]\s*\S+")
#: Il NOME di un topic nelle righe del reference monitor, nelle due sole forme
#: in cui vi compare: `SEAL-2/dossier` (il bersaglio) e `chan:SEAL-2:dossier:…`
#: (la stanza da cui parte la chiamata). In entrambe il tier sta ATTACCATO al
#: nome, ed è ciò che rende la redazione possibile a lettura.
#:
#: SHORTCUT: la redazione è testuale e regge finché il refmon scrive il tier
#:           accanto al nome. Un nome loggato nudo non è redigibile dal testo:
#:           allora il tier va messo nella riga (o il nome va tolto dal log),
#:           non va dedotto aprendo il topic — `logs.tail` è una lettura di
#:           file e non deve diventare una scansione dello store.
#:           `test_418_logs_redazione.py` fallisce se un emettitore smette di
#:           scrivere il tier.
_TOPIC_RE = re.compile(r"\b(SEAL-[0-4]|P[0-4])([/:])([A-Za-z0-9][\w.-]*)")


def _rank(tier: str | None) -> int:
    """Il livello come numero, accettando l'alias storico `P<n>`.

    Copia deliberata della scala che sta in `main._rank`: `logs` è importato DA
    `main`, e farglielo importare all'indietro per cinque costanti creerebbe un
    ciclo. Un test (`test_418_logs_redazione`) pretende che le due scale diano
    lo stesso numero, così la copia non può divergere in silenzio.
    """
    u = str(tier or "SEAL-0").strip().upper()
    if u.startswith("P") and u[1:].isdigit():
        u = f"SEAL-{u[1:]}"
    try:
        return int(u.replace("SEAL-", "").strip())
    except ValueError:
        return 0


def _redact_topics(line: str, clearance: str | None) -> str:
    """Oscura i NOMI dei topic di tier superiore alla clearance di chi legge.

    Le righe del reference monitor dicono quale stanza un agente ha toccato, e
    `logs.tail` le rende leggibili a chi ha il verbo **indipendentemente dalla
    sua clearance** (clodia-platform#418 §5). Il contenuto non c'è mai, ma il
    nome di un topic SEAL-3 è già informazione: dice che quel dossier esiste e
    come si chiama.

    Il tier resta VISIBILE: una riga «SEAL-3/•••» continua a servire a chi
    diagnostica — dice che è successo, a che livello e a chi — e toglie l'unica
    parte che non gli compete. Oscurare la riga intera avrebbe reso il log
    inutile proprio a chi lo legge per mestiere.
    """
    mio = _rank(clearance)

    def _sub(m: "re.Match[str]") -> str:
        if _rank(m.group(1)) <= mio:
            return m.group(0)
        return f"{m.group(1)}{m.group(2)}•••"

    return _TOPIC_RE.sub(_sub, line)


def _log_file(source: str = "agent-server") -> Path:
    """Il file della sorgente. Sconosciuta → errore, mai un ripiego silenzioso:
    rispondere con l'agent-server a chi ha chiesto il gateway è dargli la
    risposta giusta alla domanda sbagliata.

    `str()` prima di `.strip()`: un `source` non stringa sollevava
    `AttributeError` invece del `ValueError` che questa funzione documenta, e
    chi lo riceveva leggeva un guasto al posto di «sorgente sconosciuta»
    (clodia-platform#418 §6).
    """
    nome = SOURCES.get(str(source or "agent-server").strip().lower())
    if not nome:
        raise ValueError(
            f"sorgente di log sconosciuta: '{source}'. "
            f"Disponibili: {', '.join(sorted(SOURCES))}")
    return Path(os.environ.get("CLODIA_DATA", "/datadir")) / "logs" / nome


#: Il solo logger che finisce sul file letto da `logs.tail(source="gateway")`:
#: le decisioni del reference monitor sul compartimento per-spawn. Non il padre
#: `clodia-tools`, che porta tutti i 44 logger figli a INFO — richieste, topic,
#: destinazioni — su un file che `logs.tail` rende leggibile a chi ha il verbo,
#: indipendentemente dalla sua clearance.
REFMON_LOGGER = "clodia-tools.refmon"


def attach_gateway_file_log(level: int = logging.INFO) -> Path | None:
    """Fa scrivere il logger `REFMON_LOGGER` anche su file, oltre che su stdout.

    Idempotente (un secondo giro non duplica le righe) e **fail-open**: se il
    volume non è scrivibile il gateway parte lo stesso e continua a loggare su
    stdout. Una diagnostica che impedisce l'avvio è peggio del buco che chiude.
    """
    try:
        path = _log_file("gateway")
        path.parent.mkdir(parents=True, exist_ok=True)
        lg = logging.getLogger(REFMON_LOGGER)
        for h in lg.handlers:
            if Path(getattr(h, "baseFilename", "")) == path:
                return path
        h = RotatingFileHandler(path, maxBytes=_MAX_BYTES, backupCount=_BACKUPS,
                                encoding="utf-8")
        h.setFormatter(logging.Formatter(_FORMAT))
        lg.addHandler(h)
        if lg.level == logging.NOTSET or lg.level > level:
            lg.setLevel(level)
        return path
    except Exception as e:  # noqa: BLE001 — vedi docstring: mai bloccare l'avvio
        logging.getLogger("clodia-tools").warning(
            "log su file del gateway non attivato: %s", e)
        return None


def tail(lines: int = 100, level: str = "", source: str = "agent-server") -> dict:
    """Ultime `lines` righe del log (max 500), opzionalmente filtrate per
    `level` (INFO/WARNING/ERROR). `source`: `agent-server` (default) o
    `gateway`. Segreti redatti, e con loro i nomi dei topic sopra la clearance
    di chi legge (`_redact_topics`)."""
    tool_allowed("logs.tail")
    f = _log_file(source)
    n = max(1, min(int(lines or 100), _MAX_LINES))
    if not f.is_file():
        return {"file": str(f), "source": source, "count": 0, "lines": [],
                "note": "file di log non ancora presente"}
    rows = f.read_text(encoding="utf-8", errors="replace").splitlines()
    lv = (level or "").strip().upper()
    if lv:
        rows = [r for r in rows if f" {lv} " in r]
    cl = current_clearance()
    out = [_redact_topics(_SECRET_RE.sub(lambda m: m.group(1) + "=•••", r), cl)
           for r in rows[-n:]]
    return {"file": str(f), "source": source, "count": len(out), "lines": out}

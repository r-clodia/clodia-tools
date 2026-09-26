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

from ..whitelist import tool_allowed

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


def _log_file(source: str = "agent-server") -> Path:
    """Il file della sorgente. Sconosciuta → errore, mai un ripiego silenzioso:
    rispondere con l'agent-server a chi ha chiesto il gateway è dargli la
    risposta giusta alla domanda sbagliata."""
    nome = SOURCES.get((source or "agent-server").strip().lower())
    if not nome:
        raise ValueError(
            f"sorgente di log sconosciuta: '{source}'. "
            f"Disponibili: {', '.join(sorted(SOURCES))}")
    return Path(os.environ.get("CLODIA_DATA", "/datadir")) / "logs" / nome


def attach_gateway_file_log(level: int = logging.INFO) -> Path | None:
    """Fa scrivere il logger `clodia-tools` anche su file, oltre che su stdout.

    Idempotente (un secondo giro non duplica le righe) e **fail-open**: se il
    volume non è scrivibile il gateway parte lo stesso e continua a loggare su
    stdout. Una diagnostica che impedisce l'avvio è peggio del buco che chiude.
    """
    try:
        path = _log_file("gateway")
        path.parent.mkdir(parents=True, exist_ok=True)
        lg = logging.getLogger("clodia-tools")
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
    `gateway`. Segreti redatti."""
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
    out = [_SECRET_RE.sub(lambda m: m.group(1) + "=•••", r) for r in rows[-n:]]
    return {"file": str(f), "source": source, "count": len(out), "lines": out}

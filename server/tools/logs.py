"""logs.tail — lettura READ-ONLY degli ultimi log dell'agent-server (diagnosi
di sysadmin). Il file di log vive nel datadir CONDIVISO tra agent-server e
gateway (`/datadir/logs/agent-server.log`), quindi si legge direttamente senza
proxy REST.

Prima Legge: i segreti sono già soppressi a monte (httpx→WARNING nell'agent-server),
ma qui redigiamo comunque eventuali `token=/key=/bearer …` residui come difesa in
profondità — sysadmin non deve mai vedere una credenziale in un log.
"""
import os
import re
from pathlib import Path

from ..whitelist import tool_allowed

_LOG_FILE = Path(os.environ.get("CLODIA_DATA", "/datadir")) / "logs" / "agent-server.log"
_MAX_LINES = 500
_SECRET_RE = re.compile(
    r"(?i)\b(token|secret|key|password|authorization|bearer|api[_-]?key)\b\s*[=:]\s*\S+")


def tail(lines: int = 100, level: str = "") -> dict:
    """Ultime `lines` righe del log dell'agent-server (max 500), opzionalmente
    filtrate per `level` (INFO/WARNING/ERROR). Segreti redatti."""
    tool_allowed("logs.tail")
    n = max(1, min(int(lines or 100), _MAX_LINES))
    if not _LOG_FILE.is_file():
        return {"file": str(_LOG_FILE), "count": 0, "lines": [],
                "note": "file di log non ancora presente"}
    rows = _LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
    lv = (level or "").strip().upper()
    if lv:
        rows = [r for r in rows if f" {lv} " in r]
    out = [_SECRET_RE.sub(lambda m: m.group(1) + "=•••", r) for r in rows[-n:]]
    return {"file": str(_LOG_FILE), "count": len(out), "lines": out}

"""memory.* — seed memory scrivibile dell'agente (accumulo di esperienza).

Ogni agente (inclusi i nativi) può leggere/scrivere la propria **seed memory**:
`<CLODIA_DATA>/agents/<seed>/memory/`. La memory è **condivisa fra le istanze**
`<seed>-N` (è del seed, non dell'istanza). Universale: non richiede grant
per-agente (è la memoria dell'agente stesso, scoped alla sua sola cartella).

File di default: `memory.md` (note/esperienza, sempre in contesto lato runtime).
L'agente può anche tenere file strutturati (es. il messaggero: whitelist Telegram
in `telegram_whitelist.json`), letti dai sottosistemi che ne hanno bisogno.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

from ..whitelist import agent_name

# Convenzione di piattaforma (come Clodia Primal e l'endpoint /memories della
# webui): l'indice/note dell'agente è `MEMORY.md` (+ eventuali altri file .md).
_DEFAULT_FILE = "MEMORY.md"
# Cap difensivo sulla dimensione di un singolo file di memory (evita di gonfiare
# il contesto LLM che la carica sempre).
_MAX_BYTES = 64 * 1024


def _seed_of(name: str) -> str:
    """Seed di un'istanza: `messaggero-3` → `messaggero`. Senza suffisso `-N`
    resta invariato (`clodia` → `clodia`)."""
    return re.sub(r"-\d+$", "", str(name or "").strip()) or "anon"


def memory_dir(name: str | None = None) -> Path:
    seed = _seed_of(name or agent_name())
    base = os.environ.get("CLODIA_DATA", "/datadir")
    d = Path(base) / "agents" / seed / "memory"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _safe_file(filename: str | None) -> str:
    fn = (filename or _DEFAULT_FILE).strip() or _DEFAULT_FILE
    # Nessun path traversal: solo un nome file semplice.
    if "/" in fn or "\\" in fn or fn.startswith("."):
        raise ValueError(f"nome file memory non valido: {filename!r}")
    return fn


def read(filename: str | None = None) -> dict:
    d = memory_dir()
    p = d / _safe_file(filename)
    if not p.is_file():
        return {"file": p.name, "exists": False, "content": ""}
    return {"file": p.name, "exists": True, "content": p.read_text(encoding="utf-8")}


def write(content: str, filename: str | None = None) -> dict:
    d = memory_dir()
    p = d / _safe_file(filename)
    data = (content or "").encode("utf-8")
    if len(data) > _MAX_BYTES:
        raise ValueError(f"memory troppo grande ({len(data)}B > {_MAX_BYTES}B): "
                         "sintetizza o usa più file")
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(content or "", encoding="utf-8")
    tmp.replace(p)
    return {"file": p.name, "bytes": len(data), "ok": True}


def append(content: str, filename: str | None = None) -> dict:
    d = memory_dir()
    p = d / _safe_file(filename)
    prev = p.read_text(encoding="utf-8") if p.is_file() else ""
    joined = (prev + ("\n" if prev and not prev.endswith("\n") else "") + (content or ""))
    return write(joined, filename)


def list_files() -> dict:
    d = memory_dir()
    files = sorted(f.name for f in d.iterdir() if f.is_file() and not f.name.endswith(".tmp"))
    return {"dir": str(d), "files": files}

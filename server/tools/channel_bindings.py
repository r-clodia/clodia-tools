"""Binding di canale: `<connettore>` + `<chat_id>` → (istanza, topic).

Il legame fra una conversazione esterna e un topic è un fatto del CONNETTORE
che porta quella conversazione (clodia-platform#521, #638). Un file unico nel datadir
condiviso gateway↔backend:

    <CLODIA_DATA>/channel-bindings.json
    {
      "version": 1,
      "connectors": {
        "whatsapp": { "123@g.us": {"instance": "messaggero-1",
                                   "tier": "SEAL-1", "topic": "hedge-iot-new"} }
      }
    }

`version` e `connectors` sono chiavi esplicite perché un id di connettore è
`[a-z][a-z0-9-]*` (`connectors/SCHEMA.md`): una radice piatta renderebbe legale
un connettore che si chiama `version` e illeggibile il file il giorno dopo.

Invariante di sempre, ora per connettore: **una chat → un solo binding**. Il
gateway scrive (le azioni di topic `binding: channel`), il relay del backend
legge (`clodia-logic/server/api/channel_bindings_client.py`).

**Un binding non è un permesso.** Dice quale istanza ascolta quale chat; chi può
parlare in quella stanza resta scritto negli ingress dello scope, e il relay li
interroga a ogni messaggio (clodia-platform#364/#365).

Il vecchio `telegram-bindings.json` non si legge più: Telegram è stato tolto
dalla piattaforma (clodia-platform#683).
"""
from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
import threading
from pathlib import Path

try:  # POSIX: serialises writers across processes (gateway workers, CLI)
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX
    fcntl = None

LOG = logging.getLogger("clodia-tools.channel_bindings")

VERSION = 1
FILENAME = "channel-bindings.json"

def _data_dir(base=None) -> Path:
    if base is not None:
        return Path(base)
    return Path(os.environ.get("CLODIA_DATA", "/datadir"))


def _path(base=None) -> Path:
    return _data_dir(base) / FILENAME


class BindingsUnreadable(RuntimeError):
    """`channel-bindings.json` exists but cannot be read, is not JSON, or is
    not the expected shape. Reads serve an empty registry (and log at ERROR);
    every write refuses, so a corrupted file is never replaced and repairing it
    restores the bindings."""


def _read_json(p: Path) -> dict:
    """The registry document; `{}` if the file does not exist. Raises
    `BindingsUnreadable` if it exists but cannot be read/parsed or is not
    `{"connectors": {<id>: {<chat>: {...}}}}` — never a silent `{}` that the
    next write would turn into a wiped registry."""
    if not p.is_file():
        return {}
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise BindingsUnreadable(
            f"{p} exists but cannot be read/parsed ({type(e).__name__}: {e}); "
            f"writes refused until it is repaired") from e
    if d is None:
        return {}
    problema = None
    if not isinstance(d, dict):
        problema = f"is a JSON {type(d).__name__}, not an object"
    elif "connectors" in d and not isinstance(d["connectors"], dict):
        problema = "has a 'connectors' that is not an object"
    elif any(not isinstance(v, dict) for v in (d.get("connectors") or {}).values()):
        problema = "has a connector whose bindings are not an object"
    if problema:
        raise BindingsUnreadable(f"{p} {problema}; writes refused until it is repaired")
    return d


# ── concurrency ──────────────────────────────────────────────────────────────
#: In-process: the gateway serves verbs from several threads. Cross-process:
#: an flock on a sibling lock file (a second worker, a CLI). Every
#: read-modify-write runs under both.
_THREAD_LOCK = threading.Lock()


@contextlib.contextmanager
def _locked(base=None):
    d = _data_dir(base)
    with _THREAD_LOCK:
        if fcntl is None or not d.is_dir():
            yield
            return
        fd = os.open(str(d / (FILENAME + ".lock")), os.O_RDWR | os.O_CREAT, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)


def _write_doc(doc: dict, base=None) -> None:
    """Atomic write: a uniquely named temp file in the same directory, fsync,
    then `os.replace`. A reader (the relay) sees the old or the new document,
    never a torn one; two writers never share a temp file."""
    p = _path(base)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=FILENAME + ".", suffix=".tmp", dir=str(p.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(json.dumps(doc, ensure_ascii=False, indent=2))
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, p)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _doc(base=None, *, for_write: bool = False) -> dict:
    """Il documento intero.

    Caller must hold `_locked(base)`. An unreadable/malformed file: reads
    serve an empty registry, writes raise `BindingsUnreadable`, the file is
    never replaced."""
    p = _path(base)
    try:
        doc = _read_json(p)
    except BindingsUnreadable as e:
        LOG.error("channel-bindings: %s", e)
        if for_write:
            raise
        return {"version": VERSION, "connectors": {}}
    conn = doc.get("connectors") or {}
    return {"version": doc.get("version", VERSION), "connectors": conn}


# ── lettura ──────────────────────────────────────────────────────────────────
def load(connector: str | None = None, *, base=None) -> dict:
    """Tutti i binding (`{connettore: {chat_id: binding}}`) oppure, dato un
    connettore, i suoi soli binding (`{chat_id: binding}`)."""
    with _locked(base):
        conn = _doc(base)["connectors"]
    if connector is None:
        return conn
    return dict(conn.get(connector) or {})


def connectors(*, base=None) -> list:
    """Gli id dei connettori che hanno almeno un binding. È ciò su cui il relay
    cicla: nessun binding di un trasporto ⇒ quel trasporto non si interroga."""
    with _locked(base):
        conn = _doc(base)["connectors"]
    return [c for c, b in conn.items() if b]


def get(connector: str, chat_id, *, base=None) -> dict | None:
    return load(connector, base=base).get(str(chat_id))


# ── scrittura ────────────────────────────────────────────────────────────────
def set_binding(connector: str, chat_id, instance: str, tier: str, topic: str,
                *, base=None) -> dict:
    with _locked(base):
        doc = _doc(base, for_write=True)
        doc["version"] = VERSION
        per_conn = dict(doc["connectors"].get(connector) or {})
        per_conn[str(chat_id)] = {"instance": instance, "tier": tier, "topic": topic}
        doc["connectors"][connector] = per_conn
        _write_doc(doc, base)
        return per_conn[str(chat_id)]


def remove(connector: str, chat_id, *, base=None) -> bool:
    with _locked(base):
        doc = _doc(base, for_write=True)
        per_conn = dict(doc["connectors"].get(connector) or {})
        if str(chat_id) not in per_conn:
            return False
        del per_conn[str(chat_id)]
        doc["connectors"][connector] = per_conn
        doc["version"] = VERSION
        _write_doc(doc, base)
        return True


def replace(connector: str, bindings: dict, *, base=None) -> None:
    """Sostituisce in blocco i binding di UN connettore, lasciando intatti gli
    altri. Serve al ripristino di `topics/retier.py`, che fa e disfa in blocco:
    scrivere l'intero documento da lì cancellerebbe i trasporti che quella
    transazione non ha nemmeno guardato."""
    with _locked(base):
        doc = _doc(base, for_write=True)
        doc["connectors"][connector] = {str(k): dict(v) for k, v in (bindings or {}).items()}
        doc["version"] = VERSION
        _write_doc(doc, base)

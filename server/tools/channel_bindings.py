"""Binding di canale: `<connettore>` + `<chat_id>` → (istanza, topic).

Generalizzazione di `telegram_bindings` (clodia-platform#521, epic #527): il
legame fra una conversazione esterna e un topic non è più un fatto di Telegram
ma del CONNETTORE che porta quella conversazione. Un file unico nel datadir
condiviso gateway↔backend:

    <CLODIA_DATA>/channel-bindings.json
    {
      "version": 1,
      "connectors": {
        "telegram": { "-100123": {"instance": "messaggero-1",
                                  "tier": "SEAL-1", "topic": "hedge-iot-new"} }
      }
    }

`version` e `connectors` sono chiavi esplicite perché un id di connettore è
`[a-z][a-z0-9-]*` (`connectors/SCHEMA.md`): una radice piatta renderebbe legale
un connettore che si chiama `version` e illeggibile il file il giorno dopo.

Invariante di sempre, ora per connettore: **una chat → un solo binding**. Il
gateway scrive (verbi `*.listen`/`*.unlisten`, rotta `…/telegram-link`), il relay
del backend legge (`clodia-logic/server/api/channel_bindings_client.py`).

**Un binding non è un permesso.** Dice quale istanza ascolta quale chat; chi può
parlare in quella stanza resta scritto negli ingress dello scope, e il relay li
interroga a ogni messaggio (clodia-platform#364/#365).

Migrazione da `telegram-bindings.json`: `migrate_legacy()`, one-shot e
idempotente — vedi il suo docstring per la regola sul file vecchio.
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

#: Il file che questo sostituisce, e il connettore sotto cui finiscono le sue
#: voci. Resta nominato in un posto solo: quando #522 porterà Telegram nel
#: comms-pack, è questa coppia a sparire, non una ricerca nel codice.
LEGACY_FILENAME = "telegram-bindings.json"
LEGACY_CONNECTOR = "telegram"


def _data_dir(base=None) -> Path:
    if base is not None:
        return Path(base)
    return Path(os.environ.get("CLODIA_DATA", "/datadir"))


def _path(base=None) -> Path:
    return _data_dir(base) / FILENAME


def _legacy_path(base=None) -> Path:
    return _data_dir(base) / LEGACY_FILENAME


class BindingsUnreadable(RuntimeError):
    """`channel-bindings.json` exists but cannot be read, is not JSON, or is
    not the expected shape. Reads serve an empty registry (and log at ERROR);
    every write refuses, so a corrupted file is never replaced and repairing it
    restores the bindings."""


class LegacyBindingsUnreadable(BindingsUnreadable):
    """`telegram-bindings.json` exists but cannot be read or is not a JSON
    object. Migrating from it would write an empty registry and, since the new
    file's existence is what marks the migration as done, lose every binding
    for good. So nothing is migrated and nothing is written until the old file
    is repaired (or removed on purpose)."""


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


def _read_legacy(base=None) -> dict | None:
    """The legacy file as a dict; None if it does not exist. Raises
    `LegacyBindingsUnreadable` if it exists but is unreadable, not JSON, or not
    a JSON object — never a silent `{}`, which is what turned a corrupt file
    into a permanent, empty migration."""
    p = _legacy_path(base)
    if not p.is_file():
        return None
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise LegacyBindingsUnreadable(
            f"{p} exists but cannot be read/parsed ({type(e).__name__}: {e}); "
            f"migration to {FILENAME} refused until it is repaired") from e
    if d is None:
        return {}
    if not isinstance(d, dict):
        raise LegacyBindingsUnreadable(
            f"{p} is a JSON {type(d).__name__}, not an object; migration to "
            f"{FILENAME} refused until it is repaired")
    return {str(k): v for k, v in d.items() if isinstance(v, dict)}


# ── concurrency ──────────────────────────────────────────────────────────────
#: In-process: the gateway serves verbs from several threads. Cross-process:
#: an flock on a sibling lock file (a second worker, the migration CLI). Every
#: read-modify-write — and the migration — runs under both.
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
    """Il documento intero, migrando dal file vecchio la prima volta.

    Caller must hold `_locked(base)`. If the legacy file exists but is
    unreadable the migration is NOT done (it is retried on the next call, so
    repairing the old file is enough): a read serves an empty registry, a write
    raises `LegacyBindingsUnreadable` — writing would create the new file and
    mark the migration as done with every legacy binding missing. Same rule for
    an unreadable/malformed new file: reads empty, writes raise
    `BindingsUnreadable`, the file is never replaced."""
    p = _path(base)
    if not p.is_file() and _legacy_path(base).is_file():
        try:
            _migrate_unlocked(base=base)
        except LegacyBindingsUnreadable as e:
            LOG.error("channel-bindings: %s", e)
            if for_write:
                raise
            return {"version": VERSION, "connectors": {}}
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


# ── migrazione one-shot da telegram-bindings.json ────────────────────────────
def migrate_legacy(*, base=None, dry_run: bool = False) -> dict:
    """Porta `telegram-bindings.json` sotto il connettore `telegram`.

    **One-shot e idempotente**, e il discriminante è l'esistenza del file nuovo:
    fatta una volta, le chiamate successive non riscrivono niente. Il file
    vecchio NON si cancella — è il rollback e la prova di cosa c'era — ma da
    quel momento non si legge più.

    Per questo, se dopo la migrazione il file vecchio torna a divergere (un
    gateway di una versione precedente ripartito per sbaglio, un ripristino
    parziale), le sue voci **non vengono rifuse**: rifonderle resusciterebbe
    binding tolti di proposito, cioè farebbe ricomparire una chat in una stanza
    da cui qualcuno l'aveva staccata. Si registrano come `orphans` e si logga,
    perché una divergenza silenziosa fra due file è il modo peggiore di
    scoprirla.

    If the old file exists but cannot be read/parsed or is not a JSON object,
    raises `LegacyBindingsUnreadable` and writes nothing (not even in a
    non-dry run): the next call retries, so repairing the old file is enough.

    Ritorna `{"migrated": [chat_id…], "already": bool, "orphans": [chat_id…]}`.
    """
    with _locked(base):
        return _migrate_unlocked(base=base, dry_run=dry_run)


def _migrate_unlocked(*, base=None, dry_run: bool = False) -> dict:
    if _path(base).is_file():
        try:
            legacy = _read_legacy(base) or {}
        except LegacyBindingsUnreadable as e:
            # Already migrated: the new file is authoritative, the old one is
            # only compared against. Say so, but do not fail.
            LOG.warning("channel-bindings already migrated; orphan check skipped: %s", e)
            legacy = {}
        try:
            doc = _read_json(_path(base))
        except BindingsUnreadable as e:
            LOG.error("channel-bindings: %s", e)
            raise
        presenti = set((doc.get("connectors") or {}).get(LEGACY_CONNECTOR) or {})
        orphans = sorted(set(legacy) - presenti)
        if orphans:
            LOG.warning(
                "channel-bindings già migrato: %d voce/i di %s non vi compaiono e "
                "NON vengono rifuse (%s). Rifonderle rimetterebbe in piedi binding "
                "tolti di proposito.", len(orphans), LEGACY_FILENAME, ", ".join(orphans))
        return {"migrated": [], "already": True, "orphans": orphans}
    legacy = _read_legacy(base) or {}
    piano = sorted(legacy)
    if not dry_run:
        _write_doc({"version": VERSION,
                    "connectors": {LEGACY_CONNECTOR: {k: dict(legacy[k]) for k in piano}}},
                   base)
        LOG.info("channel-bindings: migrate %d binding da %s sotto il connettore '%s'",
                 len(piano), LEGACY_FILENAME, LEGACY_CONNECTOR)
    return {"migrated": piano, "already": False, "orphans": []}

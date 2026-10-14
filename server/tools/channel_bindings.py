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

import json
import logging
import os
from pathlib import Path

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


def _read_json(p: Path) -> dict:
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except (OSError, json.JSONDecodeError):
        return {}


def _write_doc(doc: dict, base=None) -> None:
    p = _path(base)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(p)


def _doc(base=None) -> dict:
    """Il documento intero, migrando dal file vecchio la prima volta."""
    p = _path(base)
    if not p.is_file() and _legacy_path(base).is_file():
        migrate_legacy(base=base)
    doc = _read_json(p)
    conn = doc.get("connectors")
    if not isinstance(conn, dict):
        conn = {}
    return {"version": doc.get("version", VERSION), "connectors": conn}


# ── lettura ──────────────────────────────────────────────────────────────────
def load(connector: str | None = None, *, base=None) -> dict:
    """Tutti i binding (`{connettore: {chat_id: binding}}`) oppure, dato un
    connettore, i suoi soli binding (`{chat_id: binding}`)."""
    conn = _doc(base)["connectors"]
    if connector is None:
        return conn
    return dict(conn.get(connector) or {})


def connectors(*, base=None) -> list:
    """Gli id dei connettori che hanno almeno un binding. È ciò su cui il relay
    cicla: nessun binding di un trasporto ⇒ quel trasporto non si interroga."""
    return [c for c, b in _doc(base)["connectors"].items() if b]


def get(connector: str, chat_id, *, base=None) -> dict | None:
    return load(connector, base=base).get(str(chat_id))


# ── scrittura ────────────────────────────────────────────────────────────────
def set_binding(connector: str, chat_id, instance: str, tier: str, topic: str,
                *, base=None) -> dict:
    doc = _doc(base)
    doc["version"] = VERSION
    per_conn = dict(doc["connectors"].get(connector) or {})
    per_conn[str(chat_id)] = {"instance": instance, "tier": tier, "topic": topic}
    doc["connectors"][connector] = per_conn
    _write_doc(doc, base)
    return per_conn[str(chat_id)]


def remove(connector: str, chat_id, *, base=None) -> bool:
    doc = _doc(base)
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
    doc = _doc(base)
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

    Ritorna `{"migrated": [chat_id…], "already": bool, "orphans": [chat_id…]}`.
    """
    legacy = _read_json(_legacy_path(base))
    legacy = {str(k): v for k, v in legacy.items() if isinstance(v, dict)}
    if _path(base).is_file():
        doc = _read_json(_path(base))
        presenti = set((doc.get("connectors") or {}).get(LEGACY_CONNECTOR) or {})
        orphans = sorted(set(legacy) - presenti)
        if orphans:
            LOG.warning(
                "channel-bindings già migrato: %d voce/i di %s non vi compaiono e "
                "NON vengono rifuse (%s). Rifonderle rimetterebbe in piedi binding "
                "tolti di proposito.", len(orphans), LEGACY_FILENAME, ", ".join(orphans))
        return {"migrated": [], "already": True, "orphans": orphans}
    piano = sorted(legacy)
    if not dry_run:
        _write_doc({"version": VERSION,
                    "connectors": {LEGACY_CONNECTOR: {k: dict(legacy[k]) for k in piano}}},
                   base)
        LOG.info("channel-bindings: migrate %d binding da %s sotto il connettore '%s'",
                 len(piano), LEGACY_FILENAME, LEGACY_CONNECTOR)
    return {"migrated": piano, "already": False, "orphans": []}

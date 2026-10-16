"""Percorsi dello STATO DECISIONALE del gateway (issue clodia-platform#80).

Whitelist per-agente, consensi del gate e deleghe **sono** le decisioni di
autorizzazione del reference monitor. Se un processo che il gateway deve
confinare può riscriverli, il confine cade dall'interno: si aggiunge un tool
alla propria entry di `clodia-tools-config.yaml` e le chiamate successive
passano «legittimamente» perché è lo *stato* a essere stato manomesso.

Storicamente questi file vivono in `CLODIA_DATA`, che nel compose è montato
**sia** dal gateway **sia** dall'agent-server (dove girano gli agenti). Questo
modulo li sposta in una directory di proprietà del **solo** gateway, indicata
da `CLODIA_TOOLS_STATE_DIR` (volume che l'agent-server non monta).

Compatibilità: se `CLODIA_TOOLS_STATE_DIR` non è impostata (dev locale, deploy
non ancora aggiornato) il percorso resta identico a prima. Quando invece è
impostata, l'eventuale copia legacy presente in `CLODIA_DATA` viene migrata
**una volta sola** nella nuova directory, così un'istanza esistente non perde
whitelist e consensi al primo restart dopo l'aggiornamento.
"""
from __future__ import annotations

import logging
import os
import shutil
import sys
from pathlib import Path

LOG = logging.getLogger("clodia-tools.state")

#: Nomi (relativi alla state dir) dei file di stato decisionale del gateway.
#: Elencati per la migrazione e per i test di regressione: chi aggiunge stato
#: decisionale nuovo lo aggiunge qui, non in `CLODIA_DATA`.
STATE_FILES = (
    "clodia-tools-config.yaml",
    "clodia-tools-gate.json",
    "clodia-tools-gate-revoked.json",
    "clodia-tools-gate-requests.json",
    "delegations/active.jsonl",
)

#: Suffisso applicato alla copia legacy dopo la migrazione: resta sul volume
#: condiviso come backup, ma è inerte (il gateway non la legge più).
MIGRATED_SUFFIX = ".migrated-to-state-dir"

#: Con questa env un processo DICHIARA di essere il proprietario dello stato e
#: di poter fare la migrazione una-tantum di #80 anche se sembra un test. La
#: usano i test che la migrazione la verificano: nessun altro.
MIGRATE_ENV = "CLODIA_TOOLS_MIGRATE_STATE"


def _test_runner() -> bool:
    """True se questo processo è una ESECUZIONE DI TEST, non il gateway.

    Il 14 ott 2026 una run della suite dentro lo scratch di un agente ha
    migrato tre file di stato del gateway fuori da `/datadir`, rinominando gli
    originali (clodia-platform#541, #545 §6): `CLODIA_TOOLS_STATE_DIR` puntava
    a una temp dir mentre `CLODIA_DATA` era ancora quella VERA — in ogni
    scratch quella variabile è già impostata. La migrazione ha fatto il suo
    lavoro; il difetto è che a chiederla sia stato un test, e a chiederla è
    l'IMPORT di `whitelist`, cioè prima che un `setUp` o un assert possano
    intervenire.

    Si guarda il PUNTO DI INGRESSO, non `"unittest" in sys.modules`: una
    dipendenza che importa `unittest.mock` non deve impedire la migrazione
    vera, perché allora il gateway ripartirebbe dallo stato vuoto — cioè
    esattamente la perdita che #80 esiste per evitare.
    """
    if os.environ.get(MIGRATE_ENV):
        return False
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return True
    spec = getattr(sys.modules.get("__main__"), "__spec__", None)
    entry = (getattr(spec, "name", "") or "").split(".")[0]
    if entry in {"unittest", "pytest", "nose"}:
        return True
    argv0 = os.path.basename((sys.argv or [""])[0] or "")
    return argv0 in {"unittest", "pytest", "py.test"}


def shared_dir() -> Path:
    """Datadir condivisa con l'agent-server (`CLODIA_DATA`)."""
    return Path(os.environ.get("CLODIA_DATA") or "/datadir")


def state_dir() -> Path:
    """Directory dello stato decisionale.

    `CLODIA_TOOLS_STATE_DIR` quando impostata (volume del solo gateway),
    altrimenti la datadir condivisa — comportamento pre-#80.
    """
    explicit = os.environ.get("CLODIA_TOOLS_STATE_DIR")
    return Path(explicit) if explicit else shared_dir()


def configured() -> bool:
    """True se lo stato ha una directory su volume (una delle due env è
    impostata). Se nessuna lo è siamo in dev locale: chi chiama usa il default
    baked nell'immagine."""
    return bool(os.environ.get("CLODIA_TOOLS_STATE_DIR") or os.environ.get("CLODIA_DATA"))


def is_isolated() -> bool:
    """True se lo stato NON è più sulla datadir condivisa con l'agent-server."""
    return state_dir().resolve() != shared_dir().resolve()


def state_path(name: str) -> Path:
    """Percorso del file di stato `name`, migrando l'eventuale copia legacy.

    Idempotente: la migrazione scatta solo quando lo stato è isolato e il file
    non esiste ancora nella state dir, quindi al più una volta per file. Non
    crea nulla se il legacy non c'è.

    Il PERCORSO lo restituisce sempre; a essere condizionata è solo la
    migrazione, che sposta stato vivo e quindi la fa il processo che quello
    stato lo possiede (vedi `_test_runner`).
    """
    target = state_dir() / name
    if target.exists() or not is_isolated():
        return target
    if _test_runner():
        LOG.debug("stato gateway '%s': migrazione saltata, questo processo è "
                  "una run di test (clodia-platform#541)", name)
        return target
    _migrate(name, target)
    return target


def _migrate(name: str, target: Path) -> None:
    legacy = shared_dir() / name
    if not legacy.is_file():
        return
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + ".migrating")
        shutil.copyfile(legacy, tmp)
        os.replace(tmp, target)
    except OSError as exc:  # noqa: BLE001 - migrazione best-effort, mai fatale
        LOG.error("stato gateway '%s': migrazione da %s fallita (%s); "
                  "il gateway riparte dallo stato vuoto/seed", name, legacy, exc)
        return
    LOG.warning("stato gateway '%s' migrato da %s (volume CONDIVISO con "
                "l'agent-server) a %s (volume del solo gateway) — issue #80",
                name, legacy, target)
    try:
        legacy.rename(legacy.with_name(legacy.name + MIGRATED_SUFFIX))
    except OSError as exc:  # noqa: BLE001
        LOG.warning("copia legacy %s non rinominabile (%s): resta sul volume "
                    "condiviso ma NON è più letta dal gateway", legacy, exc)

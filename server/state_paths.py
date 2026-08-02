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
    """
    target = state_dir() / name
    if target.exists() or not is_isolated():
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

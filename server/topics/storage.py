"""Contratto dello STORAGE astratto dei topic (Topic System v2, §3).

Ogni backend (local-fs, Google Drive, Dropbox, …) implementa questa interfaccia.
Il servizio topic ci lavora sopra senza sapere quale backend c'è sotto.

Requisito chiave: **versioning**. `read` ritorna una `version` (etag/rev/hash) e
`write` accetta `if_version` per la **conditional write** (optimistic concurrency).
I backend che non lo supportano nativamente lo EMULANO (es. local-fs: hash del
contenuto). `capability()` dichiara cosa il backend sa fare.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass, field


class StorageError(RuntimeError):
    """Errore generico dello storage."""


class NotFound(StorageError):
    """Path inesistente."""


class VersionConflict(StorageError):
    """`if_version` non combacia con la versione corrente (scrittura concorrente)."""


@dataclass
class Entry:
    name: str
    kind: str  # "file" | "dir"
    size: int = 0
    mime: str | None = None   # mimeType del backend (Drive): riconosce i Google Docs nativi
    url: str | None = None    # webViewLink (Drive): per i Docs nativi mostrati come proxy/link


@dataclass
class ReadResult:
    data: bytes
    version: str


@dataclass
class Stat:
    version: str   # "" per le directory
    size: int
    mtime: float
    kind: str      # "file" | "dir"
    md5: str | None = None   # md5 del contenuto (confronto con Drive md5Checksum); None per le dir


@dataclass
class Capability:
    name: str
    versioning: str = "emulated"   # "native" | "emulated"
    atomic_move: bool = True
    max_size: int = field(default=64 * 1024 * 1024)


class Storage(abc.ABC):
    """Interfaccia che ogni adapter di storage deve implementare. I path sono
    relativi alla root dell'area topic del backend (mai assoluti)."""

    @abc.abstractmethod
    def capability(self) -> Capability: ...

    @abc.abstractmethod
    def list(self, path: str) -> list[Entry]: ...

    @abc.abstractmethod
    def read(self, path: str) -> ReadResult: ...

    @abc.abstractmethod
    def write(self, path: str, data: bytes, if_version: str | None = None) -> str:
        """Scrive `data`. Se `if_version` è dato e non combacia con la versione
        corrente → VersionConflict. Ritorna la nuova versione."""

    @abc.abstractmethod
    def mkdir(self, path: str) -> None: ...

    @abc.abstractmethod
    def move(self, src: str, dst: str) -> None: ...

    @abc.abstractmethod
    def delete(self, path: str) -> None: ...

    @abc.abstractmethod
    def stat(self, path: str) -> Stat | None:
        """Stat del path, o None se non esiste."""

    def exists(self, path: str) -> bool:
        return self.stat(path) is not None

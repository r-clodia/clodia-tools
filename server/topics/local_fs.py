"""Adapter di storage su filesystem LOCALE del gateway (Topic System v2, P1).

Baseline clone: il fs locale del gateway è dove garantiamo atomicità e
versioning più facilmente. La versione è EMULATA come hash sha256 del contenuto
(deterministica, senza stato extra); la conditional write confronta l'hash.
Scrittura atomica via file temporaneo + rename.
"""
from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path

from .storage import (Capability, Entry, NotFound, ReadResult, Stat, Storage,
                      StorageError, VersionConflict)


def _version(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class LocalFsStorage(Storage):
    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def capability(self) -> Capability:
        return Capability(name="local-fs", versioning="emulated", atomic_move=True)

    def _abs(self, path: str) -> Path:
        p = (self.root / str(path).lstrip("/")).resolve()
        if not (p == self.root or self.root in p.parents):
            raise StorageError(f"path fuori dalla root: {path}")
        return p

    def list(self, path: str) -> list[Entry]:
        d = self._abs(path)
        if not d.is_dir():
            return []
        out: list[Entry] = []
        for c in sorted(d.iterdir()):
            if c.is_dir():
                out.append(Entry(c.name, "dir", 0))
            else:
                out.append(Entry(c.name, "file", c.stat().st_size))
        return out

    def read(self, path: str) -> ReadResult:
        f = self._abs(path)
        if not f.is_file():
            raise NotFound(f"non trovato: {path}")
        data = f.read_bytes()
        return ReadResult(data, _version(data))

    def write(self, path: str, data: bytes, if_version: str | None = None) -> str:
        f = self._abs(path)
        f.parent.mkdir(parents=True, exist_ok=True)
        if if_version is not None:
            cur = _version(f.read_bytes()) if f.is_file() else None
            if cur != if_version:
                raise VersionConflict(
                    f"versione cambiata per {path}: attesa {if_version}, trovata {cur}")
        tmp = f.with_name(f.name + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, f)
        try:
            os.chmod(f, 0o600)
        except OSError:
            pass
        return _version(data)

    def mkdir(self, path: str) -> None:
        self._abs(path).mkdir(parents=True, exist_ok=True)

    def move(self, src: str, dst: str) -> None:
        s = self._abs(src)
        d = self._abs(dst)
        if not s.exists():
            raise NotFound(f"non trovato: {src}")
        d.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(s), str(d))

    def delete(self, path: str) -> None:
        p = self._abs(path)
        if p.is_dir():
            shutil.rmtree(p)
        elif p.is_file():
            p.unlink()

    def stat(self, path: str) -> Stat | None:
        p = self._abs(path)
        if not p.exists():
            return None
        st = p.stat()
        if p.is_dir():
            return Stat("", 0, st.st_mtime, "dir")
        data = p.read_bytes()
        return Stat(_version(data), st.st_size, st.st_mtime, "file")

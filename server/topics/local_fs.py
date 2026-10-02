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

from .storage import (LOCAL_SHARED_ROOT, Capability, Entry, NotFound,
                      ReadResult, Stat, Storage, StorageError, VersionConflict)


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

    def _is_shared(self, p: Path) -> bool:
        """`p` (già risolto, quindi ATTRAVERSO un eventuale symlink) sta sotto
        `LOCAL_SHARED_ROOT`? Un file scritto lì è letto/scritto anche
        dall'OWNER umano dal lato Mac — un altro account Unix — quindi non
        può nascere `0o600` (solo il proprietario, cioè il container) come il
        resto dello storage dei topic: sarebbe illeggibile dal Mac, lo stesso
        difetto scoperto da Davide il 23 set 2026 sulle directory, qui sui
        file. Il resto dello storage (dati privati del topic dietro il
        gateway) resta `0o600` — la relax vale SOLO per questa sottocartella,
        di proposito."""
        try:
            p.relative_to(self.root / LOCAL_SHARED_ROOT)
            return True
        except ValueError:
            return False

    # Modes of the shared folder (clodia-platform#498): read and written from
    # the Mac by the human owner — another Unix account — so group rw, and
    # directories enterable/writable by the group. The rest of the storage is
    # private to the gateway.
    SHARED_FILE_MODE = 0o664
    SHARED_DIR_MODE = 0o775
    PRIVATE_FILE_MODE = 0o600
    PRIVATE_DIR_MODE = 0o700

    def _set_mode(self, p: Path) -> None:
        """The mode `p` must have where it now lives. Never follows symlinks."""
        try:
            if p.is_symlink():
                return
            shared = self._is_shared(p)
            if p.is_dir():
                os.chmod(p, self.SHARED_DIR_MODE if shared else self.PRIVATE_DIR_MODE)
            elif p.is_file():
                os.chmod(p, self.SHARED_FILE_MODE if shared else self.PRIVATE_FILE_MODE)
        except OSError:
            pass

    def _set_tree_mode(self, top: Path) -> None:
        """`_set_mode` on `top` and everything under it, without following
        symlinks: a moved file keeps its SOURCE mode (`shutil.move`), so a file
        born 0600 in the private storage stayed unreadable from the Mac once
        moved into the shared folder (#498)."""
        self._set_mode(top)
        if top.is_dir() and not top.is_symlink():
            for dirpath, dirnames, filenames in os.walk(top, followlinks=False):
                for n in dirnames + filenames:
                    self._set_mode(Path(dirpath) / n)

    def _mkdirs(self, d: Path) -> None:
        """mkdir -p, giving every directory it CREATES the mode of where it is
        (0775 in the shared folder, instead of the umask's 0755)."""
        missing: list[Path] = []
        cur = d
        while not cur.exists() and cur != cur.parent:
            missing.append(cur)
            cur = cur.parent
        d.mkdir(parents=True, exist_ok=True)
        for m in reversed(missing):
            self._set_mode(m)

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
        self._mkdirs(f.parent)
        if if_version is not None:
            cur = _version(f.read_bytes()) if f.is_file() else None
            if cur != if_version:
                raise VersionConflict(
                    f"versione cambiata per {path}: attesa {if_version}, trovata {cur}")
        tmp = f.with_name(f.name + ".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, f)
        self._set_mode(f)
        return _version(data)

    def mkdir(self, path: str) -> None:
        self._mkdirs(self._abs(path))

    def move(self, src: str, dst: str) -> None:
        s = self._abs(src)
        d = self._abs(dst)
        if not s.exists():
            raise NotFound(f"non trovato: {src}")
        self._mkdirs(d.parent)
        shutil.move(str(s), str(d))
        # The moved tree takes the modes of where it landed (#498): shared ->
        # 0664/0775, private -> 0600/0700.
        self._set_tree_mode(d)

    def delete(self, path: str) -> None:
        p = self._abs(path)
        if p.is_dir():
            shutil.rmtree(p)
        elif p.is_file():
            p.unlink()

    def symlink(self, path: str, target_rel: str) -> None:
        """Crea un symlink a `path` verso `target_rel`, entrambi relativi a
        questa root: `_abs()` valida ANCHE il target, così un errore di path
        (o un tentativo di uscire dalla root) fallisce qui, non silenziosamente
        a runtime alla prima lettura. Solo directory: `local_folder_add` è
        l'unico chiamante e collega sempre cartelle."""
        p = self._abs(path)
        target_abs = self._abs(target_rel)
        if p.exists() or p.is_symlink():
            raise StorageError(f"esiste già: {path}")
        if not target_abs.is_dir():
            raise StorageError(f"target inesistente o non è una cartella: {target_rel}")
        p.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target_abs, p, target_is_directory=True)

    def chmod_shared(self, path: str) -> None:
        p = self._abs(path)
        os.chmod(p, 0o775)

    def unlink_symlink(self, path: str) -> None:
        """Rimuove `path` SOLO se è un symlink (`os.lstat`, non segue il
        link). Path NON risolto — a differenza di `_abs()`/`delete()`, che
        seguirebbero il link fino al target reale e agirebbero su quello.
        Verifica il confinamento sulla forma LESSICALE del path (nessun
        `resolve()`, di proposito) prima ancora di controllare cosa c'è."""
        p = (self.root / str(path).lstrip("/"))
        p_norm = Path(os.path.normpath(p))
        if not (p_norm == self.root or self.root in p_norm.parents):
            raise StorageError(f"path fuori dalla root: {path}")
        if not p.is_symlink():
            if not p.exists():
                raise NotFound(f"non trovato: {path}")
            raise StorageError(f"non è un symlink, rifiuto di toccarlo: {path}")
        p.unlink()

    def stat(self, path: str) -> Stat | None:
        p = self._abs(path)
        if not p.exists():
            return None
        st = p.stat()
        if p.is_dir():
            return Stat("", 0, st.st_mtime, "dir")
        data = p.read_bytes()
        return Stat(_version(data), st.st_size, st.st_mtime, "file",
                    md5=hashlib.md5(data).hexdigest())

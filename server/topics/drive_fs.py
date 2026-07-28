"""DriveStorage — backend `Storage` su Google Drive (Topic System v2, §3).

Implementa l'interfaccia filesystem astratta (read/write/list/move/delete/stat/
mkdir) sopra la Drive API: la "root" è una cartella Drive (folder_id) e i path
relativi del topic (es. "SEAL-1/demo/files/x.pdf") mappano su una gerarchia di
cartelle Drive sotto la root.

Disaccoppiato dalle credenziali: riceve un `service` googleapiclient già
costruito (il factory del TopicService lo fornisce dal vault). Versioning EMULATO
via md5Checksum di Drive (come local-fs usa sha256). supportsAllDrives ovunque
(funziona anche sugli Shared Drive).
"""
from __future__ import annotations

import io
import time

from .storage import (Capability, Entry, NotFound, ReadResult, Stat, Storage,
                      StorageError, VersionConflict)

_FOLDER_MIME = "application/vnd.google-apps.folder"
_ALL = {"supportsAllDrives": True}
_ALL_LIST = {"supportsAllDrives": True, "includeItemsFromAllDrives": True}


def _q(s: str) -> str:
    return s.replace("\\", "\\\\").replace("'", "\\'")


class DriveStorage(Storage):
    def __init__(self, service, root_folder_id: str, cache_ttl: float = 5.0):
        self._svc = service
        self._root = root_folder_id
        self._cache_ttl = max(0.0, float(cache_ttl))
        self._cache: dict[str, str] = {"": root_folder_id}  # path → id (cartelle/file)
        self._list_cache: dict[str, tuple[float, list[Entry]]] = {}
        self._read_cache: dict[str, tuple[float, ReadResult]] = {}

    def _cached(self, cache: dict, key: str):
        hit = cache.get(key)
        if hit and hit[0] > time.monotonic():
            return hit[1]
        cache.pop(key, None)
        return None

    def _remember(self, cache: dict, key: str, value) -> None:
        cache[key] = (time.monotonic() + self._cache_ttl, value)

    def _invalidate(self) -> None:
        self._cache = {"": self._root}
        self._list_cache.clear()
        self._read_cache.clear()

    # ── risoluzione path → id ────────────────────────────────────────────────
    def _norm(self, path: str) -> str:
        return (path or "").strip().strip("/")

    def _child(self, parent_id: str, name: str):
        """Ritorna (id, mimeType, md5, size, mtime) del figlio `name` in `parent_id`, o None."""
        res = self._svc.files().list(
            q=f"name = '{_q(name)}' and '{parent_id}' in parents and trashed = false",
            fields="files(id, mimeType, md5Checksum, size, modifiedTime)",
            pageSize=1, **_ALL_LIST).execute()
        files = res.get("files", [])
        return files[0] if files else None

    def _resolve(self, path: str):
        """Risolve un path relativo → metadata del nodo (dict Drive), o None."""
        rel = self._norm(path)
        if rel == "":
            return {"id": self._root, "mimeType": _FOLDER_MIME}
        parent = self._root
        parts = rel.split("/")
        for i, seg in enumerate(parts):
            sub = "/".join(parts[: i + 1])
            cached = self._cache.get(sub)
            if cached and i < len(parts) - 1:
                parent = cached
                continue
            child = self._child(parent, seg)
            if not child:
                return None
            if i < len(parts) - 1:
                self._cache[sub] = child["id"]
                parent = child["id"]
            else:
                return child
        return None

    def _resolve_id(self, path: str) -> str | None:
        node = self._resolve(path)
        return node["id"] if node else None

    def _ensure_dir(self, path: str) -> str:
        """Crea (idempotente) la catena di cartelle fino a `path`; ritorna l'id finale."""
        rel = self._norm(path)
        if rel == "":
            return self._root
        parent = self._root
        cur = ""
        for seg in rel.split("/"):
            cur = f"{cur}/{seg}".strip("/")
            if cur in self._cache:
                parent = self._cache[cur]
                continue
            child = self._child(parent, seg)
            if child and child["mimeType"] == _FOLDER_MIME:
                parent = child["id"]
            elif child:
                raise StorageError(f"'{cur}' esiste ed è un file, non una cartella")
            else:
                created = self._svc.files().create(
                    body={"name": seg, "mimeType": _FOLDER_MIME, "parents": [parent]},
                    fields="id", **_ALL).execute()
                parent = created["id"]
            self._cache[cur] = parent
        return parent

    # ── interfaccia Storage ──────────────────────────────────────────────────
    def capability(self) -> Capability:
        return Capability(name="google-drive", versioning="emulated", atomic_move=True)

    def list(self, path: str) -> list[Entry]:
        rel = self._norm(path)
        cached = self._cached(self._list_cache, rel)
        if cached is not None:
            return list(cached)
        node = self._resolve(path)
        if not node:
            return []
        res = self._svc.files().list(
            q=f"'{node['id']}' in parents and trashed = false",
            fields="files(id, name, mimeType, size, webViewLink, md5Checksum)", pageSize=1000,
            orderBy="folder,name", **_ALL_LIST).execute()
        out = []
        for f in res.get("files", []):
            mime = f.get("mimeType")
            kind = "dir" if mime == _FOLDER_MIME else "file"
            out.append(Entry(name=f["name"], kind=kind, size=int(f.get("size") or 0),
                             mime=mime, url=f.get("webViewLink"),
                             version=f.get("md5Checksum")))  # md5 dai metadati (no download)
        self._remember(self._list_cache, rel, out)
        return out

    def read(self, path: str) -> ReadResult:
        rel = self._norm(path)
        cached = self._cached(self._read_cache, rel)
        if cached is not None:
            return cached
        node = self._resolve(path)
        if not node or node["mimeType"] == _FOLDER_MIME:
            raise NotFound(f"non trovato: {path}")
        from googleapiclient.http import MediaIoBaseDownload
        buf = io.BytesIO()
        mime = node.get("mimeType", "")
        if mime == "application/vnd.google-apps.document":
            request = self._svc.files().export_media(
                fileId=node["id"], mimeType="text/plain")
        elif mime == "application/vnd.google-apps.spreadsheet":
            request = self._svc.files().export_media(
                fileId=node["id"],
                mimeType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        elif mime == "application/vnd.google-apps.presentation":
            request = self._svc.files().export_media(
                fileId=node["id"], mimeType="application/pdf")
        elif mime.startswith("application/vnd.google-apps."):
            raise StorageError(f"tipo Google non esportabile: {mime}")
        else:
            request = self._svc.files().get_media(fileId=node["id"], **_ALL)
        dl = MediaIoBaseDownload(buf, request)
        done = False
        while not done:
            _s, done = dl.next_chunk()
        result = ReadResult(data=buf.getvalue(), version=node.get("md5Checksum", ""))
        self._remember(self._read_cache, rel, result)
        return result

    def write(self, path: str, data: bytes, if_version: str | None = None) -> str:
        from googleapiclient.http import MediaInMemoryUpload
        rel = self._norm(path)
        parent_path, _, fname = rel.rpartition("/")
        parent_id = self._ensure_dir(parent_path)
        existing = self._child(parent_id, fname)
        if if_version is not None:
            cur = (existing or {}).get("md5Checksum") if existing else None
            if cur != if_version:
                raise VersionConflict(
                    f"versione cambiata per {path}: attesa {if_version}, trovata {cur}")
        media = MediaInMemoryUpload(data, resumable=False)
        if existing:
            f = self._svc.files().update(
                fileId=existing["id"], media_body=media,
                fields="md5Checksum", **_ALL).execute()
        else:
            f = self._svc.files().create(
                body={"name": fname, "parents": [parent_id]}, media_body=media,
                fields="id, md5Checksum", **_ALL).execute()
            self._cache[rel] = f["id"]
        version = f.get("md5Checksum", "")
        self._invalidate()
        self._remember(self._read_cache, rel, ReadResult(data=data, version=version))
        return version

    def mkdir(self, path: str) -> None:
        self._ensure_dir(path)
        self._list_cache.clear()

    def move(self, src: str, dst: str) -> None:
        node = self._resolve(src)
        if not node:
            raise NotFound(f"non trovato: {src}")
        rel = self._norm(dst)
        new_parent_path, _, new_name = rel.rpartition("/")
        new_parent_id = self._ensure_dir(new_parent_path)
        # parent attuale (per removeParents)
        meta = self._svc.files().get(fileId=node["id"], fields="parents", **_ALL).execute()
        old_parents = ",".join(meta.get("parents", []))
        self._svc.files().update(
            fileId=node["id"], addParents=new_parent_id, removeParents=old_parents,
            body={"name": new_name}, fields="id", **_ALL).execute()
        self._invalidate()

    def delete(self, path: str) -> None:
        node = self._resolve(path)
        if not node:
            return
        self._svc.files().update(fileId=node["id"], body={"trashed": True}, **_ALL).execute()
        self._invalidate()

    def stat(self, path: str) -> Stat | None:
        node = self._resolve(path)
        if not node:
            return None
        is_dir = node["mimeType"] == _FOLDER_MIME
        mtime = 0.0
        mt = node.get("modifiedTime")
        if mt:
            from datetime import datetime
            try:
                mtime = datetime.fromisoformat(mt.replace("Z", "+00:00")).timestamp()
            except ValueError:
                mtime = 0.0
        return Stat(version=node.get("md5Checksum", "") if not is_dir else "",
                    size=int(node.get("size") or 0), mtime=mtime,
                    kind="dir" if is_dir else "file",
                    md5=node.get("md5Checksum") if not is_dir else None)

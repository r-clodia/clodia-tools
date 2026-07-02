"""Remote pluggable dei topic — local-first + sync verso un backend remoto.

Modello (spec topic-remote-storage, 2 lug 2026): lo storage di un topic è SEMPRE
locale (sorgente di verità); un `Remote` opzionale sincronizza i file verso un
backend con un'interfaccia UNIFORME a 4 verbi + ciclo di vita:

    enable(config) · disable() · add(path) · commit(msg) · push() · pull() · status()

Protocolli:
- **git**  — i verbi mappano 1:1 su git; traccia l'intero albero (con .gitignore).
- **drive** — semantica nostra con due liste:
    sync-list = file soggetti a sync · push-list = sottoinsieme cambiato da pushare
  add→liste, commit→no-op, push→carica push-list (push-only, mai delete remoto),
  pull→scarica; i nuovi entrano in sync-list ma NON in push-list.

`disable()` torna SEMPRE a un local pulito PRESERVANDO i file (Prima Legge):
git → rimuove `.git`; drive → cancella lo stato delle liste.
"""
from __future__ import annotations

import abc
import hashlib
import json
import os
import subprocess
from pathlib import Path


class RemoteError(RuntimeError):
    pass


class RemoteConflict(RemoteError):
    """Conflitto sul pull da risolvere manualmente (git) → escala, non forzare."""


def _md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


class Remote(abc.ABC):
    """`files_dir` = cartella locale dei file del topic (contenuto condiviso)."""

    def __init__(self, files_dir: str):
        self.files_dir = Path(files_dir)

    @abc.abstractmethod
    def enable(self, config: dict) -> dict: ...
    @abc.abstractmethod
    def disable(self) -> None: ...
    @abc.abstractmethod
    def add(self, path: str) -> None: ...
    @abc.abstractmethod
    def commit(self, msg: str = "") -> None: ...
    @abc.abstractmethod
    def push(self) -> dict: ...
    @abc.abstractmethod
    def pull(self) -> dict: ...
    @abc.abstractmethod
    def status(self) -> dict: ...


# ─────────────────────────────────────────────────────────────────────────────
class GitRemote(Remote):
    """Remote git: i verbi mappano su git, traccia l'intero albero di files_dir."""

    def _git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        return subprocess.run(["git", "-C", str(self.files_dir), *args],
                              capture_output=True, text=True, check=check)

    def _has_git(self) -> bool:
        return (self.files_dir / ".git").is_dir()

    def _has_origin(self) -> bool:
        r = self._git("remote", check=False)
        return "origin" in (r.stdout or "").split()

    def enable(self, config: dict) -> dict:
        self.files_dir.mkdir(parents=True, exist_ok=True)
        if not self._has_git():
            self._git("init", "-q")
            self._git("symbolic-ref", "HEAD", "refs/heads/main", check=False)
        self._git("config", "user.name", config.get("user_name") or "Clodia R Olivay")
        self._git("config", "user.email", config.get("user_email") or "devnullboxx@gmail.com")
        url = (config.get("url") or "").strip()
        if url and not self._has_origin():
            self._git("remote", "add", "origin", url)
        self._git("add", "-A")
        # commit iniziale solo se c'è qualcosa da committare
        if self._git("status", "--porcelain").stdout.strip():
            self._git("commit", "-q", "-m", config.get("message") or "enable git remote")
        if url:
            self._git("push", "-q", "-u", "origin", "main", check=False)
        return self.status()

    def disable(self) -> None:
        import shutil
        gitdir = self.files_dir / ".git"
        if gitdir.is_dir():
            shutil.rmtree(gitdir)   # i file restano; sparisce solo il tracking

    def add(self, path: str) -> None:
        self._git("add", path if path else "-A")

    def commit(self, msg: str = "") -> None:
        self._git("add", "-A")
        if self._git("status", "--porcelain").stdout.strip():
            self._git("commit", "-q", "-m", msg or "update")

    def push(self) -> dict:
        if not self._has_origin():
            return {"pushed": False, "note": "nessun origin"}
        r = self._git("push", "-q", "origin", "HEAD", check=False)
        if r.returncode != 0:
            raise RemoteError(f"git push fallito: {(r.stderr or '')[:200]}")
        return {"pushed": True}

    def pull(self) -> dict:
        if not self._has_origin():
            return {"pulled": False, "note": "nessun origin"}
        r = self._git("pull", "--no-edit", check=False)
        blob = (r.stdout or "") + (r.stderr or "")
        if r.returncode != 0 or "CONFLICT" in blob:
            # non forzare: escala (come topic-management)
            raise RemoteConflict(f"git pull in conflitto: {blob[:200]}")
        return {"pulled": True}

    def status(self) -> dict:
        if not self._has_git():
            return {"type": "git", "enabled": False}
        dirty = len([l for l in self._git("status", "--porcelain").stdout.splitlines() if l.strip()])
        return {"type": "git", "enabled": True, "origin": self._has_origin(), "dirty": dirty}


# ─────────────────────────────────────────────────────────────────────────────
class DriveRemote(Remote):
    """Remote Drive: local-first + due liste. `state_path` persiste config+liste
    (nel control-plane del topic, FUORI da files_dir → non sincronizzato).
    `drive_factory(account)` → un oggetto DriveStorage sulla cartella remota."""

    def __init__(self, files_dir: str, state_path: str, drive_factory):
        super().__init__(files_dir)
        self.state_path = Path(state_path)
        self._drive_factory = drive_factory

    # ── stato (config + liste) ──────────────────────────────────────────────
    def _load(self) -> dict:
        if not self.state_path.is_file():
            return {"config": {}, "sync": [], "push": []}
        try:
            d = json.loads(self.state_path.read_text(encoding="utf-8"))
            d.setdefault("config", {}); d.setdefault("sync", []); d.setdefault("push", [])
            return d
        except (OSError, json.JSONDecodeError):
            return {"config": {}, "sync": [], "push": []}

    def _save(self, st: dict) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(json.dumps(st, ensure_ascii=False), encoding="utf-8")

    def _ds(self, st: dict):
        cfg = st.get("config") or {}
        folder = cfg.get("folder")
        if not folder:
            raise RemoteError("drive remote: nessun folder configurato")
        return self._drive_factory(cfg.get("account"), folder)

    # ── ciclo di vita + verbi ───────────────────────────────────────────────
    def enable(self, config: dict) -> dict:
        st = self._load()
        st["config"] = {"folder": config.get("folder"), "account": config.get("account")}
        st.setdefault("sync", []); st.setdefault("push", [])
        self._save(st)
        return self.status()

    def disable(self) -> None:
        if self.state_path.is_file():
            self.state_path.unlink()   # i file locali restano; sparisce solo lo stato sync

    def add(self, path: str) -> None:
        st = self._load()
        if path not in st["sync"]:
            st["sync"].append(path)
        if path not in st["push"]:
            st["push"].append(path)
        self._save(st)

    def commit(self, msg: str = "") -> None:
        return  # no-op per Drive

    def push(self) -> dict:
        st = self._load()
        pending = list(st.get("push") or [])
        if not pending:
            return {"pushed": 0}
        ds = self._ds(st)
        done = []
        for rel in pending:
            local = self.files_dir / rel
            if not local.is_file():
                done.append(rel); continue   # rimosso localmente: lo togliamo dalla push-list (push-only, non cancella su Drive)
            ds.write(rel, local.read_bytes())
            done.append(rel)
        st["push"] = [f for f in st["push"] if f not in done]
        self._save(st)
        return {"pushed": len([r for r in done])}

    def pull(self) -> dict:
        st = self._load()
        ds = self._ds(st)
        pulled = 0
        conflicts = []
        for rel in _walk_drive(ds, ""):
            local = self.files_dir / rel
            remote = ds.read(rel)
            if not local.exists():
                local.parent.mkdir(parents=True, exist_ok=True)
                local.write_bytes(remote.data)
                if rel not in st["sync"]:
                    st["sync"].append(rel)   # nuovo → sync-list, NON push-list
                pulled += 1
            else:
                if _md5(local.read_bytes()) == _md5(remote.data):
                    continue  # identico
                # last-writer-wins per-file: chi è più recente vince (mtime).
                rstat = ds.stat(rel)
                r_m = rstat.mtime if rstat else 0
                l_m = local.stat().st_mtime
                if r_m > l_m:
                    local.write_bytes(remote.data)   # remoto più recente → aggiorna locale
                    pulled += 1
                else:
                    conflicts.append(rel)            # locale più recente → non distruggo, sarà pushato
        self._save(st)
        return {"pulled": pulled, "conflicts": conflicts}

    def status(self) -> dict:
        st = self._load()
        cfg = st.get("config") or {}
        return {"type": "drive", "enabled": bool(cfg.get("folder")),
                "folder": cfg.get("folder"), "account": cfg.get("account"),
                "synced": len(st.get("sync") or []), "pending": len(st.get("push") or [])}


def _walk_drive(ds, rel: str):
    """Genera i path relativi dei FILE nella cartella Drive (ricorsivo)."""
    for e in ds.list(rel):
        child = f"{rel}/{e.name}".lstrip("/")
        if e.kind == "dir":
            yield from _walk_drive(ds, child)
        else:
            yield child


def make_remote(rtype: str, files_dir: str, state_path: str | None = None,
                drive_factory=None) -> Remote:
    if rtype == "git":
        return GitRemote(files_dir)
    if rtype == "drive":
        return DriveRemote(files_dir, state_path or str(Path(files_dir).parent / ".remote-drive.json"),
                           drive_factory)
    raise RemoteError(f"remote type non supportato: {rtype}")

"""Remote pluggable dei topic.

Git conserva il ciclo locale add/commit/push/pull. Per Drive la cartella remota
è invece il filesystem primario: i verbi di sync restano solo per compatibilità
e sono no-op espliciti.

    enable(config) · disable() · add(path) · commit(msg) · push() · pull() · status()

Protocolli:
- **git**  — i verbi mappano 1:1 su git; traccia l'intero albero (con .gitignore).
- **drive** — vista live, upload immediato e conflitti last-write-wins.

`disable()` rimuove il tracking; TopicService materializza prima i file Drive
nel filesystem locale.
"""
from __future__ import annotations

import abc
import json
import os
import subprocess
from pathlib import Path

from . import sync_filter as sf
from .sync_filter import SyncFilter


class RemoteError(RuntimeError):
    pass


class RemoteConflict(RemoteError):
    """Conflitto sul pull da risolvere manualmente (git) → escala, non forzare."""


# Report di sync stile spec `.remoteinclude`/`.remoteignore`: liste per-stato +
# conteggi. Usato da pull/push del DriveRemote.
_REPORT_STATES = (sf.SYNCED, sf.CONFLICT, sf.SKIP_INCLUDE, sf.SKIP_IGNORE,
                  sf.SKIP_HARD_DENY, sf.ERROR)


def _empty_report() -> dict:
    return {s: [] for s in _REPORT_STATES}


def _finalize(rep: dict) -> dict:
    return {**rep, "counts": {s: len(rep[s]) for s in _REPORT_STATES}}


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
    def unstage(self, path: str = "") -> None: ...
    @abc.abstractmethod
    def commit(self, msg: str = "") -> dict: ...
    @abc.abstractmethod
    def push(self) -> dict: ...
    @abc.abstractmethod
    def pull(self) -> dict: ...
    @abc.abstractmethod
    def status(self) -> dict: ...


# ─────────────────────────────────────────────────────────────────────────────
# Credential helper inline SCOPED a github.com: fornisce a git le credenziali per
# i push/pull HTTPS senza mai mettere il PAT in un URL, in .git/config o in argv —
# il valore vive SOLO in env `GIT_PAT`, letto dall'helper al volo. `x-access-token`
# è lo username convenzionale GitHub per l'auth via token.
_GH_CRED_HELPER = (
    "!f() { test \"$1\" = get && "
    "printf 'username=x-access-token\\npassword=%s\\n' \"$GIT_PAT\"; }; f"
)


class GitRemote(Remote):
    """Remote git: i verbi mappano su git, traccia l'intero albero di files_dir."""

    def __init__(self, files_dir: str, github_token: str | None = None):
        super().__init__(files_dir)
        # Passato SOLO per i remote github.com (lo scoping evita di inviare il PAT
        # ad altri host). None → nessuna credenziale iniettata.
        self._gh_token = github_token

    def _build(self, args) -> tuple[list[str], dict]:
        """Comando git + env. `GIT_TERMINAL_PROMPT=0` → mai prompt interattivo (su
        remote privati senza credenziali fallisce subito con errore chiaro invece di
        'could not read Username'). Se c'è un token GitHub, lo passa via helper
        scoped a github.com + env GIT_PAT."""
        cmd = ["git"]
        if self._gh_token:
            cmd += ["-c", f"credential.https://github.com.helper={_GH_CRED_HELPER}"]
        cmd += ["-C", str(self.files_dir), *args]
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        if self._gh_token:
            env["GIT_PAT"] = self._gh_token
        return cmd, env

    def _git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        cmd, env = self._build(args)
        return subprocess.run(cmd, capture_output=True, text=True, check=check, env=env)

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
        # stage FILTRATO (rispetta .remoteinclude/.remoteignore fin dal 1° commit)
        self._filtered_stage()
        if self._git("diff", "--cached", "--quiet", check=False).returncode != 0:
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

    def unstage(self, path: str = "") -> None:
        """Toglie dallo staging (index) — path vuoto = tutto. Equivalente di
        `git restore --staged`; su repo senza commit (HEAD assente) fallback a
        `rm --cached` che riporta i nuovi file a untracked."""
        args = ["reset", "-q", "HEAD", "--", path] if path else ["reset", "-q", "HEAD"]
        r = self._git(*args, check=False)
        if r.returncode != 0:
            self._git("rm", "-r", "-q", "--cached", "--ignore-unmatch",
                      path or ".", check=False)

    def _filtered_stage(self) -> dict:
        """Stage selettivo secondo `.remoteinclude`/`.remoteignore`: aggiunge i
        soli path inclusi, toglie dall'index quelli filtrati. Senza file di
        config il filtro permette tutto → equivale a `git add -A`. Ritorna il
        report per-stato."""
        flt = SyncFilter.from_files_dir(self.files_dir)
        rep = _empty_report()
        porcelain = self._git("status", "--porcelain", "--untracked-files=all").stdout.splitlines()
        for line in porcelain:
            if len(line) < 4:
                continue
            rel = line[3:].strip()
            if " -> " in rel:
                rel = rel.split(" -> ", 1)[1]
            rel = rel.strip('"')
            verdict = flt.evaluate(rel)
            if verdict == sf.INCLUDED:
                self._git("add", "--", rel, check=False)
                rep[sf.SYNCED].append(rel)
            else:
                self._git("rm", "-q", "--cached", "--ignore-unmatch", "--", rel, check=False)
                rep[verdict].append(rel)
        return _finalize(rep)

    def commit(self, msg: str = "") -> dict:
        report = self._filtered_stage()
        if self._git("diff", "--cached", "--quiet", check=False).returncode != 0:
            self._git("commit", "-q", "-m", msg or "update")
        return {"report": report}

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
        # Stato PER-FILE (vocabolario comune git/drive, consumato dalla UI):
        # synced (tracked pulito), modified (worktree sporco), staged (in index),
        # unsynced (untracked).
        porcelain = self._git("status", "--porcelain", "--untracked-files=all").stdout.splitlines()
        files: dict[str, str] = {}
        for line in porcelain:
            if len(line) < 4:
                continue
            x, y, rel = line[0], line[1], line[3:].strip()
            if " -> " in rel:                     # rename: "R  old -> new"
                rel = rel.split(" -> ", 1)[1]
            if x == "?":
                files[rel] = "unsynced"
            elif x != " ":
                files[rel] = "staged"
            elif y != " ":
                files[rel] = "modified"
        for rel in self._git("ls-files").stdout.splitlines():
            files.setdefault(rel, "synced")
        dirty = len([l for l in porcelain if l.strip()])
        counts = {s: sum(1 for v in files.values() if v == s)
                  for s in ("synced", "modified", "staged", "unsynced")}
        return {"type": "git", "enabled": True, "origin": self._has_origin(), "dirty": dirty,
                "files": files, "counts": counts}


# ─────────────────────────────────────────────────────────────────────────────
class DriveRemote(Remote):
    """Remote Drive live: Drive è il filesystem primario, senza staging locale."""

    def __init__(self, files_dir: str, state_path: str, drive_factory):
        super().__init__(files_dir)
        self.state_path = Path(state_path)
        self._drive_factory = drive_factory

    # ── stato (config + liste) ──────────────────────────────────────────────
    def _load(self) -> dict:
        if not self.state_path.is_file():
            return {"config": {}}
        try:
            d = json.loads(self.state_path.read_text(encoding="utf-8"))
            d.setdefault("config", {})
            return d
        except (OSError, json.JSONDecodeError):
            return {"config": {}}

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
        self._save({
            "config": {
                "folder": config.get("folder"),
                "account": config.get("account"),
            },
            "mode": "live",
        })
        return self.status()

    def disable(self) -> None:
        if self.state_path.is_file():
            self.state_path.unlink()

    def add(self, path: str) -> None:
        return None

    def unstage(self, path: str = "") -> None:
        return None

    def commit(self, msg: str = "") -> dict:
        return {
            "noop": True,
            "deprecated": True,
            "note": "Drive è live: ogni scrittura è già persistita",
        }

    def push(self) -> dict:
        return {
            "noop": True,
            "deprecated": True,
            "pushed": 0,
            "note": "Drive è live: non esiste una coda di push",
        }

    def pull(self) -> dict:
        return {
            "noop": True,
            "deprecated": True,
            "pulled": 0,
            "note": "Drive è live: le letture vedono già il remoto",
        }

    def status(self) -> dict:
        st = self._load()
        cfg = st.get("config") or {}
        enabled = bool(cfg.get("folder"))
        files: dict[str, str] = {}
        if enabled:
            for rel, _entry in _walk_drive(self._ds(st), ""):
                files[rel] = "synced"
        counts = {
            "synced": len(files),
            "modified": 0,
            "staged": 0,
            "unsynced": 0,
        }
        return {"type": "drive", "enabled": enabled,
                "folder": cfg.get("folder"), "account": cfg.get("account"),
                "mode": "live", "synced": len(files), "pending": 0,
                "files": files, "counts": counts,
                "last_write_wins": True}


def _walk_drive(ds, rel: str):
    """Genera ricorsivamente i file visibili nella cartella Drive."""
    for e in ds.list(rel):
        child = f"{rel}/{e.name}".lstrip("/")
        if e.kind == "dir":
            yield from _walk_drive(ds, child)
        else:
            yield child, e


def make_remote(rtype: str, files_dir: str, state_path: str | None = None,
                drive_factory=None, github_token: str | None = None) -> Remote:
    if rtype == "git":
        return GitRemote(files_dir, github_token=github_token)
    if rtype == "drive":
        return DriveRemote(files_dir, state_path or str(Path(files_dir).parent / ".remote-drive.json"),
                           drive_factory)
    raise RemoteError(f"remote type non supportato: {rtype}")

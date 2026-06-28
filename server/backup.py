"""Backup gestito della piattaforma (ISO 27001 A.8.13) via restic.

La datadir (`/datadir`, montata dal gateway) è lo stato completo dell'istanza:
vault (creds+topic), DB, PKI, agents, secrets. restic la salva su uno storage
off-site **cifrato lato-client** (AES-256, passphrase nel vault) → il provider
vede solo blob cifrati. Config e credenziali stanno nel vault (mai nel datadir
che si backuppa → niente circolarità), depositate dall'admin via la pagina
Settings. Il valore non transita mai dal modello.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

from . import vault

DATADIR = os.environ.get("CLODIA_DATA", "/datadir")
CRED = "backup_config"  # credenziale infra nel vault (no grant per-agente)
# Snapshot consistenti dei DB SQLite prima del backup.
_DBS = ["contacts.db", "data/tomato/leads.db"]
# Esclusioni: backup vecchi, cache, snapshot DB temporanei (rigenerati).
_EXCLUDES = ["*.bak-*", "topics-store.bak-*", "**/__pycache__", "**/*.pyc"]


def _cfg() -> dict | None:
    """Config backup dal vault, o None se non configurato."""
    if not vault.has_credential(CRED):
        return None
    try:
        return vault.read_internal(CRED)
    except Exception:
        return None


def _restic_env(cfg: dict) -> dict:
    """Env per restic: repository + passphrase + credenziali del backend."""
    env = dict(os.environ)
    env["RESTIC_REPOSITORY"] = cfg["repository"]
    env["RESTIC_PASSWORD"] = cfg["passphrase"]
    env.update(cfg.get("env", {}))  # AWS_*/B2_* a seconda del backend
    return env


def _run(args: list[str], cfg: dict, timeout: int = 1800) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["restic", *args], env=_restic_env(cfg),
        capture_output=True, text=True, timeout=timeout,
    )


# ── configurazione ───────────────────────────────────────────────────────────
def configure(body: dict) -> dict:
    """Deposita config+creds nel vault. body: {backend, repository, env{}, passphrase,
    retention{daily,weekly,monthly}, schedule}. passphrase vuota → disconnette."""
    pp = (body.get("passphrase") or "").strip()
    repo = (body.get("repository") or "").strip()
    if not pp and not repo:
        vault.remove(CRED)
        return {"configured": False}
    if not repo or not pp:
        raise ValueError("servono 'repository' e 'passphrase'")
    cfg = {
        "backend": body.get("backend", "s3"),
        "repository": repo,
        "env": {k: v for k, v in (body.get("env") or {}).items() if v},
        "passphrase": pp,
        "retention": body.get("retention") or {"daily": 7, "weekly": 4, "monthly": 6},
        "schedule": body.get("schedule") or "0 3 * * *",  # cron: ogni notte 03:00
    }
    vault.deposit(CRED, cfg, cred_type="backup_config", grant_agents=[])
    # init idempotente del repository (se non esiste)
    chk = _run(["cat", "config"], cfg, timeout=120)
    if chk.returncode != 0:
        init = _run(["init"], cfg, timeout=120)
        if init.returncode != 0 and "already initialized" not in (init.stderr or ""):
            raise RuntimeError(f"restic init fallito: {init.stderr[:300]}")
    return {"configured": True, "backend": cfg["backend"]}


def status() -> dict:
    cfg = _cfg()
    if not cfg:
        return {"configured": False}
    out = {"configured": True, "backend": cfg["backend"], "repository": cfg["repository"],
           "schedule": cfg["schedule"], "retention": cfg["retention"]}
    snaps = _run(["snapshots", "--json", "--latest", "1"], cfg, timeout=120)
    if snaps.returncode == 0:
        try:
            arr = json.loads(snaps.stdout or "[]")
            if arr:
                out["last_snapshot"] = {"time": arr[-1].get("time"), "id": arr[-1].get("short_id")}
        except Exception:
            pass
    return out


def snapshots() -> list[dict]:
    cfg = _cfg()
    if not cfg:
        return []
    r = _run(["snapshots", "--json"], cfg, timeout=120)
    if r.returncode != 0:
        raise RuntimeError(f"restic snapshots: {r.stderr[:300]}")
    arr = json.loads(r.stdout or "[]")
    return [{"id": s.get("short_id"), "time": s.get("time"),
             "paths": s.get("paths"), "tags": s.get("tags")} for s in arr]


def _snapshot_dbs(cfg: dict) -> None:
    """Snapshot consistenti dei DB SQLite in /datadir/.db-snapshots (inclusi nel backup)."""
    dst = Path(DATADIR) / ".db-snapshots"
    dst.mkdir(exist_ok=True)
    for db in _DBS:
        src = Path(DATADIR) / db
        if src.exists():
            out = dst / f"{src.name}"
            subprocess.run(["sqlite3", str(src), f".backup '{out}'"],
                           capture_output=True, text=True, timeout=300)


def run_backup() -> dict:
    """Backup completo: snapshot DB → restic backup datadir → forget retention → check."""
    cfg = _cfg()
    if not cfg:
        raise RuntimeError("backup non configurato")
    _snapshot_dbs(cfg)
    excludes = []
    for e in _EXCLUDES:
        excludes += ["--exclude", e]
    b = _run(["backup", DATADIR, "--tag", "platform", *excludes], cfg, timeout=3600)
    result = {"backup_rc": b.returncode, "backup_err": b.stderr[-400:] if b.returncode else ""}
    if b.returncode != 0:
        raise RuntimeError(f"restic backup fallito: {b.stderr[:400]}")
    ret = cfg["retention"]
    f = _run(["forget", "--prune", "--tag", "platform",
              "--keep-daily", str(ret.get("daily", 7)),
              "--keep-weekly", str(ret.get("weekly", 4)),
              "--keep-monthly", str(ret.get("monthly", 6))], cfg, timeout=1800)
    result["forget_rc"] = f.returncode
    c = _run(["check"], cfg, timeout=600)
    result["check_rc"] = c.returncode
    result["ok"] = b.returncode == 0 and c.returncode == 0
    return result


def restore_test() -> dict:
    """Restore-test (A.8.13): ripristina l'ultimo snapshot in dir temp e verifica
    che i file chiave esistano. Evidenza che il backup è ripristinabile."""
    cfg = _cfg()
    if not cfg:
        raise RuntimeError("backup non configurato")
    with tempfile.TemporaryDirectory(prefix="restic-test-") as tmp:
        r = _run(["restore", "latest", "--target", tmp,
                  "--include", f"{DATADIR}/clodia-vault/topics-store"], cfg, timeout=1800)
        if r.returncode != 0:
            raise RuntimeError(f"restore-test fallito: {r.stderr[:300]}")
        restored = list(Path(tmp).rglob("meta.json"))
        return {"ok": len(restored) > 0, "restored_topics": len(restored)}


# ── superficie conversazionale (tool settings.*): MAI segreti ────────────────
def config_redacted() -> dict:
    """Config backup SENZA segreti (per la chat con l'agente): backend, repository,
    schedule, retention, stato, ultimo snapshot, e quali credenziali risultano
    impostate (booleani). passphrase / access keys NON sono mai esposte."""
    cfg = _cfg()
    base = status()  # configured/backend/repository/schedule/retention/last_snapshot
    if cfg:
        base["has_passphrase"] = bool(cfg.get("passphrase"))
        base["credentials_set"] = sorted(cfg.get("env", {}).keys())
    return base


_NONSECRET_FIELDS = {"backend", "repository", "schedule", "retention"}


def set_config(patch: dict) -> dict:
    """Aggiorna SOLO i campi non-segreti (backend/repository/schedule/retention),
    preservando passphrase e credenziali esistenti. NON accetta passphrase/env via
    questo path: le credenziali sensibili si impostano solo dalla pagina Settings
    (paste-key). Se il backup non è ancora configurato, rifiuta (servono prima le
    credenziali via UI)."""
    cfg = _cfg()
    if not cfg:
        raise RuntimeError("backup non ancora configurato: imposta prima credenziali e passphrase dalla pagina Settings (paste-key).")
    rejected = sorted(set(patch) - _NONSECRET_FIELDS)
    clean = {k: v for k, v in patch.items() if k in _NONSECRET_FIELDS}
    cfg.update(clean)
    vault.deposit(CRED, cfg, cred_type="backup_config", grant_agents=[])
    return {"updated": sorted(clean.keys()), "rejected": rejected, "config": config_redacted()}

"""Backup gestito della piattaforma (ISO 27001 A.8.13) via restic.

Perimetro = datadir + (se separata) la directory dello stato decisionale del
gateway (`CLODIA_TOOLS_STATE_DIR`, clodia-platform#80): da quando whitelist,
consensi e deleghe vivono fuori dalla datadir condivisa, restic deve salvarli
esplicitamente, altrimenti l'isolamento li farebbe uscire dal backup.

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
from datetime import datetime, timezone
from pathlib import Path

from . import state_paths, vault

DATADIR = os.environ.get("CLODIA_DATA", "/datadir")
CRED = "backup_config"  # credenziale infra nel vault (no grant per-agente)
# Stato dell'ultimo run di backup (esito + istante), persistito nel vault: serve
# a mostrare l'ultimo backup ESEGUITO anche quando FALLISCE (un fail non lascia
# snapshot restic, quindi last_snapshot da solo non basta).
LAST_RUN_CRED = "backup_last_run"
# Snapshot consistenti dei DB SQLite prima del backup (path relativi alla
# datadir). Configurabile per-istanza: CLODIA_BACKUP_DBS="a.db,b/c.db".
# Default vuoto: restic copre comunque l'intera datadir; lo snapshot serve
# solo alla consistenza transazionale di DB scritti di frequente.
_DBS = [d.strip() for d in (os.environ.get("CLODIA_BACKUP_DBS") or "").split(",") if d.strip()]
# Esclusioni: backup vecchi, cache, snapshot DB temporanei (rigenerati).
_EXCLUDES = ["*.bak-*", "topics-store.bak-*", "**/__pycache__", "**/*.pyc"]

#: restic esce **3** quando lo snapshot è stato creato ma qualche file non si è
#: potuto leggere. È un esito diverso da 1 (fallimento): una copia utilizzabile
#: esiste. Trattarlo come un fallimento costava tre cose in una volta — il run
#: risultava fallito pur avendo prodotto uno snapshot valido, e soprattutto
#: l'eccezione saltava `forget` e `check`, quindi la retention non girava e il
#: repository non veniva verificato. Osservato il 4 set 2026: snapshot 27fa63c7
#: creato alle 07:21, run marcato fallito alle 07:22, nessuna verifica.
_RESTIC_INCOMPLETO = 3


def _spawn_excludes() -> list[str]:
    """Le directory di lavoro degli spawn, che spariscono mentre restic legge.

    Uno spawn (`avvocato-27`) nasce e muore col turno: se termina durante il
    backup, restic trova la directory nell'elenco e non più sul filesystem, e
    l'errore che ne esce (`xattr.list … no such file or directory`) faceva
    fallire l'intero run. Non sono un dato da conservare: sono copie di lavoro
    rigenerate a ogni spawn.

    Il pattern chiude sulle CIFRE finali — uno spawn è `<seed>-<n>` — e non su
    `spawns/*` né su `*-*`: entrambi catturerebbero `spawn-seq.json`, che è il
    contatore degli ordinali e ha un trattino nel nome. Perderlo farebbe
    ripartire la numerazione su nomi già usati. Un test lo verifica, ed è così
    che il primo pattern che avevo scritto è stato scartato.
    """
    base = os.path.join(DATADIR, "spawns")
    # Fino a quattro cifre: `filepath.Match` di Go (che restic usa) ha le classi
    # di caratteri ma non i quantificatori, quindi le lunghezze si elencano.
    return [os.path.join(base, "*-" + "[0-9]" * n) for n in range(1, 5)]


def _declared_dbs() -> list[str]:
    """Datastore dichiarati dai plugin installati (perimetro dinamico).

    Scansiona CLODIA_DATA/plugins/*/plugin.yaml alla ricerca del campo
    `datastores:` (dichiarazione curated del pack developer, propagata
    dall'import a partire da plugin.json). Ogni entry con `backup: true`
    (default) entra nello snapshot pre-restic; il path è relativo alla
    datadir del plugin → `plugins/<nome>/<path>`. Ricalcolato a ogni run:
    un pack importato dopo la configurazione del backup è coperto senza
    toccare l'env.
    """
    import yaml

    found: list[str] = []
    for manifest in sorted(Path(DATADIR).glob("plugins/*/plugin.yaml")):
        try:
            meta = yaml.safe_load(manifest.read_text()) or {}
        except Exception:
            continue
        if not isinstance(meta, dict):
            continue
        for ds in meta.get("datastores") or []:
            if not isinstance(ds, dict) or not ds.get("path"):
                continue
            if ds.get("backup", True):
                rel = Path("plugins") / manifest.parent.name / str(ds["path"])
                found.append(str(rel))
    return found


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


def _record_last_run(ok: bool, error: str = "") -> None:
    """Persiste l'esito dell'ultimo run di backup nel vault (non è un segreto)."""
    rec = {"time": datetime.now(timezone.utc).isoformat(timespec="seconds"), "ok": bool(ok)}
    if error:
        rec["error"] = error[:300]
    try:
        vault.deposit(LAST_RUN_CRED, rec, cred_type="backup_state", grant_agents=[])
    except Exception:
        pass


def _last_run() -> dict | None:
    if not vault.has_credential(LAST_RUN_CRED):
        return None
    try:
        return vault.read_internal(LAST_RUN_CRED)
    except Exception:
        return None


def status() -> dict:
    cfg = _cfg()
    if not cfg:
        return {"configured": False}
    out = {"configured": True, "backend": cfg["backend"], "repository": cfg["repository"],
           "schedule": cfg["schedule"], "retention": cfg["retention"],
           "db_perimeter": {"env": _DBS, "declared": _declared_dbs()}}
    # Ultimo backup ESEGUITO (anche fallito): dal nostro record.
    lr = _last_run()
    if lr:
        out["last_run"] = {k: lr.get(k) for k in ("time", "ok", "error") if lr.get(k) is not None}
    # Ultimo backup VALIDO: l'ultimo snapshot restic (restic tiene solo i successi).
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
    """Snapshot consistenti dei DB SQLite in /datadir/.db-snapshots (inclusi nel backup).

    Perimetro = env CLODIA_BACKUP_DBS + datastore dichiarati dai plugin.
    Nome snapshot dal path relativo (slash→__) per evitare collisioni fra
    plugin che dichiarano db omonimi.
    """
    dst = Path(DATADIR) / ".db-snapshots"
    dst.mkdir(exist_ok=True)
    seen: set[str] = set()
    for db in [*_DBS, *_declared_dbs()]:
        if db in seen:
            continue
        seen.add(db)
        src = Path(DATADIR) / db
        if src.exists():
            out = dst / db.replace("/", "__")
            subprocess.run(["sqlite3", str(src), f".backup '{out}'"],
                           capture_output=True, text=True, timeout=300)


def backup_targets() -> list[str]:
    """Path salvati da restic: la datadir e, se isolata, la directory dello stato
    decisionale del gateway (whitelist/gate/deleghe, clodia-platform#80)."""
    targets = [DATADIR]
    if state_paths.is_isolated():
        targets.append(str(state_paths.state_dir()))
    return targets


def run_backup() -> dict:
    """Backup completo: snapshot DB → restic backup datadir → forget retention → check."""
    cfg = _cfg()
    if not cfg:
        raise RuntimeError("backup non configurato")
    try:
        _snapshot_dbs(cfg)
        excludes = []
        for e in [*_EXCLUDES, *_spawn_excludes()]:
            excludes += ["--exclude", e]
        b = _run(["backup", *backup_targets(), "--tag", "platform", *excludes],
                 cfg, timeout=3600)
        result = {"backup_rc": b.returncode, "backup_err": b.stderr[-400:] if b.returncode else ""}
        # Uno snapshot INCOMPLETO è comunque uno snapshot: si prosegue con
        # retention e verifica, e lo si dice. Fermarsi qui lasciava il repository
        # senza `forget` né `check` per un file sparito durante la lettura.
        incompleto = b.returncode == _RESTIC_INCOMPLETO
        if b.returncode != 0 and not incompleto:
            raise RuntimeError(f"restic backup fallito: {b.stderr[:400]}")
        if incompleto:
            result["incomplete"] = True
            result["skipped"] = b.stderr[-400:]
        ret = cfg["retention"]
        f = _run(["forget", "--prune", "--tag", "platform",
                  "--keep-daily", str(ret.get("daily", 7)),
                  "--keep-weekly", str(ret.get("weekly", 4)),
                  "--keep-monthly", str(ret.get("monthly", 6))], cfg, timeout=1800)
        result["forget_rc"] = f.returncode
        c = _run(["check"], cfg, timeout=600)
        result["check_rc"] = c.returncode
        # `ok` resta la verifica del REPOSITORY: uno snapshot incompleto non è un
        # fallimento, ma non si tace — `incomplete` viaggia nel risultato e
        # l'avviso finisce nello stato, così un'incompletezza che si ripete si
        # vede invece di sparire in un `ok` verde.
        result["ok"] = c.returncode == 0
        _record_last_run(result["ok"],
                         (f"snapshot incompleto: {result.get('skipped', '')[:200]}"
                          if incompleto else "")
                         if result["ok"] else f"check_rc={c.returncode}")
        return result
    except Exception as e:
        # Registra il FALLIMENTO (l'ultimo backup eseguito è fallito) poi rilancia.
        _record_last_run(False, str(e))
        raise


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

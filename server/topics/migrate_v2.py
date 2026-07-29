"""Migrazione offline Topic schema v2.

Uso:
    python3 -m server.topics.migrate_v2 --root /datadir/clodia-vault/topics-store

La migrazione è conservativa:
- crea un backup tar.gz pre-flight della root topic
- normalizza ogni meta.json a schema_version=2
- rimuove il campo meta `minutes`
- sposta eventuali directory minutes/ in .migrated-from-v1/minutes/
- verifica conteggi topic prima/dopo e campi v2 obbligatori
"""
from __future__ import annotations

import argparse
import json
import tarfile
from datetime import datetime, timezone
from pathlib import Path

from .service import SCHEMA_VERSION, VALID_TIER, normalize_meta_v2


def _backup(root: Path, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    dest = out_dir / f"topics-store-pre-v2-{stamp}.tar.gz"
    with tarfile.open(dest, "w:gz") as tar:
        tar.add(root, arcname="topics-store")
    return dest


def _topic_dirs(root: Path) -> list[Path]:
    out: list[Path] = []
    for tier in VALID_TIER:
        tier_dir = root / tier
        if not tier_dir.is_dir():
            continue
        out.extend(p for p in sorted(tier_dir.iterdir()) if p.is_dir())
    return out


def migrate(root: Path, dry_run: bool = False, backup_dir: Path | None = None) -> dict:
    if not root.is_dir():
        raise SystemExit(f"root topic non trovata: {root}")
    topics = _topic_dirs(root)
    backup_path = None if dry_run else _backup(root, backup_dir or (root.parent / "backups"))
    changed = 0
    moved_minutes = 0
    errors: list[str] = []
    for topic_dir in topics:
        tier = topic_dir.parent.name
        meta_path = topic_dir / "meta.json"
        if not meta_path.is_file():
            errors.append(f"{topic_dir}: meta.json assente")
            continue
        try:
            before = json.loads(meta_path.read_text(encoding="utf-8"))
            after = normalize_meta_v2(before, tier)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{topic_dir}: meta non valido: {exc}")
            continue
        minutes = topic_dir / "minutes"
        had_minutes = minutes.is_dir()
        if not dry_run:
            if after != before:
                meta_path.write_text(json.dumps(after, ensure_ascii=False, indent=2), encoding="utf-8")
            if minutes.is_dir():
                target = topic_dir / ".migrated-from-v1" / "minutes"
                target.parent.mkdir(parents=True, exist_ok=True)
                if not target.exists():
                    minutes.rename(target)
                else:
                    errors.append(f"{topic_dir}: target minutes migrato già esistente")
        changed += int(after != before)
        moved_minutes += int(had_minutes)
    # Verifica post: conteggio stabile + campi v2 obbligatori.
    post_topics = _topic_dirs(root)
    if len(post_topics) != len(topics):
        errors.append(f"conteggio topic cambiato: prima={len(topics)} dopo={len(post_topics)}")
    if not dry_run:
        for topic_dir in post_topics:
            try:
                meta = json.loads((topic_dir / "meta.json").read_text(encoding="utf-8"))
                if meta.get("schema_version") != SCHEMA_VERSION:
                    errors.append(f"{topic_dir}: schema_version non v{SCHEMA_VERSION}")
                if "deadline" not in meta or "status" not in meta:
                    errors.append(f"{topic_dir}: deadline/status mancanti")
                if (topic_dir / "minutes").exists():
                    errors.append(f"{topic_dir}: minutes/ ancora presente")
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{topic_dir}: verifica fallita: {exc}")
    return {
        "root": str(root),
        "dry_run": dry_run,
        "backup": str(backup_path) if backup_path else None,
        "topics_before": len(topics),
        "topics_after": len(post_topics),
        "meta_changed": changed,
        "minutes_moved": moved_minutes,
        "errors": errors,
        "ok": not errors,
    }


def main() -> int:
    p = argparse.ArgumentParser(description="Migra topics-store allo schema topic v2")
    p.add_argument("--root", required=True, type=Path)
    p.add_argument("--backup-dir", type=Path)
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()
    result = migrate(args.root, dry_run=args.dry_run, backup_dir=args.backup_dir)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""One-shot migration: legacy pack datastore files become instances (#685).

Until clodia-platform#684 a pack shipped a database (`datastores: [{path:
data/x.db}]`) and its MCP wrote into it — one file for everybody: Tomato's
books and Uncommon's would have ended up in the same `contabilita.db`. Now a
pack declares structures and every database is an instance
`<pack>/<structure>:<name>`. This script turns each legacy file into an
instance — same bytes, moved to `CLODIA_DATA/datastores/<pack>/<structure>/
<name>.db` — and rewrites everything that named it:

- the catalogue entry `datastore:<pack>/<name>` → `datastore:<pack>/<name>:<instance>`
  (tier, admin-set level and importers kept);
- every topic/DM import (`meta.data`);
- the job imports live in the agent-server: the mapping is written to
  `CLODIA_DATA/datastores/legacy-migration.json`, which clodia-logic's
  `python -m server.scheduler.migrate_job_data` applies.

Usage (in the gateway container, at a quiet moment):

    python -m server.migrate_legacy_datastores                 # dry run: the report only
    python -m server.migrate_legacy_datastores --apply
    python -m server.migrate_legacy_datastores --name base-pack/contacts=crm --apply
    python -m server.migrate_legacy_datastores --include-declared --apply

Which files are candidates:

1. **after the pack's update** (the normal path): the pack now declares the
   structure `<name>` with a `schema`, the catalogue still lists the old key
   `datastore:<pack>/<name>`, and the old file is still in the plugin's
   folder (`plugins/<pack>/**/<name>.db`). Migrated by `--apply`.
2. **still declared the legacy way** (`path:` in the installed manifest): the
   pack has not moved to structures yet, so its MCP — if it has one — may
   still open the file by path and would create an empty one after the move.
   Listed, migrated only with `--include-declared`, and never when the plugin
   declares MCP servers (update the pack first).

Instance name: `--name <pack>/<datastore>=<instance>`, else the known names
below (`assetti-contabili/contabilita` → `tomato`, owner 15 Nov 2026), else
`default`. Idempotent: an already migrated file is not a candidate any more.
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import data_catalog as cat
from . import datastores

#: Instance names decided by the owner for existing pack datastores.
KNOWN_NAMES = {"assetti-contabili/contabilita": "tomato"}
DEFAULT_NAME = "default"
MAP_FILE = "legacy-migration.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _legacy_file(pack: str, name: str) -> Path | None:
    root = Path(datastores.DATADIR) / "plugins" / pack
    if not root.is_dir():
        return None
    hits = sorted(p for p in root.rglob(f"{name}.db") if p.is_file())
    if not hits:
        return None
    preferred = [p for p in hits if p.parent.name == "data"]
    return (preferred or hits)[0]


def candidates(names: dict[str, str] | None = None) -> list[dict]:
    """Every legacy pack datastore file that can become an instance, with
    what would happen to it (`action`: migrate | skip, `reason`)."""
    names = dict(names or {})
    structs = datastores.structures()
    registry = datastores.instance_registry()
    migrated = {m.get("legacy_of") for m in registry.values() if isinstance(m, dict)}
    out: list[dict] = []
    seen: set[str] = set()
    manifests = {pack: meta for pack, _r, meta in datastores._manifests()}

    def add(old: str, path: Path | None, kind: str, st: dict | None):
        if old in seen:
            return
        seen.add(old)
        pack, name = old.split("/", 1)
        inst = names.get(old) or KNOWN_NAMES.get(old) or DEFAULT_NAME
        new = datastores.instance_id(old, inst)
        row = {"from": old, "to": new, "file": str(path) if path else None, "kind": kind,
               "target": str(datastores.instance_file(pack, name, inst)),
               "action": "migrate", "reason": ""}
        servers = (manifests.get(pack) or {}).get("mcp_servers") or {}
        if old in migrated:
            row.update(action="skip", reason="già migrato")
        elif not datastores.INSTANCE_RE.match(inst):
            row.update(action="skip", reason=f"nome d'istanza non valido: '{inst}'")
        elif cat.tombstoned("datastore", old):
            row.update(action="skip", reason="eliminato (tombstone)")
        elif path is None or not path.is_file():
            row.update(action="skip", reason="file assente")
        elif new in registry or Path(row["target"]).exists():
            row.update(action="skip", reason=f"esiste già '{new}'")
        elif cat.tombstoned("datastore", new):
            row.update(action="skip", reason=f"'{new}' è stato eliminato: scegli un altro nome")
        elif kind == "declared" and servers:
            row.update(action="needs-pack-update",
                       reason=("il pack dichiara ancora il file e ha server MCP "
                               f"({', '.join(sorted(servers))}) che possono aprirlo per path: "
                               "aggiorna prima il pack"))
        elif kind == "declared":
            row.update(action="needs-flag", reason="dichiarato col vecchio formato: --include-declared")
        row["tier"] = _tier(old, st)
        out.append(row)

    # 1. structures whose old flat key is still in the catalogue
    for e in cat.entries():
        if e["kind"] != "datastore":
            continue
        old = e["name"]
        pack, _, name = old.partition("/")
        if pack == datastores.PLATFORM or datastores.INSTANCE_SEP in name:
            continue
        st = structs.get(old)
        if st is None or st["legacy"]:
            continue
        add(old, _legacy_file(pack, name), "structure", st)
    # 2. legacy `path:` declarations
    for ds in datastores._legacy_entries():
        old = f"{ds['pack']}/{ds['name']}"
        add(old, Path(ds["abs_path"]), "declared", structs.get(old))
    return out


def _tier(old: str, st: dict | None) -> str:
    try:
        e = cat.get("datastore", old)
    except Exception:  # noqa: BLE001
        e = None
    if e:
        return cat.effective_tier(e)
    if st and st.get("tier_hint"):
        return st["tier_hint"]
    return "SEAL-4"


def _move(src: Path, dst: Path) -> None:
    """Same bytes: checkpoint the WAL into the file, then rename it (and any
    leftover companion files) to the instance's place."""
    conn = sqlite3.connect(str(src), timeout=10)
    try:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        conn.close()
    dst.parent.mkdir(parents=True, exist_ok=True)
    os.replace(src, dst)
    for suffix in ("-wal", "-shm", "-journal"):
        side = src.with_name(src.name + suffix)
        if side.exists():
            os.replace(side, dst.with_name(dst.name + suffix))


def _rewrite_topics(old: str, new: str) -> list[str]:
    from . import topic_data
    svc = topic_data._svc()
    done = []
    for row in svc.list(include_archived=True):
        try:
            if topic_data.rename_import(row["tier"], row["name"], "datastore", old, new):
                done.append(f"{row['tier']}/{row['name']}")
        except Exception as e:  # noqa: BLE001 — reported, the rest goes on
            done.append(f"{row['tier']}/{row['name']}: ERRORE {type(e).__name__}: {str(e)[:120]}")
    return done


def apply(rows: list[dict], *, include_declared: bool = False) -> list[dict]:
    """Migrate the rows marked `migrate` (and `needs-flag` with
    `include_declared`). Each row gets `done` (bool) and what moved."""
    mapping = {}
    for row in rows:
        go = row["action"] == "migrate" or (include_declared and row["action"] == "needs-flag")
        if not go:
            row["done"] = False
            continue
        old, new = row["from"], row["to"]
        pack, name = old.split("/", 1)
        inst = new.rsplit(datastores.INSTANCE_SEP, 1)[1]
        st = datastores.structure(old)
        src, dst = Path(row["file"]), Path(row["target"])
        _move(src, dst)
        reg = datastores.instance_registry()
        reg[new] = {"structure": old, "name": inst, "tier": row["tier"],
                    "purpose": None, "pii": None, "backup": None,
                    # The legacy file is taken to be at the schema its pack
                    # ships now: a structure without migrations is at 0.
                    "schema_version": max((st or {}).get("latest_version", 0), 0),
                    "created_by": "migration", "created_at": _now(),
                    "legacy_of": old, "legacy_path": str(src)}
        datastores.save_instance_registry(reg)
        moved = cat.rekey("datastore", old, new, migrated_from=old)
        if moved is None:
            cat.register("datastore", new, tier=row["tier"], source=f"pack:{pack}")
        row["topics"] = _rewrite_topics(old, new)
        row["catalog"] = "rekeyed" if moved else "registered"
        row["done"] = True
        mapping[f"datastore:{old}"] = f"datastore:{new}"
    if mapping:
        p = datastores.platform_dir() / MAP_FILE
        prev = {}
        try:
            prev = json.loads(p.read_text(encoding="utf-8")).get("map") or {}
        except (OSError, ValueError):
            pass
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"updated_at": _now(), "map": {**prev, **mapping}},
                                indent=1, ensure_ascii=False), encoding="utf-8")
    try:
        from . import authz_runtime
        authz_runtime.invalidate()
    except Exception:  # noqa: BLE001 — another process: its cache expires by itself
        pass
    return rows


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m server.migrate_legacy_datastores",
                                 description="Legacy pack datastore files → instances "
                                             "(clodia-platform#685). Dry run by default.")
    ap.add_argument("--apply", action="store_true", help="do it (default: report only)")
    ap.add_argument("--name", action="append", default=[], metavar="PACK/DS=INSTANCE",
                    help="instance name for one datastore (repeatable)")
    ap.add_argument("--include-declared", action="store_true",
                    help="also migrate files still declared with `path:` by a pack without MCP servers")
    args = ap.parse_args(argv)
    names = {}
    for item in args.name:
        k, sep, v = item.partition("=")
        if not sep or not k.strip() or not v.strip():
            ap.error(f"--name: atteso PACK/DS=INSTANCE, non '{item}'")
        names[k.strip()] = v.strip()
    rows = candidates(names)
    if args.apply:
        rows = apply(rows, include_declared=args.include_declared)
    print(json.dumps({"apply": bool(args.apply), "datadir": datastores.DATADIR,
                      "candidates": rows}, indent=1, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Datastore dichiarati dai pack installati — unica fonte di lettura.

`CLODIA_DATA/plugins/*/plugin.yaml` porta un campo `datastores:` (dichiarazione
curated del pack developer, propagata dall'import a partire da plugin.json/
pack.yaml — vedi clodia-logic `plugin_import.py::_sanitize_datastores`). Questo
modulo è il solo punto che lo percorre nel gateway: prima viveva duplicato
dentro `backup.py` (che lo usava per il perimetro di backup), ora serve anche
`_datastore_authorize` in `main.py` (the catalog entry the scope import is
checked against, clodia-platform#669: no seed allowlist). Una lettura sola,
due consumatori.
"""
from __future__ import annotations

import fcntl
import json
import logging
import os
import re
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

DATADIR = os.environ.get("CLODIA_DATA", "/datadir")
LOG = logging.getLogger("clodia-tools.datastores")

#: The pseudo-pack of the datastores an admin creates from the Databases page
#: (clodia-platform#671): `platform/<name>`, file `CLODIA_DATA/datastores/<name>.db`.
#: A pack cannot take this name (`plugin_import` refuses it, and `declared`
#: below skips a pack folder called so).
PLATFORM = "platform"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


def platform_dir() -> Path:
    return Path(DATADIR) / "datastores"


def _platform_registry() -> Path:
    return platform_dir() / "registry.json"


def platform_registry() -> dict:
    """`{name: {purpose, pii, clearance, created_by, created_at}}`."""
    try:
        data = json.loads(_platform_registry().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        LOG.error("platform datastores: registry unreadable (%s)", type(e).__name__)
        return {}


def save_platform_registry(data: dict) -> None:
    p = _platform_registry()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True, ensure_ascii=False),
                   encoding="utf-8")
    tmp.replace(p)


def _platform_declared() -> list[dict]:
    out = []
    for name, meta in sorted(platform_registry().items()):
        if not NAME_RE.match(str(name)) or not isinstance(meta, dict):
            continue
        out.append({
            "pack": PLATFORM, "name": name, "path": f"{name}.db",
            "abs_path": str((platform_dir() / f"{name}.db").resolve()),
            "purpose": str(meta.get("purpose") or ""), "pii": bool(meta.get("pii", False)),
            "backup": True, "clearance": str(meta.get("clearance") or "SEAL-4"),
            "seeds": [],
        })
    return out


def _tombstoned_keys() -> set[str]:
    try:
        from . import data_catalog
        return {k.split(":", 1)[1] for k in data_catalog.tombstones()
                if k.startswith("datastore:")}
    except Exception:  # noqa: BLE001 — no tombstones readable, none applied
        return set()


def _manifests() -> list[tuple[str, Path, dict]]:
    """`(pack, plugin dir, manifest)` of every installed plugin that parses."""
    import yaml

    out = []
    for manifest in sorted(Path(DATADIR).glob("plugins/*/plugin.yaml")):
        try:
            meta = yaml.safe_load(manifest.read_text()) or {}
        except Exception:
            continue
        if not isinstance(meta, dict):
            continue
        pack = manifest.parent.name
        if pack == PLATFORM:
            continue
        out.append((pack, manifest.parent, meta))
    return out


def _legacy_entries() -> list[dict]:
    """The pack datastores declared the old way, a shipped file (`path:`)."""
    found: list[dict] = []
    for pack, root, meta in _manifests():
        for ds in meta.get("datastores") or []:
            if not isinstance(ds, dict) or not ds.get("path") or ds.get("schema"):
                continue
            rel = str(ds["path"])
            name = str(ds.get("name") or Path(rel).stem)
            found.append({
                "pack": pack,
                "name": name,
                "path": rel,
                "abs_path": str((root / rel).resolve()),
                "purpose": str(ds.get("purpose") or ""),
                "pii": bool(ds.get("pii", False)),
                "backup": bool(ds.get("backup", True)),
                "clearance": str(ds.get("clearance") or "SEAL-4"),
            })
    return found


def declared() -> list[dict]:
    """Ogni entry: `{pack, name, path, abs_path, purpose, pii, backup,
    clearance}`. `path` è relativo alla cartella del pack; `abs_path` è già
    risolto sotto `CLODIA_DATA/plugins/<pack>/`. `clearance` mancante nel
    manifest → `SEAL-4`, fail-closed. A `seeds:` list in an older manifest is
    ignored (clodia-platform#669).

    Since clodia-platform#684 a pack declares STRUCTURES, never databases:
    every instance of a structure is an entry here too, named
    `<structure>:<instance>` (key `<pack>/<structure>:<instance>`), with its
    file under `CLODIA_DATA/datastores/<pack>/<structure>/` (`path` relative
    to `CLODIA_DATA`, `structure`, `instance`, `schema_version`). A legacy
    `path:` declaration is served as before until it has been migrated to an
    instance (`migrate_legacy_datastores`); after that its structure has
    instances and the old flat key is gone."""
    found: list[dict] = []
    migrated = {i["structure"] for i in instances()}
    for ds in _legacy_entries():
        if f"{ds['pack']}/{ds['name']}" in migrated:
            continue
        found.append(ds)
    found += _instance_declared()
    # The datastores created from the Databases page, then the tombstones:
    # a datastore deleted on purpose is not declared any more, even if its
    # pack still names it (#671).
    found += _platform_declared()
    dead = _tombstoned_keys()
    return [ds for ds in found if f"{ds['pack']}/{ds['name']}" not in dead]


# ── Structures and instances (clodia-platform#684, #685) ─────────────────────
#
# A pack declares datastore STRUCTURES (`datastores: [{name, schema,
# migrations?, purpose?, pii?, backup?, tier_hint?}]`); a structure has any
# number of INSTANCES, each created explicitly (`packs.create_datastore` or
# the Databases page). Ids: structure `<pack>/<structure>`, instance
# `<pack>/<structure>:<name>`. The registry of instances is gateway state
# (`state/datastore-instances.json`), the files live in the datadir (restic).

INSTANCE_SEP = ":"
INSTANCE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
_MIGRATION_RE = re.compile(r"^(\d{3,})_[A-Za-z0-9_.-]*\.sql$")


def _registry_path() -> Path:
    from . import state_paths
    return Path(state_paths.state_path("datastore-instances.json"))


def instance_registry() -> dict:
    """`{instance id: {structure, name, tier, purpose?, pii?, backup?,
    schema_version, created_by, created_at, path?, archived_at?, legacy_of?}}`.
    An unreadable registry is an error, never an empty one written over it."""
    p = _registry_path()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        raise RuntimeError(f"registro delle istanze illeggibile ({type(e).__name__}): {p}") from e


_REG_RLOCK = threading.RLock()
_REG_DEPTH = threading.local()


@contextmanager
def registry_lock():
    """Exclusive access to the instance registry, across threads AND
    processes (the one-off migration script runs beside the gateway): an
    in-process re-entrant lock plus `flock` on `datastore-instances.lock`,
    taken once at the outermost level."""
    with _REG_RLOCK:
        depth = getattr(_REG_DEPTH, "n", 0)
        if depth:
            _REG_DEPTH.n = depth + 1
            try:
                yield
            finally:
                _REG_DEPTH.n = depth
            return
        p = _registry_path().with_suffix(".lock")
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a+") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            _REG_DEPTH.n = 1
            try:
                yield
            finally:
                _REG_DEPTH.n = 0
                fcntl.flock(fh, fcntl.LOCK_UN)


def save_instance_registry(data: dict) -> None:
    p = _registry_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True, ensure_ascii=False),
                   encoding="utf-8")
    tmp.replace(p)


def instance_id(structure: str, name: str) -> str:
    return f"{structure}{INSTANCE_SEP}{name}"


def split_instance(key: str) -> tuple[str, str, str] | None:
    """`"<pack>/<structure>:<name>"` → `(pack, structure, name)`, else None."""
    s = str(key or "").strip()
    pack, _, rest = s.partition("/")
    structure, sep, name = rest.partition(INSTANCE_SEP)
    if not (pack and sep and structure and name):
        return None
    return pack, structure, name


def instance_file(pack: str, structure: str, name: str) -> Path:
    return platform_dir() / pack / structure / f"{name}.db"


def _confined(root: Path, rel: str) -> Path | None:
    """`root/rel`, resolved, only if it stays inside `root`."""
    rel = str(rel or "").strip()
    if not rel or rel.startswith(("/", "~")) or ".." in Path(rel).parts:
        return None
    p = (root / rel).resolve()
    try:
        inside = p.relative_to(root.resolve())
    except ValueError:
        return None
    if not inside.parts:
        return None             # the plugin's folder itself is not a schema or migrations dir
    return p


def migration_files(directory: str | Path | None) -> list[tuple[int, Path]]:
    """`[(version, file)]` of `NNN_description.sql` in `directory`, sorted.
    Two files with the same number: the directory is refused (ValueError)."""
    if not directory:
        return []
    d = Path(directory)
    if not d.is_dir():
        return []
    out: dict[int, Path] = {}
    for f in sorted(d.iterdir()):
        m = _MIGRATION_RE.match(f.name)
        if not m or not f.is_file():
            continue
        n = int(m.group(1))
        if n in out:
            raise ValueError(f"migrazioni: due file con il numero {n} in {d}")
        out[n] = f
    return sorted(out.items())


def structures() -> dict[str, dict]:
    """The structures of the installed packs, `{id: {...}}`:
    `{id, pack, name, schema, migrations, purpose, pii, backup, tier_hint,
    latest_version, legacy}`. `schema`/`migrations` are absolute paths
    confined to the plugin's folder (None when missing). A legacy `path:`
    declaration is a structure too (`legacy: True`, no schema): its file
    becomes an instance with the one-off migration; nobody creates new ones."""
    from . import data_catalog as _cat
    out: dict[str, dict] = {}
    for pack, root, meta in _manifests():
        for ds in meta.get("datastores") or []:
            if not isinstance(ds, dict):
                continue
            raw_hint = ds.get("tier_hint") if ds.get("schema") else ds.get("clearance")
            hint = _cat.norm_tier(raw_hint) if _cat.valid_tier(raw_hint) else None
            if ds.get("schema"):
                name = str(ds.get("name") or "").strip()
                if not NAME_RE.match(name):
                    LOG.warning("datastores: struttura senza nome valido in %s", pack)
                    continue
                schema = _confined(root, str(ds["schema"]))
                mig = _confined(root, str(ds.get("migrations") or "")) \
                    if ds.get("migrations") else None
                try:
                    latest = max((n for n, _f in migration_files(mig)), default=0)
                except ValueError as e:
                    LOG.error("datastores: %s/%s: %s", pack, name, e)
                    latest = -1
                legacy = False
            elif ds.get("path"):
                name = str(ds.get("name") or Path(str(ds["path"])).stem)
                schema, mig, latest, legacy = None, None, 0, True
            else:
                continue
            sid = f"{pack}/{name}"
            if sid in out:
                continue
            env_key = re.sub(r"[^A-Z0-9]", "_", name.upper())
            clash = next((o for o in out.values() if o["pack"] == pack
                          and re.sub(r"[^A-Z0-9]", "_", o["name"].upper()) == env_key), None)
            if clash is not None:
                # `a-b` and `a_b` would hand the MCP the same CLODIA_DATASTORE_A_B.
                LOG.error("datastores: %s: la struttura '%s' collide con '%s' "
                          "(stessa variabile d'ambiente): ignorata", pack, name, clash["name"])
                continue
            out[sid] = {
                "id": sid, "pack": pack, "name": name,
                "schema": str(schema) if schema and schema.is_file() else None,
                "migrations": str(mig) if mig else None,
                "purpose": str(ds.get("purpose") or ""), "pii": bool(ds.get("pii", False)),
                "backup": bool(ds.get("backup", True)), "tier_hint": hint,
                "latest_version": latest, "legacy": legacy,
                "legacy_path": str(ds["path"]) if legacy else None,
            }
    return out


def structure(sid: str) -> dict | None:
    return structures().get(str(sid or "").strip())


def _instance_abs(iid: str, meta: dict) -> Path:
    if meta.get("path"):
        return (Path(DATADIR) / str(meta["path"])).resolve()
    pack, struct, name = split_instance(iid) or ("", "", "")
    return instance_file(pack, struct, name).resolve()


def instances(*, include_archived: bool = False) -> list[dict]:
    """The registered instances, resolved against their structure:
    `{id, pack, structure, structure_name, name, tier, purpose, pii, backup,
    schema_version, created_by, created_at, abs_path, path, installed,
    archived_at, legacy_of}`. purpose/pii/backup are the instance's override
    when it has one, else the structure's.

    An instance whose pack is no longer installed and whose file is gone was
    archived with the pack (clodia-logic moves `datastores/<pack>/` into the
    plugin's archive): it is marked so once, and never listed again unless
    asked."""
    try:
        reg = instance_registry()
    except RuntimeError as e:
        LOG.error("datastores: %s", e)
        return []
    structs = structures()
    out = []
    marks: dict[str, str | None] = {}
    for iid, meta in sorted(reg.items()):
        parts = split_instance(iid)
        if not parts or not isinstance(meta, dict):
            continue
        pack, struct_name, name = parts
        sid = f"{pack}/{struct_name}"
        st = structs.get(sid)
        p = _instance_abs(iid, meta)
        if st is None and not meta.get("archived_at") and not p.exists():
            meta["archived_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
            marks[iid] = meta["archived_at"]
        elif st is not None and meta.get("archived_at") and p.is_file():
            # Its pack is back and its file was put back in place (from
            # `plugins-archive/…/datastores/`): the instance is usable again.
            meta["archived_at"] = None
            marks[iid] = None
        if meta.get("archived_at") and not include_archived:
            continue

        def pick(k, default):
            v = meta.get(k)
            return v if v is not None else (st or {}).get(k, default)
        try:
            rel = str(p.relative_to(Path(DATADIR).resolve()))
        except ValueError:
            rel = str(p)
        out.append({
            "id": iid, "pack": pack, "structure": sid, "structure_name": struct_name,
            "name": name, "tier": str(meta.get("tier") or "SEAL-4"),
            "purpose": str(pick("purpose", "") or ""), "pii": bool(pick("pii", False)),
            "backup": bool(pick("backup", True)),
            "schema_version": int(meta.get("schema_version") or 0),
            "created_by": meta.get("created_by") or "", "created_at": meta.get("created_at"),
            "abs_path": str(p), "path": rel, "installed": st is not None,
            "archived_at": meta.get("archived_at"), "legacy_of": meta.get("legacy_of"),
        })
    if marks:
        try:
            with registry_lock():
                fresh = instance_registry()
                for iid, mark in marks.items():
                    if isinstance(fresh.get(iid), dict):
                        fresh[iid]["archived_at"] = mark
                save_instance_registry(fresh)
        except (OSError, RuntimeError) as e:
            LOG.warning("datastores: archiviazione non registrata (%s)", type(e).__name__)
    return out


def _instance_declared() -> list[dict]:
    """The instances of INSTALLED structures, in the shape of `declared()`."""
    return [{
        "pack": i["pack"], "name": f"{i['structure_name']}{INSTANCE_SEP}{i['name']}",
        "path": i["path"], "abs_path": i["abs_path"], "purpose": i["purpose"],
        "pii": i["pii"], "backup": i["backup"], "clearance": i["tier"],
        "structure": i["structure"], "instance": i["name"],
        "schema_version": i["schema_version"],
    } for i in instances() if i["installed"]]


def find_instance(iid: str) -> dict | None:
    """The `declared()` entry of an instance id, or None (unknown, of a pack
    no longer installed, or deleted)."""
    parts = split_instance(iid)
    if not parts:
        return None
    return find(parts[0], f"{parts[1]}{INSTANCE_SEP}{parts[2]}")


def drop_instance(iid: str) -> bool:
    """Forget an instance (after the #671 delete has exported and removed its
    file). The tombstone, not the registry, keeps the name from coming back."""
    with registry_lock():
        reg = instance_registry()
        if reg.pop(iid, None) is None:
            return False
        save_instance_registry(reg)
        return True


def declared_collections() -> dict[str, dict]:
    """RAG collections declared by the installed packs (`rag_collections:` in
    `plugins/*/plugin.yaml`): `{name: {pack, tier}}`. `tier` is the declared
    level, `None` when missing or not a SEAL level — never a default. The pack
    provisioner may create and feed only these (clodia-platform#669: the
    exception is for initial provisioning). A manifest that does not parse
    declares nothing; for one name declared twice the first pack in
    alphabetical order wins (collection names are global in the RAG service)."""
    import yaml

    found: dict[str, dict] = {}
    for manifest in sorted(Path(DATADIR).glob("plugins/*/plugin.yaml")):
        try:
            meta = yaml.safe_load(manifest.read_text()) or {}
        except Exception:
            continue
        if not isinstance(meta, dict):
            continue
        for col in meta.get("rag_collections") or []:
            if not isinstance(col, dict):
                continue
            name = str(col.get("name") or "").strip()
            if not name or name in found:
                continue
            raw = str(col.get("tier") or "").strip().upper()
            raw = {"P0": "SEAL-0", "P1": "SEAL-1", "P2": "SEAL-2", "P3": "SEAL-3"}.get(raw, raw)
            tier = raw if raw in ("SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4") else None
            found[name] = {"pack": manifest.parent.name, "tier": tier}
    return found


def find(pack: str, name: str) -> dict | None:
    """Un'entry per `<pack>/<name>` esatti, o `None`."""
    for ds in declared():
        if ds["pack"] == pack and ds["name"] == name:
            return ds
    return None


def parse_key(key: str) -> tuple[str, str]:
    """`"<pack>/<name>"` → `(pack, name)`. Stessa forma delle chiavi di scope
    egress/topic (`<tier>/<name>`), per coerenza col resto del gateway."""
    s = (key or "").strip()
    if "/" not in s:
        raise ValueError(
            f"datastore non valido: '{key}' — atteso '<pack>/<nome>' "
            f"(es. 'base-pack/contacts')")
    pack, name = s.split("/", 1)
    if not pack or not name:
        raise ValueError(f"datastore non valido: '{key}'")
    return pack, name

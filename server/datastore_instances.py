"""Instances of pack datastore structures (clodia-platform#684: #685, #686, #687).

A pack defines datastore STRUCTURES (schema + migrations), never databases
(owner, 14-15 Nov 2026). Installing a pack creates no instance; each one is
created explicitly, any number of times per structure:

- **create** (`create`): `packs.create_datastore(structure, name, tier, …)`
  for agents (A·V·R·Q decides, default ask), `POST /internal/databases
  {action: create_instance}` for admins. The file is built from the
  structure's `schema`, its `schema_version` is the latest migration, and it
  enters the #671 catalogue as `datastore:<pack>/<structure>:<name>` — an
  ordinary resource: imported into scopes, deleted with the #671 flow (export
  first, tombstone), archived with its pack.
- **list** (`structures_view`): the structures of the installed packs with
  their instances — `packs.datastore_structures` and
  `GET /internal/databases/structures`.
- **resolve** (`resolve`): which instance of a structure a call in a scope
  works on — one import → that one, several → the call names it, none →
  refused. Used by the MCP proxy (a pack's MCP gets the instance's file in
  `CLODIA_DATASTORE_<STRUCTURE>`) and by `datastore.*` called with a
  structure id (the `<DATASTORE:name>` token of a skill).
- **migrate** (`migrate`): on pack update every instance below the latest
  `NNN_*.sql` is backed up (`CLODIA_DATA/migrations/`) and migrated in one
  transaction; a failure rolls back that instance only and is reported.

Nothing here decides access to the CONTENT of an instance: that stays
`topic_data.authorize` (scope import, clearance, scope tier), the one entry
point every datastore goes through.
"""
from __future__ import annotations

import logging
import os
import re
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import data_catalog as cat
from . import datastores

LOG = logging.getLogger("clodia-tools.datastore_instances")

#: The environment variable that carries an instance's file to a pack's MCP.
ENV_PREFIX = "CLODIA_DATASTORE_"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def env_name(structure_name: str) -> str:
    """`contabilita` → `CLODIA_DATASTORE_CONTABILITA` (`-` → `_`)."""
    return ENV_PREFIX + re.sub(r"[^A-Z0-9]", "_", str(structure_name).upper())


def _audit(action: str, resource: str, by: str, **details) -> None:
    from .audit import control as _control
    _control.safe(_control.emit, "databases", action, resource, by=by, **details)


# ── Create ───────────────────────────────────────────────────────────────────

def _valid_instance_name(name: str) -> str:
    name = str(name or "").strip()
    if not datastores.INSTANCE_RE.match(name):
        raise ValueError("nome dell'istanza non valido: minuscole, cifre e '-' "
                         "(max 41), iniziale lettera o cifra")
    return name


def _apply_script(conn: sqlite3.Connection, script: str) -> None:
    """Execute a SQL script statement by statement INSIDE the caller's
    transaction (`executescript` would commit first)."""
    buf = ""
    for line in script.splitlines(keepends=True):
        buf += line
        if sqlite3.complete_statement(buf):
            stmt = buf.strip()
            buf = ""
            if stmt and stmt != ";":
                conn.execute(stmt)
    if buf.strip():
        if sqlite3.complete_statement(buf + ";"):
            conn.execute(buf)
        else:
            raise ValueError("script SQL incompleto")


def _build_file(path: Path, schema: str, version: int) -> None:
    """The instance's file from the structure's schema, atomically: a
    half-built database never appears under the instance's name."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    os.close(fd)
    try:
        conn = sqlite3.connect(tmp, isolation_level=None)
        try:
            conn.execute("BEGIN")
            _apply_script(conn, Path(schema).read_text(encoding="utf-8"))
            conn.execute(f"PRAGMA user_version = {int(version)}")
            conn.execute("COMMIT")
        finally:
            conn.close()
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def entry_of(iid: str, *, scopes: list[str] | None = None) -> dict:
    """The catalogue row of an instance (the shape the WebUI reads)."""
    inst = next((i for i in datastores.instances() if i["id"] == iid), None)
    if inst is None:
        raise LookupError(f"istanza '{iid}' sconosciuta")
    e = cat.get("datastore", iid)
    return {
        "id": iid, "kind": "datastore", "name": iid, "key": f"datastore:{iid}",
        "pack": inst["pack"], "structure": inst["structure"], "instance": inst["name"],
        "tier": cat.effective_tier(e) if e else inst["tier"],
        "purpose": inst["purpose"], "pii": inst["pii"], "backup": inst["backup"],
        "schema_version": inst["schema_version"], "created_by": inst["created_by"],
        "created_at": inst["created_at"], "status": "active",
        "imported_by_scopes": list(scopes or []),
    }


def create(structure: str, name: str, *, tier: str, by: str, clearance: str | None,
           purpose: str | None = None, pii: bool | None = None,
           backup: bool | None = None) -> dict:
    """Create an EMPTY instance of `structure` (#685). Raises ValueError
    (bad input, duplicate), LookupError (no such structure), PermissionError
    (tier above the caller's clearance, name deleted on purpose)."""
    sid = str(structure or "").strip()
    st = datastores.structure(sid)
    if st is None:
        raise LookupError(f"struttura '{sid}' sconosciuta: non è dichiarata da un pack installato")
    if st["legacy"] or not st["schema"]:
        raise ValueError(f"la struttura '{sid}' non ha uno schema: non si possono crearne istanze")
    if st["latest_version"] < 0:
        raise ValueError(f"la struttura '{sid}' ha migrazioni non valide: correggi il pack")
    name = _valid_instance_name(name)
    if not cat.valid_tier(tier):
        raise ValueError(f"tier sconosciuto: '{tier}' (SEAL-0 … SEAL-4)")
    tier = cat.norm_tier(tier)
    if cat.rank_have(clearance) < cat.rank(tier):
        raise PermissionError(
            f"clearance di '{by}' ({clearance or 'nessuna'}) inferiore a {tier}: "
            f"non può creare un'istanza di quel livello")
    iid = datastores.instance_id(sid, name)
    if cat.tombstoned("datastore", iid):
        raise PermissionError(
            f"'{iid}' è stata eliminata: il nome resta riservato (ripristino dalla "
            "pagina Databases, o scegli un altro nome)")
    with datastores.registry_lock():
        reg = datastores.instance_registry()
        path = datastores.instance_file(st["pack"], st["name"], name)
        if isinstance(reg.get(iid), dict) and reg[iid].get("archived_at"):
            raise ValueError(
                f"'{iid}' è stata archiviata con il pack il {reg[iid]['archived_at']}: il "
                "nome resta suo. Per riusarla rimetti il file da plugins-archive/<pack>-<data>/"
                f"datastores/{st['name']}/{name}.db in datastores/{st['pack']}/{st['name']}/ "
                "(torna attiva da sola), oppure scegli un altro nome")
        if iid in reg or path.exists():
            raise ValueError(f"esiste già un'istanza '{iid}'")
        _build_file(path, st["schema"], st["latest_version"])
        reg[iid] = {"structure": sid, "name": name, "tier": tier,
                    "purpose": None if purpose in (None, "") else str(purpose),
                    "pii": None if pii is None else bool(pii),
                    "backup": None if backup is None else bool(backup),
                    "schema_version": st["latest_version"], "created_by": by,
                    "created_at": _now().isoformat(timespec="seconds")}
        try:
            datastores.save_instance_registry(reg)
        except BaseException:
            path.unlink(missing_ok=True)
            raise
    cat.register("datastore", iid, tier=tier, owner=by, source=f"pack:{st['pack']}")
    return {"ok": True, **entry_of(iid),
            "created": {"kind": "datastore", "name": iid, "tier": tier}}


# ── List ─────────────────────────────────────────────────────────────────────

def structures_view(*, scopes_of: dict[str, list[str]] | None = None,
                    visible: set[str] | None = None, clearance: str | None = None,
                    for_agent: bool = False) -> dict:
    """`{structures: [{id, pack, name, purpose, pii, backup, tier_hint,
    schema_version, creatable, legacy, instances: [{id, name, tier, purpose,
    pii, backup, schema_version, created_by, created_at, imported_by_scopes,
    imported_count}]}]}`.

    `imported_by_scopes` is the LIST of scopes (`<tier>/<topic>`; the
    agent-server adds `job:<id>`), as in the catalogue; `imported_count` its
    length. `visible`: the instance ids the caller may see (None = all);
    `scopes_of`: `{catalog key: [scope, …]}` (default: the topics).
    `for_agent`: only the instances within `clearance`, without who created
    them (`packs.datastore_structures`)."""
    if scopes_of is None:
        from . import topic_data
        try:
            scopes_of = topic_data.importing_topics()
        except Exception as e:  # noqa: BLE001 — the structures stay listable
            LOG.warning("datastore structures: imports not read (%s)", type(e).__name__)
            scopes_of = {}
    by_struct: dict[str, list[dict]] = {}
    for i in datastores.instances():
        if not i["installed"] or cat.tombstoned("datastore", i["id"]):
            continue
        if visible is not None and i["id"] not in visible:
            continue
        e = cat.get("datastore", i["id"])
        tier = cat.effective_tier(e) if e else i["tier"]
        if for_agent and cat.rank_have(clearance) < cat.rank(tier):
            continue
        scopes = list(scopes_of.get(f"datastore:{i['id']}", []))
        row = {
            "id": i["id"], "name": i["name"], "tier": tier,
            "purpose": i["purpose"], "pii": i["pii"], "backup": i["backup"],
            "schema_version": i["schema_version"], "created_by": i["created_by"],
            "created_at": i["created_at"],
            "imported_by_scopes": scopes, "imported_count": len(scopes),
        }
        if for_agent:
            row.pop("created_by")
        by_struct.setdefault(i["structure"], []).append(row)
    rows = []
    for sid, st in sorted(datastores.structures().items()):
        if st["legacy"] and sid not in by_struct:
            continue                # a legacy file not migrated yet: a flat datastore
        rows.append({
            "id": sid, "pack": st["pack"], "name": st["name"], "purpose": st["purpose"],
            "pii": st["pii"], "backup": st["backup"], "tier_hint": st["tier_hint"],
            "schema_version": max(st["latest_version"], 0),
            "creatable": bool(st["schema"]) and not st["legacy"] and st["latest_version"] >= 0,
            "legacy": st["legacy"], "instances": by_struct.get(sid, []),
        })
    return {"structures": rows}


# ── Resolve the instance of a scope (#686) ───────────────────────────────────

def _norm_requested(sid: str, requested: str) -> str:
    r = str(requested or "").strip()
    if datastores.split_instance(r):
        return r
    return datastores.instance_id(sid, r)


def resolve(sid: str, *, scope: str | None, agent: str, clearance: str | None,
            instance: str | None = None, write: bool = True) -> dict:
    """The `declared()` entry of THE instance of structure `sid` this call
    works on, from the imports of `scope` (the signed claim's, never an
    argument): one import → it; several → `instance` must name one of them
    (ValueError listing them otherwise); none → PermissionError. Access is
    then `topic_data.authorize` (scope import, participant, clearance, scope
    tier), and an instance below its structure's schema is refused."""
    from . import topic_data
    st = datastores.structure(sid)
    if st is None:
        raise LookupError(f"struttura '{sid}' sconosciuta")
    if not scope:
        raise PermissionError(
            f"nessuna istanza di {sid} importata in questo scope (la chiamata non "
            "avviene in un topic, DM o job)")
    prefix = sid + datastores.INSTANCE_SEP
    imported = sorted({e["name"] for e in topic_data.scope_imports(scope)
                       if e["kind"] == "datastore" and e["name"].startswith(prefix)})
    if instance:
        chosen = _norm_requested(sid, instance)
        if chosen not in imported:
            raise PermissionError(
                f"'{chosen}' non è importata in questo scope"
                + (f" (importate: {', '.join(imported)})" if imported else ""))
    elif len(imported) == 1:
        chosen = imported[0]
    elif imported:
        raise ValueError(
            f"in questo scope sono importate più istanze di {sid}: "
            f"{', '.join(imported)} — indica quale con l'argomento `instance`")
    else:
        raise PermissionError(f"nessuna istanza di {sid} importata in questo scope")
    topic_data.authorize("datastore", chosen, write=write, agent=agent,
                         clearance=clearance, scope=scope)
    entry = datastores.find_instance(chosen)
    if entry is None:
        raise PermissionError(f"istanza '{chosen}' non disponibile (eliminata o archiviata)")
    if not Path(entry["abs_path"]).is_file():
        raise PermissionError(f"istanza '{chosen}': file assente")
    check_current(entry)
    return entry


#: What to do about an instance left behind by a failed migration.
RETRY_HINT = ("riprova con un nuovo Update del pack, oppure (admin) «Riprova migrazione» "
              "sull'istanza nella pagina Databases; il backup è in CLODIA_DATA/migrations/")


def check_current(entry: dict) -> None:
    """PermissionError when the instance `entry` (a `declared()` entry) is
    below its structure's latest schema: it is not served until migrated —
    the pack's code expects the new schema. No-op for other datastores."""
    sid = entry.get("structure")
    if not sid:
        return
    st = datastores.structure(sid)
    if st is None:
        return
    if int(entry.get("schema_version") or 0) < st["latest_version"]:
        raise PermissionError(
            f"istanza '{entry['pack']}/{entry['name']}' allo schema "
            f"{entry.get('schema_version', 0)}, la struttura è alla {st['latest_version']}: "
            f"va migrata prima dell'uso — {RETRY_HINT}")


# ── Schema migrations on pack update (#687) ──────────────────────────────────

def _migrations_dir() -> Path:
    return Path(datastores.DATADIR) / "migrations"


def _backup(src: Path, iid: str, version: int) -> Path:
    """`sqlite3` online backup into the datadir (restic keeps it)."""
    from urllib.parse import quote
    d = _migrations_dir()
    d.mkdir(parents=True, exist_ok=True)
    safe = iid.replace("/", "__").replace(datastores.INSTANCE_SEP, "__")
    dst_path = d / f"{safe}-{version}-{_now().strftime('%Y%m%dT%H%M%S%fZ')}.db"
    s = sqlite3.connect(f"file:{quote(str(src))}?mode=ro", uri=True, timeout=10)
    dst = sqlite3.connect(str(dst_path))
    try:
        s.backup(dst)
        ok = dst.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        dst.close()
        s.close()
    if ok != "ok":
        raise RuntimeError(f"backup non integro ({ok})")
    return dst_path


def _migrate_one(inst: dict, steps: list[tuple[int, Path]], latest: int) -> dict:
    path = Path(inst["abs_path"])
    if not path.is_file():
        raise RuntimeError("file dell'istanza assente")
    conn = sqlite3.connect(str(path), isolation_level=None, timeout=10)
    try:
        # The file's own version wins over a registry that lost a write: never
        # apply a migration twice.
        on_file = int(conn.execute("PRAGMA user_version").fetchone()[0] or 0)
    finally:
        conn.close()
    current = max(int(inst["schema_version"]), on_file if on_file <= latest else 0)
    pending = [(n, f) for n, f in steps if n > current]
    if not pending:
        return {"from": current, "to": current, "backup": None}
    backup = _backup(path, inst["id"], current)
    conn = sqlite3.connect(str(path), isolation_level=None, timeout=10)
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            for n, f in pending:
                _apply_script(conn, f.read_text(encoding="utf-8"))
            conn.execute(f"PRAGMA user_version = {int(latest)}")
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    except BaseException as e:
        e.backup = str(backup)        # reported with the failure
        raise
    finally:
        conn.close()
    return {"from": current, "to": latest, "backup": str(backup)}


def migrate(packs: list[str] | None = None, *, by: str = "platform",
            ids: list[str] | None = None) -> dict:
    """Migrate every instance of the INSTALLED structures (of `packs`, or all)
    to its structure's latest version. Per instance: backup, pending
    migrations in one transaction, version bumped. A failure rolls back that
    instance only, and is in the report and the audit — never silent.
    Idempotent: an instance at the latest version is skipped."""
    want = {str(p) for p in packs} if packs else None
    only = {str(i) for i in ids} if ids else None
    if only:
        unknown = sorted(i for i in only if not datastores.split_instance(i))
        if unknown:
            raise ValueError(f"id d'istanza non validi: {', '.join(unknown)}")
        want = (want or set()) | {datastores.split_instance(i)[0] for i in only}
    structs = {sid: st for sid, st in datastores.structures().items()
               if not st["legacy"] and (want is None or st["pack"] in want)}
    report = {"migrated": [], "failed": [], "current": []}
    for sid, st in sorted(structs.items()):
        try:
            steps = datastores.migration_files(st["migrations"])
        except ValueError as e:
            report["failed"].append({"structure": sid, "error": str(e)[:300]})
            _audit("migrate", sid, by, result="failed", error=str(e)[:200])
            continue
        latest = st["latest_version"]
        for inst in datastores.instances():
            if inst["structure"] != sid or not inst["installed"] \
                    or cat.tombstoned("datastore", inst["id"]):
                continue
            if only is not None and inst["id"] not in only:
                continue
            if inst["schema_version"] >= latest:
                report["current"].append({"id": inst["id"], "version": inst["schema_version"]})
                continue
            try:
                done = _migrate_one(inst, steps, latest)
            except Exception as e:  # noqa: BLE001 — reported, the others go on
                row = {"id": inst["id"], "from": inst["schema_version"], "to": latest,
                       "error": str(e)[:300], "backup": getattr(e, "backup", None)}
                report["failed"].append(row)
                LOG.error("datastore migration %s failed: %s", inst["id"], str(e)[:200])
                _audit("migrate", inst["id"], by, result="failed", error=str(e)[:200],
                       version_from=inst["schema_version"], version_to=latest,
                       backup=row["backup"])
                continue
            with datastores.registry_lock():
                reg = datastores.instance_registry()
                if inst["id"] in reg:
                    reg[inst["id"]]["schema_version"] = done["to"]
                    datastores.save_instance_registry(reg)
            row = {"id": inst["id"], "from": done["from"], "to": done["to"],
                   "backup": done["backup"]}
            report["migrated"].append(row)
            _audit("migrate", inst["id"], by, result="ok", version_from=done["from"],
                   version_to=done["to"], backup=done["backup"])
    if report["failed"]:
        report["retry"] = RETRY_HINT
    return report

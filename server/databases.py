"""The Databases page's backend (clodia-platform#671, epic #668).

One catalogue for both kinds of data resource — SQLite datastores and RAG
collections — and the operations a PERSON performs on them from the webui:

- **catalogue**: a uniform row per resource (`kind, name, pack, tier, status,
  size, updated_at, imported_by_scopes`). A topic's own index (`topic-*`) is
  never listed: it belongs to its room, not to the instance catalogue.
- **containers** (admins): create a datastore outside packs
  (`platform/<name>`, an empty SQLite under `CLODIA_DATA/datastores/`), create
  a collection, **delete** either one. A delete first writes an export under
  `CLODIA_DATA/deleted/<kind>-<name>-<ts>/` — the restic backup covers the
  datadir, not pgvector, so for a collection this export is the only copy
  left — then removes the imports in every scope, the data and the catalogue
  entry, and records a tombstone so that the pack declaring it cannot bring it
  back silently (`data_catalog.tombstone`).
- **content**: tables and rows (insert/update/delete), schema changes
  (admins), documents and chunks of a collection, upload and indexing of a
  file (PDF, DOCX, PPTX, MD, TXT), removal of a document.

WHO may touch the content of a resource is decided in one place,
`authorize_person`: an admin reaches everything in the catalogue (within their
clearance); anybody else only a resource imported into a scope they are in, and
that decision is `topic_data.authorize` — the same entry point agents go
through — never a second copy of it.
"""
from __future__ import annotations

import json
import logging
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from . import data_catalog as cat
from . import datastores

LOG = logging.getLogger("clodia-tools.databases")

#: Upload ceiling (bytes), and the formats the indexer can read.
UPLOAD_MAX_BYTES = 20 * 1024 * 1024
UPLOAD_EXT = (".pdf", ".docx", ".pptx", ".md", ".txt")
#: An agent's `rag.ingest` of a topic file also takes spreadsheets, as before.
AGENT_INGEST_EXT = UPLOAD_EXT + (".xlsx", ".xlsm")
TOPIC_PREFIX = "topic-"


class NotFound(LookupError):
    pass


def _upload_max() -> int:
    import os
    try:
        return int(os.environ.get("CLODIA_DB_UPLOAD_MAX_BYTES") or UPLOAD_MAX_BYTES)
    except ValueError:
        return UPLOAD_MAX_BYTES


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


def _is_topic_index(kind: str, name: str) -> bool:
    return kind == "rag" and str(name).startswith(TOPIC_PREFIX)


# ── Access ───────────────────────────────────────────────────────────────────

def _need(kind: str, name: str) -> str:
    entry = cat.get(kind, name)
    if entry:
        return cat.effective_tier(entry)
    return cat.source_tier(kind, name) or "SEAL-4"


def authorize_person(kind: str, name: str, *, write: bool, who: str, is_admin: bool,
                     clearance: str | None, scope: str | None) -> None:
    """May the person `who` read (or write) the content of this resource?
    Raises PermissionError with the reason.

    - a deleted resource (tombstone) and a topic's index: nobody, from here;
    - an admin: everything in the catalogue, if their clearance covers it;
    - anyone else: only through a scope that imports it, decided by
      `topic_data.authorize` with the person as the actor."""
    if _is_topic_index(kind, name):
        raise PermissionError(f"'{name}' è l'indice di un topic: si consulta dal topic")
    if cat.tombstoned(kind, name):
        raise PermissionError(f"{kind} '{name}' è stato eliminato")
    if is_admin:
        need = _need(kind, name)
        if cat.rank_have(clearance) < cat.rank(need):
            raise PermissionError(
                f"clearance di '{who}' ({clearance or 'nessuna'}) insufficiente per "
                f"{kind} '{name}' ({need})")
        return
    from . import topic_data
    topic_data.authorize(kind, name, write=write, agent=who, clearance=clearance, scope=scope)


def _readable_scopes(kind: str, name: str, scopes: list[str], *, who: str,
                     clearance: str | None) -> list[str]:
    from . import topic_data
    out = []
    for s in scopes:
        try:
            topic_data.authorize(kind, name, write=False, agent=who, clearance=clearance, scope=s)
        except PermissionError:
            continue
        out.append(s)
    return out


# ── Catalogue ────────────────────────────────────────────────────────────────

def _collection_packs() -> dict[str, str]:
    """`{collection: pack}` from the installed packs' `rag_collections:`
    (names only — who may use a collection is not the manifest's business)."""
    import yaml
    out: dict[str, str] = {}
    for manifest in sorted(Path(datastores.DATADIR).glob("plugins/*/plugin.yaml")):
        try:
            meta = yaml.safe_load(manifest.read_text()) or {}
        except Exception:  # noqa: BLE001
            continue
        for col in (meta.get("rag_collections") if isinstance(meta, dict) else None) or []:
            if isinstance(col, dict) and str(col.get("name") or "").strip():
                out.setdefault(str(col["name"]).strip(), manifest.parent.name)
    return out


def _datastore_stats(ds: dict) -> tuple[dict, str | None, str]:
    """(size, updated_at, status) of one datastore file."""
    p = Path(ds["abs_path"])
    if not p.is_file():
        return {"tables": 0, "rows": 0, "bytes": 0}, None, "missing"
    st = p.stat()
    size = {"tables": 0, "rows": 0, "bytes": st.st_size}
    try:
        from urllib.parse import quote
        conn = sqlite3.connect(f"file:{quote(str(p))}?mode=ro", uri=True, timeout=2)
        try:
            names = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
            size["tables"] = len(names)
            for n in names:
                q = '"' + n.replace('"', '""') + '"'
                size["rows"] += conn.execute(f"SELECT count(*) FROM {q}").fetchone()[0]
        finally:
            conn.close()
    except sqlite3.Error as e:
        LOG.warning("databases: %s/%s unreadable (%s)", ds["pack"], ds["name"], e)
        return size, _iso(st.st_mtime), "unreadable"
    return size, _iso(st.st_mtime), "active"


def catalogue(*, who: str, is_admin: bool, clearance: str | None) -> dict:
    """The uniform catalogue. An admin sees every resource and every scope
    importing it, plus the tombstones; anybody else only the resources
    imported into scopes they are in, and only those scopes."""
    from . import topic_data
    if cat.sync_due():
        cat.sync()
    try:
        from .tools import eu_corpus
        service = {c.get("collection"): c for c in
                   (eu_corpus.collections() or {}).get("collections") or []}
        rag_ok = True
    except Exception as e:  # noqa: BLE001 — the datastores stay listable
        LOG.warning("databases: RAG service unreachable (%s)", type(e).__name__)
        service, rag_ok = {}, False
    declared = {f"{d['pack']}/{d['name']}": d for d in datastores.declared()}
    packs = _collection_packs()
    used = topic_data.importing_topics()
    rows = []
    for e in cat.entries():
        kind, name = e["kind"], e["name"]
        if _is_topic_index(kind, name):
            continue
        scopes = list(used.get(e["key"], []))
        if not is_admin:
            scopes = _readable_scopes(kind, name, scopes, who=who, clearance=clearance)
            if not scopes:
                continue
        row = {"kind": kind, "name": name, "key": e["key"], "tier": cat.effective_tier(e),
               "imported_by_scopes": scopes, "created_at": e.get("created_at"),
               "importers": e.get("importers") or [cat.ADMIN]}
        if kind == "datastore":
            pack = name.split("/", 1)[0]
            ds = declared.get(name)
            row["pack"] = None if pack == datastores.PLATFORM else pack
            if ds:
                row["size"], row["updated_at"], row["status"] = _datastore_stats(ds)
                row["purpose"], row["pii"] = ds.get("purpose", ""), bool(ds.get("pii"))
            else:
                row.update(size=None, updated_at=None, status="missing")
        else:
            col = service.get(name)
            row["pack"] = packs.get(name)
            if col:
                row["size"] = {"documents": col.get("documents", 0), "chunks": col.get("chunks", 0)}
                row["updated_at"] = col.get("updated_at")
                row["status"] = "active"
            else:
                row.update(size=None, updated_at=None,
                           status="missing" if rag_ok else "unknown")
        rows.append(row)
    out = {"entries": rows, "rag_available": rag_ok, "upload_max_bytes": _upload_max(),
           "upload_formats": list(UPLOAD_EXT), "is_admin": is_admin}
    if is_admin:
        out["tombstones"] = sorted(cat.tombstones().values(),
                                   key=lambda t: t.get("deleted_at") or "", reverse=True)
    return out


# ── Containers (admins) ──────────────────────────────────────────────────────

def _valid_name(name: str) -> str:
    name = str(name or "").strip()
    if not datastores.NAME_RE.match(name):
        raise ValueError("nome non valido: minuscole, cifre, '-' e '_' (max 63), "
                         "iniziale lettera o cifra")
    return name


def create_datastore(name: str, *, purpose: str, tier: str, pii: bool, by: str,
                     clearance: str | None) -> dict:
    name = _valid_name(name)
    if not cat.valid_tier(tier):
        raise ValueError(f"tier sconosciuto: '{tier}' (SEAL-0 … SEAL-4)")
    _require_clearance(clearance, tier, f"creare un datastore {cat.norm_tier(tier)}")
    reg = datastores.platform_registry()
    path = datastores.platform_dir() / f"{name}.db"
    if name in reg or path.exists():
        raise ValueError(f"esiste già un datastore 'platform/{name}'")
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("PRAGMA user_version = 1")
        conn.commit()
    finally:
        conn.close()
    reg[name] = {"purpose": str(purpose or ""), "pii": bool(pii),
                 "clearance": cat.norm_tier(tier), "created_by": by,
                 "created_at": _now().isoformat(timespec="seconds")}
    datastores.save_platform_registry(reg)
    key = f"{datastores.PLATFORM}/{name}"
    cat.clear_tombstone("datastore", key)       # an explicit re-creation
    entry = cat.register("datastore", key, tier=tier, owner=by, source="platform")
    return {"ok": True, "created": {"kind": "datastore", "name": key, "tier": entry["tier"]}}


def create_collection(name: str, *, tier: str, description: str = "", by: str,
                      clearance: str | None) -> dict:
    name = _valid_name(name)
    if name.startswith(TOPIC_PREFIX):
        raise ValueError("i nomi 'topic-*' sono degli indici dei topic")
    if not cat.valid_tier(tier):
        raise ValueError(f"tier sconosciuto: '{tier}' (SEAL-0 … SEAL-4)")
    _require_clearance(clearance, tier, f"creare una collection {cat.norm_tier(tier)}")
    from .tools import eu_corpus
    existing = {c.get("collection") for c in
                (eu_corpus.collections() or {}).get("collections") or []}
    if name in existing:
        raise ValueError(f"esiste già una collection '{name}'")
    cat.clear_tombstone("rag", name)
    out = eu_corpus.create_collection(name, tier=cat.norm_tier(tier), description=description)
    entry = cat.register("rag", name, tier=tier, owner=by, source=f"databases:{by}")
    return {"ok": True, "created": {"kind": "rag", "name": name, "tier": entry["tier"]},
            "service": out}


def restore(kind: str, name: str, *, by: str, clearance: str | None) -> dict:
    """Clear a tombstone: the resource may be re-created by its pack again,
    and the next sync lists what exists under that name. The level is the one
    the resource had when deleted (unknown → the highest)."""
    t = cat.tombstoned(kind, name)
    if not t:
        raise NotFound(f"nessuna eliminazione registrata per {kind} '{name}'")
    _require_clearance(clearance, t.get("tier") or "SEAL-4", f"ripristinare {kind} '{name}'")
    cat.clear_tombstone(kind, name)
    cat.sync()
    return {"ok": True, "restored": {"kind": kind, "name": name}}


def _export_root() -> Path:
    return Path(datastores.DATADIR) / "deleted"


def _export_dir(kind: str, name: str) -> Path:
    safe = name.replace("/", "__")
    d = _export_root() / f"{kind}-{safe}-{_now().strftime('%Y%m%dT%H%M%SZ')}"
    d.mkdir(parents=True, exist_ok=False)
    return d


def _export_datastore(ds: dict | None, name: str, d: Path) -> dict:
    """`sqlite3` online backup of the file: consistent even while written."""
    if not ds or not Path(ds["abs_path"]).is_file():
        return {"file": None, "note": "file assente: nessun dato da esportare"}
    from urllib.parse import quote
    dst_path = d / f"{name.split('/', 1)[1]}.db"
    src = sqlite3.connect(f"file:{quote(ds['abs_path'])}?mode=ro", uri=True, timeout=10)
    dst = sqlite3.connect(str(dst_path))
    try:
        src.backup(dst)
        ok = dst.execute("PRAGMA integrity_check").fetchone()[0]
    finally:
        dst.close()
        src.close()
    if ok != "ok":
        raise RuntimeError(f"export di '{name}' non integro ({ok}): eliminazione annullata")
    return {"file": dst_path.name, "bytes": dst_path.stat().st_size}


def _export_collection(name: str, d: Path, *, expected_chunks: int) -> dict:
    """documents.jsonl + chunks.jsonl, checked against the service's own counts
    of documents and of chunks."""
    from .tools import eu_corpus
    expected = len((eu_corpus.list_documents(name) or {}).get("documents") or [])
    counts = {"documents": 0, "chunks": 0}
    with open(d / "documents.jsonl", "w", encoding="utf-8") as docs, \
            open(d / "chunks.jsonl", "w", encoding="utf-8") as chunks:
        for row in eu_corpus.export_rows(name):
            t = row.get("type")
            if t == "chunk":
                chunks.write(json.dumps(row, ensure_ascii=False) + "\n")
                counts["chunks"] += 1
            elif t in ("document", "collection"):
                docs.write(json.dumps(row, ensure_ascii=False) + "\n")
                if t == "document":
                    counts["documents"] += 1
    if counts["documents"] != expected or counts["chunks"] != expected_chunks:
        raise RuntimeError(
            f"export di '{name}' incompleto ({counts['documents']} documenti su {expected}, "
            f"{counts['chunks']} chunk su {expected_chunks}): eliminazione annullata")
    return counts


def _require_clearance(clearance: str | None, need: str, what: str) -> None:
    if cat.rank_have(clearance) < cat.rank(need):
        raise PermissionError(
            f"clearance ({clearance or 'nessuna'}) inferiore a {cat.norm_tier(need)}: "
            f"{what} è riservato a chi ha almeno quel livello")


def delete(kind: str, name: str, *, by: str, clearance: str | None,
           job_scopes: list[str] | None = None) -> dict:
    """Tombstone, export, imports out of every scope, data, catalogue entry —
    in this order (#671 review):

    1. the **tombstone first** freezes the resource: `datastores.declared`
       hides it (so `datastore.*` refuse it) and every `eu_corpus` write path
       refuses it, so nothing is written between the export and the drop;
    2. the **export** is written and checked (documents AND chunks for a
       collection). If it fails the tombstone is lifted and nothing changes;
    3. imports, data and catalogue entry go.

    `job_scopes`: the jobs importing it, which the agent-server holds and
    removes itself after this returns (`job:<id>`); recorded in the export."""
    from . import topic_data
    if kind not in cat.KINDS:
        raise ValueError("kind: datastore | rag")
    if _is_topic_index(kind, name):
        raise PermissionError("l'indice di un topic si spegne dal topic, non da qui")
    if cat.tombstoned(kind, name):
        raise ValueError(f"{kind} '{name}' è già stato eliminato")
    entry = cat.get(kind, name)
    ds = None
    col = None
    if kind == "datastore":
        pack, dsname = datastores.parse_key(name)
        ds = datastores.find(pack, dsname)
        if ds is None and entry is None:
            raise NotFound(f"datastore '{name}' sconosciuto")
    else:
        from .tools import eu_corpus
        col = {c.get("collection"): c for c in
               (eu_corpus.collections() or {}).get("collections") or []}.get(name)
        if col is None and entry is None:
            raise NotFound(f"collection '{name}' sconosciuta")
    need = _need(kind, name)
    _require_clearance(clearance, need, f"eliminare {kind} '{name}'")
    cat.tombstone(kind, name, by=by, tier=need)                      # 1. freeze
    d = None
    try:                                                              # 2. export
        d = _export_dir(kind, name)
        if kind == "datastore":
            exported = _export_datastore(ds, name, d)
        elif col is not None:
            exported = _export_collection(name, d, expected_chunks=int(col.get("chunks") or 0))
        else:
            exported = {"documents": 0, "chunks": 0}
        scopes = topic_data.importing_topics().get(f"{kind}:{name}", [])
        (d / "meta.json").write_text(json.dumps({
            "kind": kind, "name": name, "deleted_by": by,
            "deleted_at": _now().isoformat(timespec="seconds"), "catalog": entry,
            "declaration": ds, "imported_by_scopes": scopes + list(job_scopes or []),
            "export": exported,
        }, indent=1, ensure_ascii=False, default=str), encoding="utf-8")
    except Exception:
        cat.clear_tombstone(kind, name)
        if d is not None:
            shutil.rmtree(d, ignore_errors=True)
        raise
    rel = str(d.relative_to(Path(datastores.DATADIR)))
    cat.set_tombstone_export(kind, name, rel)
    removed, failed = [], []                                          # 3. the rest
    for s in scopes:
        tier, _, tname = s.partition("/")
        try:
            topic_data.remove(tier, tname, kind, name)
            removed.append(s)
        except Exception as e:  # noqa: BLE001 — reported; the tombstone already cuts access
            failed.append({"scope": s, "error": str(e)[:200]})
    if kind == "datastore":
        if ds:
            base = Path(ds["abs_path"])
            for p in (base, base.with_name(base.name + "-wal"), base.with_name(base.name + "-shm"),
                      base.with_name(base.name + "-journal")):
                try:
                    p.unlink()
                except FileNotFoundError:
                    pass
        pack, dsname = datastores.parse_key(name)
        if pack == datastores.PLATFORM:
            reg = datastores.platform_registry()
            if reg.pop(dsname, None) is not None:
                datastores.save_platform_registry(reg)
    elif col is not None:
        from .tools import eu_corpus
        eu_corpus.drop_collection(name)
    cat.retire(kind, name)
    return {"ok": True, "deleted": {"kind": kind, "name": name}, "export_dir": rel,
            "export": exported, "imports_removed": removed, "imports_failed": failed,
            "job_scopes": list(job_scopes or [])}


# ── Collection content ───────────────────────────────────────────────────────

def extract_text(filename: str, data: bytes, formats: tuple[str, ...] = UPLOAD_EXT) -> str:
    """The topic indexer's extractor (`main._extract_document_text`), PPTX
    included (and its ZIP-bomb guard), limited to `formats`."""
    low = filename.lower()
    if not low.endswith(formats):
        raise ValueError(f"formato non ammesso: {', '.join(formats)}")
    if low.endswith((".md", ".txt")):
        return data.decode("utf-8", errors="replace")
    from . import main
    text, _pages = main._extract_document_text(filename, data)
    return text


def upload(collection: str, filename: str, data: bytes, *, doc_name: str = "",
           version: str = "1", who: str, clearance: str | None) -> dict:
    """Index one uploaded file into `collection`. The caller has authorized
    the WRITE; here the rules of the upload itself: the uploader's clearance
    covers the collection's tier (an upload is data entering at that level),
    size and format, and an audit line."""
    from .tools import eu_corpus
    filename = Path(str(filename or "").replace("\\", "/")).name
    if not filename:
        raise ValueError("nome del file richiesto")
    if len(data) > _upload_max():
        raise ValueError(f"file troppo grande: {len(data)} byte (max {_upload_max()})")
    if not data:
        raise ValueError("file vuoto")
    if collection not in {c.get("collection") for c in
                          (eu_corpus.collections() or {}).get("collections") or []}:
        raise NotFound(f"collection '{collection}' inesistente: creala prima")
    need = _need("rag", collection)
    if cat.rank_have(clearance) < cat.rank(need):
        raise PermissionError(
            f"clearance di '{who}' ({clearance or 'nessuna'}) inferiore al tier della "
            f"collection '{collection}' ({need}): il caricamento è rifiutato")
    text = extract_text(filename, data)
    if not text.strip():
        raise ValueError(f"nessun testo estraibile da '{filename}'")
    name = str(doc_name or "").strip() or filename.rsplit(".", 1)[0]
    res = eu_corpus.ingest_text(collection, name, text, version=str(version or "1"),
                                source=f"upload:{who}:{filename}", provenance="untrusted")
    return {"ok": True, "collection": collection, "document": name,
            "version": str(version or "1"), "chunks": (res or {}).get("chunks"),
            "bytes": len(data), "characters": len(text)}

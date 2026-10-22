"""Every topic indexed in its own RAG collection (clodia-platform#590 phase 2:
D7 #599 the collection, D9 #601 the indexer).

The gateway does the work: it holds the topic files and their provenance, the
text extraction and the RAG service's token. The agent-server only calls
`sync` topic by topic, at a pace it chooses (deterministic code, never a
model).

- **The collection**: `topic-<random>`, kept in `meta.index.collection` so it
  survives renames and re-tiers; its tier is the topic's. It is a catalog
  resource (D1), imported into its own topic (D2) with `read` for every
  participant (D3) — a participant who joins later gets read once; a grant
  the owner revoked stays revoked. Only this indexer writes it.
- **What goes in**, one RAG document each:
  - `msg/<YYYY-MM-DD>`: the day's messages ("author: text"). Provenance
    `untrusted` if any of them came from a proxy or a connector (mail,
    Telegram), `agent` if an agent wrote some, else `trusted`;
  - `summary`: the summary (`agent`);
  - `file/<path>`: text of the topic's files (`files/`, `local/`), with the
    file's own provenance label (no label → `untrusted`).
- **Incremental**: a state file per collection remembers the last indexed day
  and each file's size+mtime; changed days and files are re-ingested, deleted
  files removed. Bounded per call (`MAX_FILES`, `MAX_BYTES`, `MAX_CHARS`).
- **Opt-out**: `meta.index.enabled = false` (owner) drops the collection's
  documents and stops indexing. Archived topics are not indexed further.
"""
from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime, timezone

from . import data_catalog as cat, topic_data as td

LOG = logging.getLogger("clodia-tools.topic_index")

PREFIX = "topic-"
TEXT_EXT = (".md", ".txt", ".csv", ".json", ".html", ".htm", ".xml", ".yaml", ".yml")
DOC_EXT = (".pdf", ".docx", ".xlsx")
EML_EXT = (".eml",)
ROOTS = ("files", "local")
MAX_FILES = 15
MAX_BYTES = 15 * 1024 * 1024
MAX_CHARS = 400_000
UNTRUSTED_KINDS = ("proxy", "telegram")


def _svc():
    from . import main
    return main._topics()


def _state_path(collection: str):
    from . import state_paths
    d = state_paths.state_path("topic-index")
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{collection}.json"


def _load(collection: str) -> dict:
    try:
        return json.loads(_state_path(collection).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"days": {}, "files": {}, "summary": "", "seen": []}


def _save(collection: str, st: dict) -> None:
    p = _state_path(collection)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(st, ensure_ascii=False), encoding="utf-8")
    tmp.replace(p)


def settings(meta: dict) -> dict:
    ix = meta.get("index") if isinstance(meta.get("index"), dict) else {}
    return {"collection": str(ix.get("collection") or ""),
            "enabled": ix.get("enabled", True) is not False}


def _rag():
    from .tools import eu_corpus
    return eu_corpus


def ensure(tier: str, name: str) -> dict:
    """The topic's collection exists with the topic's tier, is in the catalog,
    is imported in the topic, and every participant not yet seen reads it.
    Returns {collection, enabled, tier}."""
    svc = _svc()
    meta, ver = svc._read_meta(tier, name)
    ix = settings(meta)
    t = cat.norm_tier(meta.get("tier") or tier)
    if not ix["enabled"]:
        return {**ix, "tier": t}
    changed = False
    if not ix["collection"]:
        ix["collection"] = PREFIX + secrets.token_hex(4)
        meta["index"] = {**(meta.get("index") or {}), "collection": ix["collection"],
                         "enabled": True}
        changed = True
    coll = ix["collection"]
    # the catalog entry follows the topic's tier (D7)
    entry = cat.get("rag", coll)
    if entry is None:
        cat.register("rag", coll, tier=t, owner=str(meta.get("owner") or ""),
                     importers=[cat.ADMIN] + ([meta["owner"]] if meta.get("owner") else []),
                     source=f"topic:{tier}/{name}")
        _rag().set_collection(coll, t)
    elif entry.get("tier") != t:
        cat.update("rag", coll, tier=t)
        _rag().set_collection(coll, t)
    # imported in its own topic, read for the participants not yet seen
    st = _load(coll)
    entries = td.imports(meta)
    imp = next((e for e in entries if e["kind"] == "rag" and e["name"] == coll), None)
    if imp is None:
        imp = {"kind": "rag", "name": coll, "grants": {}}
        entries.append(imp)
        changed = True
    from .topics.service import TopicService
    from . import whitelist
    agents = set((whitelist.CONFIG.get("agents") or {}))
    seen = set(st.get("seen") or [])
    for p in TopicService.participants_map(meta):
        if p in agents and p not in seen:
            if p not in imp["grants"]:
                imp["grants"][p] = "read"
                changed = True
            seen.add(p)
    if changed:
        meta[td.FIELD] = entries
        svc._write_meta(tier, name, meta, base_version=ver)
    if seen != set(st.get("seen") or []):
        st["seen"] = sorted(seen)
        _save(coll, st)
    return {"collection": coll, "enabled": True, "tier": t}


def set_enabled(tier: str, name: str, enabled: bool) -> dict:
    """Owner's opt-out (or back in). Off: the collection's documents go."""
    svc = _svc()
    meta, ver = svc._read_meta(tier, name)
    ix = settings(meta)
    meta["index"] = {**(meta.get("index") or {}), "enabled": bool(enabled)}
    svc._write_meta(tier, name, meta, base_version=ver)
    if not enabled and ix["collection"]:
        try:
            _rag().drop_collection(ix["collection"])
        except Exception as e:  # noqa: BLE001
            LOG.warning("topic index: %s non svuotata (%s)", ix["collection"], type(e).__name__)
        _save(ix["collection"], {"days": {}, "files": {}, "summary": "", "seen": []})
    return {"enabled": bool(enabled), "collection": ix["collection"]}


# ── extraction ─────────────────────────────────────────────────────────────

def _eml_text(data: bytes) -> str:
    import email
    from email import policy
    msg = email.message_from_bytes(data, policy=policy.default)
    head = "\n".join(f"{h}: {msg.get(h)}" for h in ("From", "To", "Date", "Subject") if msg.get(h))
    body = msg.get_body(preferencelist=("plain",))
    return head + "\n\n" + (body.get_content() if body else "")


def file_text(path: str, data: bytes) -> str:
    low = path.lower()
    if low.endswith(TEXT_EXT):
        return data.decode("utf-8", errors="replace")
    if low.endswith(EML_EXT):
        return _eml_text(data)
    if low.endswith(DOC_EXT):
        from . import main
        text, _pages = main._extract_document_text(path.rsplit("/", 1)[-1], data)
        return text
    return ""


def _walk(svc, tier: str, name: str, root: str, out: list, depth: int = 0) -> None:
    if depth > 6:
        return
    try:
        entries = svc.list_files(tier, name, root)
    except Exception:  # noqa: BLE001 — a root that does not exist
        return
    for e in entries:
        if e.get("kind") == "dir":
            _walk(svc, tier, name, e["path"], out, depth + 1)
        elif str(e.get("path") or "").lower().endswith(TEXT_EXT + DOC_EXT + EML_EXT):
            out.append(e)


# ── sync ───────────────────────────────────────────────────────────────────

def _day(ts: str) -> str:
    return str(ts or "")[:10] or datetime.now(timezone.utc).date().isoformat()


def _messages_provenance(msgs: list[dict]) -> str:
    kinds = {str(m.get("kind") or "") for m in msgs}
    if kinds & set(UNTRUSTED_KINDS):
        return "untrusted"
    return "agent" if "ai" in kinds else "trusted"


def sync(tier: str, name: str) -> dict:
    """One bounded pass over a topic. Returns counts and `pending` (more to do)."""
    svc = _svc()
    info = ensure(tier, name)
    if not info.get("enabled") or not info.get("collection"):
        return {"skipped": "indicizzazione spenta"}
    meta = svc._read_meta(tier, name)[0]
    if str(meta.get("status") or "") == "archived":
        return {"skipped": "topic archiviato"}
    coll, t = info["collection"], info["tier"]
    rag = _rag()
    st = _load(coll)
    done = {"days": 0, "files": 0, "removed": 0}
    # messages, by day: the last indexed day is re-done (it may have grown)
    msgs = svc.list_messages(tier, name, limit=1_000_000)
    by_day: dict[str, list] = {}
    for m in msgs:
        by_day.setdefault(_day(m.get("ts")), []).append(m)
    for day in sorted(by_day):
        n = len(by_day[day])
        if st["days"].get(day) == n:
            continue
        text = "\n".join(f"[{str(m.get('ts'))[11:16]}] {m.get('author')}: {m.get('text') or ''}"
                         for m in by_day[day])[:MAX_CHARS]
        rag.ingest_text(coll, f"msg/{day}", text, source=f"{tier}/{name} messaggi {day}",
                        provenance=_messages_provenance(by_day[day]), tier=t)
        st["days"][day] = n
        done["days"] += 1
    # summary
    try:
        summary = svc.s.read(svc._summary_p(tier, name)).data.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        summary = ""
    import hashlib
    h = hashlib.sha256(summary.encode()).hexdigest()[:16]
    if summary.strip() and st.get("summary") != h:
        rag.ingest_text(coll, "summary", summary[:MAX_CHARS], source=f"{tier}/{name} summary",
                        provenance="agent", tier=t)
        st["summary"] = h
    # files
    found: list[dict] = []
    for root in ROOTS:
        _walk(svc, tier, name, root, found)
    present = {}
    budget = MAX_FILES
    for e in found:
        path = e["path"]
        sig = f"{e.get('size')}:{e.get('mtime_iso')}"
        present[path] = sig
        if st["files"].get(path) == sig:
            continue
        if budget <= 0:
            continue
        budget -= 1
        if (e.get("size") or 0) > MAX_BYTES:
            st["files"][path] = sig
            continue
        try:
            data = svc.read_file(tier, name, path)
            text = file_text(path, data)
        except Exception as err:  # noqa: BLE001 — one file never stops the pass
            LOG.warning("topic index: %s/%s %s non letto (%s)", tier, name, path,
                        type(err).__name__)
            st["files"][path] = sig
            continue
        if text.strip():
            prov = svc.provenance_of(tier, name, path) or "untrusted"
            rag.ingest_text(coll, f"file/{path}", text[:MAX_CHARS],
                            source=f"{tier}/{name}/{path}", provenance=prov, tier=t)
            done["files"] += 1
        st["files"][path] = sig
    for path in [p for p in st["files"] if p not in present]:
        try:
            rag.remove(f"file/{path}", None, coll)
        except Exception:  # noqa: BLE001
            pass
        st["files"].pop(path, None)
        done["removed"] += 1
    _save(coll, st)
    pending = any(st["files"].get(p) != sig for p, sig in present.items())
    return {"collection": coll, **done, "pending": pending}


def topics() -> list[dict]:
    """The topics to index: not archived, indexing on."""
    svc = _svc()
    out = []
    for row in svc.list():
        try:
            meta = svc._read_meta(row["tier"], row["name"])[0]
        except Exception:  # noqa: BLE001
            continue
        if settings(meta)["enabled"]:
            out.append({"tier": row["tier"], "name": row["name"],
                        "collection": settings(meta)["collection"]})
    return out

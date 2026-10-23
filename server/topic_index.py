"""Every topic indexed in its own RAG collection (clodia-platform#590 phase 2:
D7 #599 the collection, D9 #601 the indexer).

The gateway does the work: it holds the topic files and their provenance, the
text extraction and the RAG service's token. The agent-server only calls
`sync` topic by topic, at a pace it chooses (deterministic code, never a
model).

- **The collection**: `topic-<random>`, in `meta.index.collection`, created
  ONLY here (`TopicService.new` and archive imports drop any `index` a caller
  brings) and BOUND to its topic in a gateway-side map: a meta naming a
  collection bound to another live topic is refused, never trusted (review
  of clodia-tools#422, B1). Its tier is the topic's. A catalog resource (D1),
  imported into its own topic (D2) with `read` for every agent participant,
  once (D3): a grant the owner revoked stays revoked (`meta.index.seen`).
  Only this indexer writes it: every write verb on `topic-*` is refused at the
  gateway, for everyone (B2).
- **What goes in**, one RAG document each:
  - `msg/<YYYY-MM-DD>`: the day's messages. `untrusted` if a proxy or a
    connector spoke, or if the channel was tainted that day (an agent may
    have echoed what it read); else `agent` if an agent spoke; else `trusted`;
  - `summary`: the summary (`agent`);
  - `file/<path>`: the text of the topic's files (`files/`, `local/`) with
    the file's own label (none → `untrusted`).
- **Incremental and bounded**: per-collection state (message count per day,
  file size+mtime), saved after every document; one character budget per
  call across days and files; a topic is synced by one call at a time. A root
  whose listing fails removes nothing; a removal that fails is retried.
- **Opt-out**: `meta.index.enabled = false` (owner) drops the collection's
  documents; a failed drop stays pending and is retried.
"""
from __future__ import annotations

import hashlib
import json
import logging
import secrets
import threading
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
BUDGET_CHARS = 600_000          # per sync call, days + files together
UNTRUSTED_KINDS = ("proxy", "telegram")

_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


def _lock(key: str) -> threading.Lock:
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(key, threading.Lock())


def _svc():
    from . import main
    return main._topics()


def _state_dir():
    from . import state_paths
    d = state_paths.state_path("topic-index")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _state_path(collection: str):
    return _state_dir() / f"{collection}.json"


def _load(collection: str) -> dict:
    try:
        st = json.loads(_state_path(collection).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        st = {}
    st.setdefault("days", {})
    st.setdefault("files", {})
    st.setdefault("summary", "")
    return st


def _save(collection: str, st: dict) -> None:
    p = _state_path(collection)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(st, ensure_ascii=False), encoding="utf-8")
    tmp.replace(p)


# ── binding collection ↔ topic (B1) ──────────────────────────────────────────

def _bindings_path():
    return _state_dir() / "bindings.json"


def _bindings() -> dict:
    try:
        return json.loads(_bindings_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _bind(collection: str, key: str) -> None:
    b = _bindings()
    b[collection] = key
    tmp = _bindings_path().with_suffix(".tmp")
    tmp.write_text(json.dumps(b), encoding="utf-8")
    tmp.replace(_bindings_path())


def _bound_elsewhere(svc, collection: str, key: str) -> bool:
    """Is `collection` the index of ANOTHER live topic? A re-tier moves a
    topic's key; the old key then no longer names a topic with this
    collection, and the binding follows."""
    other = _bindings().get(collection)
    if not other or other == key:
        return False
    t, _, n = other.partition("/")
    try:
        m = svc._read_meta(t, n)[0]
        return settings(m)["collection"] == collection
    except Exception:  # noqa: BLE001 — the old key is gone: is it live elsewhere?
        pass
    # Fail closed (second review of #422): the binding follows only when no
    # live topic names this collection — a re-tiered topic is found by name.
    for row in svc.list(include_archived=True):
        if row["name"] != n or f"{row['tier']}/{row['name']}" == key:
            continue
        try:
            if settings(svc._read_meta(row["tier"], row["name"])[0])["collection"] == collection:
                return True
        except Exception:  # noqa: BLE001
            return True
    return False


def settings(meta: dict) -> dict:
    ix = meta.get("index") if isinstance(meta.get("index"), dict) else {}
    return {"collection": str(ix.get("collection") or ""),
            "enabled": ix.get("enabled", True) is not False,
            "drop_pending": bool(ix.get("drop_pending")),
            "seen": [str(s) for s in ix.get("seen") or []]}


def _rag():
    from .tools import eu_corpus
    return eu_corpus


def is_topic_collection(name: str) -> bool:
    return str(name or "").startswith(PREFIX)


def ensure(tier: str, name: str) -> dict:
    """The topic's collection exists with the topic's tier, is bound to this
    topic, is in the catalog, is imported here, and every agent participant
    not yet seen reads it. Returns {collection, enabled, tier}."""
    svc = _svc()
    key = f"{tier}/{name}"
    meta, ver = svc._read_meta(tier, name)
    ix = settings(meta)
    t = cat.norm_tier(meta.get("tier") or tier)
    if not ix["enabled"]:
        return {**ix, "tier": t}
    index = dict(meta.get("index") or {})
    changed = False
    coll = ix["collection"]
    if coll and (not is_topic_collection(coll) or _bound_elsewhere(svc, coll, key)):
        LOG.warning("topic index: %s names %s, bound to another topic — refused, new one", key, coll)
        coll = ""
    if not coll:
        coll = PREFIX + secrets.token_hex(4)
        index.update(collection=coll, enabled=True, seen=[])
        changed = True
    # the name is the topic's BEFORE anything is created for it (S1)
    from .topics.service import TopicService
    from . import whitelist
    agents = set(whitelist.CONFIG.get("agents") or {})
    seen = set(index.get("seen") or [])
    entries = td.imports(meta)
    imp = next((e for e in entries if e["kind"] == "rag" and e["name"] == coll), None)
    if imp is None:
        imp = {"kind": "rag", "name": coll, "grants": {}}
        entries.append(imp)
        changed = True
    for p in TopicService.participants_map(meta):
        if p in agents and p not in seen:
            imp["grants"].setdefault(p, "read")
            seen.add(p)
            changed = True
    if changed:
        index["seen"] = sorted(seen)
        meta["index"] = index
        meta[td.FIELD] = entries
        svc._write_meta(tier, name, meta, base_version=ver)
    _bind(coll, key)
    entry = cat.get("rag", coll)
    if entry is None:
        # The service first: a catalog entry for a collection that does not
        # exist would never be created again.
        _rag().set_collection_tier(coll, t)
        cat.register("rag", coll, tier=t, owner=str(meta.get("owner") or ""),
                     importers=[cat.ADMIN], source=f"topic-index:{coll}")
    elif entry.get("tier") != t:
        cat.update("rag", coll, tier=t)              # the topic was re-tiered
        _rag().set_collection_tier(coll, t)
    return {"collection": coll, "enabled": True, "tier": t}


def set_enabled(tier: str, name: str, enabled: bool) -> dict:
    """Owner's opt-out (or back in). Off: the collection's documents go; a
    failed drop stays pending and the indexer retries it."""
    with _lock(f"{tier}/{name}"):
        svc = _svc()
        meta, ver = svc._read_meta(tier, name)
        ix = settings(meta)
        index = dict(meta.get("index") or {})
        index["enabled"] = bool(enabled)
        if not enabled and ix["collection"]:
            index["drop_pending"] = True
        meta["index"] = index
        svc._write_meta(tier, name, meta, base_version=ver)
        if not enabled and ix["collection"]:
            _drop(tier, name, ix["collection"])
        return {"enabled": bool(enabled), "collection": ix["collection"]}


def _drop(tier: str, name: str, coll: str) -> bool:
    try:
        _rag().drop_collection(coll)
    except Exception as e:  # noqa: BLE001 — stays pending, retried
        LOG.warning("topic index: %s non svuotata (%s)", coll, type(e).__name__)
        return False
    _save(coll, {"days": {}, "files": {}, "summary": ""})
    svc = _svc()
    meta, ver = svc._read_meta(tier, name)
    index = dict(meta.get("index") or {})
    index.pop("drop_pending", None)
    meta["index"] = index
    svc._write_meta(tier, name, meta, base_version=ver)
    return True


# ── extraction ─────────────────────────────────────────────────────────────

def _eml_text(data: bytes) -> str:
    import email
    from email import policy
    msg = email.message_from_bytes(data, policy=policy.default)
    head = "\n".join(f"{h}: {msg.get(h)}" for h in ("From", "To", "Date", "Subject") if msg.get(h))
    body = msg.get_body(preferencelist=("plain",))
    return head + "\n\n" + (body.get_content() if body else "")


def file_text(path: str, data: bytes) -> str:
    return _file_text(path, data).replace("\x00", "")   # NUL: PostgreSQL refuses it


def _file_text(path: str, data: bytes) -> str:
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


def _walk(svc, tier: str, name: str, root: str, out: list, depth: int = 0) -> bool:
    """Collect indexable files under `root`. False when a listing failed: the
    caller then removes nothing (a folder briefly unreachable is not a folder
    emptied, S3). A root that simply does not exist lists as empty."""
    if depth > 6:
        return True
    try:
        entries = svc.list_files(tier, name, root)
    except Exception:  # noqa: BLE001
        return depth == 0 and root in ROOTS and _missing_root(svc, tier, name, root)
    ok = True
    for e in entries:
        if e.get("kind") == "dir":
            ok = _walk(svc, tier, name, e["path"], out, depth + 1) and ok
        elif str(e.get("path") or "").lower().endswith(TEXT_EXT + DOC_EXT + EML_EXT):
            out.append(e)
    return ok


def _missing_root(svc, tier: str, name: str, root: str) -> bool:
    """A top root that is not there at all (a topic without `local/`) is
    fine; anything else is a failure."""
    try:
        top = svc.list_files(tier, name, "")
    except Exception:  # noqa: BLE001
        return False
    return root not in {e.get("name") for e in top}


# ── sync ───────────────────────────────────────────────────────────────────

def _day(ts: str) -> str:
    return str(ts or "")[:10] or datetime.now(timezone.utc).date().isoformat()


def _tainted_on(tier: str, name: str, day: str) -> bool:
    """Was the channel tainted on `day` (S7)? Conservative: tainted now and
    since no later than the end of that day."""
    try:
        from . import taint
        st = taint.status(f"{tier}/{name}")
    except Exception:  # noqa: BLE001
        return True
    if not st.get("tainted"):
        return False
    since = st.get("since")
    if not since:
        return True
    end = datetime.fromisoformat(day + "T23:59:59+00:00").timestamp()
    return float(since) <= end


def _messages_provenance(msgs: list[dict], tainted: bool) -> str:
    kinds = {str(m.get("kind") or "") for m in msgs}
    if kinds & set(UNTRUSTED_KINDS):
        return "untrusted"
    if kinds & {"ai", "system"}:
        return "untrusted" if tainted else "agent"
    return "trusted"


def sync(tier: str, name: str) -> dict:
    """One bounded pass over a topic. Returns counts and `pending`."""
    lk = _lock(f"{tier}/{name}")
    if not lk.acquire(blocking=False):
        return {"skipped": "sincronizzazione già in corso", "pending": True}
    try:
        return _sync(tier, name)
    finally:
        lk.release()


def _sync(tier: str, name: str) -> dict:
    svc = _svc()
    meta = svc._read_meta(tier, name)[0]
    ix = settings(meta)
    if ix["drop_pending"] and ix["collection"]:
        _drop(tier, name, ix["collection"])
    if str(meta.get("status") or "") == "archived":
        return {"skipped": "topic archiviato"}
    if not ix["enabled"]:
        return {"skipped": "indicizzazione spenta"}
    info = ensure(tier, name)
    coll, t = info["collection"], info["tier"]
    rag = _rag()
    st = _load(coll)
    done = {"days": 0, "files": 0, "removed": 0}
    budget = BUDGET_CHARS
    pending = False
    # messages, by day (append-only: a day with more messages is re-done)
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
        if len(text) > budget:
            pending = True
            break
        rag.ingest_text(coll, f"msg/{day}", text, source=f"{tier}/{name} messaggi {day}",
                        provenance=_messages_provenance(by_day[day], _tainted_on(tier, name, day)),
                        tier=t)
        budget -= len(text)
        st["days"][day] = n
        _save(coll, st)
        done["days"] += 1
    # summary
    try:
        summary = svc.s.read(svc._summary_p(tier, name)).data.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        summary = ""
    h = hashlib.sha256(summary.encode()).hexdigest()[:16]
    if st.get("summary") != h and not pending:
        if summary.strip():
            rag.ingest_text(coll, "summary", summary[:MAX_CHARS],
                            source=f"{tier}/{name} summary", provenance="agent", tier=t)
            budget -= min(len(summary), MAX_CHARS)
        else:
            try:
                rag.remove("summary", None, coll)
            except Exception:  # noqa: BLE001
                pass
        st["summary"] = h
        _save(coll, st)
    # files
    found: list[dict] = []
    roots_ok = all([_walk(svc, tier, name, root, found) for root in ROOTS])
    present = {}
    files_left = MAX_FILES
    for e in found:
        path = e["path"]
        sig = f"{e.get('size')}:{e.get('mtime_iso')}"
        present[path] = sig
        if st["files"].get(path) == sig:
            continue
        if files_left <= 0 or budget <= 0 or pending:
            pending = True
            continue
        files_left -= 1
        if (e.get("size") or 0) > MAX_BYTES:
            st["files"][path] = sig
            _save(coll, st)
            continue
        try:
            data = svc.read_file(tier, name, path)
            text = file_text(path, data)[:MAX_CHARS]
        except Exception as err:  # noqa: BLE001 — one file never stops the pass
            LOG.warning("topic index: %s/%s %s non letto (%s)", tier, name, path,
                        type(err).__name__)
            st["files"][path] = sig
            _save(coll, st)
            continue
        if text.strip():
            prov = svc.provenance_of(tier, name, path) or "untrusted"
            rag.ingest_text(coll, f"file/{path}", text, source=f"{tier}/{name}/{path}",
                            provenance=prov, tier=t)
            budget -= len(text)
            done["files"] += 1
        st["files"][path] = sig
        _save(coll, st)
    if roots_ok:
        for path in [p for p in st["files"] if p not in present]:
            try:
                rag.remove(f"file/{path}", None, coll)
            except Exception:  # noqa: BLE001 — retried next pass (S3)
                pending = True
                continue
            st["files"].pop(path, None)
            _save(coll, st)
            done["removed"] += 1
    return {"collection": coll, **done, "pending": pending}


def topics() -> list[dict]:
    """The topics to visit: not archived, indexing on — or a drop pending."""
    svc = _svc()
    out = []
    for row in svc.list():
        try:
            meta = svc._read_meta(row["tier"], row["name"])[0]
        except Exception:  # noqa: BLE001
            continue
        s = settings(meta)
        if s["enabled"] or s["drop_pending"]:
            out.append({"tier": row["tier"], "name": row["name"], "collection": s["collection"]})
    return out

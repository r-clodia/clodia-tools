"""Every topic indexed in its own RAG collection (clodia-platform#590 phase 2:
D7 #599 the collection, D9 #601 the indexer; #648 the toggle).

**#648 (owner, 5 Nov 2026): one toggle per room.** `meta.index.on` is the
switch, OFF unless the owner turns it on (every room starts off at release).
- ON: a JOB indexes, at once, every file of the room (`files/`, `local/`,
  courier mail included) and the content of its linked Google Drive folders,
  then keeps them current; chat messages are indexed one by one AS THEY ARE
  POSTED from that moment (`index.since`) — earlier messages are not.
- OFF: a JOB empties the collection — files, Drive, messages.
- The job's state (`job_status`) lives in the gateway's state dir: the webui
  polls it, and a switch is refused while a job runs.
- Changes inside the room (a message posted, a file written, moved, deleted)
  reach the RAG through a queue, immediately; the periodic pass of the
  agent-server is the safety net (Drive changes are picked up there).

What follows describes the documents and their safeguards.

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
#: `channel` (#638) is a pack relay's message: the same standing as `telegram`.
UNTRUSTED_KINDS = ("proxy", "telegram", "channel")

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
    st.setdefault("drive", {})
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


def _own_collection(svc, tier: str, name: str, coll: str) -> str:
    """`coll` if it is THIS topic's index, else "" — checked before anything
    empties it: a meta forged to name another topic's collection must never
    get that collection dropped (review of #648, as B1 for `ensure`)."""
    if not coll or not is_topic_collection(coll):
        return ""
    return "" if _bound_elsewhere(svc, coll, f"{tier}/{name}") else coll


def settings(meta: dict) -> dict:
    """`on` is the room's switch (#648): only an explicit `on: true` counts —
    the old `enabled` (default on) is ignored, so every room starts off."""
    ix = meta.get("index") if isinstance(meta.get("index"), dict) else {}
    on = ix.get("on") is True
    return {"collection": str(ix.get("collection") or ""),
            "on": on, "enabled": on,
            "since": str(ix.get("since") or ""),
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
    if not ix["on"]:
        return {**ix, "tier": t}
    index = dict(meta.get("index") or {})
    changed = False
    coll = ix["collection"]
    if coll and (not is_topic_collection(coll) or _bound_elsewhere(svc, coll, key)):
        LOG.warning("topic index: %s names %s, bound to another topic — refused, new one", key, coll)
        coll = ""
    if not coll:
        coll = PREFIX + secrets.token_hex(4)
        index.update(collection=coll, seen=[])
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


# ── the toggle and its job (#648) ──────────────────────────────────────────

_JOBS_GUARD = threading.Lock()
_RUNNING: dict[str, threading.Thread] = {}
RUNNING_STATES = ("indexing", "deindexing")


def _job_path(tier: str, name: str):
    d = _state_dir() / "jobs"
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{tier}__{name}.json"


def _job_read(tier: str, name: str) -> dict:
    try:
        return json.loads(_job_path(tier, name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _job_write(tier: str, name: str, **fields) -> dict:
    job = {**_job_read(tier, name), **fields}
    p = _job_path(tier, name)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(job, ensure_ascii=False), encoding="utf-8")
    tmp.replace(p)
    return job


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def job_running(tier: str, name: str) -> bool:
    th = _RUNNING.get(f"{tier}/{name}")
    return th is not None and th.is_alive()


def job_status(tier: str, name: str) -> dict:
    """`{on, collection, since, job}` for the room. A job left «running» by a
    gateway restart is resumed here: the room never stays «in corso» forever."""
    meta = _svc()._read_meta(tier, name)[0]
    ix = settings(meta)
    job = _job_read(tier, name)
    if job.get("state") in RUNNING_STATES and not job_running(tier, name):
        _start_job(tier, name, job["state"] == "indexing")
        job = _job_read(tier, name)
    return {"on": ix["on"], "collection": ix["collection"], "since": ix["since"],
            "job": job or {"state": "idle"}}


def set_enabled(tier: str, name: str, enabled: bool) -> dict:
    """The owner flips the room's toggle (#648). Answers at once; the job runs
    in the background. Refused while a job runs. Flipping to the value it
    already has re-runs the job (a failed indexing is retried this way)."""
    from .topics.service import TopicError
    key = f"{tier}/{name}"
    with _JOBS_GUARD:
        if job_running(tier, name):
            raise TopicError("indicizzazione in corso: attendi che finisca")
        svc = _svc()
        meta, ver = svc._read_meta(tier, name)
        index = dict(meta.get("index") or {})
        index["on"] = bool(enabled)
        index.pop("enabled", None)
        if enabled:
            index["since"] = _now_iso()
        meta["index"] = index
        svc._write_meta(tier, name, meta, base_version=ver)
        _start_job(tier, name, bool(enabled))
    LOG.info("topic index: %s %s", key, "ON" if enabled else "OFF")
    return {"enabled": bool(enabled), **job_status(tier, name)}


def _start_job(tier: str, name: str, on: bool) -> None:
    key = f"{tier}/{name}"
    _job_write(tier, name, state="indexing" if on else "deindexing", done=0, total=0,
               started_at=_now_iso(), finished_at=None, error=None)
    th = threading.Thread(target=_run_job, args=(tier, name, on),
                          name=f"topic-index-{key}", daemon=True)
    _RUNNING[key] = th
    th.start()


def _run_job(tier: str, name: str, on: bool) -> None:
    with _lock(f"{tier}/{name}"):
        try:
            if on:
                _index_all(tier, name)
            else:
                _deindex_all(tier, name)
            _job_write(tier, name, state="done", finished_at=_now_iso(), error=None)
        except Exception as e:  # noqa: BLE001 — the room shows the error, toggling again retries
            LOG.warning("topic index: job %s/%s fallito (%s)", tier, name, type(e).__name__)
            _job_write(tier, name, state="error", finished_at=_now_iso(),
                       error=f"{type(e).__name__}: {str(e)[:200]}")


def _fresh_state() -> dict:
    return {"days": {}, "files": {}, "drive": {}, "summary": "", "v2": True}


def _index_all(tier: str, name: str) -> None:
    """ON: a clean collection, then every file, the Drive content, the summary."""
    svc = _svc()
    info = ensure(tier, name)
    coll, t = info["collection"], info["tier"]
    rag = _rag()
    rag.drop_collection(coll)          # whatever was there before the switch
    rag.set_collection_tier(coll, t)
    st = _fresh_state()
    _save(coll, st)
    meta = svc._read_meta(tier, name)[0]
    files: list[dict] = []
    for root in ROOTS:
        _walk(svc, tier, name, root, files)
    drive = _drive_files(meta)
    drive_rows = drive["files"] if drive else []
    total = len(files) + len(drive_rows) + 1
    done = 0
    _job_write(tier, name, total=total, done=0)
    for e in files:
        _ingest_file(svc, rag, tier, name, coll, t, st, e)
        done += 1
        _job_write(tier, name, done=done)
    for row in drive_rows:
        _ingest_drive(rag, tier, name, coll, t, st, row)
        done += 1
        _job_write(tier, name, done=done)
    _ingest_summary(svc, rag, tier, name, coll, t, st)
    _job_write(tier, name, done=total)


def _deindex_all(tier: str, name: str) -> None:
    """OFF: the collection is emptied — files, Drive, messages."""
    svc = _svc()
    meta = svc._read_meta(tier, name)[0]
    coll = _own_collection(svc, tier, name, settings(meta)["collection"])
    _job_write(tier, name, total=1, done=0)
    if coll:
        _rag().drop_collection(coll)
        st = _fresh_state()
        st["cleared"] = True
        _save(coll, st)
    _job_write(tier, name, done=1)


def _drop(tier: str, name: str, coll: str) -> bool:
    try:
        _rag().drop_collection(coll)
    except Exception as e:  # noqa: BLE001 — stays pending, retried
        LOG.warning("topic index: %s non svuotata (%s)", coll, type(e).__name__)
        return False
    st = _fresh_state()
    st["cleared"] = True
    _save(coll, st)
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


# ── one document at a time ─────────────────────────────────────────────────

def _ingest_file(svc, rag, tier, name, coll, t, st, e) -> bool:
    """One room file → `file/<path>`. Too big or unreadable: remembered, not
    retried until it changes."""
    path = e["path"]
    sig = f"{e.get('size')}:{e.get('mtime_iso')}"
    if (e.get("size") or 0) > MAX_BYTES:
        st["files"][path] = sig
        _save(coll, st)
        return False
    try:
        text = file_text(path, svc.read_file(tier, name, path))[:MAX_CHARS]
    except Exception as err:  # noqa: BLE001 — one file never stops the pass
        LOG.warning("topic index: %s/%s %s non letto (%s)", tier, name, path,
                    type(err).__name__)
        st["files"][path] = sig
        _save(coll, st)
        return False
    if text.strip():
        prov = svc.provenance_of(tier, name, path) or "untrusted"
        rag.ingest_text(coll, f"file/{path}", text, source=f"{tier}/{name}/{path}",
                        provenance=prov, tier=t)
    st["files"][path] = sig
    _save(coll, st)
    return bool(text.strip())


def _drive_files(meta: dict) -> dict | None:
    """Every file under the room's linked Drive folders, through google-pack's
    `index_walk` (#648). None when the component is not here: then Drive is
    neither indexed nor cleaned (nothing seen, nothing removed)."""
    from .topics.service import drive_folders
    folders = drive_folders(meta)
    if not folders:
        return {"files": [], "complete": True}
    try:
        from .components import loader as _components
        svc = _components.service("google-pack", "index_walk")
    except Exception:  # noqa: BLE001
        svc = None
    if svc is None:
        return None
    rows, complete = [], True
    for f in folders:
        try:
            out = svc.handler(str(f.get("folder") or ""), f.get("account"))
        except Exception as e:  # noqa: BLE001 — a folder not listed is not emptied
            LOG.warning("topic index: Drive %s non elencata (%s)", f.get("folder"),
                        type(e).__name__)
            complete = False
            continue
        complete = complete and bool(out.get("complete", True))
        for r in out.get("files") or []:
            rows.append({**r, "account": f.get("account"),
                         "mount": str(f.get("name") or "drive")})
    return {"files": rows, "complete": complete}


def _ingest_drive(rag, tier, name, coll, t, st, row) -> bool:
    """One Drive file → `drive/<mount>/<path>`, always `untrusted` (nobody in
    the room vouched for it)."""
    doc = f"drive/{row['mount']}/{row['path']}"
    sig = f"{row.get('size')}:{row.get('modifiedTime')}"
    if (row.get("size") or 0) > MAX_BYTES:
        st["drive"][doc] = sig
        _save(coll, st)
        return False
    try:
        from .components import loader as _components
        svc = _components.service("google-pack", "index_read")
        if svc is None:
            return False
        fname, data = svc.handler(row["id"], row.get("account"))
        text = file_text(fname, data)[:MAX_CHARS]
    except Exception as err:  # noqa: BLE001
        LOG.warning("topic index: %s/%s Drive %s non letto (%s)", tier, name, row.get("id"),
                    type(err).__name__)
        st["drive"][doc] = sig
        _save(coll, st)
        return False
    if text.strip():
        rag.ingest_text(coll, doc, text, source=f"{tier}/{name}/{doc}",
                        provenance="untrusted", tier=t)
    st["drive"][doc] = sig
    _save(coll, st)
    return bool(text.strip())


def _ingest_summary(svc, rag, tier, name, coll, t, st) -> None:
    try:
        summary = svc.s.read(svc._summary_p(tier, name)).data.decode("utf-8", "replace")
    except Exception:  # noqa: BLE001
        summary = ""
    h = hashlib.sha256(summary.encode()).hexdigest()[:16]
    if st.get("summary") == h:
        return
    if summary.strip():
        rag.ingest_text(coll, "summary", summary[:MAX_CHARS],
                        source=f"{tier}/{name} summary", provenance="agent", tier=t)
    else:
        try:
            rag.remove("summary", None, coll)
        except Exception:  # noqa: BLE001
            pass
    st["summary"] = h
    _save(coll, st)


def _message_provenance(tier: str, name: str, msg: dict) -> str:
    kind = str(msg.get("kind") or "")
    if kind in UNTRUSTED_KINDS:
        return "untrusted"
    if kind in ("ai", "system"):
        return "untrusted" if _tainted_on(tier, name, _day(msg.get("ts"))) else "agent"
    return "trusted"


_LAST: dict[str, str] = {}


def _ingest_message(rag, tier, name, coll, t, msg: dict) -> None:
    """One chat message → `msg/<id>`, with the previous one as context (a «sì,
    procedi» alone is not findable)."""
    key = f"{tier}/{name}"
    line = f"[{str(msg.get('ts'))[:16]}] {msg.get('author')}: {msg.get('text') or ''}"
    prev = _LAST.get(key)
    text = (f"(prima: {prev[:500]})\n{line}" if prev else line)[:MAX_CHARS]
    _LAST[key] = line
    if not str(msg.get("text") or "").strip():
        return
    rag.ingest_text(coll, f"msg/{msg['id']}", text, source=f"{tier}/{name} messaggio {msg['id']}",
                    provenance=_message_provenance(tier, name, msg), tier=t)


# ── changes inside the room, at once (#648) ─────────────────────────────────

import queue as _queue

_Q: "_queue.Queue[tuple]" = _queue.Queue()
_WORKER: list[threading.Thread] = []
_WORKER_GUARD = threading.Lock()


def notify(event: str, tier: str, name: str, **kw) -> None:
    """Called by the topic service after a message is posted (`message`, msg=…)
    or a file is written, moved or deleted (`file`, paths=[…]). Never blocks
    and never fails the caller: the work happens on the queue's thread."""
    try:
        _Q.put_nowait((event, tier, name, kw))
        with _WORKER_GUARD:
            if not (_WORKER and _WORKER[0].is_alive()):
                th = threading.Thread(target=_drain, name="topic-index-live", daemon=True)
                _WORKER[:] = [th]
                th.start()
    except Exception:  # noqa: BLE001
        pass


class _Busy(Exception):
    """The topic is held by its job: the event goes back to the queue."""


def _drain() -> None:
    import time as _time
    while True:
        item = _Q.get()
        event, tier, name, kw = item
        try:
            _apply(event, tier, name, kw)
        except _Busy:
            # One room's long job must not hold up every other room's
            # messages: this event waits its turn at the back of the queue.
            _time.sleep(0.5 if _Q.empty() else 0)
            _Q.put(item)
        except Exception as e:  # noqa: BLE001 — the safety-net pass catches up
            LOG.warning("topic index: %s su %s/%s non applicato (%s)", event, tier, name,
                        type(e).__name__)


def _apply(event: str, tier: str, name: str, kw: dict, wait: float = 0.2) -> None:
    svc = _svc()
    meta = svc._read_meta(tier, name)[0]
    ix = settings(meta)
    if not ix["on"] or not ix["collection"]:
        return
    lk = _lock(f"{tier}/{name}")
    if not lk.acquire(timeout=wait):        # after a running job, never during
        raise _Busy()
    try:
        _apply_locked(svc, meta, ix, event, tier, name, kw)
    finally:
        lk.release()


def _apply_locked(svc, meta, ix, event, tier, name, kw) -> None:
    coll = ix["collection"]
    t = cat.norm_tier(meta.get("tier") or tier)
    rag = _rag()
    if event == "message":
        msg = kw.get("msg") or {}
        if ix["since"] and str(msg.get("ts") or "") < ix["since"]:
            return
        _ingest_message(rag, tier, name, coll, t, msg)
        return
    if event == "file":
        st = _load(coll)
        for path in kw.get("paths") or []:
            path = str(path or "").strip("/")
            if not path or path.split("/", 1)[0] not in ROOTS:
                continue
            gone = [p for p in st["files"] if p == path or p.startswith(path + "/")]
            for p in gone:
                rag.remove(f"file/{p}", None, coll)
                st["files"].pop(p, None)
            _save(coll, st)
            found: list[dict] = []
            try:
                entries = svc.list_files(tier, name, path.rsplit("/", 1)[0])
            except Exception:  # noqa: BLE001 — gone, or the pass will see it
                entries = []
            for e in entries:
                if e.get("path") == path and e.get("kind") != "dir":
                    found.append(e)
                elif e.get("path") == path and e.get("kind") == "dir":
                    _walk(svc, tier, name, path, found)
            for e in found:
                if str(e.get("path") or "").lower().endswith(TEXT_EXT + DOC_EXT + EML_EXT):
                    _ingest_file(svc, rag, tier, name, coll, t, st, e)


# ── the periodic pass: the safety net ───────────────────────────────────────

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
    if job_running(tier, name):
        return {"skipped": "job in corso", "pending": True}
    if not ix["on"]:
        # Off (#648): nothing of the room stays in the RAG. A collection
        # indexed before the toggle existed is emptied once.
        coll = _own_collection(svc, tier, name, ix["collection"])
        if coll and not _load(coll).get("cleared"):
            _drop(tier, name, coll)
            return {"collection": coll, "cleared": True, "pending": False}
        return {"skipped": "indicizzazione spenta"}
    if str(meta.get("status") or "") == "archived":
        return {"skipped": "topic archiviato"}
    info = ensure(tier, name)
    coll, t = info["collection"], info["tier"]
    rag = _rag()
    st = _load(coll)
    done = {"files": 0, "drive": 0, "removed": 0}
    pending = False
    _ingest_summary(svc, rag, tier, name, coll, t, st)
    # room files
    found: list[dict] = []
    roots_ok = all([_walk(svc, tier, name, root, found) for root in ROOTS])
    present = {}
    left = MAX_FILES
    for e in found:
        sig = f"{e.get('size')}:{e.get('mtime_iso')}"
        present[e["path"]] = sig
        if st["files"].get(e["path"]) == sig:
            continue
        if left <= 0:
            pending = True
            continue
        left -= 1
        done["files"] += int(_ingest_file(svc, rag, tier, name, coll, t, st, e))
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
    # Drive: changes there are picked up here (Drive does not tell us)
    drive = _drive_files(meta)
    if drive is not None:
        seen = {}
        for row in drive["files"]:
            doc = f"drive/{row['mount']}/{row['path']}"
            sig = f"{row.get('size')}:{row.get('modifiedTime')}"
            seen[doc] = sig
            if st["drive"].get(doc) == sig:
                continue
            if left <= 0:
                pending = True
                continue
            left -= 1
            done["drive"] += int(_ingest_drive(rag, tier, name, coll, t, st, row))
        if drive["complete"]:
            for doc in [d for d in st["drive"] if d not in seen]:
                try:
                    rag.remove(doc, None, coll)
                except Exception:  # noqa: BLE001
                    pending = True
                    continue
                st["drive"].pop(doc, None)
                _save(coll, st)
                done["removed"] += 1
    return {"collection": coll, **done, "pending": pending}


_CLEAR_STARTED: list[bool] = []


def _clear_before_toggle() -> None:
    """Once per gateway (#648): every room starts OFF, so the collections
    indexed before the toggle are emptied now — not one room per pass, which
    would leave them searchable for hours. Rooms already switched on are not
    touched; a failure is left to the periodic pass."""
    svc = _svc()
    for row in svc.list(include_archived=True):
        try:
            meta = svc._read_meta(row["tier"], row["name"])[0]
            s = settings(meta)
            coll = _own_collection(svc, row["tier"], row["name"], s["collection"])
            if s["on"] or not coll or _load(coll).get("cleared"):
                continue
            with _lock(f"{row['tier']}/{row['name']}"):
                _drop(row["tier"], row["name"], coll)
        except Exception as e:  # noqa: BLE001
            LOG.warning("topic index: pulizia di %s/%s rimandata (%s)", row.get("tier"),
                        row.get("name"), type(e).__name__)


def topics() -> list[dict]:
    """The topics to visit: indexing on — or a collection from before the
    toggle (#648) still to empty."""
    if not _CLEAR_STARTED:
        _CLEAR_STARTED.append(True)
        threading.Thread(target=_clear_before_toggle, name="topic-index-clear",
                         daemon=True).start()
    svc = _svc()
    out = []
    for row in svc.list():
        try:
            meta = svc._read_meta(row["tier"], row["name"])[0]
        except Exception:  # noqa: BLE001
            continue
        s = settings(meta)
        if s["on"] or (s["collection"] and not _load(s["collection"]).get("cleared")):
            out.append({"tier": row["tier"], "name": row["name"], "collection": s["collection"]})
    return out

"""The instance's data catalog (clodia-platform#590, D1 #591).

Datastores (SQLite, declared by packs) and RAG collections (pgvector) are
INSTANCE resources: a topic imports them (`topic_data`), and the topic's owner
grants each agent of the channel read or write. A pack may create a resource;
it does not own it — removing the pack keeps the data, the catalog entry and
the imports.

One entry per resource, keyed `datastore:<pack>/<name>` or `rag:<name>`:

    {kind, name, tier, owner, importers, created_at, source}

- `tier`: the catalog's level. The level that counts at use is the HIGHER of
  this and the source's own (`datastores[].clearance`, the RAG service's tier):
  an admin can raise a resource, never lower it below what its data declares.
- `importers`: who may import it into a topic — principals, or `@admin` (any
  platform admin). Default `["@admin"]`.
- `owner`: who registered it ("" for the ones seeded from what exists).

Seeded at boot (`sync`) from what exists today, so the switch to topic access
(D4) finds every resource already listed. Retiring an entry never deletes data.
"""
from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone

LOG = logging.getLogger("clodia-tools.data_catalog")

KINDS = ("datastore", "rag")
ADMIN = "@admin"
_LOCK = threading.Lock()
_TIERS = ("SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4")


def _path():
    from . import state_paths
    return state_paths.state_path("data-catalog.json")


def rank(tier: str | None) -> int:
    t = str(tier or "").strip().upper()
    legacy = {"P0": "SEAL-0", "P1": "SEAL-1", "P2": "SEAL-2", "P3": "SEAL-3"}
    t = legacy.get(t, t)
    return _TIERS.index(t) if t in _TIERS else len(_TIERS) - 1   # unknown → highest


def rank_have(tier: str | None) -> int:
    """The rank of a level someone or something HAS (clearance, topic tier):
    unknown → below everything. `rank` reads a NEED, where unknown is the top."""
    t = str(tier or "").strip().upper()
    legacy = {"P0": "SEAL-0", "P1": "SEAL-1", "P2": "SEAL-2", "P3": "SEAL-3"}
    t = legacy.get(t, t)
    return _TIERS.index(t) if t in _TIERS else -1


def valid_tier(tier: str | None) -> bool:
    return rank_have(tier) >= 0


def norm_tier(tier: str | None) -> str:
    return _TIERS[rank(tier)]


def key(kind: str, name: str) -> str:
    if kind not in KINDS:
        raise ValueError(f"tipo di dato sconosciuto: '{kind}' (datastore | rag)")
    name = str(name or "").strip()
    if not name:
        raise ValueError("nome della risorsa richiesto")
    if kind == "datastore":
        from . import datastores
        datastores.parse_key(name)          # `<pack>/<name>` or ValueError
    return f"{kind}:{name}"


def _load() -> dict:
    p = _path()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        # An unreadable catalog grants nothing: imports are refused until it is
        # repaired, never re-created over it.
        raise RuntimeError(f"catalogo dati illeggibile ({type(e).__name__}): {p}") from e


def _save(data: dict) -> None:
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True, ensure_ascii=False),
                   encoding="utf-8")
    tmp.replace(p)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def source_tier(kind: str, name: str) -> str | None:
    """The level the data itself declares, None when the source is gone."""
    if kind == "datastore":
        from . import datastores
        pack, ds = datastores.parse_key(name)
        entry = datastores.find(pack, ds)
        return norm_tier(entry["clearance"]) if entry else None
    from .tools import eu_corpus
    try:
        return norm_tier(eu_corpus.collection_tier(name))
    except Exception:  # noqa: BLE001 — service down: the catalog's own tier
        return None


def entries() -> list[dict]:
    return [dict(v, key=k) for k, v in sorted(_load().items())]


def get(kind: str, name: str) -> dict | None:
    e = _load().get(key(kind, name))
    return dict(e) if e else None


def effective_tier(entry: dict) -> str:
    src = source_tier(entry["kind"], entry["name"])
    tiers = [entry.get("tier") or "SEAL-4"] + ([src] if src else [])
    return _TIERS[max(rank(t) for t in tiers)]


def register(kind: str, name: str, *, tier: str, owner: str = "",
             importers: list[str] | None = None, source: str = "") -> dict:
    """Add a resource (idempotent: an existing entry is kept as it is)."""
    k = key(kind, name)
    with _LOCK:
        data = _load()
        if k not in data:
            data[k] = {"kind": kind, "name": name, "tier": norm_tier(tier),
                       "owner": owner, "importers": list(importers or [ADMIN]),
                       "created_at": _now(), "source": source}
            _save(data)
        return dict(data[k])


def update(kind: str, name: str, *, tier: str | None = None,
           importers: list[str] | None = None) -> dict:
    k = key(kind, name)
    with _LOCK:
        data = _load()
        if k not in data:
            raise KeyError(f"risorsa non in catalogo: {k}")
        if tier is not None:
            if not valid_tier(tier):
                raise ValueError(f"tier sconosciuto: '{tier}' (SEAL-0 … SEAL-4)")
            data[k]["tier"] = norm_tier(tier)
        if importers is not None:
            clean = sorted({str(i).strip() for i in importers if str(i).strip()})
            data[k]["importers"] = clean or [ADMIN]
        _save(data)
        return dict(data[k])


def retire(kind: str, name: str) -> bool:
    """Drop the catalog entry (the data stays; topics importing it lose
    access at the next call, since `topic_data` requires the entry)."""
    k = key(kind, name)
    with _LOCK:
        data = _load()
        if data.pop(k, None) is None:
            return False
        _save(data)
        return True


def may_import(entry: dict, principal: str, *, is_admin: bool, clearance: str | None) -> str:
    """"" when `principal` may import `entry` into a topic, else the reason."""
    allowed = set(entry.get("importers") or [ADMIN])
    if not (principal in allowed or (is_admin and ADMIN in allowed)):
        return f"'{principal}' non è fra chi può importare {entry['kind']} '{entry['name']}'"
    need = effective_tier(entry)
    if rank_have(clearance) < rank(need):
        return (f"clearance di '{principal}' ({clearance or 'nessuna'}) insufficiente "
                f"per {entry['kind']} '{entry['name']}' ({need})")
    return ""


_LAST_SYNC = [0.0]


def sync_due(every: float = 60.0) -> bool:
    """At most one on-demand sync a minute (an import of a bogus name must not
    become a way to hammer the RAG service)."""
    import time
    now = time.monotonic()
    if now - _LAST_SYNC[0] < every:
        return False
    _LAST_SYNC[0] = now
    return True


def sync() -> int:
    """Register what exists and is not listed yet: the declared datastores
    (tier = their clearance) and the RAG collections (tier = the service's).
    Returns how many entries were added. Never removes anything."""
    added = 0
    try:
        from . import datastores
        for ds in datastores.declared():
            name = f"{ds['pack']}/{ds['name']}"
            if get("datastore", name) is None:
                register("datastore", name, tier=ds["clearance"], source=f"pack:{ds['pack']}")
                added += 1
    except Exception as e:  # noqa: BLE001
        LOG.warning("data catalog: datastores not synced (%s)", type(e).__name__)
    try:
        from .tools import eu_corpus
        for col in (eu_corpus.collections() or {}).get("collections") or []:
            name = str((col or {}).get("collection") or "").strip()
            if name and get("rag", name) is None:
                register("rag", name, tier=col.get("tier") or "SEAL-4", source="rag-service")
                added += 1
    except Exception as e:  # noqa: BLE001
        LOG.warning("data catalog: RAG collections not synced (%s)", type(e).__name__)
    if added:
        LOG.info("data catalog: %d resources registered", added)
    return added

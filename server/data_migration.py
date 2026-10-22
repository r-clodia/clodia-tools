"""From seed grants to topic imports (clodia-platform#590, D6 #596).

`plan()` is a DRY RUN: for every catalog resource, the agents that reach it
today (a datastore's manifest `seeds`, a collection's `rag_read`/`rag_write`)
and the topics where those agents are participants. Each proposal is an
import with per-agent grants, or a skipped one with its reason (the topic's
tier is below the resource's). Nothing is written.

`apply(items, by, ...)` writes the proposals the owner approved, through the
same `topic_data` functions the webui uses, so every rule holds (importer,
clearance, tier). It never switches `data_access`; that is a separate,
explicit step.

Super-agents reached every datastore regardless of `seeds`; topic mode has no
such bypass (decision 5 of #590). The plan lists them only where a grant names
them, and says so.
"""
from __future__ import annotations

import logging

from . import data_catalog as cat, topic_data as td

LOG = logging.getLogger("clodia-tools.data_migration")


def _agents_cfg() -> dict:
    from . import whitelist
    return whitelist.CONFIG.get("agents") or {}


def _verb_ok(agent: str, verb: str) -> bool:
    from . import main
    a = _agents_cfg().get(agent) or {}
    allowed = set(a.get("allowed_tools") or [])
    return main._is_super(agent) or main._tool_allowed(verb, allowed)


def _datastore_agents(name: str) -> dict[str, str]:
    from . import datastores
    pack, ds = datastores.parse_key(name)
    entry = datastores.find(pack, ds) or {}
    out = {}
    for ag in entry.get("seeds") or []:
        if _verb_ok(ag, "datastore.write"):
            out[ag] = "write"
        elif _verb_ok(ag, "datastore.read"):
            out[ag] = "read"
    return out


_GRANTS: dict[str, dict] = {}


def _grants(ag: str) -> dict | None:
    """`runtime.rag_grants`, once per agent per plan (N agents × M collections
    calls to the core otherwise)."""
    from .tools import runtime
    if ag not in _GRANTS:
        try:
            _GRANTS[ag] = runtime.rag_grants(ag)
        except Exception:  # noqa: BLE001 — an agent the core does not know
            _GRANTS[ag] = None
    return _GRANTS[ag]


def _rag_agents(name: str) -> dict[str, str]:
    from . import main
    try:
        members = main._rag_declared_members(name)     # the pack's own list (#343)
    except PermissionError:
        members = []
    out = {}
    for ag in _agents_cfg():
        if members is not None and ag not in members:
            continue                    # denied today: the plan grants no more
        g = _grants(ag)
        if g is None:
            continue
        w, r = set(g.get("rag_write") or []), set(g.get("rag_read") or [])
        if "*" in w or name in w:
            out[ag] = "write"
        elif "*" in r or name in r:
            out[ag] = "read"
    return out


def _topics() -> list[tuple[str, str, dict]]:
    from . import main
    svc = main._topics()
    out = []
    for row in svc.list():
        try:
            meta = svc._read_meta(row["tier"], row["name"])[0]
        except Exception:  # noqa: BLE001
            continue
        out.append((row["tier"], row["name"], meta))
    return out


def plan() -> dict:
    _GRANTS.clear()
    items, notes = [], []
    topics = _topics()
    for entry in cat.entries():
        kind, name = entry["kind"], entry["name"]
        who = _datastore_agents(name) if kind == "datastore" else _rag_agents(name)
        if not who:
            continue
        need = cat.effective_tier(entry)
        for tier, tname, meta in topics:
            from .topics.service import TopicService
            parts = set(TopicService.participants_map(meta)) | {meta.get("owner")}
            grants = {a: m for a, m in who.items() if a in parts}
            if not grants:
                continue
            already = any(e["kind"] == kind and e["name"] == name for e in td.imports(meta))
            item = {"topic": f"{tier}/{tname}", "kind": kind, "name": name,
                    "tier": need, "grants": grants}
            if cat.rank(tier) < cat.rank(need):
                item.update(status="skipped", reason=f"topic {tier} sotto il tier {need}")
            else:
                item.update(status="already" if already else "ok")
            items.append(item)
    from . import main
    supers = sorted(a for a in _agents_cfg() if main._is_super(a))
    if supers:
        notes.append(f"super-agent senza bypass in modalità topic: {', '.join(supers)} "
                     "(compaiono solo dove un grant li nomina)")
    notes.append("in modalità topic l'accesso ai dati c'è solo nei turni di canale: "
                 "job non legati a un topic, Telegram 1:1 e DM non vedono nessun dato")
    return {"items": items, "notes": notes,
            "counts": {s: sum(1 for i in items if i["status"] == s)
                       for s in ("ok", "already", "skipped")}}


def apply(items: list[dict], *, by: str, is_admin: bool, clearance: str | None) -> dict:
    done, failed = [], []
    for it in items or []:
        if it.get("status") not in ("ok", "already"):
            continue
        tier, _, name = str(it.get("topic") or "").partition("/")
        kind, res = it.get("kind"), it.get("name")
        try:
            td.import_resource(tier, name, kind, res, principal=by, is_admin=is_admin,
                               clearance=clearance)
            for agent, mode in (it.get("grants") or {}).items():
                td.grant(tier, name, kind, res, agent, mode)
            done.append(it["topic"] + " " + f"{kind}:{res}")
        except Exception as e:  # noqa: BLE001 — one item never stops the others
            failed.append({"item": f"{it.get('topic')} {kind}:{res}", "error": str(e)[:200]})
    LOG.info("data migration: %d applied, %d failed (by %s)", len(done), len(failed), by)
    return {"applied": done, "failed": failed}

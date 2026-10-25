"""The A·V·R·Q migration plan (clodia-platform#616, S3 of #613).

A DRY RUN: it reads what happened and what is configured, and proposes the
tuples that would replace the seeds' verbs. It writes nothing. The owner
approves the plan; applying it is a separate step.

What it reads:

- the AUDIT (the last `days`): every `tool.call` with its agent's seed, the
  room of its turn (`turn.start` resource `chan:<tier>:<topic>:<agent>`), its
  outcome (`tool.result`), and the targets the gateway recorded for it
  (`flow.egress` destinations, `flow.ingress` sources and their vetting);
- the CONFIGURATION: every agent's resolved verbs, the global and room
  egress/ingress lists, the rooms' toolboxes (#605), Drive folders and data
  grants (#590).

What it proposes (owner's decisions, 24-25 Oct 2026):

- **global**: the room floor (`topic.*`) and personal memory for everyone;
  each agent's governance verbs; the verbs an agent used OUTSIDE rooms (DMs,
  jobs not bound to a topic), with the targets it reached;
- **per topic**, for every participant (`*`, as the toolbox of #605): the
  verbs used in the room, the verbs the owner enabled there, the room's Drive
  folders (read-only unless something was written there) and the data grants.
  Q allows the targets observed and the entries of the room's and the global
  lists of the verb's schemes; anything else takes the default (ask for a
  write, allow-untrusted for a read). A global list entry has no tuple of its
  own: without a verb it would make nothing available, and with one it would
  make the verb available everywhere;
- **dropped**: seed verbs nobody used in the window, governance excepted.
"""
from __future__ import annotations

import json
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from . import authz as A

#: Verbs of the platform/governance namespaces stay global, per agent.
GOVERNANCE = A.GOVERNANCE
#: An agent's own tools, not the room's (room_tools `_PER_SEED`): global, per agent.
PER_AGENT = frozenset({"copybrain", "fs"})
#: Data is granted collection by collection (#590): a room row with resource
#: `*` would open every collection, so usage of these is left to the grants.
BY_DATA = frozenset({"rag", "datastore", "eu_corpus"})
#: Everyone, everywhere: the room floor (decision 2 of #604) and personal memory.
FLOOR = (("topic.*", "partecipare alla stanza: il pavimento di ogni topic (#604)"),
         ("memory.*", "memoria personale dell'agente"))
#: Drive verbs that only read (a linked folder is read-only by default).
DRIVE_READ = ("gdrive.list", "gdrive.search", "gdrive.download")
DRIVE_WRITE = ("gdrive.upload", "gdrive.update", "gdrive.mkdir", "gdrive.move",
               "gdrive.rename")


def _scope_of_chat(chat: str) -> Optional[str]:
    """`chan:SEAL-1:tomato-blogging:clodia` → `SEAL-1/tomato-blogging`; else None."""
    parts = str(chat or "").split(":")
    if len(parts) >= 3 and parts[0] == "chan":
        return f"{parts[1]}/{parts[2]}"
    return None


def _audit_files(days: int) -> list[Path]:
    from . import audit as _audit
    root = _audit.root_dir()
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y%m%d")
    return sorted(p for p in root.glob("events-*.jsonl") if p.stem[7:] >= since)


def usage(days: int = 30) -> dict:
    """`{(scope|None, seed, verb): {calls, ok, targets: {uri: kind}}}` from the audit."""
    turns: dict[str, Optional[str]] = {}
    calls: dict[str, tuple] = {}
    results: dict[str, str] = {}
    flows: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for path in _audit_files(days):
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                ev = e.get("event") or {}
                t = ev.get("type")
                if t == "turn.start" and e.get("span_id"):
                    turns[e["span_id"]] = _scope_of_chat(ev.get("resource") or "")
                elif t == "tool.call":
                    seed = (e.get("agent") or {}).get("seed") or ""
                    if seed:
                        calls[e["event_id"]] = (seed, ev.get("resource") or "",
                                                e.get("parent_span_id"))
                elif t == "tool.result":
                    status = str((e.get("result") or {}).get("status") or "")
                    if e.get("parent_span_id"):
                        results[e["parent_span_id"]] = status
                elif t == "flow.egress":
                    for d in (e.get("tool") or {}).get("destination") or []:
                        flows[e.get("parent_span_id") or ""].append((str(d), "egress"))
                elif t == "flow.ingress":
                    src = (e.get("tool") or {}).get("source")
                    if src:
                        kind = ("trusted" if (e.get("tool") or {}).get("vetted") == "vetted"
                                else "ingress")
                        flows[e.get("parent_span_id") or ""].append((str(src), kind))
    out: dict = {}
    for cid, (seed, verb, parent) in calls.items():
        key = (turns.get(parent), seed, verb)
        u = out.setdefault(key, {"calls": 0, "ok": 0, "targets": {}})
        u["calls"] += 1
        if results.get(cid, "ok") in ("ok", "success", ""):
            u["ok"] += 1
        for uri, kind in flows.get(cid, ()):
            u["targets"][uri] = kind
    return out


# ── what is configured ──────────────────────────────────────────────────────

def _agents() -> list[str]:
    from . import whitelist as _wl
    return sorted((_wl.CONFIG or {}).get("agents") or {})


def _seed_verbs(agent: str) -> set[str]:
    from . import main as _m
    try:
        return set(_m._declared_tools(agent))
    except Exception:  # noqa: BLE001
        return set()


def _topics() -> list[tuple[str, str, dict]]:
    from . import main as _m
    svc = _m._topics()
    out = []
    for t in svc.list():
        tier, name = t.get("tier"), t.get("name")
        try:
            meta = svc._read_meta(tier, name)[0]
        except Exception:  # noqa: BLE001
            continue
        out.append((tier, name, meta))
    return out


def _list_entries(direction: str, scope: Optional[str]) -> list[str]:
    from . import egress as _eg
    try:
        return [u for u in _eg.effective_uris(direction, scope) if u]
    except Exception:  # noqa: BLE001
        return []


def _schemes_of(verb: str) -> tuple[set[str], set[str]]:
    """The schemes a verb writes to and reads from, per the manifests."""
    from .connectors import resolved as _c
    return ({m.scheme for m in _c.egress_mappings(verb)},
            {m.scheme for m in _c.source_mappings(verb)})


def _clauses(verb: str, scope: Optional[str], observed: dict) -> list[dict]:
    """Q for one verb in one place: the targets observed, plus the list
    entries of the verb's schemes; the rest takes the verb's default."""
    out_s, in_s = _schemes_of(verb)
    rule: list[dict] = []
    seen = set()

    def add(c):
        key = (c["effect"], c["match"])
        if key in seen:
            return
        try:
            A.parse_clause(c)
        except A.AuthzError:
            return
        seen.add(key)
        rule.append(c)
    for uri, kind in sorted(observed.items()):
        if kind == "egress":
            add({"effect": "allow", "match": uri})
        elif kind == "trusted":
            add({"effect": "allow", "match": uri, "trust": "trusted"})
    for u in _list_entries("egress", scope):
        if u.split(":", 1)[0] in out_s or (u.startswith("http") and "https" in out_s):
            add({"effect": "allow", "match": u})
    for u in _list_entries("ingress", scope):
        if u.split(":", 1)[0] in in_s or (u.startswith("http") and "https" in in_s):
            add({"effect": "allow", "match": u, "trust": "trusted"})
    if not rule:
        # No list and nothing observed: the default (ask for a write,
        # allow-untrusted for a read) decides every target.
        rule = [{"effect": "allow", "match": "*"}] if not out_s else [
            {"effect": "ask", "match": "*"}]
    return rule


def _reads(verb: str) -> bool:
    from . import authz_shadow as _s
    return _s.facts(verb, {})["kind"] == A.READ


def plan(days: int = 30) -> dict:
    """The proposed tuples, global and per topic, with the reason of each, and
    what is dropped. Writes nothing."""
    used = usage(days)
    agents = _agents()
    seed = {a: _seed_verbs(a) for a in agents}
    glob: list[dict] = []
    topics: dict[str, list[dict]] = {}
    dropped: dict[str, list[str]] = {}
    n = [0]

    def tid(prefix):
        n[0] += 1
        return f"{prefix}-{n[0]:04d}"

    for verb, why in FLOOR:
        glob.append({"id": tid("g"), "agent": "*", "verb": verb, "resource": "*",
                     "rule": [{"effect": "allow", "match": "*"}], "why": why})
    for a in agents:
        gov = sorted(v for v in seed[a] if v.split(".", 1)[0] in GOVERNANCE or v == "*")
        for v in gov:
            glob.append({"id": tid("g"), "agent": a, "verb": v, "resource": "*",
                         "rule": [{"effect": "allow", "match": "*"}],
                         "why": "verbo di governo del seed: resta globale, per agente"})
    outside = defaultdict(dict)
    for (scope, a, verb), u in used.items():
        ns = verb.split(".", 1)[0]
        if not u["ok"] or ns in GOVERNANCE or ns in BY_DATA \
                or verb.startswith(("topic.", "memory.")):
            continue
        # An agent's own tools go global for that agent wherever they were used.
        if scope is None or ns in PER_AGENT:
            outside[(a, verb)].update(u["targets"])
    for (a, verb), observed in sorted(outside.items()):
        own = verb.split(".", 1)[0] in PER_AGENT
        row = {"id": tid("g"), "agent": a, "verb": verb, "resource": "*",
               "rule": _clauses(verb, None, observed),
               "why": ("strumento proprio dell'agente: globale" if own else
                       f"usato fuori dai canali (DM o job) negli ultimi {days} giorni")}
        if not own:
            # What an agent does in the owner's DMs is not what it does in
            # every room (#614 §1 `where`).
            row["where"] = "outside"
        glob.append(row)

    from . import room_tools as _rt
    from .topics.service import drive_folders
    drive_unlinked: dict[str, set] = {}
    for tier, name, meta in _topics():
        scope = f"{tier}/{name}"
        rows: list[dict] = []
        # (agent, verb) → targets. A verb that WRITES stays with the agents that
        # used it — a room does not hand its outward verbs to every participant
        # because one of them sent a mail; a verb that reads goes to `*`.
        per_verb: dict[tuple[str, str], dict] = defaultdict(dict)
        reasons: dict[tuple[str, str], set] = defaultdict(set)
        for (s, a, verb), u in used.items():
            ns = verb.split(".", 1)[0]
            if s != scope or not u["ok"] or verb.startswith(("topic.", "memory.")) \
                    or ns in GOVERNANCE or ns in PER_AGENT or ns in BY_DATA:
                continue
            if ns == "gdrive":
                # Drive in a room is granted through its linked folder (read at
                # runtime, writes below): a `gdrive.list` used without one would
                # become «the whole account», the case of 24 Oct.
                if not drive_folders(meta):
                    drive_unlinked.setdefault(scope, set()).add(a)
                continue
            who = a if _schemes_of(verb)[0] or not _reads(verb) else "*"
            per_verb[(who, verb)].update(u["targets"])
            reasons[(who, verb)].add(f"usato da {a}")
        for v in _rt.toolbox(meta)["enabled"]:
            per_verb.setdefault(("*", v), {})
            reasons[("*", v)].add("abilitato dall'owner nella sezione Strumenti")
        for (who, verb) in sorted(per_verb):
            rows.append({"id": tid("t"), "agent": who, "verb": verb, "resource": "*",
                         "rule": _clauses(verb, scope, per_verb[(who, verb)]),
                         "why": "; ".join(sorted(reasons[(who, verb)]))})
        # Linked Drive folders grant reading at runtime (`authz_runtime`): only
        # the writes observed there need a tuple.
        for f in drive_folders(meta):
            folder = f"gdrive:folder/{f['folder']}"
            wrote = any(s == scope and v in DRIVE_WRITE and u["ok"]
                        for (s, _a, v), u in used.items())
            for v in (DRIVE_WRITE if wrote else ()):
                rows.append({"id": tid("t"), "agent": "*", "verb": v, "resource": "*",
                             "rule": [{"effect": "allow", "match": folder}],
                             "why": "cartella Drive collegata al topic, scritture osservate"})
        # Data grants (#590) are read as tuples at runtime: nothing to write.
        if rows:
            topics[scope] = rows

    granted_somewhere = {(a, v) for (_s, a, v), u in used.items() if u["ok"]}
    for a in agents:
        unused = sorted(v for v in seed[a]
                        if "*" not in v and v.split(".", 1)[0] not in GOVERNANCE
                        and not v.startswith(("topic.", "memory."))
                        and (a, v) not in granted_somewhere)
        if unused:
            dropped[a] = unused
    return {"generated_at": time.time(), "days": days, "global": glob, "topics": topics,
            "dropped": dropped,
            "drive_unlinked": {k: sorted(v) for k, v in sorted(drive_unlinked.items())},
            "stats": {"calls": sum(u["calls"] for u in used.values()),
                      "global_tuples": len(glob),
                      "topic_tuples": sum(len(v) for v in topics.values()),
                      "topics": len(topics)}}


def markdown(p: dict) -> str:
    """The plan as the owner reads it."""
    def rule(r):
        return ", ".join(f"{c['effect']}({c['match']}{', fidato' if c.get('trust') == 'trusted' else ''})"
                         for c in r)
    lines = [f"# Piano di migrazione A·V·R·Q (ultimi {p['days']} giorni, "
             f"{p['stats']['calls']} chiamate)", "",
             f"{p['stats']['global_tuples']} tuple globali, {p['stats']['topic_tuples']} tuple "
             f"in {p['stats']['topics']} topic.", "", "## Globali", "",
             "| agente | verbo | risorsa | regola | perché |", "|---|---|---|---|---|"]
    for t in p["global"]:
        dove = " (solo fuori dai canali)" if t.get("where") == "outside" else ""
        lines.append(f"| {t['agent']} | `{t['verb']}`{dove} | {t['resource']} | {rule(t['rule'])} | {t['why']} |")
    for scope, rows in sorted(p["topics"].items()):
        lines += ["", f"## {scope}", "", "| agente | verbo | risorsa | regola | perché |",
                  "|---|---|---|---|---|"]
        for t in rows:
            lines.append(f"| {t['agent']} | `{t['verb']}` | {t['resource']} | {rule(t['rule'])} | {t['why']} |")
    if p.get("drive_unlinked"):
        lines += ["", "## Stanze che hanno usato Drive senza cartella collegata", "",
                  "Dopo la migrazione Drive non è disponibile qui finché non si collega "
                  "una cartella (lettura) o si abilita la scrittura.", ""]
        for scope, who in p["drive_unlinked"].items():
            lines.append(f"- **{scope}** — usato da " + ", ".join(who))
    lines += ["", "## Verbi tolti dai seed senza sostituto (mai usati nel periodo)", ""]
    for a, vs in sorted(p["dropped"].items()):
        lines.append(f"- **{a}**: " + ", ".join(f"`{v}`" for v in vs))
    return "\n".join(lines) + "\n"


# ── applying an approved plan ───────────────────────────────────────────────

BACKUP_PREFIX = "authz-backup-"


def _validate(p: dict) -> list[str]:
    bad = []
    _ok, b = A.parse_tuples(p.get("global") or [], level=A.GLOBAL)
    bad += [f"globale: {x}" for x in b]
    for scope, rows in (p.get("topics") or {}).items():
        _ok, b = A.parse_tuples(rows, level=A.TOPIC)
        bad += [f"{scope}: {x}" for x in b]
    return bad


def apply(p: dict, *, by: str) -> dict:
    """Write an APPROVED plan: the global tuples and every topic's `meta.authz`.

    All or nothing on validation: one invalid tuple and nothing is written. The
    state before is saved first (`authz-backup-<ts>.json`), and `rollback` puts
    it back. The mode is not touched: enforcing is a separate, explicit act.
    """
    bad = _validate(p)
    if bad:
        raise A.AuthzError("piano non valido, nulla scritto: " + "; ".join(bad[:5]))
    from . import authz_shadow as _s
    from . import main as _m
    from . import state_paths
    svc = _m._topics()
    gpath = _s._global_path()
    before = {"global": json.loads(gpath.read_text()) if gpath.exists() else None,
              "topics": {}}
    for scope in p.get("topics") or {}:
        tier, _, name = scope.partition("/")
        try:
            before["topics"][scope] = svc._read_meta(tier, name)[0].get("authz")
        except Exception:  # noqa: BLE001
            before["topics"][scope] = None
    ts = time.strftime("%Y%m%d-%H%M%S")
    backup = state_paths.state_path(f"{BACKUP_PREFIX}{ts}.json")
    backup.write_text(json.dumps(before, ensure_ascii=False))
    stamp = {"by": by, "at": time.time()}
    gpath.write_text(json.dumps({"tuples": [{**t, **stamp} for t in p.get("global") or []],
                                 "applied_by": by, "applied_at": stamp["at"]},
                                ensure_ascii=False, indent=1))
    written, failed = 0, []
    for scope, rows in (p.get("topics") or {}).items():
        tier, _, name = scope.partition("/")
        try:
            meta, ver = svc._read_meta(tier, name)
            meta["authz"] = [{**r, **stamp} for r in rows]
            svc._write_meta(tier, name, meta, base_version=ver)
            written += 1
        except Exception as e:  # noqa: BLE001
            failed.append(f"{scope}: {type(e).__name__}: {e}"[:200])
    from . import authz_runtime as _rt
    _rt.invalidate()
    return {"ok": not failed, "backup": backup.name, "global": len(p.get("global") or []),
            "topics_written": written, "failed": failed}


def rollback(backup_name: str, *, by: str) -> dict:
    """Put back the global tuples and the topics' `meta.authz` of a backup."""
    from . import authz_shadow as _s
    from . import main as _m
    from . import state_paths
    if not backup_name.startswith(BACKUP_PREFIX) or "/" in backup_name:
        raise A.AuthzError(f"backup sconosciuto: {backup_name!r}")
    before = json.loads(state_paths.state_path(backup_name).read_text())
    gpath = _s._global_path()
    if before.get("global") is None:
        gpath.unlink(missing_ok=True)
    else:
        gpath.write_text(json.dumps(before["global"], ensure_ascii=False, indent=1))
    svc = _m._topics()
    restored = 0
    for scope, prev in (before.get("topics") or {}).items():
        tier, _, name = scope.partition("/")
        try:
            meta, ver = svc._read_meta(tier, name)
            if prev is None:
                meta.pop("authz", None)
            else:
                meta["authz"] = prev
            svc._write_meta(tier, name, meta, base_version=ver)
            restored += 1
        except Exception:  # noqa: BLE001
            continue
    from . import authz_runtime as _rt
    _rt.invalidate()
    return {"ok": True, "restored_topics": restored, "by": by}


def set_mode(m: str) -> dict:
    from . import whitelist as _wl
    if m not in ("off", "shadow", "enforce"):
        raise A.AuthzError(f"authz_mode: off | shadow | enforce, non {m!r}")
    _wl.reload_config()
    _wl.CONFIG["authz_mode"] = m
    _wl.save_config()
    return {"ok": True, "authz_mode": m}

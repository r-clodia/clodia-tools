"""A·V·R·Q in SHADOW mode (clodia-platform#615, S2 of #613).

For every call the gateway serves, the A·V·R·Q engine (`authz`) decides on the
same facts, and the decision is recorded next to what actually happened — it
changes nothing. This is how the egress PDP went from `report` to `gate`: the
divergences are read before anything is enforced.

What it decides on:

- the call's FACTS (`facts`): the resource, the targets the connector manifests
  map (egress destinations, read sources), whether the verb reads or writes;
- the tuples in force: those written explicitly (global `authz.json` in the
  gateway's state dir, a topic's `meta.authz`) — none yet — PLUS the tuples
  that say what today's mechanisms say (`derived`): the verb is the agent's
  (seed, room toolbox, data grants, scoped grants), the destinations are those
  of the global and room egress lists, the trusted sources those of the ingress
  lists, a gated verb asks. A divergence between the engine and the outcome is
  therefore a gap in the engine or in that translation, which is exactly what
  S3 (the migration) needs to know before it writes real tuples.

Recording never fails a call: any error here is logged and dropped.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Optional

from . import authz as A

LOG = logging.getLogger("clodia-tools.authz_shadow")

MODE_KEY = "authz_mode"
MODES = ("off", "shadow")
GLOBAL_FILE = "authz.json"
LOG_FILE = "authz-shadow.jsonl"
_MAX_LOG = 5 << 20
_lock = threading.Lock()

#: The kind of resource each namespace acts WITH, and the argument naming the
#: account when a connector has several. A manifest field replaces this table
#: in the next step (#614 §2); until then it is the one place that says it.
_RESOURCE_KIND = {
    "email": ("mail", "account"), "mail": ("mail", "account"),
    "gdrive": ("google", "account"), "gdocs": ("google", "account"),
    "gsheets": ("google", "account"), "gcalendar": ("google", "account"),
    "gslides": ("google", "account"),
    "github": ("github", None), "telegram": ("telegram", None),
    "rag": ("rag", "collection"), "eu_corpus": ("rag", "collection"),
    "datastore": ("datastore", "datastore"),
    "web": ("web", None), "topic": ("topic", None), "artifact": ("topic", None),
}

_READ_WORDS = frozenset({"list", "read", "get", "search", "show", "open", "status",
                         "fetch", "download", "collections", "files", "messages",
                         "history", "info", "query", "find", "lookup"})


def mode() -> str:
    from . import whitelist as _wl
    m = str((_wl.CONFIG or {}).get(MODE_KEY) or "shadow").strip().lower()
    return m if m in MODES else "shadow"


# ── the call's facts ────────────────────────────────────────────────────────

def resource_of(verb: str, arguments: dict) -> str:
    ns = verb.split(".", 1)[0]
    kind, arg = _RESOURCE_KIND.get(ns, (ns, None))
    if kind in ("web", "topic"):
        return kind
    ident = str((arguments or {}).get(arg) or "").strip() if arg else ""
    return f"{kind}:{ident or 'default'}"


def facts(verb: str, arguments: dict) -> dict:
    """`{resource, kind, targets}` for one call, from the connector manifests."""
    from .connectors import resolved as _c
    out, writes, reads = [], False, False
    for m in _c.egress_mappings(verb):
        writes = True
        out += _c.destinations(m, arguments)
    for m in _c.source_mappings(verb):
        reads = True
        out += _c.destinations(m, arguments)
    if writes:
        kind = A.WRITE
    elif reads:
        kind = A.READ
    else:
        # The verb's first word, not a prefix: `telegram.listen` is not a list.
        word = verb.split(".", 1)[-1].replace("-", "_").split("_", 1)[0].lower()
        kind = A.READ if word in _READ_WORDS else A.WRITE
    return {"resource": resource_of(verb, arguments), "kind": kind,
            "targets": list(dict.fromkeys(out)), "mapped": writes or reads}


# ── the tuples in force ─────────────────────────────────────────────────────

def _global_path() -> Path:
    from . import state_paths
    return state_paths.state_path(GLOBAL_FILE)


def global_tuples() -> tuple[list[A.Tuple], list[str]]:
    try:
        raw = json.loads(_global_path().read_text())
    except FileNotFoundError:
        return [], []
    except Exception as e:  # noqa: BLE001 — unreadable: grants nothing
        return [], [f"{GLOBAL_FILE} illeggibile: {type(e).__name__}"]
    return A.parse_tuples(raw.get("tuples") if isinstance(raw, dict) else raw)


def topic_tuples(scope: Optional[str]) -> tuple[Optional[list[A.Tuple]], list[str]]:
    if not scope:
        return None, []
    tier, _, name = scope.partition("/")
    try:
        from . import main as _m
        meta = _m._topics()._read_meta(tier, name)[0]
    except Exception:  # noqa: BLE001
        return [], []
    raw = meta.get("authz")
    return A.parse_tuples(raw if isinstance(raw, list) else [], level=A.TOPIC)


def derived(agent: str, verb: str, scope: Optional[str], f: dict) -> list[A.Tuple]:
    """The tuple today's mechanisms amount to for this agent and verb, or none."""
    from . import egress as _eg
    from . import gate as _gate
    from . import main as _m
    from . import whitelist as _wl
    if not _m._agent_tool_reachable(verb, agent) or _wl.agent_denies(verb, agent):
        return []
    gated = _gate.is_gated(verb)
    rule: list[dict] = []
    if f["kind"] == A.WRITE and f["mapped"]:
        if _eg.mode() in ("off", "report"):
            rule = [{"effect": "allow", "match": "*"}]
        elif gated and not _gate.perimeter_answers(verb):
            rule = [{"effect": "ask", "match": "*"}]
        else:
            rule = [{"effect": "allow", "match": u}
                    for u in _eg.effective_uris("egress", scope) if u]
    elif f["kind"] == A.READ and f["mapped"]:
        rule = [{"effect": "allow", "match": u, "trust": "trusted"}
                for u in _eg.effective_uris("ingress", scope) if u]
    else:
        rule = [{"effect": "ask" if gated else "allow", "match": "*"}]
    if not rule:
        # Nothing listed: the verb's default decides every target (§4.1),
        # which is what an empty list means today. A tuple must exist for the
        # verb to be available, so it carries the default as a `*` clause.
        rule = [{"effect": "ask" if f["kind"] == A.WRITE else "allow", "match": "*"}]
    rule = [c for c in rule if c["match"] == "*" or ":" in c["match"]]
    ok, bad = A.parse_tuples([{"id": f"derived:{verb}", "agent": agent, "verb": verb,
                               "resource": "*", "rule": rule or [
                                   {"effect": "ask" if f["kind"] == A.WRITE else "allow",
                                    "match": "*"}]}])
    if bad:
        # Never silent: a dropped tuple would read as «not available» and flood
        # would_block with calls that work.
        LOG.warning("authz shadow: tupla derivata di %s scartata: %s", verb, bad[0][:200])
    return ok


def decide(agent: str, verb: str, arguments: dict, scope: Optional[str],
           tainted: bool) -> tuple[A.Decision, dict]:
    f = facts(verb, arguments)
    g, _ = global_tuples()
    t, _ = topic_tuples(scope)
    d = A.decide(g + derived(agent, verb, scope, f), t, agent=agent, verb=verb,
                 resource=f["resource"], targets=f["targets"], kind=f["kind"],
                 tainted=tainted)
    return d, f


# ── recording ───────────────────────────────────────────────────────────────

#: Refusals decided by checks outside A·V·R·Q (#614 §7 and the runtime): they
#: are not the engine's to agree or disagree with.
_OUT_OF_MODEL = frozenset({"unattended", "clearance", "version_conflict", "other"})


def divergence(d: A.Decision, actual: str, *, denial: Optional[str] = None,
               facts_ok: bool = True, on_behalf: bool = False) -> Optional[str]:
    """The class of a disagreement worth reading, or None.

    - `would_block`: the engine denies (or the verb is not available) and the
      call ran — enforcing would break something that works today;
    - `would_allow`: the engine allows and the gateway refused — enforcing
      would open something closed today;
    - `would_ask`: the engine asks and the call ran — enforcing adds a question
      (it may be one the gateway already asked: the gate's consent is in the
      audit next to it).
    """
    if on_behalf or not facts_ok:
        return None
    if actual == "denied" and denial in _OUT_OF_MODEL:
        return None
    if actual == "ok" and (not d.available or d.effect == A.DENY):
        return "would_block"
    if actual == "denied" and d.available and d.effect == A.ALLOW:
        return "would_allow"
    if actual == "ok" and d.effect == A.ASK:
        return "would_ask"
    return None


def _append(entry: dict) -> None:
    from . import state_paths
    p = state_paths.state_path(LOG_FILE)
    line = json.dumps(entry, ensure_ascii=False, default=str) + "\n"
    with _lock:
        try:
            if p.exists() and p.stat().st_size > _MAX_LOG:
                os.replace(p, p.with_suffix(p.suffix + ".1"))
        except OSError:
            pass
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as fh:
            fh.write(line)


def decide_now(verb: str, arguments: dict, *, agent: Optional[str],
               scope: Optional[str], chat: Optional[str]) -> Optional[dict]:
    """The shadow decision on the state BEFORE the call (a gate approval adds
    the destination to the room's list during the call). Never raises."""
    if mode() == "off" or not agent:
        return None
    try:
        from . import taint as _taint
        tainted = bool(_taint.status(chat).get("tainted"))
        d, f = decide(agent, verb, arguments or {}, scope, tainted)
        # A mapped verb whose targets are not in its arguments (a component
        # resolves them: email.reply, gdrive.update) is not judged on a guess.
        facts_ok = not (f["mapped"] and not f["targets"])
        return {"agent": agent, "verb": verb, "scope": scope, "resource": f["resource"],
                "kind": f["kind"], "targets": f["targets"][:5], "facts_ok": facts_ok,
                "tainted": tainted, "decision": d}
    except Exception as e:  # noqa: BLE001 — shadow must never change a call
        _warn(verb, e)
        return None


def record(pre: Optional[dict], actual: str, *, denial: Optional[str] = None,
           on_behalf: bool = False) -> Optional[dict]:
    """Write the pre-call decision next to the outcome. Never raises."""
    if not pre:
        return None
    try:
        d: A.Decision = pre["decision"]
        entry = {k: v for k, v in pre.items() if k != "decision"}
        entry.update({"ts": time.time(), "effect": d.effect, "available": d.available,
                      "reason": d.reason[:300], "actual": actual, "denial": denial,
                      "on_behalf": on_behalf,
                      "divergence": divergence(d, actual, denial=denial,
                                               facts_ok=pre["facts_ok"], on_behalf=on_behalf)})
        _append(entry)
        return entry
    except Exception as e:  # noqa: BLE001
        _warn(pre.get("verb", "?"), e)
        return None


def observe(verb: str, arguments: dict, actual: str, *, agent: Optional[str],
            scope: Optional[str], tainted: bool = False, chat: Optional[str] = None,
            denial: Optional[str] = None, on_behalf: bool = False) -> Optional[dict]:
    """Decide and record in one go (tests and synchronous callers)."""
    return record(decide_now(verb, arguments, agent=agent, scope=scope, chat=chat),
                  actual, denial=denial, on_behalf=on_behalf)


_last_warn = [0.0]


def _warn(verb: str, e: Exception) -> None:
    """One warning per minute at most: a read-only state dir must not turn
    every call into a log line."""
    now = time.monotonic()
    if now - _last_warn[0] > 60:
        _last_warn[0] = now
        LOG.warning("authz shadow: %s non valutato (%s: %s)", verb, type(e).__name__, e)


def summary(limit: int = 50) -> dict:
    """Counts by divergence class and verb, and the latest divergences."""
    from . import state_paths
    p = state_paths.state_path(LOG_FILE)
    counts: dict[str, int] = {}
    by_verb: dict[str, dict[str, int]] = {}
    latest: list[dict] = []
    total = 0
    try:
        with p.open(encoding="utf-8") as fh:
            for line in fh:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                total += 1
                cls = e.get("divergence") or "agree"
                counts[cls] = counts.get(cls, 0) + 1
                if e.get("divergence"):
                    v = by_verb.setdefault(e.get("verb") or "?", {})
                    v[cls] = v.get(cls, 0) + 1
                    latest.append(e)
                    latest = latest[-limit:]
    except FileNotFoundError:
        pass
    return {"mode": mode(), "total": total, "counts": counts, "by_verb": by_verb,
            "latest": list(reversed(latest))}

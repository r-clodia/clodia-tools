"""Remembering a gate's answer as a rule (clodia-platform#693).

The gate card is a matrix: WHO (this spawn · this seed · every agent) × WHERE
(this room · the whole instance). «This spawn» is the consent of today — the
capability, until the spawn ends — and is not written anywhere. The other
cells write a rule, and this module decides which cells a gate HAS and writes
them:

- a destination gate of the egress PDP (`egress:<type>:<uri>`):
  * every agent → the room's list or the global one, as before;
  * one seed → A·V·R·Q allow tuples for that seed, on every verb whose
    destination mapping reaches the address's scheme, matching the address.
    They satisfy A·V·R·Q in a room, and the egress PDP accepts the address for
    that seed only (`seed_accepts`, tuples written by a gate only);
- a trusted-source gate (`ingress:…`): every agent only — the taint is the
  channel's, not an agent's, so «trusted for one seed» means nothing;
- an A·V·R·Q ask (`authz:<verb>|<targets>` from a room's rules,
  `authz-global:<verb>|<targets>` from the global ones): an allow tuple
  (agent = the seed or `*`, the verb, every target that asked), at the level
  that asked: §5 lets a room only narrow a global allow, so a global rule never
  lifts a room's ask, and a room rule over a room that is silent on the verb
  would take over its other targets from the global level too;
- anything else (native tools, topic access, unattended, …): no rule.

A cell whose rule would not take effect — an explicit ask or deny of the room
(or a global deny) covering the same agent and target wins over the allow —
is offered disabled with that reason, instead of writing a dead rule.

What is remembered is the exact targets of THIS gate, never the whole verb
(owner, 17 Nov 2026).
"""
from __future__ import annotations

import hashlib
import json
import logging
import threading
import time

from . import authz as A

LOG = logging.getLogger("clodia-tools.gate_remember")

SEED, ALL = "seed", "all"
CHAT, GLOBAL = "chat", "global"

#: The id prefix of every tuple a gate writes: the egress PDP honours only
#: those (`seed_accepts`), and the rules panel names their origin.
GATE_ID = "gate-"

_INGRESS_SEED = ("una fonte fidata vale per tutto il canale: la contaminazione è "
                 "della conversazione, non del singolo agente")
_ROOM_ASK_GLOBAL = ("la conferma la chiede una regola della stanza: una regola "
                    "globale non la scavalca, si decide nella stanza")
_GLOBAL_ASK_ROOM = ("la conferma la chiede una regola globale e la stanza non ne "
                    "ha per questo verbo: si decide a livello globale")
_NOTHING = "questo gate non diventa una regola: vale solo per questo spawn"
_NO_SCHEME = "nessun verbo raggiunge questo tipo di indirizzo: nulla da ricordare"
_SHADOWED = ("una regola esplicita {where} chiede o nega per {who} su questo "
             "bersaglio: una regola «consenti» non avrebbe effetto")

_GLOBAL_LOCK = threading.Lock()


class RememberError(ValueError):
    """A remember that cannot be written (with the reason to show)."""


# ── what a gate key names ───────────────────────────────────────────────────

def _egress_uri(key: str) -> str:
    """The address of an `egress:<type>:<uri>` key, or ""."""
    if not key.startswith("egress:"):
        return ""
    parts = key.split(":", 2)
    return parts[2] if len(parts) == 3 else ""


def _authz(key: str) -> tuple[str, str, list[str]] | None:
    """`(level, verb, targets)` of an A·V·R·Q gate key, or None."""
    for prefix, level in (("authz-global:", A.GLOBAL), ("authz:", A.TOPIC)):
        if key.startswith(prefix):
            verb, _, targets = key[len(prefix):].partition("|")
            return level, verb, [t for t in targets.split(",") if t]
    return None


def _scheme(uri: str) -> str:
    s = uri.partition(":")[0].lower()
    return "http" if s in ("http", "https") else s


def destination_verbs(uri: str) -> list[str]:
    """Every verb whose DESTINATION mapping reaches `uri`'s scheme: one address
    for one seed, whichever of its verbs goes there (as a list entry is one
    address for every verb). Delivery-only verbs are included: they carry a
    `channel.deliver` of the same agent to the same address."""
    from .connectors import resolved
    want = _scheme(uri)
    out = set()
    for c in resolved.registry().connectors:
        for v in c.verbs:
            if v.direction == "egress" and _scheme(f"{v.scheme}:") == want:
                out.add(v.verb)
    return sorted(out)


# ── the tuples a cell writes ────────────────────────────────────────────────

def _tuple(agent: str, verb: str, targets: list[str], level: str, by: str) -> dict:
    rule = [{"effect": A.ALLOW, "match": t} for t in sorted(set(targets))]
    raw = {"agent": agent, "verb": verb, "resource": A.ANY, "rule": rule}
    digest = hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest()[:10]
    raw = {"id": f"{GATE_ID}{digest}", **raw, "by": by, "at": time.time(),
           "origin": "gate"}
    try:
        A.parse_tuple(raw, level=level)
    except A.AuthzError as e:
        raise RememberError(str(e)) from None
    return raw


def tuples_for(key: str, agent: str, level: str, by: str = "") -> list[dict]:
    """The allow tuples one cell writes: one for an A·V·R·Q ask, one per
    destination verb for an egress gate of one seed."""
    uri = _egress_uri(key)
    if uri:
        verbs = destination_verbs(uri)
        if not verbs:
            raise RememberError(_NO_SCHEME)
        return [_tuple(agent, v, [uri], level, by) for v in verbs]
    parsed = _authz(key)
    if parsed is None:
        raise RememberError(_NOTHING)
    _level, verb, targets = parsed
    if not targets:
        raise RememberError("il gate non dice su che cosa: nulla da ricordare")
    if len(",".join(targets)) >= 900:
        # The key keeps 900 characters of targets: past that it may have lost
        # some, and a rule for the visible ones only would be another rule.
        raise RememberError("troppi bersagli in questo gate per ricordarli: "
                            "approva solo per stavolta")
    return [_tuple(agent, verb, targets, level, by)]


def tuple_for(key: str, agent: str, by: str = "") -> dict:
    """The (single) tuple of an A·V·R·Q ask — kept for its callers."""
    parsed = _authz(key)
    if parsed is None:
        raise RememberError(_NOTHING)
    return tuples_for(key, agent, parsed[0], by)[0]


# ── which cells apply ───────────────────────────────────────────────────────

def _view(scope: str):
    from . import authz_runtime as _rt
    v = _rt._room_view(scope or None)
    room = (v["explicit"] + v["derived"]) if scope else None
    return v["global"], room


def _effective(rows: list[dict], level: str, scope: str, agent: str) -> bool:
    """Would these allow tuples, once written, make `agent` (a seed; `*` is
    judged for a hypothetical other agent) allowed on their targets? An
    explicit ask/deny that is at least as specific wins (§4), a global deny
    holds (§5)."""
    try:
        g, room = _view(scope)
    except Exception:  # noqa: BLE001 — unreadable rules: let the write decide
        return True
    parsed = [A.parse_tuple(r, level=level) for r in rows]
    if level == A.TOPIC:
        room = list(room or []) + parsed
    else:
        g = list(g) + parsed
    who = agent if agent != A.ANY else "\x00any"
    for t in parsed:
        targets = [c.match for c in t.rule]
        d = A.decide(g, room, agent=who, verb=t.verb, resource=None,
                     targets=targets, kind=A.WRITE)
        if d.effect != A.ALLOW:
            return False
    return True


def cells(key: str, agent: str = "", scope: str = "") -> dict[str, str]:
    """`{"seed:chat": "", "seed:global": "<why not>", …}`: an empty reason is a
    cell that applies. `agent` (the seed) and `scope` (the room the gate came
    from) let it say when a rule would not take effect. The approver's title
    (owner, admin) is not judged here: the agent-server knows the person."""
    out = {f"{w}:{c}": _NOTHING for w in (SEED, ALL) for c in (CHAT, GLOBAL)}
    if key.startswith("ingress:"):
        out.update({"seed:chat": _INGRESS_SEED, "seed:global": _INGRESS_SEED,
                    "all:chat": "", "all:global": ""})
        return out
    if _egress_uri(key):
        out.update({"all:chat": "", "all:global": ""})
        try:
            ok = bool(destination_verbs(_egress_uri(key)))
        except Exception:  # noqa: BLE001
            ok = False
        out.update({"seed:chat": "" if ok else _NO_SCHEME,
                    "seed:global": "" if ok else _NO_SCHEME})
        rows_level = {"seed:chat": A.TOPIC, "seed:global": A.GLOBAL}
    else:
        parsed = _authz(key)
        if parsed is None:
            return out
        level = parsed[0]
        for w in (SEED, ALL):
            out[f"{w}:{CHAT}"] = "" if level == A.TOPIC else _GLOBAL_ASK_ROOM
            out[f"{w}:{GLOBAL}"] = "" if level == A.GLOBAL else _ROOM_ASK_GLOBAL
        rows_level = {f"{w}:{c}": (A.TOPIC if c == CHAT else A.GLOBAL)
                      for w in (SEED, ALL) for c in (CHAT, GLOBAL)}
    # «chiedi batte consenti»: a rule that would be shadowed is not offered.
    for cell, level in rows_level.items():
        if out.get(cell):
            continue
        who = cell.split(":", 1)[0]
        a = A.ANY if who == ALL else agent
        if not a or (level == A.TOPIC and not scope):
            continue
        try:
            rows = tuples_for(key, a, level)
        except RememberError as e:
            out[cell] = str(e)
            continue
        if not _effective(rows, level, scope if level == A.TOPIC else "", a):
            out[cell] = _SHADOWED.format(
                where="della stanza" if level == A.TOPIC else "globale",
                who=("tutti gli agenti" if a == A.ANY else a))
    return out


# ── writing ─────────────────────────────────────────────────────────────────

def _write_room(scope: str, rows: list[dict]) -> int:
    from . import main
    tier, _, name = scope.partition("/")
    if not (tier and name):
        raise RememberError("serve la stanza in cui ricordarlo")
    svc = main._topics()
    meta, ver = svc._read_meta(tier, name)
    cur = meta.get("authz") if isinstance(meta.get("authz"), list) else []
    have = {r.get("id") for r in cur if isinstance(r, dict)}
    new = [r for r in rows if r["id"] not in have]
    if new:
        meta["authz"] = list(cur) + new
        svc._write_meta(tier, name, meta, ver)
    return len(new)


def _read_global() -> dict:
    from . import authz_shadow as S
    path = S._global_path()
    try:
        doc = json.loads(path.read_text())
    except FileNotFoundError:
        return {"tuples": []}
    except Exception as e:  # noqa: BLE001 — never overwrite what we cannot read
        raise RememberError(f"{S.GLOBAL_FILE} illeggibile ({type(e).__name__}): "
                            "nulla scritto") from None
    if isinstance(doc, list):
        doc = {"tuples": doc}
    if not isinstance(doc.get("tuples"), list):
        doc["tuples"] = []
    return doc


def _write_global_doc(doc: dict) -> None:
    from . import authz_shadow as S
    from .authz_migration import _atomic_write
    _atomic_write(S._global_path(), json.dumps(doc, ensure_ascii=False, indent=1))


def _write_global(rows: list[dict]) -> int:
    with _GLOBAL_LOCK:
        doc = _read_global()
        have = {r.get("id") for r in doc["tuples"] if isinstance(r, dict)}
        new = [r for r in rows if r["id"] not in have]
        if new:
            doc["tuples"] = list(doc["tuples"]) + new
            _write_global_doc(doc)
    return len(new)


def remember(key: str, *, agent: str, scope: str, by: str = "") -> dict:
    """Write the rule of one cell: `agent` is the seed or `*`, `scope` the
    room (`tier/name`) or "" for the instance. A destination for every agent
    goes to the lists (`egress.scope_allow` / `allow`), as before."""
    agent = str(agent or "").strip()
    scope = str(scope or "").strip()
    who = ALL if agent == A.ANY else SEED
    where = CHAT if scope else GLOBAL
    if who == SEED and not agent:
        raise RememberError("serve il seed per cui ricordarlo")
    why = cells(key, agent if who == SEED else "", scope).get(f"{who}:{where}")
    if why:
        raise RememberError(why)
    if who == ALL and key.startswith(("egress:", "ingress:")):
        from . import egress as _eg
        direction, kind, uri = (key.split(":", 2) + ["", ""])[:3]
        if direction == "ingress" and kind == "web":
            uri = uri.rsplit("|", 1)[0]
        try:
            res = _eg.scope_allow(direction, scope, uri) if scope else _eg.allow(direction, uri)
        except (ValueError, PermissionError) as e:
            raise RememberError(str(e)[:300]) from None
        return {"remembered": True, "kind": "list", "uri": uri, "direction": direction,
                "scope": scope or None, **(res if isinstance(res, dict) else {})}
    level = A.TOPIC if scope else A.GLOBAL
    rows = tuples_for(key, agent, level, by)
    new = _write_room(scope, rows) if scope else _write_global(rows)
    from . import authz_runtime as _rt
    _rt.invalidate()
    LOG.info("GATE ricordato come regola %s · %s · %s → %s (%d nuove) da %s",
             agent, [r["verb"] for r in rows], rows[0]["rule"][0]["match"],
             scope or "GLOBALE", new, by)
    return {"remembered": True, "kind": "rule", "rules": rows, "rule": rows[0],
            "scope": scope or None, "new": bool(new)}


# ── the egress PDP, per seed ────────────────────────────────────────────────

def seed_accepts(agent: str, verb: str, dests: list[str],
                 scope: str | None) -> set[str]:
    """The destinations of `dests` a gate-written allow tuple grants to THIS
    agent for `verb`: the egress PDP's per-seed acceptance (#693). Decided by
    the A·V·R·Q engine over the explicit tuples (global, and the room's when
    the agent takes part in it), so a global deny or a more specific explicit
    ask/deny still wins; only a tuple a gate wrote (`gate-…`) naming this agent
    and this exact address counts — no derived row, no `*` agent, no `*`
    clause. Never raises: in doubt, nothing is accepted."""
    if not agent or not dests:
        return set()
    try:
        from . import authz_runtime as _rt
        v = _rt._room_view(scope or None)
        g = v["global"]
        room = None
        if scope:
            room = (v["explicit"] if agent in v["members"] and not v["archived"] else [])
        by_id = {t.id: t for t in list(g) + list(room or [])}
        out = set()
        for d in dests:
            dec = A.decide(g, room, agent=agent, verb=verb, resource=None,
                           targets=[d], kind=A.WRITE)
            if dec.effect != A.ALLOW or not dec.targets:
                continue
            td = dec.targets[0]
            t = by_id.get(td.tuple_id or "")
            if (t is not None and str(t.id).startswith(GATE_ID) and t.agent == agent
                    and td.clause is not None and t.rule[td.clause].match != A.ANY):
                out.add(d)
        return out
    except Exception as e:  # noqa: BLE001
        LOG.warning("egress per seed non valutabile (%s): nessuna eccezione",
                    type(e).__name__)
        return set()


# ── the rules panel ─────────────────────────────────────────────────────────

def _row(raw: dict, level: str) -> dict:
    rule = raw.get("rule") if isinstance(raw.get("rule"), list) else []
    return {"id": raw.get("id"), "level": level, "agent": raw.get("agent"),
            "verb": raw.get("verb"), "resource": raw.get("resource"),
            "rule": [{"effect": c.get("effect"), "match": c.get("match")}
                     for c in rule if isinstance(c, dict)],
            "origin": raw.get("origin") or ("gate" if str(raw.get("id") or "").startswith(GATE_ID)
                                            else "plan" if level == A.GLOBAL else "manual"),
            "by": raw.get("by") or "", "at": raw.get("at")}


def list_room(scope: str) -> list[dict]:
    from . import main
    tier, _, name = scope.partition("/")
    meta = main._topics()._read_meta(tier, name)[0]
    rows = meta.get("authz") if isinstance(meta.get("authz"), list) else []
    return [_row(r, A.TOPIC) for r in rows if isinstance(r, dict)]


def list_global() -> list[dict]:
    return [_row(r, A.GLOBAL) for r in _read_global()["tuples"] if isinstance(r, dict)]


def remove_room(scope: str, rule_id: str, by: str = "") -> bool:
    from . import main
    from . import authz_runtime as _rt
    tier, _, name = scope.partition("/")
    svc = main._topics()
    meta, ver = svc._read_meta(tier, name)
    rows = meta.get("authz") if isinstance(meta.get("authz"), list) else []
    keep = [r for r in rows if not (isinstance(r, dict) and r.get("id") == rule_id)]
    if len(keep) == len(rows):
        return False
    meta["authz"] = keep
    svc._write_meta(tier, name, meta, ver)
    _rt.invalidate()
    LOG.info("regola %s tolta da %s da %s", rule_id, scope, by)
    return True


def remove_global(rule_id: str, by: str = "") -> bool:
    from . import authz_runtime as _rt
    with _GLOBAL_LOCK:
        doc = _read_global()
        keep = [r for r in doc["tuples"]
                if not (isinstance(r, dict) and r.get("id") == rule_id)]
        if len(keep) == len(doc["tuples"]):
            return False
        doc["tuples"] = keep
        _write_global_doc(doc)
    _rt.invalidate()
    LOG.info("regola globale %s tolta da %s", rule_id, by)
    return True

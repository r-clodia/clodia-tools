"""A·V·R·Q enforced (clodia-platform#617, S2/S3 of #613).

With `authz_mode: enforce` the tuples are the authority on WHICH verbs an
agent has (discovery and dispatch: `available`) and on each call's effect
(`check`: deny refuses, ask raises the gate card). The seeds' verbs no longer
grant anything to an agent.

What stays, on purpose, as a second line: the egress/ingress PDP, the gates,
the data grants of #590, the Drive perimeter, the origin chain, denied_tools,
the unattended block. Enforcement therefore only NARROWS what those allow —
the switch can be turned on without opening anything that is closed today, and
turned off (`shadow`) to return exactly to today.

The tuples in force: the global file (`authz.json`) and, in a room, the
topic's `meta.authz` plus its toolbox (#605) read as tuples — so the
«Strumenti» panel keeps working until it edits tuples directly.
"""
from __future__ import annotations

import logging
from typing import Optional

from . import authz as A
from . import authz_shadow as S

LOG = logging.getLogger("clodia-tools.authz_runtime")

ENFORCE = "enforce"


def mode() -> str:
    from . import whitelist as _wl
    m = str((_wl.CONFIG or {}).get(S.MODE_KEY) or "shadow").strip().lower()
    return m if m in ("off", "shadow", ENFORCE) else "shadow"


def enforcing() -> bool:
    return mode() == ENFORCE


def _toolbox_tuples(meta: dict) -> list[A.Tuple]:
    """The room's toolbox (#605) as topic tuples: `* · verb · * · allow *`, and
    each exception as `agent · verb · * · deny *` (more specific: it wins)."""
    from . import room_tools as _rt
    tb = _rt.toolbox(meta)
    raw = [{"id": f"toolbox:{v}", "agent": "*", "verb": v, "resource": "*",
            "rule": [{"effect": "allow", "match": "*"}]} for v in tb["enabled"]]
    for agent, verbs in tb["except"].items():
        for v in verbs:
            # `*` = everything the room gives: one deny per enabled entry and
            # the floor (a topic tuple may not name the bare `*` verb).
            targets = (tb["enabled"] + ["topic.*"]) if v == "*" else [v]
            for x in targets:
                raw.append({"id": f"toolbox-except:{agent}:{x}", "agent": agent,
                            "verb": x, "resource": "*",
                            "rule": [{"effect": "deny", "match": "*"}]})
    ok, _bad = A.parse_tuples(raw, level=A.TOPIC)
    return ok


def _data_tuples(meta: dict) -> list[A.Tuple]:
    """The room's data grants (#590) as tuples on the collection or datastore,
    so a grant made in the «Dati» panel after the migration is in force."""
    from . import topic_data as _td
    raw = []
    for imp in _td.imports(meta):
        res = f"{imp['kind']}:{imp['name']}"
        for agent, mode in imp["grants"].items():
            verbs = _td._READ_VERBS.get(imp["kind"], ()) + (
                _td._WRITE_VERBS.get(imp["kind"], ()) if mode == "write" else ())
            for v in verbs:
                raw.append({"id": f"data:{res}:{agent}:{v}", "agent": agent, "verb": v,
                            "resource": res, "rule": [{"effect": "allow", "match": "*"}]})
    ok, _bad = A.parse_tuples(raw, level=A.TOPIC)
    return ok


#: A linked Drive folder grants reading it (owner, 25 Oct 2026): linking and
#: enabling are one act. Writing is an explicit tuple.
DRIVE_READ = ("gdrive.list", "gdrive.search", "gdrive.download")


def _drive_tuples(meta: dict) -> list[A.Tuple]:
    from .topics.service import drive_folders
    raw = []
    for f in drive_folders(meta):
        for v in DRIVE_READ:
            raw.append({"id": f"drive:{f['folder']}:{v}", "agent": "*", "verb": v,
                        "resource": "*",
                        "rule": [{"effect": "allow", "match": f"gdrive:folder/{f['folder']}"}]})
    ok, _bad = A.parse_tuples(raw, level=A.TOPIC)
    return ok


#: A few seconds of memory per room: discovery asks `available` for every verb
#: of the instance, hundreds in a row, and must not re-read the global file and
#: the topic's meta each time. Short enough that a rule the owner changes is in
#: force before anyone notices; `invalidate()` makes it immediate.
_TTL = 2.0
_cache: dict = {}


def invalidate() -> None:
    _cache.clear()


def tuples_in_force(scope: Optional[str]) -> tuple[list[A.Tuple], Optional[list[A.Tuple]]]:
    import time as _time
    hit = _cache.get(scope)
    now = _time.monotonic()
    if hit and now - hit[0] < _TTL:
        return hit[1]
    out = _tuples_in_force(scope)
    _cache[scope] = (now, out)
    return out


def _tuples_in_force(scope: Optional[str]) -> tuple[list[A.Tuple], Optional[list[A.Tuple]]]:
    g, _ = S.global_tuples()
    if not scope:
        return g, None
    tier, _, name = scope.partition("/")
    try:
        from . import main as _m
        meta = _m._topics()._read_meta(tier, name)[0]
    except Exception:  # noqa: BLE001 — no room readable: only what holds everywhere
        return g, []
    raw = meta.get("authz")
    t, _ = A.parse_tuples(raw if isinstance(raw, list) else [], level=A.TOPIC)
    return g, t + _toolbox_tuples(meta) + _data_tuples(meta) + _drive_tuples(meta)


def available(agent: Optional[str], verb: str, scope: Optional[str]) -> bool:
    """The verb is the agent's here. A failure reading the tuples is a no:
    enforcement fails closed."""
    if not agent:
        return False
    try:
        g, t = tuples_in_force(scope)
        return A.available(g, t, agent=agent, verb=verb)
    except Exception as e:  # noqa: BLE001
        LOG.error("authz: disponibilità di %s per %s non calcolabile (%s): negato",
                  verb, agent, type(e).__name__)
        return False


def check(agent: str, verb: str, arguments: dict, scope: Optional[str],
          tainted: bool) -> A.Decision:
    """The enforced decision for one call."""
    f = S.facts(verb, arguments or {})
    g, t = tuples_in_force(scope)
    return A.decide(g, t, agent=agent, verb=verb, resource=f["resource"],
                    targets=f["targets"], kind=f["kind"], tainted=tainted)


def gate_key(d: A.Decision, verb: str) -> str:
    """The consent key of an `ask`: the verb and the target that asked, and the
    level — a room's rule is its owner's to answer, a global one an admin's."""
    asked = next((x for x in d.targets if x.effect == A.ASK), None)
    target = (asked.target if asked else "") or "*"
    prefix = "authz-global:" if asked and asked.level == A.GLOBAL else "authz:"
    return f"{prefix}{verb}|{target}"

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
    """The room's toolbox (#605) as topic tuples. An enabled verb becomes
    AVAILABLE, and its targets take the verb's default (`DEFAULT`): enabling
    `email.*` does not decide who a mail may reach — the room's and the
    global rules still do (review of #435, S1). Each exception is
    `agent · verb · * · deny *`, more specific: it wins."""
    from . import room_tools as _rt
    tb = _rt.toolbox(meta)
    raw = [{"id": f"toolbox:{v}", "agent": "*", "verb": v, "resource": "*",
            "rule": [{"effect": A.DEFAULT}]} for v in tb["enabled"]]
    for agent, verbs in tb["except"].items():
        for v in verbs:
            if v == "*":
                continue  # handled as «nothing from the room» (`_room_view`)
            raw.append({"id": f"toolbox-except:{agent}:{v}", "agent": agent,
                        "verb": v, "resource": "*",
                        "rule": [{"effect": "deny", "match": "*"}]})
    ok, _bad = A.parse_tuples(raw, level=A.TOPIC, internal=True)
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
    """Read the linked folders — and only them: any other Drive target is
    denied (a read would otherwise take the default allow, review of #435
    B1). A call with no target (a search) is confined by the topic's Drive
    perimeter (`gdrive_root.roots_for_call`), the second line."""
    from .topics.service import drive_folders
    folders = [f"gdrive:folder/{f['folder']}" for f in drive_folders(meta)]
    if not folders:
        return []
    raw = []
    for v in DRIVE_READ:
        raw.append({"id": f"drive:{v}", "agent": "*", "verb": v, "resource": "*",
                    "rule": [{"effect": "allow", "match": f} for f in folders]
                    + [{"effect": "deny", "match": "gdrive:*"}]})
    ok, _bad = A.parse_tuples(raw, level=A.TOPIC)
    return ok


#: A few seconds of memory per room: discovery asks `available` for every verb
#: of the instance, hundreds in a row, and must not re-read the global file and
#: the topic's meta each time. Short enough that a rule the owner changes is in
#: force before anyone notices; `invalidate()` makes it immediate. An error is
#: never cached.
_TTL = 2.0
_cache: dict = {}


def invalidate() -> None:
    _cache.clear()


class RoomUnreadable(RuntimeError):
    """The room's rules cannot be read: in a room, nothing is decided without
    them (review of #435, S7)."""


def _room_view(scope: Optional[str]) -> dict:
    import time as _time
    hit = _cache.get(scope)
    now = _time.monotonic()
    if hit and now - hit[0] < _TTL:
        return hit[1]
    g, gbad = S.global_tuples()
    view = {"global": g, "global_problems": gbad, "explicit": [], "derived": [],
            "members": set(), "archived": False, "except_all": set()}
    if scope:
        tier, _, name = scope.partition("/")
        from . import main as _m
        from . import room_tools as _rt
        from .topics.service import TopicService
        try:
            meta = _m._topics()._read_meta(tier, name)[0]
        except Exception as e:  # noqa: BLE001
            raise RoomUnreadable(f"regole della stanza {scope} illeggibili "
                                 f"({type(e).__name__})") from None
        raw = meta.get("authz")
        view["explicit"], _ = A.parse_tuples(raw if isinstance(raw, list) else [],
                                             level=A.TOPIC)
        view["derived"] = _toolbox_tuples(meta) + _data_tuples(meta) + _drive_tuples(meta)
        view["members"] = set(TopicService.participants_map(meta))
        view["archived"] = str(meta.get("status") or "").strip().lower() == "archived"
        view["except_all"] = {a for a, vs in _rt.toolbox(meta)["except"].items() if "*" in vs}
    _cache[scope] = (now, view)
    return view


def tuples_for(agent: str, scope: Optional[str]) -> tuple[list[A.Tuple], Optional[list[A.Tuple]]]:
    """The tuples in force for THIS agent here. A room gives nothing to whoever
    does not take part in it, nothing from its panels once archived, and
    nothing at all to an agent excepted from everything (`*`) — review of
    #435, B2 and S3. Outside a room: the global level only."""
    v = _room_view(scope)
    if not scope:
        return v["global"], None
    if agent not in v["members"] or v["archived"]:
        return v["global"], []
    if agent in v["except_all"]:
        return v["global"], [A.Tuple(f"except-all:{agent}", agent, "topic.*", "*",
                                     (A.Clause(A.DENY, A.ANY),))]
    return v["global"], v["explicit"] + v["derived"]


def tuples_in_force(scope: Optional[str]) -> tuple[list[A.Tuple], Optional[list[A.Tuple]]]:
    """Every tuple of the place, regardless of who asks (introspection, tests)."""
    v = _room_view(scope)
    return v["global"], (None if not scope else v["explicit"] + v["derived"])


def available(agent: Optional[str], verb: str, scope: Optional[str]) -> bool:
    """The verb is the agent's here. A failure reading the tuples is a no:
    enforcement fails closed."""
    if not agent:
        return False
    try:
        g, t = tuples_for(agent, scope)
        return A.available(g, t, agent=agent, verb=verb)
    except Exception as e:  # noqa: BLE001
        LOG.error("authz: disponibilità di %s per %s non calcolabile (%s): negato",
                  verb, agent, type(e).__name__)
        return False


def check(agent: str, verb: str, arguments: dict, scope: Optional[str],
          tainted: bool) -> A.Decision:
    """The enforced decision for one call. A room whose rules cannot be read
    denies."""
    try:
        g, t = tuples_for(agent, scope)
    except RoomUnreadable as e:
        return A.Decision(A.DENY, False, [], str(e))
    f = S.facts(verb, arguments or {})
    return A.decide(g, t, agent=agent, verb=verb, resource=f["resource"],
                    targets=f["targets"], kind=f["kind"], tainted=tainted)


def asked_targets(d: A.Decision) -> list[A.TargetDecision]:
    return [x for x in d.targets if x.effect == A.ASK]


def gate_key(d: A.Decision, verb: str) -> str:
    """The consent key of an `ask`: the verb and EVERY target that asked
    (review of #435, S2 — approving one recipient must not send to another),
    and the level: a room's rule is its owner's to answer, a global one an
    admin's."""
    asked = asked_targets(d)
    targets = sorted({(x.target or "*") for x in asked}) or ["*"]
    prefix = "authz-global:" if any(x.level == A.GLOBAL for x in asked) else "authz:"
    return f"{prefix}{verb}|{','.join(targets)[:900]}"


def ask_reason(d: A.Decision, verb: str) -> str:
    asked = asked_targets(d)
    names = ", ".join(sorted({x.target or "(nessun bersaglio)" for x in asked}))
    return f"Regola A·V·R·Q: {verb} chiede conferma per {names or 'questa chiamata'}"

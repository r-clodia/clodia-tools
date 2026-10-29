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

import contextvars
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
    """The room's toolbox (#605, by MCP since #620) as topic tuples. An
    enabled verb becomes AVAILABLE, and its targets take the verb's default
    (`DEFAULT`): enabling `email.*` does not decide who a mail may reach — the
    room's resource rows and the global rules still do (review of #435, S1).
    The same for every participant: per-agent exceptions were removed (26 Oct)."""
    from . import room_tools as _rt
    tb = _rt.toolbox(meta)
    raw = [{"id": f"toolbox:{v}", "agent": "*", "verb": v, "resource": "*",
            "rule": [{"effect": A.DEFAULT}]} for v in tb["enabled"]]
    ok, _bad = A.parse_tuples(raw, level=A.TOPIC, internal=True)
    return ok


def _data_tuples(meta: dict) -> list[A.Tuple]:
    """The room's data grants (#590) as tuples on the collection or datastore,
    so a grant made in the «Dati» panel after the migration is in force."""
    from . import topic_data as _td
    raw = []
    for imp in _td.imports(meta):
        res = f"{imp['kind']}:{imp['name']}"
        if imp["kind"] in _td.READ_FOR_PARTICIPANTS:
            # Read by every participant (26 Oct): a room's tuples reach only
            # its members (`tuples_for`), so `*` here is «whoever is in».
            for v in _td._READ_VERBS.get(imp["kind"], ()):
                raw.append({"id": f"data:{res}:*:{v}", "agent": "*", "verb": v,
                            "resource": res, "rule": [{"effect": "allow", "match": "*"}]})
        for agent, mode in imp["grants"].items():
            verbs = _td._READ_VERBS.get(imp["kind"], ()) + (
                _td._WRITE_VERBS.get(imp["kind"], ()) if mode == "write" else ())
            for v in verbs:
                raw.append({"id": f"data:{res}:{agent}:{v}", "agent": agent, "verb": v,
                            "resource": res, "rule": [{"effect": "allow", "match": "*"}]})
    ok, _bad = A.parse_tuples(raw, level=A.TOPIC)
    return ok


def _resource_tuples(meta: dict) -> list[A.Tuple]:
    """The resource rows of the room's MCPs (#620) as topic tuples: per verb
    of the MCP that reaches the row's scheme (or the verbs the row names), a
    clause `<effect> <uri>`. A row is more specific than the MCP's own
    `DEFAULT`, so it decides its targets; the rest keep the verb's default."""
    from . import room_tools as _rt
    rows_by = _rt.resources(meta)
    if not any(rows_by.values()):
        return []
    cat = _rt.mcp_catalogue()
    per_verb: dict[str, list[dict]] = {}
    for mid, rows in rows_by.items():
        e = cat.get(mid)
        if not e:
            continue
        by_scheme: dict[str, set[str]] = {}
        for sc in e["schemes"]:
            by_scheme.setdefault(sc["scheme"], set()).update(sc["verbs"])
        # Verbs with no mapping whose resource the serving component names
        # (#635: `github.clone`/`pull`): a row covers them on its scheme too.
        named = _component_named_verbs(e)
        for verbs in by_scheme.values():
            verbs.update(named)
        for r in rows:
            verbs = by_scheme.get(r["uri"].partition(":")[0], set())
            if r.get("verbs"):
                verbs = verbs & set(r["verbs"])
            for v in verbs:
                # A family (`github.create_*`) cannot be a tuple's verb — only
                # `ns.*` can. The row's clause matches its scheme's targets
                # only, so widening the verb to the namespace keeps it on them.
                if "*" in v:
                    v = f"{v.partition('.')[0]}.*"
                per_verb.setdefault(v, []).append({"effect": r["effect"], "match": r["uri"]})
    raw = [{"id": f"resource:{v}", "agent": "*", "verb": v, "resource": "*", "rule": rule}
           for v, rule in sorted(per_verb.items())]
    ok, _bad = A.parse_tuples(raw, level=A.TOPIC)
    return ok


#: A linked Drive folder grants reading it (owner, 25 Oct 2026): linking and
#: enabling are one act. Writing is an explicit tuple.
DRIVE_READ = ("gdrive.list", "gdrive.search", "gdrive.download")


def _drive_tuples(meta: dict) -> list[A.Tuple]:
    """Read the linked folders — and no other folder (a read would otherwise
    take the default allow, review of #435 B1). Files and calls with no target
    (a search) are confined by the topic's Drive perimeter
    (`gdrive_root.roots_for_call`), the second line."""
    from .topics.service import drive_folders
    folders = [f"gdrive:folder/{f['folder']}" for f in drive_folders(meta)]
    if not folders:
        return []
    raw = []
    for v in DRIVE_READ:
        rule = [{"effect": "allow", "match": f} for f in folders]
        if v != "gdrive.download":
            # Verbs on FOLDERS: any other Drive target is another folder,
            # denied. `gdrive.download` acts on FILES (`gdrive:file/<id>`):
            # inside or outside a linked folder is a question of the file's
            # parents, which the topic's Drive perimeter answers (second line)
            # until the ancestry resolver of #614 §3 exists. (A rule cannot
            # say «every folder»: a wildcard only opens a scheme's value.)
            rule.append({"effect": "deny", "match": "gdrive:*"})
        raw.append({"id": f"drive:{v}", "agent": "*", "verb": v, "resource": "*",
                    "rule": rule})
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
            "members": set(), "archived": False}
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
        view["derived"] = (_toolbox_tuples(meta) + _resource_tuples(meta)
                           + _data_tuples(meta) + _drive_tuples(meta))
        view["members"] = set(TopicService.participants_map(meta))
        view["archived"] = str(meta.get("status") or "").strip().lower() == "archived"
    _cache[scope] = (now, view)
    return view


def tuples_for(agent: str, scope: Optional[str]) -> tuple[list[A.Tuple], Optional[list[A.Tuple]]]:
    """The tuples in force for THIS agent here. A room gives nothing to whoever
    does not take part in it and nothing from its panels once archived —
    review of #435, B2. Outside a room: the global level only."""
    v = _room_view(scope)
    if not scope:
        return v["global"], None
    if agent not in v["members"] or v["archived"]:
        return v["global"], []
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
          tainted: bool, targets: Optional[list[str]] = None) -> A.Decision:
    """The enforced decision for one call. A room whose rules cannot be read
    denies."""
    try:
        g, t = tuples_for(agent, scope)
    except RoomUnreadable as e:
        return A.Decision(A.DENY, False, [], str(e))
    f = S.facts(verb, arguments or {})
    if targets is not None:
        # The serving component named what the call acts on (#635): that is
        # the target, never the caller's mapped argument — `github.push`
        # ignores a `repo` argument, so judging it would judge a fiction.
        f["targets"] = list(targets)
    return A.decide(g, t, agent=agent, verb=verb, resource=f["resource"],
                    targets=f["targets"], kind=f["kind"], tainted=tainted)


#: The component service that names the resource a call acts on (#635):
#: `authz_targets(verb, arguments) -> [uri, ...]`. it-pack's git verbs: the
#: repository of `clone`/`pull_request` (argument) and of `pull`/`push` (the
#: working tree's origin), which the call does not carry in a mapped argument.
TARGETS_SERVICE = "authz_targets"

#: The targets A·V·R·Q judged for the call in flight, for the component to
#: compare with what it is about to act on (`host.judged_targets`): the
#: origin of a working tree can change between the check and the act.
JUDGED: contextvars.ContextVar[Optional[tuple[str, ...]]] = contextvars.ContextVar(
    "authz_judged_targets", default=None)


def _targets_service(verb: str):
    """The `authz_targets` service of the component serving `verb`, or None."""
    from . import main as _m
    spec = _m._component_verb(verb)
    if spec is None:
        return None
    from . import components as _components
    return _components.service(spec.pack, TARGETS_SERVICE)


def component_targets(verb: str, arguments: dict) -> Optional[list[str]]:
    """What the serving component says this call acts on.

    None: no component names targets for this verb (the mapped arguments
    decide, as before). []: it does, but cannot read them now — the call is
    judged on no target, i.e. it asks, as before #635. Runs git (`pull`/
    `push` read the working tree's origin): call it off the event loop."""
    try:
        svc = _targets_service(verb)
    except Exception as e:  # noqa: BLE001
        LOG.warning("authz: servizio bersagli di %s non consultabile (%s)", verb, type(e).__name__)
        return None
    if svc is None:
        return None
    try:
        out = svc.handler(verb, dict(arguments or {}))
    except Exception as e:  # noqa: BLE001 — unreadable: no target, the ask stands
        LOG.warning("authz: bersaglio di %s non determinabile (%s)", verb, type(e).__name__)
        return []
    if out is None:
        # The service does not handle this verb: the mappings decide.
        return None
    return [str(u).strip() for u in out if isinstance(u, str) and str(u).strip()]


def _component_named_verbs(entry: dict) -> set[str]:
    """The MCP's verbs that have no destination mapping but whose serving
    component names their resource (`authz_targets`)."""
    out = set()
    mapped = {v for sc in entry.get("schemes") or [] for v in sc.get("verbs") or []}
    for v in entry.get("verbs") or []:
        if v in mapped:
            continue
        try:
            if _targets_service(v) is not None:
                out.add(v)
        except Exception:  # noqa: BLE001
            continue
    return out


def allowed_by_room_rows(d: Optional[A.Decision]) -> bool:
    """Every target of an `allow` was decided by a resource row of the room's
    panel (#620): the owner approved exactly that resource there. The
    outward gate of a verb (`github.push`) has nothing left to ask (#635)."""
    if d is None or d.effect != A.ALLOW or not d.targets:
        return False
    return all(x.effect == A.ALLOW and x.target and x.target != A.NO_TARGET
               and x.level == A.TOPIC
               and str(x.tuple_id or "").startswith("resource:")
               for x in d.targets)


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

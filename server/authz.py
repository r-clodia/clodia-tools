"""Authorization as A·V·R·Q tuples: agent, verb, resource, rule
(clodia-platform#613, specification #614).

A tuple says what an agent may do with a verb on a resource, and its rule Q
says on which TARGETS — the recipients of a mail, the URL of a fetch, the folder
of a Drive call — with an effect per clause:

    {id: t-7f3a, agent: clodia, verb: email.send, resource: mail:studio,
     rule: [{effect: allow, match: "mailto:*@foo.bar"},
            {effect: ask,   match: "mailto:*"}]}

This module is PURE: it parses tuples and decides on the facts it is given
(agent, verb, resource, targets, kind, taint). Where tuples live, how a call's
facts are read and what happens to the decision are its callers' business
(`authz_shadow`, then the enforcing dispatch of a later step).

The rules of the specification, in the order they apply:

- §4 one level: the candidate tuples cover agent, verb and resource; per target
  the most specific matching clause wins (exact > longest hierarchical prefix >
  longest wildcard > `*`), then the more specific tuple, then deny > ask > allow.
  A target no clause matches takes the verb's default (§4.1): ask for a write,
  allow-untrusted for a read. The call's effect is the worst over its targets.
- §5 two levels: a global deny holds everywhere; a global allow the topic may
  only narrow; where the global is ask or silent the topic decides. A verb with
  no tuple at either level is NOT AVAILABLE.
- §6 `trust` (reads) and `when_tainted` (the trifecta's context condition).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Optional

ALLOW, ASK, DENY = "allow", "ask", "deny"
EFFECTS = (ALLOW, ASK, DENY)
#: Lower is stricter: the worst of several effects is the minimum.
RANK = {DENY: 0, ASK: 1, ALLOW: 2}
TRUSTED, UNTRUSTED = "trusted", "untrusted"
READ, WRITE = "read", "write"
ANY = "*"

#: A target that names nothing (a verb with `target: none`): only `*` covers it.
NO_TARGET = ""

GLOBAL, TOPIC = "global", "topic"

#: Platform/governance namespaces: global tuples only (#614 §7.3). A room does
#: not decide who installs packs or grants verbs.
GOVERNANCE = frozenset({"agents", "egress", "ingress", "integrations", "jobs", "logs",
                        "mcp", "native", "packs", "profile", "providers", "runtime",
                        "settings", "vault", "pki"})

_NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,62}$")
#: Verb names as the gateway serves them: MCP backends and third-party tools
#: name verbs with dashes, capitals and dots (`ns.list-invoices`, `x.getDoc`).
_VERB = re.compile(r"^(?:\*|[A-Za-z0-9_-]+\.(?:\*|[A-Za-z0-9_][A-Za-z0-9_.-]*))$")
_RESOURCE = re.compile(r"^(?:\*|web|topic|[a-z0-9_]+:[^\s]{1,200})$")


class AuthzError(ValueError):
    """A tuple that does not follow the specification."""


@dataclass(frozen=True)
class Clause:
    effect: str
    match: str
    trust: Optional[str] = None
    when_tainted: Optional[str] = None


@dataclass(frozen=True)
class Tuple:
    id: str
    agent: str
    verb: str
    resource: str
    rule: tuple[Clause, ...]
    by: str = ""

    def covers(self, agent: str, verb: str, resource: str) -> bool:
        return (self.agent in (ANY, agent)
                and _verb_covers(self.verb, verb)
                and self.resource in (ANY, resource))

    def specificity(self) -> tuple[int, int, int]:
        """Named agent over `*`, exact verb over `ns.*` over `*`, named
        resource over `*` — the tie-break after the clause's own specificity,
        compared in that order (agent first): who the rule is about is the
        strongest statement, then what, then with what."""
        verb = 2 if "*" not in self.verb else (1 if self.verb != ANY else 0)
        return (int(self.agent != ANY), verb, int(self.resource != ANY))


def _verb_covers(pattern: str, verb: str) -> bool:
    if pattern == ANY or pattern == verb:
        return True
    return pattern.endswith(".*") and verb.startswith(pattern[:-1])


def parse_clause(raw) -> Clause:
    if not isinstance(raw, dict):
        raise AuthzError(f"clausola non valida: {raw!r}")
    effect = str(raw.get("effect") or "").strip().lower()
    if effect not in EFFECTS:
        raise AuthzError(f"effect deve essere {', '.join(EFFECTS)}: {raw.get('effect')!r}")
    match = " ".join(str(raw.get("match") or "").split())
    if not match:
        raise AuthzError("una clausola deve dire su che cosa vale (`match`)")
    if match != ANY:
        # A rule that can never match is refused, not stored: under enforcement
        # a `deny` that never fires would read as protection.
        from . import egress as _eg
        if ":" not in match or _eg._is_degenerate(_eg.canonical(match).lower()):
            raise AuthzError(f"match {match!r}: serve `*` o un URI (`schema:valore`) "
                             "che possa combaciare con qualcosa")
    trust = raw.get("trust")
    if trust is not None and trust not in (TRUSTED, UNTRUSTED):
        raise AuthzError(f"trust deve essere trusted o untrusted: {trust!r}")
    if trust == TRUSTED and effect != ALLOW:
        raise AuthzError("solo una clausola allow può dichiarare fidato ciò che legge")
    wt = raw.get("when_tainted")
    if wt is not None and wt not in (ASK, DENY):
        raise AuthzError(f"when_tainted deve essere ask o deny: {wt!r}")
    return Clause(effect, match, trust, wt)


def parse_tuple(raw, *, level: str = GLOBAL) -> Tuple:
    """A tuple from its stored form, or `AuthzError` saying what is wrong."""
    if not isinstance(raw, dict):
        raise AuthzError(f"tupla non valida: {raw!r}")
    tid = str(raw.get("id") or "").strip()
    agent = str(raw.get("agent") or "").strip()
    verb = str(raw.get("verb") or "").strip()
    resource = str(raw.get("resource") or "").strip()
    if not tid:
        raise AuthzError("una tupla ha un id")
    if agent != ANY and not _NAME.match(agent):
        raise AuthzError(f"agent: un nome o `*`, non {agent!r}")
    if not _VERB.match(verb):
        raise AuthzError(f"verb: `ns.verbo`, `ns.*` o `*`, non {verb!r}")
    if not _RESOURCE.match(resource):
        raise AuthzError(f"resource: `<tipo>:<id>`, `web`, `topic` o `*`, non {resource!r}")
    if level == TOPIC and (verb == ANY or verb.split(".", 1)[0] in GOVERNANCE):
        raise AuthzError(f"{tid}: {verb!r} non si decide in un topic (verbi di "
                         "governance: solo regole globali)")
    rule = raw.get("rule")
    if not isinstance(rule, list) or not rule:
        raise AuthzError(f"{tid}: la regola Q è una lista non vuota di clausole")
    return Tuple(tid, agent, verb, resource, tuple(parse_clause(c) for c in rule),
                 str(raw.get("by") or ""))


def parse_tuples(raws: Iterable, *, level: str = GLOBAL) -> tuple[list[Tuple], list[str]]:
    """The valid tuples, and one line per tuple refused. A refused tuple grants
    nothing: it is left out, never read leniently."""
    ok, bad = [], []
    for raw in raws or ():
        try:
            ok.append(parse_tuple(raw, level=level))
        except AuthzError as e:
            bad.append(str(e))
    return ok, bad


# ── matching a clause against a target ──────────────────────────────────────

def _clause_specificity(match: str, target: str) -> Optional[tuple[int, int]]:
    """How specifically `match` covers `target`, or None if it does not.

    `(3, n)` exact, `(2, n)` hierarchical prefix, `(1, n)` wildcard, `(0, 0)` the
    bare `*`; `n` is the rule's length, so a longer prefix or suffix is the more
    specific. The covering itself is the platform's (`egress._matches`): one
    definition of «this rule covers this destination» for the lists and the
    tuples alike.
    """
    if match == ANY:
        return (0, 0)
    if target == NO_TARGET:
        return None
    from . import egress as _eg
    if not _eg._matches(target, match):
        return None
    r = _eg.canonical(match).lower()
    d = _eg.canonical(target).lower()
    if r == d:
        return (3, len(r))
    if "*" in r:
        return (1, len(r))
    return (2, len(r))


# ── deciding ────────────────────────────────────────────────────────────────

@dataclass
class TargetDecision:
    target: str
    effect: str
    level: str
    tuple_id: Optional[str] = None
    clause: Optional[int] = None
    trusted: bool = False
    default: bool = False


@dataclass
class Decision:
    """The answer for one call. `available=False`: no tuple at either level —
    the verb is not the agent's (§5)."""
    effect: str
    available: bool
    targets: list[TargetDecision] = field(default_factory=list)
    reason: str = ""

    def as_dict(self) -> dict:
        return {"effect": self.effect, "available": self.available, "reason": self.reason,
                "targets": [vars(t) for t in self.targets]}


def default_effect(kind: str) -> str:
    """§4.1: ask for what writes or leaves, allow-untrusted for a read."""
    return ALLOW if kind == READ else ASK


def _level(tuples: list[Tuple], agent: str, verb: str, resource: str,
           targets: list[str], kind: str, tainted: bool,
           level: str) -> Optional[list[TargetDecision]]:
    """One level's per-target answers, or None if the level is silent."""
    cands = [t for t in tuples if t.covers(agent, verb, resource)]
    if not cands:
        return None
    out = []
    for target in targets:
        best = None
        for t in cands:
            for i, c in enumerate(t.rule):
                spec = _clause_specificity(c.match, target)
                if spec is None:
                    continue
                key = (spec, t.specificity(), -RANK[c.effect])
                if best is None or key > best[0]:
                    best = (key, t, i, c)
        if best is None:
            eff = default_effect(kind)
            out.append(TargetDecision(target, eff, level, default=True))
            continue
        _, t, i, c = best
        eff = c.effect
        if tainted and c.when_tainted and RANK[c.when_tainted] < RANK[eff]:
            eff = c.when_tainted
        out.append(TargetDecision(target, eff, level, t.id, i,
                                  trusted=(eff == ALLOW and c.trust == TRUSTED)))
    return out


def _combine(g: Optional[TargetDecision], t: Optional[TargetDecision]) -> TargetDecision:
    """§5 for one target: a global deny holds; otherwise the topic, when it
    speaks, decides — which narrows a global allow (allow is the top, so the
    topic can only keep or lower it) and settles a global ask or silence."""
    if g is not None and g.effect == DENY:
        return g
    return t if t is not None else g  # type: ignore[return-value]


def decide(global_tuples: list[Tuple], topic_tuples: Optional[list[Tuple]], *,
           agent: str, verb: str, resource: str, targets: list[str],
           kind: str = WRITE, tainted: bool = False) -> Decision:
    """The A·V·R·Q decision for one call (§4–§6). `topic_tuples=None` outside a
    room: only the global level applies."""
    tgs = [t for t in dict.fromkeys(targets or ()) if t is not None] or [NO_TARGET]
    g = _level(global_tuples, agent, verb, resource, tgs, kind, tainted, GLOBAL)
    t = (_level(topic_tuples, agent, verb, resource, tgs, kind, tainted, TOPIC)
         if topic_tuples is not None else None)
    if g is None and t is None:
        return Decision(DENY, False, [], f"nessuna tupla concede {verb} a {agent}")
    per = [_combine(g[i] if g else None, t[i] if t else None) for i in range(len(tgs))]
    worst = min(per, key=lambda d: RANK[d.effect])
    reason = (f"{worst.effect} su {worst.target or '(nessun bersaglio)'}: "
              + (f"tupla {worst.tuple_id} ({worst.level}), clausola {worst.clause}"
                 if worst.tuple_id else f"default del verbo ({kind})"))
    return Decision(worst.effect, True, per, reason)

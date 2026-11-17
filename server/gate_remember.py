"""Remembering a gate's answer as a rule (clodia-platform#693).

The gate card is a matrix: WHO (this spawn · this seed · every agent) × WHERE
(this room · the whole instance). «This spawn» is the consent of today — the
capability, until the spawn ends — and is not written anywhere. The other
cells write a rule, and this module decides which cells a gate HAS and writes
them:

- a destination gate of the legacy lists (`egress:<type>:<uri>`,
  `ingress:…`): the lists hold addresses for every agent, so only the «every
  agent» row applies — the room's list or the global one, as before (#…, the
  «Approva sempre» / «Ovunque» of the card);
- an A·V·R·Q ask (`authz:<verb>|<targets>` from a room's rules,
  `authz-global:<verb>|<targets>` from the global ones): an allow tuple
  (agent = the seed or `*`, the verb, every target that asked). Only at the
  level that asked: §5 lets a room only narrow a global allow, so a global
  rule never lifts a room's ask, and a room rule over a room that is silent
  on the verb would take over its other targets from the global level too.
- anything else (native tools, topic access, unattended, copybrain, …): no
  rule — only this spawn.

What is remembered is the verb and the exact targets of THIS gate, never the
whole verb (owner, 17 Nov 2026).
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

#: The reason of a cell that does not apply, by gate kind.
_DEST_SEED = ("una destinazione della lista vale per tutti gli agenti: "
              "non si ricorda per un solo agente")
_ROOM_ASK_GLOBAL = ("la conferma la chiede una regola della stanza: una regola "
                    "globale non la scavalca, si decide nella stanza")
_GLOBAL_ASK_ROOM = ("la conferma la chiede una regola globale e la stanza non ne "
                    "ha per questo verbo: si decide a livello globale")
_NOTHING = "questo gate non diventa una regola: vale solo per questo spawn"

_GLOBAL_LOCK = threading.Lock()


class RememberError(ValueError):
    """A remember that cannot be written (with the reason to show)."""


def _destination(key: str) -> bool:
    return key.startswith(("egress:", "ingress:"))


def _authz(key: str) -> tuple[str, str, list[str]] | None:
    """`(level, verb, targets)` of an A·V·R·Q gate key, or None."""
    for prefix, level in (("authz-global:", A.GLOBAL), ("authz:", A.TOPIC)):
        if key.startswith(prefix):
            verb, _, targets = key[len(prefix):].partition("|")
            return level, verb, [t for t in targets.split(",") if t]
    return None


def cells(key: str) -> dict[str, str]:
    """`{"seed:chat": "", "seed:global": "<why not>", …}`: an empty reason is a
    cell that applies. The approver's title (owner, admin) is not judged here:
    the card and the agent-server know the person."""
    out = {f"{w}:{c}": _NOTHING for w in (SEED, ALL) for c in (CHAT, GLOBAL)}
    if _destination(key):
        out.update({"seed:chat": _DEST_SEED, "seed:global": _DEST_SEED,
                    "all:chat": "", "all:global": ""})
        return out
    parsed = _authz(key)
    if parsed is None:
        return out
    level = parsed[0]
    for w in (SEED, ALL):
        out[f"{w}:{CHAT}"] = "" if level == A.TOPIC else _GLOBAL_ASK_ROOM
        out[f"{w}:{GLOBAL}"] = "" if level == A.GLOBAL else _ROOM_ASK_GLOBAL
    return out


def tuple_for(key: str, agent: str, by: str = "") -> dict:
    """The allow tuple a remember writes for an A·V·R·Q gate key."""
    parsed = _authz(key)
    if parsed is None:
        raise RememberError(_NOTHING)
    level, verb, targets = parsed
    if not targets:
        raise RememberError("il gate non dice su che cosa: nulla da ricordare")
    if len(",".join(targets)) >= 900:
        # The key keeps 900 characters of targets: past that it may have lost
        # some, and a rule for the visible ones only would be another rule.
        raise RememberError("troppi bersagli in questo gate per ricordarli: "
                            "approva solo per stavolta")
    rule = [{"effect": A.ALLOW, "match": t} for t in sorted(set(targets))]
    raw = {"agent": agent, "verb": verb, "resource": A.ANY, "rule": rule}
    digest = hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest()[:10]
    raw = {"id": f"gate-{digest}", **raw, "by": by, "at": time.time(),
           "origin": "gate"}
    try:
        A.parse_tuple(raw, level=level)
    except A.AuthzError as e:
        raise RememberError(str(e)) from None
    return raw


def _same(a: dict, b: dict) -> bool:
    return a.get("id") == b.get("id")


def _write_room(scope: str, raw: dict) -> bool:
    from . import main
    tier, _, name = scope.partition("/")
    if not (tier and name):
        raise RememberError("serve la stanza in cui ricordarlo")
    svc = main._topics()
    meta, ver = svc._read_meta(tier, name)
    rows = meta.get("authz") if isinstance(meta.get("authz"), list) else []
    if any(isinstance(r, dict) and _same(r, raw) for r in rows):
        return False
    meta["authz"] = list(rows) + [raw]
    svc._write_meta(tier, name, meta, ver)
    return True


def _write_global(raw: dict) -> bool:
    from . import authz_shadow as S
    from .authz_migration import _atomic_write
    with _GLOBAL_LOCK:
        path = S._global_path()
        try:
            doc = json.loads(path.read_text())
        except FileNotFoundError:
            doc = {"tuples": []}
        except Exception as e:  # noqa: BLE001 — never overwrite what we cannot read
            raise RememberError(f"{S.GLOBAL_FILE} illeggibile ({type(e).__name__}): "
                                "nulla scritto") from None
        if isinstance(doc, list):
            doc = {"tuples": doc}
        rows = doc.get("tuples") if isinstance(doc.get("tuples"), list) else []
        if any(isinstance(r, dict) and _same(r, raw) for r in rows):
            return False
        doc["tuples"] = list(rows) + [raw]
        _atomic_write(path, json.dumps(doc, ensure_ascii=False, indent=1))
    return True


def remember(key: str, *, agent: str, scope: str, by: str = "") -> dict:
    """Write the rule of one cell: `agent` is the seed or `*`, `scope` the
    room (`tier/name`) or "" for the instance. Destination gates for every
    agent go to the lists (`egress.scope_allow` / `allow`), as before."""
    agent = str(agent or "").strip()
    scope = str(scope or "").strip()
    who = ALL if agent == A.ANY else SEED
    where = CHAT if scope else GLOBAL
    why = cells(key).get(f"{who}:{where}")
    if why:
        raise RememberError(why)
    if _destination(key):
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
    raw = tuple_for(key, agent, by)
    new = _write_room(scope, raw) if scope else _write_global(raw)
    from . import authz_runtime as _rt
    _rt.invalidate()
    LOG.info("GATE ricordato come regola %s · %s · %s → %s (%s) da %s",
             agent, raw["verb"], [c["match"] for c in raw["rule"]],
             scope or "GLOBALE", "nuova" if new else "già presente", by)
    return {"remembered": True, "kind": "rule", "rule": raw, "scope": scope or None,
            "new": new}

"""Control-plane events: changes to the RULES, not to the work (clodia-platform#439).

The reference monitor decides on a rule set; `policy_bundle_hash` (#436) says
which one. These events say who changed it, when, and how.

`config_changes()` is the generic part: every mutation of the gateway config
(per-agent whitelists and grants, global and scope egress/ingress lists, gdrive
roots, datastore and RAG declarations …) goes through `whitelist.save_config`,
and that function reports the delta it is about to write. One hook, so the
next mutating verb cannot forget to be audited.

The specific emitters (`vault`, `pki`, `participants`, `topic_tier`,
`topic_status`, `backup`) cover state that does not live in the config.
Credential VALUES never appear: a vault event names the credential and the
change, nothing else.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

MAX_CHANGES = 200


def _h(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


def config_changes(before: dict, after: dict, prefix: str = "", depth: int = 0) -> list[dict]:
    """The delta from `before` to `after`, as `[{path, op, …}]`.

    Lists of scalars (whitelists, URIs) report the entries added and removed —
    they ARE the rules. Other changed values report hashes only.
    """
    out: list[dict] = []
    keys = sorted(set(before or {}) | set(after or {}), key=str)
    for k in keys:
        path = f"{prefix}{k}"
        b, a = (before or {}).get(k), (after or {}).get(k)
        if b == a:
            continue
        if (isinstance(b, dict) or isinstance(a, dict)) and \
                isinstance(b or {}, dict) and isinstance(a or {}, dict) and depth < 4:
            # A new or removed section is walked too, so that a scope list
            # created from nothing still reports the entries it opens.
            out += config_changes(b or {}, a or {}, path + ".", depth + 1)
        elif isinstance(a, list) and isinstance(b, (list, type(None))) and \
                all(not isinstance(x, (dict, list)) for x in (a or []) + (b or [])):
            added = [x for x in a if x not in (b or [])]
            removed = [x for x in (b or []) if x not in a]
            if added or removed:
                out.append({"path": path, "op": "list", "added": added or None,
                            "removed": removed or None})
        elif a is None:
            out.append({"path": path, "op": "removed", "before_hash": _h(b)})
        elif b is None:
            out.append({"path": path, "op": "added", "after_hash": _h(a)})
        else:
            out.append({"path": path, "op": "changed", "before_hash": _h(b), "after_hash": _h(a)})
        if len(out) >= MAX_CHANGES:
            out.append({"path": "…", "op": "truncated"})
            break
    return out


def config(before: dict, after: dict) -> None:
    changes = config_changes(before, after)
    if not changes:
        return
    from .. import audit
    audit.emit("control.config", action="change", resource="clodia-tools-config",
               input={"before_hash": _h(before), "after_hash": _h(after)},
               result={"changes": changes})


def emit(kind: str, action: str, resource: str, **details) -> None:
    """A specific control-plane event, e.g. `emit("vault", "grant", "google_x", agent=…)`."""
    from .. import audit
    audit.emit(f"control.{kind}", action=action, resource=resource,
               result={k: v for k, v in details.items() if v is not None} or None)


def safe(fn, *a, **kw) -> None:
    """Run an emitter without ever breaking the change it records (fail-closed aside)."""
    from .. import audit
    try:
        fn(*a, **kw)
    except audit.AuditWriteError:
        raise
    except Exception as e:  # noqa: BLE001
        import logging
        logging.getLogger("clodia-tools.audit").error(
            "audit: control-plane event not recorded (%s)", type(e).__name__)

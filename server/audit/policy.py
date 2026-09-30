"""Reference-monitor decisions, and the version of the rules they were made under
(clodia-platform#436).

`egress.check()` and the dispatch compute allow / deny / gate, and until now
the verdict lived only in a log line. `decision()` records it as a
`policy.decision` event with the policy that decided, the rule that matched
(global or scope list), and `policy_bundle_hash`.

**Why a bundle hash.** "Denied by `egress`" says nothing if one does not know
which egress lists were in force. The bundle is everything the gateway decides
on: the effective config (per-agent whitelists, global and scope
egress/ingress lists, gdrive roots), the seeds it reads grants from
(`<CLODIA_DATA>/agents/*/agent.yaml`), and the environment switches that change
decisions. Two events with the same hash were decided under the same rules;
a different hash means the rules changed in between — and the control-plane
events (#439) say who changed them.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

#: Environment switches that change what the reference monitor decides.
POLICY_ENV = ("CLODIA_EGRESS_ENFORCE", "CLODIA_GATED_VERBS", "CLODIA_DANGEROUSLY_SKIP_GATES",
              "CLODIA_SPAWN_COMPARTMENT", "CLODIA_OBSERVE_ONLY")

_cache: dict = {"key": None, "hash": None}


def _seed_files() -> list[Path]:
    root = Path(os.environ.get("CLODIA_DATA", "/datadir")) / "agents"
    try:
        return sorted(root.glob("*/agent.yaml"))
    except OSError:
        return []


def bundle_hash() -> str:
    """sha256 of the rule set in force, recomputed only when an input changes."""
    from .. import whitelist
    seeds = _seed_files()
    stats = []
    for p in seeds:
        try:
            st = p.stat()
            stats.append((str(p), st.st_mtime_ns, st.st_size))
        except OSError:
            continue
    cfg = whitelist.CONFIG or {}
    try:
        cfg_bytes = json.dumps(cfg, sort_keys=True, default=str).encode()
    except Exception:  # noqa: BLE001
        cfg_bytes = repr(cfg).encode()
    env = tuple((k, os.environ.get(k, "")) for k in POLICY_ENV)
    key = (hashlib.sha256(cfg_bytes).hexdigest(), tuple(stats), env)
    if _cache["key"] == key:
        return _cache["hash"]
    h = hashlib.sha256()
    h.update(b"config\0" + cfg_bytes)
    for path, _m, _s in stats:
        try:
            h.update(b"seed\0" + path.encode() + b"\0" + Path(path).read_bytes())
        except OSError:
            continue
    h.update(b"env\0" + json.dumps(env).encode())
    _cache.update(key=key, hash="sha256:" + h.hexdigest())
    return _cache["hash"]


def matched_rules(verdict: dict) -> list[dict]:
    """For an egress verdict: which rule admitted each destination, and whether
    it sits in the global list or in the list of the calling scope."""
    from .. import egress
    dests = verdict.get("destinations") or []
    rules = verdict.get("rules") or []
    try:
        scope = egress._scope_of_call()
        scoped = set(egress.scope_uris("egress", scope)) if scope else set()
    except Exception:  # noqa: BLE001
        scoped = set()
    out = []
    for d in dests:
        rule = next((r for r in rules if egress._matches(d, r)), None)
        out.append({"destination": d, "rule": rule,
                    "list": None if rule is None else ("scope" if rule in scoped else "global")})
    return out


def decision(verb: str, policy: str, result: str, *, reason_class: str | None = None,
             rule: list | None = None, mode: dict | None = None) -> None:
    """Emit one `policy.decision`. Never raises into the caller's decision path,
    except `AuditWriteError` when the owner asked for fail-closed."""
    from .. import audit
    audit.emit("policy.decision", action=result, resource=verb,
               decision={"policy": policy, "result": result, "reason_class": reason_class,
                         "rule": rule, "policy_bundle_hash": bundle_hash(), **(mode or {})})

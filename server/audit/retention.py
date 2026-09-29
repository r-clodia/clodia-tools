"""Retention of the trail and of the evidence (clodia-platform#446).

Two clocks, because they protect different things:

* **the trail** — metadata and hashes, no content. Kept whole by default
  (`CLODIA_AUDIT_TRAIL_RETENTION_DAYS=0`). When a retention is set, only whole
  daily segments older than it are removed, and never without leaving a
  signed `pruned.jsonl` record of where the chain now starts (`up_to_seq`,
  `last_hash`). The verifier starts the chain from that record, so a pruned
  trail still verifies — and an unrecorded deletion of the head still fails.
* **the evidence** — the content, per tier. `CLODIA_AUDIT_EVIDENCE_RETENTION`
  is `SEAL-0=365,SEAL-1=365,…` (days; `0` = keep). Default 365 days for every
  tier: the owner shortens it where minimisation weighs more than evidence.

Every run is a `control.retention` event with what was removed. The store and
the evidence live on the gateway state volume, which the backup includes, so
removed objects remain in older backup snapshots until the backup's own
retention drops them — stated here, not hidden.
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import record

PRUNED_NAME = "pruned.jsonl"
_TIERS = ("SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4")
DEFAULT_EVIDENCE_DAYS = 365


def trail_days() -> int:
    try:
        return max(0, int(os.environ.get("CLODIA_AUDIT_TRAIL_RETENTION_DAYS") or 0))
    except ValueError:
        return 0


def evidence_days() -> dict[str, int]:
    out = {t: DEFAULT_EVIDENCE_DAYS for t in _TIERS}
    raw = (os.environ.get("CLODIA_AUDIT_EVIDENCE_RETENTION") or "").strip()
    for part in raw.split(","):
        if "=" in part:
            k, v = part.split("=", 1)
            k = k.strip().upper()
            if k in out:
                try:
                    out[k] = max(0, int(v))
                except ValueError:
                    pass
    return out


def last_prune(root: Path) -> dict | None:
    p = root / PRUNED_NAME
    if not p.is_file():
        return None
    last = None
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.strip():
            last = json.loads(line)
    return last


def _prune_trail(store, now: datetime) -> dict:
    days = trail_days()
    if not days:
        return {"segments": 0}
    cutoff = (now - timedelta(days=days)).strftime("%Y%m%d")
    segs = store.segments()
    # Never the newest segment: the chain head lives there.
    old = [s for s in segs[:-1] if s.name[len("events-"):len("events-") + 8] < cutoff]
    if not old:
        return {"segments": 0}
    last_line = store._last_line(old[-1])
    integ = json.loads(last_line)["integrity"]
    rec = {"schema": "clodia.audit.pruned/1", "up_to_seq": int(integ["seq"]),
           "last_hash": integ["hash"], "timestamp": record.now_iso(),
           "key_id": store.signer.key_id,
           "segments": [s.name for s in old]}
    rec["signature"] = store.signer.sign(record.canonical_json(rec))
    with (store.root / PRUNED_NAME).open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    for s in old:
        s.unlink()
    return {"segments": len(old), "up_to_seq": rec["up_to_seq"]}


def _prune_evidence(now: float) -> dict:
    from . import evidence
    out = {}
    for tier, days in evidence_days().items():
        d = evidence.root() / tier
        if not days or not d.is_dir():
            continue
        cutoff = now - days * 86400
        n = 0
        for p in d.rglob("*"):
            if p.is_file() and p.stat().st_mtime < cutoff:
                p.unlink()
                n += 1
        if n:
            out[tier] = n
    return out


def apply(now: datetime | None = None) -> dict:
    """Apply both retentions once, and record what was removed."""
    from .. import audit
    now = now or datetime.now(timezone.utc)
    st = audit.store()
    res = {"trail": _prune_trail(st, now), "evidence": _prune_evidence(now.timestamp()),
           "policy": {"trail_days": trail_days(), "evidence_days": evidence_days()}}
    audit.emit("control.retention", identity="explicit", action="apply", resource="audit",
               actor={"type": "service", "id": "clodia-tools"}, result=res)
    return res


async def retention_loop(interval: int = 86400) -> None:
    import asyncio
    import logging
    while True:
        await asyncio.sleep(interval)
        try:
            await asyncio.to_thread(apply)
        except Exception as e:  # noqa: BLE001 - the loop must survive
            logging.getLogger("clodia-tools.audit").error("audit: retention failed (%s)", e)

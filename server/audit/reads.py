"""Human read access, as evidence of confidentiality (clodia-platform#444).

Only writes used to leave traces. Confidentiality is shown by reads too: who
opened a SEAL-2 topic, who downloaded which file, who exported what.

A topic VIEW is recorded once per (person, topic) per window, not per request:
the webui polls an open topic several times a minute (≈3,900 GETs of one topic
in an hour on 29 Sep), and one event per poll would bury the trail without
saying anything more. Downloads and exports are recorded every time.
"""
from __future__ import annotations

import os
import threading
import time

#: Views below this tier are not recorded (SEAL-0/1: public and internal).
MIN_TIER = os.environ.get("CLODIA_AUDIT_READS_MIN_TIER", "SEAL-2")
VIEW_WINDOW_S = int(os.environ.get("CLODIA_AUDIT_VIEW_WINDOW_S", "1800"))

_seen: dict[tuple[str, str], float] = {}
_lock = threading.Lock()


def _rank(tier: str | None) -> int:
    try:
        return int(str(tier or "").upper().replace("SEAL-", "").replace("P", ""))
    except ValueError:
        return 0


def covered(tier: str) -> bool:
    return _rank(tier) >= _rank(MIN_TIER)


def actor_of(payload: dict) -> dict:
    """The person from a verified session payload (the carrier is `via`)."""
    return {"type": "human", "id": payload.get("principal"),
            "role": payload.get("human_role"), "via": payload.get("agent"),
            "source": "claims"}


def view(payload: dict, tier: str, name: str, what: str = "topic") -> None:
    if not covered(tier):
        return
    who = str(payload.get("principal") or "?")
    key = (who, f"{tier}/{name}")
    now = time.monotonic()
    with _lock:
        last = _seen.get(key)
        if last is not None and now - last < VIEW_WINDOW_S:
            return
        _seen[key] = now
    from .. import audit
    audit.emit("human.view", identity="explicit", action="open", resource=f"{tier}/{name}",
               actor=actor_of(payload), scope={"tier": tier, "topic": name},
               result={"what": what, "window_s": VIEW_WINDOW_S})


def download(payload: dict, tier: str, name: str, path: str, version: str | None) -> None:
    if not covered(tier):
        return
    from .. import audit
    audit.emit("human.download", identity="explicit", action="download",
               resource=f"topic:{tier}/{name}/{path}", actor=actor_of(payload),
               scope={"tier": tier, "topic": name},
               provenance={"sources": [{"ref": f"topic:{tier}/{name}/{path}",
                                        "content_hash": version, "hash_of": "file"}]})


def export(payload: dict, topics: list[str], size: int | None = None) -> None:
    from .. import audit
    audit.emit("human.export", identity="explicit", action="export", resource="topics",
               actor=actor_of(payload),
               result={"topics": topics, "count": len(topics), "bytes": size})


def safe(fn, *a, **kw) -> None:
    from .. import audit
    try:
        fn(*a, **kw)
    except audit.AuditWriteError:
        raise
    except Exception as e:  # noqa: BLE001
        import logging
        logging.getLogger("clodia-tools.audit").error(
            "audit: human read not recorded (%s)", type(e).__name__)

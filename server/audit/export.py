"""Signed export of the audit trail for an external auditor (clodia-platform#447).

The bundle (tar.gz) verifies OFFLINE with nothing but itself:

    events-YYYYMMDD.jsonl …   the whole daily segments covering the range
    audit.pub.pem             the audit public key
    checkpoints.jsonl         signed checkpoints (local copy) that fall inside
                              the exported chain — none after its last event
    export_start.json         signed record of where the chain starts in this
                              bundle (the events before the range are not in
                              it); schema clodia.audit.export_start/1, valid
                              only together with the signed manifest
    pruned.jsonl              the store's own retention record, when the
                              bundle starts where retention left the chain
    manifest.json             range, reader, sha256 of every file, head; signed
    verifier/                 the verifier's own source (stdlib + cryptography)
    README.txt                how to verify

    tar xzf bundle.tgz && cd bundle && python -m verifier.verify . --checkpoints <worm-dir>

Segments are exported whole: filtering events inside a segment would break the
chain, and then the bundle could not prove anything. A filtered view is for
reading, the whole segments are for proving.

An export is itself an event (`audit.export`), with the reader and the range.
"""
from __future__ import annotations

import hashlib
import io
import json
import tarfile
from datetime import date, datetime, timezone
from pathlib import Path

from . import record
from .keys import PUB_NAME

_VERIFIER_FILES = ("verify.py", "record.py", "keys.py", "checkpoint.py")
EXPORT_START_NAME = "export_start.json"
EXPORT_START_SCHEMA = "clodia.audit.export_start/1"

README = """Clodia audit trail export
=========================

Verify offline (Python 3.10+, package `cryptography`):

    python -m verifier.verify . \\
        --pubkey <audit public key obtained OUT OF BAND> \\
        --checkpoints <dir of checkpoints exported to WORM>

Two things this bundle cannot prove about itself, and that you must supply:

1. WHO signed it. audit.pub.pem travels inside the bundle, so a bundle forged
   with another key verifies against its own key. Obtain the platform's audit
   key, or its fingerprint, through a separate channel (the owner reads
   `key_id` from GET /internal/audit/status), then either pass that key with
   --pubkey, or at least compare the `key_id` in the report with the
   fingerprint you were given. A different key_id means the bundle is not
   from that platform, whatever `ok` says.
2. That NOTHING WAS CUT at the end. A chain alone cannot show a missing tail.
   Pass --checkpoints with the checkpoints exported to WORM storage (read
   them from the WORM bucket or directory, not from the platform). Without
   it the report's `unanchored_events` says how much of the tail is unproven.

`ok: true` means: every event in the included segments is intact, in order,
chained and signed by the key used, from the start recorded in
export_start.json (or pruned.jsonl); every checkpoint in the bundle matches
its event; and manifest.json, signed with the same key, lists the sha256 of
every file, all of which match.
"""


def _day(seg: Path) -> str:
    return seg.name[len("events-"):len("events-") + 8]


def build(store, *, reader: str, since: date | None = None, until: date | None = None,
          purpose: str = "") -> bytes:
    from .. import audit
    segs = store.segments()
    lo = since.strftime("%Y%m%d") if since else "00000000"
    hi = until.strftime("%Y%m%d") if until else "99999999"
    chosen = [s for s in segs if lo <= _day(s) <= hi]
    files: dict[str, bytes] = {}
    for s in chosen:
        files[s.name] = s.read_bytes()
    pub = store.root / PUB_NAME
    files[PUB_NAME] = pub.read_bytes()
    # Where the chain starts and ends in THIS bundle.
    first = last = None
    if chosen:
        first_line = next((ln for ln in files[chosen[0].name].decode().splitlines()
                           if ln.strip()), None)
        if first_line:
            first = json.loads(first_line)["integrity"]
        last_line = store._last_line(chosen[-1])
        if last_line:
            last = json.loads(last_line)["integrity"]
    lo_seq = int(first["seq"]) if first else 0
    hi_seq = int(last["seq"]) if last else -1
    # Only the checkpoints that anchor events IN the bundle. One after its
    # last event (a later day, outside `until`) would read as a cut tail.
    cps = store.root / "checkpoints.jsonl"
    if cps.is_file():
        keep = [ln for ln in cps.read_text(encoding="utf-8").splitlines()
                if ln.strip() and lo_seq <= int(json.loads(ln)["checkpoint"]["seq"]) <= hi_seq]
        if keep:
            files["checkpoints.jsonl"] = ("\n".join(keep) + "\n").encode()
    start = None
    if first and int(first["seq"]) > 1:
        from .retention import last_prune
        prune = last_prune(store.root)
        if prune and int(prune.get("up_to_seq") or 0) + 1 == int(first["seq"]):
            # The bundle starts where retention left the chain: the store's
            # own record says so.
            files["pruned.jsonl"] = (store.root / "pruned.jsonl").read_bytes()
        else:
            # A boundary of THIS export, not a deletion. Its own schema, so
            # that it can never stand in for a retention record: the verifier
            # accepts it only inside a bundle whose signed manifest names it.
            start = {"schema": EXPORT_START_SCHEMA, "up_to_seq": int(first["seq"]) - 1,
                     "last_hash": first["previous_hash"], "timestamp": record.now_iso(),
                     "key_id": store.signer.key_id, "reason": "not in this export"}
            start["signature"] = store.signer.sign(record.canonical_json(start))
            files[EXPORT_START_NAME] = (json.dumps(start, sort_keys=True) + "\n").encode()
    here = Path(__file__).parent
    for name in _VERIFIER_FILES:
        src = (here / name).read_text(encoding="utf-8")
        files[f"verifier/{name}"] = src.encode()
    files["verifier/__init__.py"] = b""
    files["README.txt"] = README.encode()
    seq, head = store.head()
    manifest = {"schema": "clodia.audit.export/1", "created": record.now_iso(),
                "reader": reader, "purpose": purpose or None,
                "range": {"since": since.isoformat() if since else None,
                          "until": until.isoformat() if until else None},
                "segments": [s.name for s in chosen], "head_at_export": {"seq": seq, "hash": head},
                "start": ({"up_to_seq": start["up_to_seq"], "last_hash": start["last_hash"]}
                          if start else None),
                "end": {"seq": hi_seq, "hash": last["hash"]} if last else None,
                "key_id": store.signer.key_id,
                "files": {k: hashlib.sha256(v).hexdigest() for k, v in sorted(files.items())}}
    manifest["signature"] = store.signer.sign(record.canonical_json(manifest))
    files["manifest.json"] = json.dumps(manifest, indent=2, sort_keys=True).encode()

    buf = io.BytesIO()
    now = datetime.now(timezone.utc).timestamp()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in sorted(files.items()):
            ti = tarfile.TarInfo(f"bundle/{name}")
            ti.size, ti.mtime, ti.mode = len(data), int(now), 0o644
            tar.addfile(ti, io.BytesIO(data))
    blob = buf.getvalue()
    audit.emit("audit.export", identity="explicit", action="export", resource="audit-trail",
               actor={"type": "human", "id": reader},
               result={"segments": len(chosen), "range": manifest["range"],
                       "bundle_hash": "sha256:" + hashlib.sha256(blob).hexdigest(),
                       "purpose_hash": record.content_hash(purpose) if purpose else None})
    return blob

"""Signed export of the audit trail for an external auditor (clodia-platform#447).

The bundle (tar.gz) verifies OFFLINE with nothing but itself:

    events-YYYYMMDD.jsonl …   the whole daily segments covering the range
    audit.pub.pem             the audit public key
    checkpoints.jsonl         signed checkpoints (local copy)
    pruned.jsonl              signed record of where the chain starts in this
                              bundle (the events before the range are not in it)
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

README = """Clodia audit trail export
=========================

Verify offline (Python 3.10+, package `cryptography`):

    python -m verifier.verify .
    python -m verifier.verify . --checkpoints <dir of checkpoints exported to WORM>

`ok: true` means: every event in the included segments is intact, in order,
chained and signed by the key in audit.pub.pem, from the start recorded in
pruned.jsonl. With --checkpoints, a checkpoint beyond the last event proves the
tail was cut after export or at the source. manifest.json lists the sha256 of
every file and is signed with the same key.
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
    cps = store.root / "checkpoints.jsonl"
    if cps.is_file():
        files["checkpoints.jsonl"] = cps.read_bytes()
    # Where the chain starts in THIS bundle.
    first = None
    if chosen:
        first_line = next((ln for ln in files[chosen[0].name].decode().splitlines() if ln.strip()), None)
        if first_line:
            first = json.loads(first_line)["integrity"]
    if first and int(first["seq"]) > 1:
        start = {"schema": "clodia.audit.pruned/1", "up_to_seq": int(first["seq"]) - 1,
                 "last_hash": first["previous_hash"], "timestamp": record.now_iso(),
                 "key_id": store.signer.key_id, "reason": "not in this export"}
        start["signature"] = store.signer.sign(record.canonical_json(start))
        files["pruned.jsonl"] = (json.dumps(start, sort_keys=True) + "\n").encode()
    elif (store.root / "pruned.jsonl").is_file():
        files["pruned.jsonl"] = (store.root / "pruned.jsonl").read_bytes()
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

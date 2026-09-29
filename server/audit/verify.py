"""Offline verifier of an audit store (clodia-platform#431).

    python -m server.audit.verify <store-dir> [--checkpoints <dir>] [--pubkey <pem>]

Needs only the store directory (events, local checkpoints, public key) and,
for truncation evidence, the checkpoints exported off-system. It checks:

1. every line parses and carries `integrity`;
2. `seq` runs 1, 2, 3 … with no gap and no repeat, across segments in order;
3. `previous_hash` equals the `hash` of the event before (genesis for seq 1);
4. `hash` recomputes from the record;
5. `signature` verifies with the audit public key, and `key_id` matches it;
6. every checkpoint (local and exported) is correctly signed and matches the
   event at its `seq`;
7. **truncation**: an exported checkpoint beyond the last event in the store
   means the tail was cut.

Exit status 0 if everything verifies, 1 otherwise; the report is JSON.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import checkpoint, record
from .keys import PUB_NAME, key_id_of, load_public, verify as verify_sig


def _load_external(path: Path | None) -> list[dict]:
    if not path:
        return []
    files = sorted(path.glob("checkpoint-*.json")) if path.is_dir() else [path]
    return [json.loads(f.read_text(encoding="utf-8")) for f in files]


def verify(root: Path, *, pubkey_pem: bytes | None = None,
           external: list[dict] | None = None, max_errors: int = 50) -> dict:
    errors: list[str] = []

    def err(msg: str) -> None:
        if len(errors) < max_errors:
            errors.append(msg)

    pem = pubkey_pem if pubkey_pem is not None else (root / PUB_NAME).read_bytes()
    pub = load_public(pem)
    kid = key_id_of(pub)

    hashes: dict[int, str] = {}
    expected_seq, prev = 1, record.GENESIS
    count = 0
    # A signed prune record (#446) moves the start of the chain: the events up
    # to `up_to_seq` were removed by retention, and the chain resumes after the
    # hash they ended on. Only the LAST record counts, and it must verify.
    pruned = None
    pp = root / "pruned.jsonl"
    if pp.is_file():
        lines = [x for x in pp.read_text(encoding="utf-8").splitlines() if x.strip()]
        if lines:
            pruned = json.loads(lines[-1])
            body = {k: v for k, v in pruned.items() if k != "signature"}
            if pruned.get("key_id") != kid or not verify_sig(
                    pub, record.canonical_json(body), pruned.get("signature") or ""):
                err("pruned.jsonl: the last prune record does not verify")
            else:
                expected_seq = int(pruned["up_to_seq"]) + 1
                prev = pruned["last_hash"]
    for seg in sorted(root.glob("events-*.jsonl")):
        with seg.open("r", encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                where = f"{seg.name}:{n}"
                try:
                    rec = json.loads(line)
                    integ = rec["integrity"]
                    seq = int(integ["seq"])
                except (ValueError, KeyError, TypeError) as exc:
                    err(f"{where}: unreadable event ({exc})")
                    continue
                count += 1
                if seq != expected_seq:
                    err(f"{where}: seq {seq}, expected {expected_seq} (gap, repeat or reorder)")
                if integ.get("previous_hash") != prev:
                    err(f"{where}: seq {seq} does not chain to the event before")
                h = record.event_hash(rec)
                if h != integ.get("hash"):
                    err(f"{where}: seq {seq} hash mismatch (record altered)")
                if integ.get("key_id") != kid:
                    err(f"{where}: seq {seq} signed by key {integ.get('key_id')}, not {kid}")
                elif not verify_sig(pub, bytes.fromhex(integ.get("hash") or "00"),
                                    integ.get("signature") or ""):
                    err(f"{where}: seq {seq} signature does not verify")
                hashes[seq] = integ.get("hash")
                prev = integ.get("hash")
                expected_seq = seq + 1
    last_seq = expected_seq - 1

    first_seq = int(pruned["up_to_seq"]) + 1 if pruned else 1

    def check_cp(cp: dict, origin: str) -> bool:
        if int(cp.get("seq") or 0) < first_seq:
            return True  # anchors a pruned part of the chain: nothing left to compare
        if cp.get("key_id") != kid or not verify_sig(pub, checkpoint.unsigned(cp),
                                                     cp.get("signature") or ""):
            err(f"{origin} checkpoint seq {cp.get('seq')}: signature does not verify")
            return False
        seq = int(cp.get("seq") or 0)
        if seq > last_seq:
            err(f"{origin} checkpoint seq {seq} is beyond the last event ({last_seq}): "
                "the log has been TRUNCATED")
            return False
        if hashes.get(seq) != cp.get("hash"):
            err(f"{origin} checkpoint seq {seq} does not match the event at that seq")
            return False
        return True

    local_cps = []
    lp = checkpoint.local_path(root)
    if lp.is_file():
        for line in lp.read_text(encoding="utf-8").splitlines():
            if line.strip():
                local_cps.append(json.loads(line)["checkpoint"])
    ext = external or []
    local_ok = sum(check_cp(cp, "local") for cp in local_cps)
    ext_ok = sum(check_cp(cp, "exported") for cp in ext)
    truncated = any(int(cp.get("seq") or 0) > last_seq for cp in ext)
    covered = max([int(cp.get("seq") or 0) for cp in ext] or [0])
    return {
        "ok": not errors,
        "events": count,
        "last_seq": last_seq,
        "last_hash": prev if count else None,
        "key_id": kid,
        "checkpoints": {"local": len(local_cps), "local_ok": local_ok,
                        "exported": len(ext), "exported_ok": ext_ok},
        "truncated": truncated,
        # Events after the last exported checkpoint are chained and signed, but
        # a cut of exactly those would not be detectable yet.
        "unanchored_events": max(0, last_seq - covered),
        "pruned_up_to": int(pruned["up_to_seq"]) if pruned else None,
        "errors": errors,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m server.audit.verify",
                                 description="Verify a Clodia audit store offline.")
    ap.add_argument("store", type=Path)
    ap.add_argument("--checkpoints", type=Path, default=None,
                    help="directory (or file) of checkpoints exported off-system")
    ap.add_argument("--pubkey", type=Path, default=None,
                    help="audit public key PEM (default: <store>/audit.pub.pem)")
    a = ap.parse_args(argv)
    rep = verify(a.store, pubkey_pem=a.pubkey.read_bytes() if a.pubkey else None,
                 external=_load_external(a.checkpoints))
    print(json.dumps(rep, indent=2))
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())

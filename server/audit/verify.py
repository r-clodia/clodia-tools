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

# Kept here, not imported from retention/export: this module is bundled with
# every export and must stand alone (with record, keys, checkpoint).
PRUNED_NAME = "pruned.jsonl"
PRUNED_SCHEMA = "clodia.audit.pruned/1"
EXPORT_START_NAME = "export_start.json"
EXPORT_START_SCHEMA = "clodia.audit.export_start/1"


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

    def signed_ok(rec: dict) -> bool:
        body = {k: v for k, v in rec.items() if k != "signature"}
        return rec.get("key_id") == kid and verify_sig(
            pub, record.canonical_json(body), rec.get("signature") or "")

    # An export bundle (#447) carries a signed manifest of every file in it.
    # Checked FIRST: whether an export boundary may be honoured depends on it.
    manifest_state, man = None, None
    mp = root / "manifest.json"
    if mp.is_file():
        import hashlib as _hl
        man = json.loads(mp.read_text(encoding="utf-8"))
        if not signed_ok(man):
            err("manifest.json: signature does not verify")
            manifest_state = "bad_signature"
        else:
            manifest_state = "ok"
            listed = man.get("files") or {}
            for name, digest in listed.items():
                f = root / name
                if not f.is_file():
                    err(f"manifest.json: {name} is missing from the bundle")
                    manifest_state = "incomplete"
                elif _hl.sha256(f.read_bytes()).hexdigest() != digest:
                    err(f"manifest.json: {name} does not match its hash")
                    manifest_state = "altered"
            # A file the manifest does not name is not part of the export: a
            # segment or a start record added next to it is rejected.
            for f in sorted(root.glob("events-*.jsonl")) + [root / PRUNED_NAME,
                                                             root / EXPORT_START_NAME]:
                if f.is_file() and f.name not in listed:
                    err(f"manifest.json: {f.name} is not listed in the manifest")
                    manifest_state = "altered"

    hashes: dict[int, str] = {}
    expected_seq, prev = 1, record.GENESIS
    count = 0
    # Where the chain starts. Two records can move it, and they are NOT
    # interchangeable:
    # * pruned.jsonl (#446), schema clodia.audit.pruned/1: retention removed
    #   the events up to `up_to_seq`. Only the LAST record counts.
    # * export_start.json (#447), schema clodia.audit.export_start/1: the
    #   events before `up_to_seq` + 1 are simply not in this export. Honoured
    #   ONLY with a valid signed manifest that names it and states the same
    #   start — otherwise copying an export's boundary into a store would
    #   mask a deletion of the head.
    pruned = None
    pp = root / PRUNED_NAME
    if pp.is_file():
        lines = [x for x in pp.read_text(encoding="utf-8").splitlines() if x.strip()]
        if lines:
            rec = json.loads(lines[-1])
            if rec.get("schema") != PRUNED_SCHEMA:
                err(f"pruned.jsonl: the last record has schema {rec.get('schema')!r}, "
                    f"not a retention record ({PRUNED_SCHEMA})")
            elif not signed_ok(rec):
                err("pruned.jsonl: the last prune record does not verify")
            else:
                pruned = rec
    es = root / EXPORT_START_NAME
    if es.is_file():
        rec = json.loads(es.read_text(encoding="utf-8"))
        stated = (man or {}).get("start") or {}
        if rec.get("schema") != EXPORT_START_SCHEMA or not signed_ok(rec):
            err("export_start.json: not a valid, signed export boundary")
        elif manifest_state != "ok":
            err("export_start.json: an export boundary is only valid inside an "
                "export bundle with a valid signed manifest")
        elif (stated.get("up_to_seq"), stated.get("last_hash")) != (
                rec.get("up_to_seq"), rec.get("last_hash")):
            err("export_start.json: does not match the start stated by the manifest")
        elif pruned is not None:
            err("export_start.json and pruned.jsonl both present: ambiguous start")
        else:
            pruned = rec
    if pruned is not None:
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

    # An export states where its chain ENDS (signed manifest). Checkpoints
    # made after the export's boundary — a later day than `until`, or after
    # the export was built — anchor events that are not in it by design, and
    # prove nothing about it; one made before that boundary and beyond the
    # last event still means the tail was cut.
    end = (man or {}).get("end") if manifest_state == "ok" else None
    boundary = None
    if end:
        if last_seq != int(end.get("seq") or 0) or (count and prev != end.get("hash")):
            err(f"the bundle ends at seq {last_seq}, its manifest says {end.get('seq')}: "
                "the log has been TRUNCATED")
        rng = man.get("range") or {}
        boundary = (f"{rng['until']}T23:59:59.999Z" if rng.get("until")
                    else man.get("created"))
    beyond_export = 0
    cut = []

    def check_cp(cp: dict, origin: str) -> bool:
        nonlocal beyond_export
        if int(cp.get("seq") or 0) < first_seq:
            return True  # anchors a pruned part of the chain: nothing left to compare
        if cp.get("key_id") != kid or not verify_sig(pub, checkpoint.unsigned(cp),
                                                     cp.get("signature") or ""):
            err(f"{origin} checkpoint seq {cp.get('seq')}: signature does not verify")
            return False
        seq = int(cp.get("seq") or 0)
        if seq > last_seq and boundary and str(cp.get("timestamp") or "") > boundary:
            beyond_export += 1
            return True
        if seq > last_seq:
            cut.append(seq)
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
    truncated = bool(cut)
    covered = max([int(cp.get("seq") or 0) for cp in ext
                   if int(cp.get("seq") or 0) <= last_seq] or [0])
    return {
        "ok": not errors,
        "manifest": manifest_state,
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
        "pruned_up_to": (int(pruned["up_to_seq"])
                         if pruned and pruned.get("schema") == PRUNED_SCHEMA else None),
        "export_starts_after": (int(pruned["up_to_seq"])
                                if pruned and pruned.get("schema") == EXPORT_START_SCHEMA
                                else None),
        "checkpoints_beyond_export": beyond_export,
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

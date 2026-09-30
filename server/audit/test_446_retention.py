"""clodia-platform#446 — retention that a verifier can still follow.

Deleting old segments of a hash chain breaks it: the first surviving event
points to a hash nobody holds any more. Retention therefore removes whole
segments only, and writes a signed prune record of where the chain resumes.
These tests hold that a pruned trail verifies, that an unrecorded deletion
still fails, that a forged prune record is rejected, and that evidence is
removed per tier on its own clock.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from .. import audit
from . import evidence, retention, verify


class _Env(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        self.root = base / "audit"
        env = patch.dict(os.environ, {"CLODIA_AUDIT_DIR": str(self.root),
                                      "CLODIA_AUDIT_KEY_DIR": str(base / "k")})
        env.start()
        self.addCleanup(env.stop)
        for k in ("CLODIA_AUDIT_TRAIL_RETENTION_DAYS", "CLODIA_AUDIT_EVIDENCE_RETENTION"):
            os.environ.pop(k, None)

    def old_segment_then_today(self, old: int = 3, new: int = 2) -> None:
        for i in range(old):
            audit.emit("tool.call", identity="explicit", resource=f"old{i}")
        seg = sorted(self.root.glob("events-*.jsonl"))[-1]
        seg.rename(self.root / "events-20250101.jsonl")
        for i in range(new):
            audit.emit("tool.call", identity="explicit", resource=f"new{i}")


class TrailRetentionTests(_Env):
    def test_default_keeps_the_whole_trail(self) -> None:
        self.old_segment_then_today()
        res = retention.apply()
        self.assertEqual(res["trail"]["segments"], 0)
        self.assertTrue((self.root / "events-20250101.jsonl").exists())

    def test_a_pruned_trail_still_verifies_from_the_signed_record(self) -> None:
        self.old_segment_then_today()
        os.environ["CLODIA_AUDIT_TRAIL_RETENTION_DAYS"] = "30"
        res = retention.apply()
        self.assertEqual(res["trail"], {"segments": 1, "up_to_seq": 3})
        self.assertFalse((self.root / "events-20250101.jsonl").exists())
        rep = verify.verify(self.root)
        self.assertTrue(rep["ok"], rep["errors"])
        self.assertEqual(rep["pruned_up_to"], 3)
        # the retention run itself is on the trail
        self.assertEqual(rep["events"], 3)  # 2 new + control.retention

    def test_deleting_the_head_without_a_record_still_fails(self) -> None:
        self.old_segment_then_today()
        (self.root / "events-20250101.jsonl").unlink()
        self.assertFalse(verify.verify(self.root)["ok"])

    def test_a_forged_prune_record_is_rejected(self) -> None:
        self.old_segment_then_today()
        (self.root / "events-20250101.jsonl").unlink()
        forged = {"schema": "clodia.audit.pruned/1", "up_to_seq": 3, "last_hash": "0" * 64,
                  "key_id": audit.store().signer.key_id, "signature": "AAAA"}
        (self.root / "pruned.jsonl").write_text(json.dumps(forged) + "\n")
        rep = verify.verify(self.root)
        self.assertFalse(rep["ok"])
        self.assertTrue(any("prune record" in e for e in rep["errors"]))

    def test_the_newest_segment_is_never_pruned(self) -> None:
        audit.emit("tool.call", identity="explicit")
        os.environ["CLODIA_AUDIT_TRAIL_RETENTION_DAYS"] = "1"
        far = datetime(2100, 1, 1, tzinfo=timezone.utc)
        self.assertEqual(retention.apply(now=far)["trail"]["segments"], 0)


class EvidenceRetentionTests(_Env):
    def test_each_tier_on_its_own_clock(self) -> None:
        h1 = evidence.keep(b"public", "SEAL-0")
        h2 = evidence.keep(b"confidential", "SEAL-2")
        old = time.time() - 40 * 86400
        for p in evidence.root().rglob("*"):
            if p.is_file():
                os.utime(p, (old, old))
        os.environ["CLODIA_AUDIT_EVIDENCE_RETENTION"] = "SEAL-0=30,SEAL-2=0"
        res = retention.apply()
        self.assertEqual(res["evidence"], {"SEAL-0": 1})
        with self.assertRaises(FileNotFoundError):
            evidence.fetch(h1, "SEAL-0", "SEAL-4")
        self.assertEqual(evidence.fetch(h2, "SEAL-2", "SEAL-4"), b"confidential")


    def test_evidence_kept_again_is_not_pruned_as_old(self) -> None:
        # First seen long ago, referenced again today: still evidence.
        h = evidence.keep(b"still referenced", "SEAL-1")
        old = time.time() - 400 * 86400
        for p in evidence.root().rglob("*"):
            if p.is_file():
                os.utime(p, (old, old))
        self.assertEqual(evidence.keep(b"still referenced", "SEAL-1"), h)
        res = retention.apply()
        self.assertEqual(res["evidence"], {})
        self.assertEqual(evidence.fetch(h, "SEAL-1", "SEAL-4"), b"still referenced")


class LoopTests(unittest.TestCase):
    def test_the_first_pass_runs_shortly_after_startup(self) -> None:
        import asyncio
        slept: list[float] = []

        async def fake_sleep(s):
            slept.append(s)
            if len(slept) >= 2:
                raise asyncio.CancelledError

        async def go():
            with patch("asyncio.sleep", fake_sleep), \
                    patch.object(retention, "apply", lambda: None):
                try:
                    await retention.retention_loop()
                except asyncio.CancelledError:
                    pass
        asyncio.run(go())
        self.assertEqual(slept, [retention.FIRST_PASS_DELAY, 86400])
        self.assertLess(retention.FIRST_PASS_DELAY, 3600)


if __name__ == "__main__":
    unittest.main()

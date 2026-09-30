"""clodia-platform#447 — a signed export that verifies offline, from itself.

The bundle carries the whole segments of the range, the public key, the
checkpoints, a signed record of where its chain starts, a signed manifest of
every file, and the verifier's own source. These tests unpack it into an empty
directory and verify it with the bundled verifier in a fresh interpreter: no
repository, no gateway.
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.testclient import TestClient

from .. import audit, audit_api
from . import export


class ExportTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.root = self.base / "audit"
        env = patch.dict(os.environ, {"CLODIA_AUDIT_DIR": str(self.root),
                                      "CLODIA_AUDIT_KEY_DIR": str(self.base / "k"),
                                      "CLODIA_ORCHESTRATOR_SECRET": "s"})
        env.start()
        self.addCleanup(env.stop)
        for i in range(3):
            audit.emit("tool.call", identity="explicit", resource=f"old{i}")
        seg = sorted(self.root.glob("events-*.jsonl"))[-1]
        seg.rename(self.root / "events-20260901.jsonl")
        for i in range(2):
            audit.emit("tool.call", identity="explicit", resource=f"new{i}")
        audit.checkpoint_now()

    def unpack(self, blob: bytes) -> Path:
        out = self.base / "unpacked"
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
            tar.extractall(out, filter="data")
        return out / "bundle"

    def run_verifier(self, bundle: Path, *extra: str) -> tuple[int, dict]:
        # A fresh interpreter, cwd = the bundle: only the bundled verifier is importable.
        p = subprocess.run([sys.executable, "-m", "verifier.verify", ".", *extra], cwd=bundle,
                           capture_output=True, text=True, env={"PATH": os.environ.get("PATH", "")})
        return p.returncode, json.loads(p.stdout or "{}")

    def test_a_full_export_verifies_offline_with_the_bundled_verifier(self) -> None:
        bundle = self.unpack(export.build(audit.store(), reader="auditor"))
        rc, rep = self.run_verifier(bundle)
        self.assertEqual(rc, 0, rep)
        self.assertEqual(rep["manifest"], "ok")
        # The five events emitted in setUp; the export event is written after
        # the bundle is built, so it is not in it.
        self.assertEqual(rep["events"], 5)
        self.assertFalse(rep["truncated"])

    def test_a_range_export_starts_its_chain_from_a_signed_record(self) -> None:
        bundle = self.unpack(export.build(audit.store(), reader="auditor",
                                          since=date(2026, 9, 2)))
        self.assertNotIn("events-20260901.jsonl", [p.name for p in bundle.iterdir()])
        rc, rep = self.run_verifier(bundle)
        self.assertEqual(rc, 0, rep)
        self.assertEqual(rep["export_starts_after"], 3)
        self.assertIsNone(rep["pruned_up_to"])
        self.assertIn("export_start.json", [p.name for p in bundle.iterdir()])
        self.assertNotIn("pruned.jsonl", [p.name for p in bundle.iterdir()])

    def test_an_altered_bundle_fails(self) -> None:
        bundle = self.unpack(export.build(audit.store(), reader="auditor"))
        seg = sorted(bundle.glob("events-*.jsonl"))[-1]
        lines = seg.read_text().splitlines()
        rec = json.loads(lines[0])
        rec["event"]["resource"] = "edited"
        lines[0] = json.dumps(rec)
        seg.write_text("\n".join(lines) + "\n")
        rc, rep = self.run_verifier(bundle)
        self.assertEqual(rc, 1)
        self.assertEqual(rep["manifest"], "altered")

    def worm(self) -> Path:
        """The store's checkpoints as an off-system (WORM) directory."""
        d = self.base / "worm"
        d.mkdir(exist_ok=True)
        for line in (self.root / "checkpoints.jsonl").read_text().splitlines():
            cp = json.loads(line)["checkpoint"]
            (d / f"checkpoint-{cp['seq']:012d}.json").write_text(json.dumps(cp))
        return d

    def test_checkpoints_after_until_are_not_in_the_bundle_and_do_not_read_as_a_cut(self) -> None:
        # 20260901: seq 1-3; 20260902: seq 4-7 (checkpoint at 5); today: seq 8
        # with a checkpoint at 8, outside the range.
        for i in range(2):
            audit.emit("tool.call", identity="explicit", resource=f"mid{i}")
        seg = sorted(self.root.glob("events-*.jsonl"))[-1]
        seg.rename(self.root / "events-20260902.jsonl")
        audit.emit("tool.call", identity="explicit", resource="today")
        audit.checkpoint_now()
        bundle = self.unpack(export.build(audit.store(), reader="auditor",
                                          until=date(2026, 9, 2)))
        seqs = [json.loads(x)["checkpoint"]["seq"]
                for x in (bundle / "checkpoints.jsonl").read_text().splitlines()]
        self.assertEqual(seqs, [5])
        rc, rep = self.run_verifier(bundle)
        self.assertEqual(rc, 0, rep)
        self.assertFalse(rep["truncated"])
        rc, rep = self.run_verifier(bundle, "--checkpoints", str(self.worm()))
        self.assertEqual(rc, 0, rep)
        self.assertEqual(rep["checkpoints_beyond_export"], 1)
        self.assertEqual(rep["checkpoints"]["exported_ok"], 2)

    def test_a_tail_cut_before_the_export_is_still_caught_by_worm_checkpoints(self) -> None:
        # checkpoint at seq 5, then the last event is cut, then the export.
        seg = sorted(self.root.glob("events-*.jsonl"))[-1]
        lines = seg.read_text().splitlines()
        seg.write_text("\n".join(lines[:-1]) + "\n")
        worm = self.worm()
        (self.root / "checkpoints.jsonl").unlink()
        bundle = self.unpack(export.build(audit.store(), reader="auditor"))
        rc, rep = self.run_verifier(bundle, "--checkpoints", str(worm))
        self.assertEqual(rc, 1, rep)
        self.assertTrue(rep["truncated"])

    def test_an_export_boundary_cannot_mask_a_deleted_head(self) -> None:
        # The attack: take a range export (it starts at seq 4 with a signed
        # boundary), delete the head of the LIVE store without a retention
        # record, and paste the export's boundary next to it.
        from . import verify
        bundle = self.unpack(export.build(audit.store(), reader="auditor",
                                          since=date(2026, 9, 2)))
        (self.root / "events-20260901.jsonl").unlink()
        start = (bundle / "export_start.json").read_text()
        # (a) pasted as the store's retention record
        (self.root / "pruned.jsonl").write_text(start)
        rep = verify.verify(self.root)
        self.assertFalse(rep["ok"])
        self.assertTrue(any("not a retention record" in e for e in rep["errors"]), rep)
        (self.root / "pruned.jsonl").unlink()
        # (b) pasted as an export boundary, without a manifest
        (self.root / "export_start.json").write_text(start)
        rep = verify.verify(self.root)
        self.assertFalse(rep["ok"])
        self.assertTrue(any("only valid inside an export bundle" in e for e in rep["errors"]),
                        rep)
        # (c) with the export's signed manifest too: it does not describe this store
        (self.root / "manifest.json").write_text((bundle / "manifest.json").read_text())
        rep = verify.verify(self.root)
        self.assertFalse(rep["ok"])
        # and the unmodified store without the head fails as before
        for n in ("export_start.json", "manifest.json"):
            (self.root / n).unlink()
        self.assertFalse(verify.verify(self.root)["ok"])

    def test_an_export_of_a_pruned_store_carries_the_retention_record(self) -> None:
        from . import retention
        with patch.dict(os.environ, {"CLODIA_AUDIT_TRAIL_RETENTION_DAYS": "1"}):
            retention.apply()
        bundle = self.unpack(export.build(audit.store(), reader="auditor"))
        self.assertNotIn("export_start.json", [p.name for p in bundle.iterdir()])
        rc, rep = self.run_verifier(bundle)
        self.assertEqual(rc, 0, rep)
        self.assertEqual(rep["pruned_up_to"], 3)

    def test_the_export_is_itself_recorded(self) -> None:
        c = TestClient(Starlette(routes=audit_api.routes))
        self.assertEqual(c.post("/internal/audit/export", json={"reader": "x"}).status_code, 401)
        r = c.post("/internal/audit/export", headers={"x-orchestrator-secret": "s"},
                   json={"reader": "auditor", "purpose": "ISO 27001 surveillance audit"})
        self.assertEqual(r.status_code, 200)
        last = sorted(self.root.glob("events-*.jsonl"))[-1].read_text().splitlines()[-1]
        ev = json.loads(last)
        self.assertEqual((ev["event"]["type"], ev["actor"]["id"]), ("audit.export", "auditor"))
        self.assertNotIn("surveillance", last)


if __name__ == "__main__":
    unittest.main()

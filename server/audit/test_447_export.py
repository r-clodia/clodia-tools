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

    def run_verifier(self, bundle: Path) -> tuple[int, dict]:
        # A fresh interpreter, cwd = the bundle: only the bundled verifier is importable.
        p = subprocess.run([sys.executable, "-m", "verifier.verify", "."], cwd=bundle,
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
        self.assertEqual(rep["pruned_up_to"], 3)

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

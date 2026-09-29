"""clodia-platform#431 — append-only, hash-chained, signed store with checkpoints.

What these tests hold the store to (#425 §1.6):
  * a chain of signed events verifies offline from the directory alone;
  * altering, deleting or reordering an event is detected, and so is a
    re-signature with another key;
  * cutting the TAIL is detected by a checkpoint exported off-system — the one
    thing a chain alone cannot prove;
  * content cannot enter the trail by accident;
  * a failed write is never silent, and fails closed when asked to;
  * the signing key lives in the gateway state dir, not in the secrets dir.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.testclient import TestClient

from .. import audit, audit_api
from . import checkpoint, record, sigv4, verify


class _Env(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.data, self.state, self.export = base / "data", base / "state", base / "worm"
        for d in (self.data, self.state):
            d.mkdir()
        self._env = patch.dict(os.environ, {
            "CLODIA_DATA": str(self.data), "CLODIA_TOOLS_STATE_DIR": str(self.state),
            "CLODIA_VAULT_DIR": str(base / "vault"),
        }, clear=False)
        self._env.start()
        for k in ("CLODIA_AUDIT_DIR", "CLODIA_AUDIT_KEY_DIR", "CLODIA_AUDIT_EXPORT_DIR",
                  "CLODIA_AUDIT_FAIL_CLOSED"):
            os.environ.pop(k, None)
        audit._failures, audit._last_error = 0, None
        self.root = self.state / "audit"

    def tearDown(self) -> None:
        self._env.stop()
        self._tmp.cleanup()

    def emit(self, n: int = 3) -> list[dict]:
        return [audit.emit("tool.call", action="execute", resource=f"topic.put#{i}",
                           scope={"topic": "t", "tier": "SEAL-2"},
                           tool={"name": "topic.put",
                                 "parameters_hash": audit.content_hash(f"x{i}")})
                for i in range(n)]

    def lines(self) -> list[str]:
        seg = sorted(self.root.glob("events-*.jsonl"))[-1]
        return seg.read_text(encoding="utf-8").splitlines()

    def rewrite(self, lines: list[str]) -> None:
        seg = sorted(self.root.glob("events-*.jsonl"))[-1]
        seg.write_text("\n".join(lines) + "\n", encoding="utf-8")


class ChainTests(_Env):
    def test_events_chain_and_verify_offline(self) -> None:
        evs = self.emit(3)
        self.assertEqual([e["integrity"]["seq"] for e in evs], [1, 2, 3])
        self.assertEqual(evs[0]["integrity"]["previous_hash"], record.GENESIS)
        self.assertEqual(evs[1]["integrity"]["previous_hash"], evs[0]["integrity"]["hash"])
        rep = verify.verify(self.root)
        self.assertTrue(rep["ok"], rep["errors"])
        self.assertEqual(rep["events"], 3)

    def test_altered_event_is_detected(self) -> None:
        self.emit(3)
        ls = self.lines()
        rec = json.loads(ls[1])
        rec["event"]["resource"] = "something-else"
        ls[1] = json.dumps(rec)
        self.rewrite(ls)
        rep = verify.verify(self.root)
        self.assertFalse(rep["ok"])
        self.assertTrue(any("hash mismatch" in e for e in rep["errors"]))

    def test_deleted_middle_event_is_detected(self) -> None:
        self.emit(4)
        ls = self.lines()
        del ls[1]
        self.rewrite(ls)
        rep = verify.verify(self.root)
        self.assertFalse(rep["ok"])
        self.assertTrue(any("expected 2" in e for e in rep["errors"]))

    def test_reordered_events_are_detected(self) -> None:
        self.emit(3)
        ls = self.lines()
        ls[0], ls[1] = ls[1], ls[0]
        self.rewrite(ls)
        self.assertFalse(verify.verify(self.root)["ok"])

    def test_resigning_with_another_key_is_detected(self) -> None:
        self.emit(2)
        from .keys import Signer
        other = Signer(Path(self._tmp.name) / "evil-key", Path(self._tmp.name) / "evil-pub")
        ls = self.lines()
        rec = json.loads(ls[1])
        rec["event"]["resource"] = "forged"
        rec["integrity"]["key_id"] = other.key_id
        rec["integrity"]["hash"] = record.event_hash(rec)
        rec["integrity"]["signature"] = other.sign(bytes.fromhex(rec["integrity"]["hash"]))
        ls[1] = json.dumps(rec)
        self.rewrite(ls)
        rep = verify.verify(self.root)
        self.assertFalse(rep["ok"])
        self.assertTrue(any("signed by key" in e for e in rep["errors"]))

    def test_concurrent_emits_do_not_fork_the_chain(self) -> None:
        threads = [threading.Thread(target=self.emit, args=(5,)) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        rep = verify.verify(self.root)
        self.assertTrue(rep["ok"], rep["errors"])
        self.assertEqual(rep["events"], 40)


class CheckpointTests(_Env):
    def test_cut_tail_is_detected_by_an_exported_checkpoint(self) -> None:
        os.environ["CLODIA_AUDIT_EXPORT_DIR"] = str(self.export)
        self.emit(5)
        res = audit.checkpoint_now()
        self.assertEqual(res["checkpoint"]["seq"], 5)
        self.assertTrue(res["exports"][0]["ok"])
        # A chain alone does not see a cut tail …
        ls = self.lines()
        self.rewrite(ls[:3])
        cp_local = checkpoint.local_path(self.root)
        cp_local.unlink()  # … and the attacker removes the local checkpoints too.
        self.assertTrue(verify.verify(self.root)["ok"])
        # … the exported checkpoint does.
        rep = verify.verify(self.root, external=verify._load_external(self.export))
        self.assertFalse(rep["ok"])
        self.assertTrue(rep["truncated"])

    def test_checkpoint_only_when_there_is_something_new(self) -> None:
        self.assertIsNone(audit.checkpoint_now())
        self.emit(1)
        self.assertIsNotNone(audit.checkpoint_now())
        self.assertIsNone(audit.checkpoint_now())

    def test_exported_checkpoint_is_never_rewritten(self) -> None:
        self.emit(1)
        cp = checkpoint.make(1, "a" * 64, audit.store().signer, "x")
        ex = checkpoint.DirExporter(self.export)
        ex.export(cp)
        with self.assertRaises(FileExistsError):
            ex.export(cp)

    def test_status_says_when_no_off_system_copy_exists(self) -> None:
        self.emit(2)
        audit.checkpoint_now()
        s = audit.status()
        self.assertEqual(s["events"], 2)
        self.assertEqual(s["exporters"], [])
        self.assertFalse(s["off_system"])
        self.assertTrue(s["isolated"])


class ContentAndFailureTests(_Env):
    def test_content_cannot_enter_the_trail(self) -> None:
        for bad in ({"input": {"text": "hello"}}, {"tool": {"arguments": {"to": "x"}}},
                    {"result": {"nested": [{"content": "x"}]}}):
            with self.assertRaises(audit.RecordError):
                audit.emit("tool.call", **bad)
        with self.assertRaises(audit.RecordError):
            audit.emit("notatype")
        self.assertFalse(self.root.exists() and list(self.root.glob("events-*")))

    def test_failed_write_is_loud_not_silent(self) -> None:
        with patch.object(audit.store(), "append", side_effect=OSError("disk full")):
            self.assertIsNone(audit.emit("tool.call"))
        s = audit.status()
        self.assertFalse(s["ok"])
        self.assertEqual(s["failures"], 1)
        self.assertIn("disk full", s["last_error"])

    def test_failed_write_raises_when_fail_closed(self) -> None:
        os.environ["CLODIA_AUDIT_FAIL_CLOSED"] = "1"
        with patch.object(audit.store(), "append", side_effect=OSError("disk full")):
            with self.assertRaises(audit.AuditWriteError):
                audit.emit("tool.call")

    def test_signing_key_is_in_the_gateway_state_dir(self) -> None:
        self.emit(1)
        key = audit.store().signer.key_path
        self.assertTrue(str(key).startswith(str(self.state)))
        self.assertFalse(str(key).startswith(str(self.data)))
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertTrue((self.root / "audit.pub.pem").is_file())

    def test_verifier_cli_exit_codes(self) -> None:
        self.emit(2)
        with patch("sys.stdout"):
            self.assertEqual(verify.main([str(self.root)]), 0)
        ls = self.lines()
        self.rewrite(ls[1:])
        with patch("sys.stdout"):
            self.assertEqual(verify.main([str(self.root)]), 1)


class SigV4Tests(unittest.TestCase):
    def test_aws_documented_example(self) -> None:
        # The worked example of the AWS SigV4 documentation (IAM ListUsers).
        out = sigv4.sign(
            "GET", "iam.amazonaws.com", "/",
            {"Action": "ListUsers", "Version": "2010-05-08"},
            {"content-type": "application/x-www-form-urlencoded; charset=utf-8"}, b"",
            access_key="AKIDEXAMPLE", secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            region="us-east-1", service="iam", amz_date="20150830T123600Z")
        self.assertIn("Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7",
                      out["Authorization"])
        self.assertIn("SignedHeaders=content-type;host;x-amz-date", out["Authorization"])

    def test_s3_export_request_locks_the_object_and_hides_credentials(self) -> None:
        ex = checkpoint.S3Exporter({"endpoint": "https://s3.eu-west-1.amazonaws.com",
                                    "bucket": "b", "region": "eu-west-1",
                                    "access_key_id": "AKID", "secret_access_key": "SECRET"})
        cp = {"schema": checkpoint.SCHEMA, "seq": 7, "hash": "ab" * 32, "signature": "s"}
        url, headers, _body = ex.request(cp, now=datetime(2026, 9, 29, tzinfo=timezone.utc))
        self.assertTrue(url.startswith("https://s3.eu-west-1.amazonaws.com/b/audit-checkpoints/"))
        self.assertEqual(headers["x-amz-object-lock-mode"], "COMPLIANCE")
        self.assertEqual(headers["x-amz-object-lock-retain-until-date"], "2027-11-03T00:00:00Z")
        self.assertEqual(headers["if-none-match"], "*")
        self.assertIn("content-md5", headers)
        self.assertNotIn("SECRET", json.dumps(ex.describe()))


class ApiTests(_Env):
    def _client(self) -> TestClient:
        return TestClient(Starlette(routes=audit_api.routes))

    def test_requires_the_orchestrator_secret(self) -> None:
        with patch.dict(os.environ, {"CLODIA_ORCHESTRATOR_SECRET": "s3cr3t"}):
            c = self._client()
            self.assertEqual(c.get("/internal/audit/status").status_code, 401)
            self.assertEqual(c.post("/internal/audit/checkpoint").status_code, 401)
            r = c.get("/internal/audit/status", headers={"x-orchestrator-secret": "s3cr3t"})
            self.assertEqual(r.status_code, 200)
            self.assertIn("events", r.json())

    def test_fail_closed_without_a_configured_secret(self) -> None:
        os.environ.pop("CLODIA_ORCHESTRATOR_SECRET", None)
        r = self._client().get("/internal/audit/status", headers={"x-orchestrator-secret": ""})
        self.assertEqual(r.status_code, 401)


if __name__ == "__main__":
    unittest.main()

"""clodia-platform#445 — the content behind the trail's hashes.

Every hash the trail records for content resolves, in the evidence store, to
the exact bytes it was computed on — for a reader cleared for the tier, and to
nothing for others. At rest the evidence is encrypted, filed per tier.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from mcp.types import TextContent
from starlette.applications import Starlette
from starlette.testclient import TestClient

from .. import audit, audit_api, main
from ..claims import ClaimsContext
from . import evidence

TOKEN = {"agent": "clodia", "execution_id": "clodia-320", "principal": "davide",
         "chat": "chan:SEAL-2:titulon-tech:clodia"}


class _Env(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        self.root = base / "audit"
        env = patch.dict(os.environ, {"CLODIA_AUDIT_DIR": str(self.root),
                                      "CLODIA_AUDIT_KEY_DIR": str(base / "k"),
                                      "CLODIA_DATA": str(base / "data"),
                                      "CLODIA_ORCHESTRATOR_SECRET": "s"})
        env.start()
        self.addCleanup(env.stop)
        for k in ("CLODIA_AUDIT_EVIDENCE", "CLODIA_AUDIT_EVIDENCE_DIR",
                  "CLODIA_AUDIT_EVIDENCE_MAX_BYTES"):
            os.environ.pop(k, None)

    def events(self, t: str) -> list[dict]:
        out = []
        for seg in sorted(self.root.glob("events-*.jsonl")):
            out += [json.loads(x) for x in seg.read_text().splitlines() if x.strip()]
        return [e for e in out if e["event"]["type"] == t]


class StoreTests(_Env):
    def test_keep_returns_the_trail_hash_and_encrypts_at_rest(self) -> None:
        h = evidence.keep(b"mario.rossi@example.com", "SEAL-2")
        self.assertEqual(h, audit.content_hash(b"mario.rossi@example.com"))
        files = [p for p in evidence.root().rglob("*") if p.is_file()]
        self.assertEqual(len(files), 1)
        self.assertIn("SEAL-2", str(files[0]))
        self.assertNotIn(b"mario.rossi", files[0].read_bytes())
        self.assertEqual(evidence.fetch(h, "SEAL-2", "SEAL-3"), b"mario.rossi@example.com")

    def test_a_reader_without_clearance_gets_nothing(self) -> None:
        h = evidence.keep(b"x", "SEAL-3")
        with self.assertRaises(evidence.EvidenceDenied):
            evidence.fetch(h, "SEAL-3", "SEAL-1")
        with self.assertRaises(evidence.EvidenceDenied):
            evidence.fetch("sha256:" + "0" * 64, "SEAL-3", "SEAL-1")  # existence not revealed

    def test_a_tampered_object_does_not_decrypt(self) -> None:
        h = evidence.keep(b"payload", "SEAL-2")
        p = next(p for p in evidence.root().rglob("*") if p.is_file())
        blob = bytearray(p.read_bytes())
        blob[-1] ^= 1
        p.write_bytes(bytes(blob))
        with self.assertRaises(Exception):
            evidence.fetch(h, "SEAL-2", "SEAL-4")

    def test_too_large_keeps_the_hash_not_a_truncated_copy(self) -> None:
        os.environ["CLODIA_AUDIT_EVIDENCE_MAX_BYTES"] = "4"
        h = evidence.keep(b"123456789", "SEAL-1")
        self.assertEqual(h, audit.content_hash(b"123456789"))
        with self.assertRaises(FileNotFoundError):
            evidence.fetch(h, "SEAL-1", "SEAL-4")

    def test_off_keeps_nothing(self) -> None:
        os.environ["CLODIA_AUDIT_EVIDENCE"] = "off"
        evidence.keep(b"x", "SEAL-1")
        self.assertFalse(evidence.root().exists())


class TrailToEvidenceTests(_Env):
    def test_every_content_hash_of_a_call_resolves_in_the_evidence_store(self) -> None:
        args = {"to": "mario.rossi@example.com", "body": "offerta riservata"}

        async def inner(name, arguments):
            return [TextContent(type="text", text='{"sent": true}')]

        async def go():
            with ClaimsContext(TOKEN, "t"), patch.object(main, "_call_tool_unaudited", inner):
                return await main.call_tool("email.send", args)
        asyncio.run(go())
        call = self.events("tool.call")[0]
        res = self.events("tool.result")[0]
        raw_args = evidence.fetch(call["tool"]["parameters_hash"], "SEAL-2", "SEAL-2")
        self.assertEqual(json.loads(raw_args), args)
        self.assertEqual(evidence.fetch(res["result"]["output_hash"], "SEAL-2", "SEAL-2"),
                         b'{"sent": true}')


class ApiTests(_Env):
    def test_reading_evidence_is_itself_an_event(self) -> None:
        h = evidence.keep(b"secret", "SEAL-2")
        c = TestClient(Starlette(routes=audit_api.routes))
        hdr = {"x-orchestrator-secret": "s"}
        ok = c.get("/internal/audit/evidence", headers=hdr,
                   params={"hash": h, "tier": "SEAL-2", "reader": "auditor", "clearance": "SEAL-2"})
        self.assertEqual(ok.content, b"secret")
        no = c.get("/internal/audit/evidence", headers=hdr,
                   params={"hash": h, "tier": "SEAL-2", "reader": "intern", "clearance": "SEAL-1"})
        self.assertEqual(no.status_code, 403)
        reads = self.events("audit.evidence_read")
        self.assertEqual([(e["actor"]["id"], e["event"]["action"]) for e in reads],
                         [("auditor", "served"), ("intern", "denied")])
        self.assertEqual(c.get("/internal/audit/evidence").status_code, 401)


if __name__ == "__main__":
    unittest.main()

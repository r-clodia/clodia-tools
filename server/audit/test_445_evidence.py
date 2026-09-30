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


    def _call(self, chat_tier: str, arguments: dict) -> dict:
        tok = {**TOKEN, "chat": f"chan:{chat_tier}:ch:clodia"}

        async def inner(name, arguments):
            return [TextContent(type="text", text='{"text": "riservato"}')]

        async def go():
            with ClaimsContext(tok, "t"), patch.object(main, "_call_tool_unaudited", inner):
                return await main.call_tool("topic.read_file", arguments)
        asyncio.run(go())
        return self.events("tool.result")[-1]

    def test_a_crosstopic_read_is_filed_under_the_resource_tier(self) -> None:
        # A SEAL-3 topic read from a SEAL-1 channel is SEAL-3 evidence.
        res = self._call("SEAL-1", {"tier": "SEAL-3", "name": "vault", "path": "files/x"})
        h = res["result"]["output_hash"]
        self.assertEqual(evidence.fetch(h, "SEAL-3", "SEAL-3"), b'{"text": "riservato"}')
        with self.assertRaises(FileNotFoundError):
            evidence.fetch(h, "SEAL-1", "SEAL-4")
        with self.assertRaises(evidence.EvidenceDenied):
            evidence.fetch(h, "SEAL-3", "SEAL-1")

    def test_an_argument_cannot_lower_the_channel_tier(self) -> None:
        res = self._call("SEAL-3", {"tier": "SEAL-0", "name": "pub", "path": "files/x"})
        h = res["result"]["output_hash"]
        self.assertEqual(evidence.fetch(h, "SEAL-3", "SEAL-3"), b'{"text": "riservato"}')
        with self.assertRaises(FileNotFoundError):
            evidence.fetch(h, "SEAL-0", "SEAL-4")


class ClearanceTests(_Env):
    def test_an_unknown_or_empty_clearance_reads_nothing(self) -> None:
        h = evidence.keep(b"public", "SEAL-0")
        for bad in ("", None, "SEAL-9", "admin", "top-secret"):
            with self.assertRaises(evidence.EvidenceDenied, msg=repr(bad)):
                evidence.fetch(h, "SEAL-0", bad)
        self.assertEqual(evidence.fetch(h, "SEAL-0", "P0"), b"public")

    def test_an_unknown_tier_is_still_filed_as_the_most_restrictive(self) -> None:
        h = evidence.keep(b"x", "weird")
        with self.assertRaises(evidence.EvidenceDenied):
            evidence.fetch(h, "weird", "SEAL-3")
        self.assertEqual(evidence.fetch(h, "weird", "SEAL-4"), b"x")


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


    def test_clearance_is_required_and_must_be_a_tier(self) -> None:
        h = evidence.keep(b"secret", "SEAL-0")
        c = TestClient(Starlette(routes=audit_api.routes))
        hdr = {"x-orchestrator-secret": "s"}
        base = {"hash": h, "tier": "SEAL-0", "reader": "r"}
        self.assertEqual(c.get("/internal/audit/evidence", headers=hdr,
                               params=base).status_code, 400)
        self.assertEqual(c.get("/internal/audit/evidence", headers=hdr,
                               params={**base, "clearance": "root"}).status_code, 400)

    def test_a_hash_that_is_not_hex_is_a_404(self) -> None:
        c = TestClient(Starlette(routes=audit_api.routes))
        hdr = {"x-orchestrator-secret": "s"}
        for bad in ("sha256:../../audit-key/evidence.key", "sha256:zz", "nothex"):
            r = c.get("/internal/audit/evidence", headers=hdr,
                      params={"hash": bad, "tier": "SEAL-0", "reader": "r",
                              "clearance": "SEAL-4"})
            self.assertEqual(r.status_code, 404, bad)


if __name__ == "__main__":
    unittest.main()

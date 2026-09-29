"""clodia-platform#433 and #450.

#450 — the gateway's signer dropped `origin` and `scope_tier`, so in
gateway-minting mode (production) the signed token carried neither.
#433 — every gateway event of a spawn's turn carries the turn's W3C trace id,
announced by the agent-server; the agent-server can deposit its own events,
marked as its word, but cannot forge the gateway's evidence.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp.types import TextContent
from starlette.applications import Starlette
from starlette.testclient import TestClient

from . import audit_api, main, mint_api, pki_mint
from .audit import trace
from .claims import ClaimsContext

TRACE, SPAN = "4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7"
SPAWN_TOKEN = {"agent": "clodia", "execution_id": "clodia-320",
               "chat": "chan:SEAL-2:titulon-tech:clodia"}


def _payload(token: str) -> dict:
    body = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))


class MintForwardsEveryClaimTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        kd = Path(tmp.name) / "agents" / "clodia"
        kd.mkdir(parents=True)
        (kd / "identity.key").write_bytes(Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        env = patch.dict(os.environ, {"CLODIA_SECRETS_DIR": tmp.name,
                                      "CLODIA_ORCHESTRATOR_SECRET": "s"})
        env.start()
        self.addCleanup(env.stop)

    def test_origin_and_scope_tier_are_signed_by_the_gateway(self) -> None:
        c = TestClient(Starlette(routes=mint_api.routes))
        r = c.post("/internal/mint", headers={"x-orchestrator-secret": "s"},
                   json={"kind": "session", "agent": "clodia", "execution_id": "clodia-7",
                         "origin": ["davide", "clodia"], "scope_tier": "SEAL-2"})
        self.assertEqual(r.status_code, 200, r.text)
        p = _payload(r.json()["token"])
        self.assertEqual(p["origin"], ["davide", "clodia"])
        self.assertEqual(p["scope_tier"], "SEAL-2")

    def test_every_claim_the_local_signer_knows_the_gateway_signs(self) -> None:
        import inspect
        gw = set(inspect.signature(pki_mint.mint_session_token).parameters)
        for claim in ("origin", "scope_tier", "unattended", "chat", "clearance", "principal"):
            self.assertIn(claim, gw)


class _AuditEnv(unittest.TestCase):
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
        trace._by_spawn.clear()
        self.c = TestClient(Starlette(routes=audit_api.routes))
        self.h = {"x-orchestrator-secret": "s"}

    def events(self) -> list[dict]:
        out = []
        for seg in sorted(self.root.glob("events-*.jsonl")):
            out += [json.loads(x) for x in seg.read_text().splitlines() if x.strip()]
        return out

    def call(self):
        async def inner(name, arguments):
            return [TextContent(type="text", text="ok")]

        async def go():
            with ClaimsContext(SPAWN_TOKEN, "t"), patch.object(main, "_call_tool_unaudited", inner):
                return await main.call_tool("topic.open", {})
        asyncio.run(go())


class TurnTraceTests(_AuditEnv):
    def test_calls_inside_an_announced_turn_carry_its_trace(self) -> None:
        r = self.c.post("/internal/audit/event", headers=self.h, json={
            "type": "turn.start", "action": "start", "resource": "chan:SEAL-2:titulon-tech:clodia",
            "trace_id": TRACE, "span_id": SPAN,
            "agent": {"seed": "clodia", "spawn": "clodia-320"}})
        self.assertEqual(r.status_code, 200, r.text)
        self.call()
        self.c.post("/internal/audit/event", headers=self.h, json={
            "type": "turn.end", "action": "end", "trace_id": TRACE,
            "agent": {"seed": "clodia", "spawn": "clodia-320"}})
        self.call()
        evs = self.events()
        types = [(e["event"]["type"], e.get("trace_id")) for e in evs]
        self.assertEqual(types[:4], [("turn.start", TRACE), ("tool.call", TRACE),
                                     ("tool.result", TRACE), ("turn.end", TRACE)])
        self.assertEqual(evs[1]["parent_span_id"], SPAN)          # the call hangs under the turn
        self.assertEqual(evs[2]["parent_span_id"], evs[1]["event_id"])
        self.assertEqual([e.get("trace_id") for e in evs[4:]], [None, None])  # after the end
        self.assertEqual(evs[0]["actor"]["source"], "agent-server")

    def test_another_spawn_is_not_in_the_trace(self) -> None:
        trace.start("clodia-999", TRACE, SPAN)
        self.call()
        self.assertTrue(all(e.get("trace_id") is None for e in self.events()))

    def test_the_agent_server_cannot_forge_gateway_evidence(self) -> None:
        for t in ("tool.call", "policy.decision", "gate.decision", "flow.egress", "audit.start"):
            r = self.c.post("/internal/audit/event", headers=self.h, json={"type": t})
            self.assertEqual(r.status_code, 403, t)
        self.assertEqual(self.c.post("/internal/audit/event",
                                     json={"type": "turn.start"}).status_code, 401)

    def test_a_malformed_trace_is_refused(self) -> None:
        r = self.c.post("/internal/audit/event", headers=self.h, json={
            "type": "turn.start", "trace_id": "0" * 32, "span_id": SPAN,
            "agent": {"spawn": "clodia-320"}})
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()

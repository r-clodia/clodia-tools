"""clodia-platform#432 — the gate lifecycle leaves a history.

Before: `gate.py` kept current state only. `consume()` and `revoke_instance()`
deleted the consent, a decided request left the queue, and nothing showed,
after the fact, who had approved what. These tests hold every transition to an
audit event — request, decision (with the deciding human and role), consume,
revoke, expiry — and check that the store being empty does not mean the
history is.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.testclient import TestClient

from . import audit, gate, gate_api
from .audit import verify

CHAT = "chan:SEAL-2:titulon-tech:clodia"


def _cap(tok: str) -> dict:
    # tok = "<verb>" — the capability the approval flow would mint for it.
    return {"agent": "clodia", "cap": f"gate:{tok}", "exp": time.time() + 600,
            "jti": f"jti-{tok}", "by": "davide"}


class _Env(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        self.root = base / "audit"
        env = patch.dict(os.environ, {"CLODIA_AUDIT_DIR": str(self.root),
                                      "CLODIA_AUDIT_KEY_DIR": str(base / "key")})
        env.start()
        self.addCleanup(env.stop)
        for name, path in (("_store_path", "store.json"), ("_revoked_path", "revoked.json"),
                           ("_req_path", "requests.json")):
            p = patch.object(gate, name, return_value=base / path)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(gate.pki_verify, "verify_capability", side_effect=_cap)
        p.start()
        self.addCleanup(p.stop)

    def events(self) -> list[dict]:
        out = []
        for seg in sorted(self.root.glob("events-*.jsonl")):
            out += [json.loads(ln) for ln in seg.read_text().splitlines() if ln.strip()]
        return out

    def types(self) -> list[str]:
        return [e["event"]["type"] for e in self.events()]


class LifecycleTests(_Env):
    def test_one_shot_consent_keeps_its_history_after_consumption(self) -> None:
        gate.request("clodia", "clodia-320", "email.send", chat=CHAT, human="davide",
                     reason="send the call summary to the customer")
        gate.grant("clodia", "clodia-320", "email.send", "email.send",
                   decided_by="davide", decided_by_role="admin")
        gate.resolve_request("clodia", "clodia-320", "email.send")
        gate.consume("clodia", "clodia-320", "email.send")

        self.assertFalse(gate.active("clodia", "clodia-320", "email.send"))
        self.assertEqual(self.types(), ["gate.request", "gate.decision", "gate.consume"])
        req, dec, con = self.events()
        self.assertEqual(req["scope"], {"tier": "SEAL-2", "topic": "titulon-tech"})
        self.assertEqual(req["agent"], {"seed": "clodia", "spawn": "clodia-320"})
        self.assertEqual(req["actor"]["on_behalf"], "davide")
        self.assertEqual(dec["authorization"]["result"], "approved")
        self.assertEqual(dec["authorization"]["actor"], "davide")
        self.assertEqual(dec["authorization"]["role"], "admin")
        self.assertEqual(dec["authorization"]["scope"], "one-shot")
        self.assertEqual(dec["authorization"]["jti"], "jti-email.send")
        self.assertEqual(dec["scope"]["topic"], "titulon-tech")  # taken from the request
        self.assertEqual(con["authorization"]["result"], "consumed")
        self.assertEqual(req["authorization"]["gate_ref"], dec["authorization"]["gate_ref"])
        self.assertTrue(verify.verify(self.root)["ok"])

    def test_the_agents_reason_is_hashed_not_written(self) -> None:
        gate.request("clodia", "clodia-320", "email.send", chat=CHAT,
                     reason="send the invoice to mario.rossi@example.com")
        raw = "".join(p.read_text() for p in self.root.glob("events-*.jsonl"))
        self.assertNotIn("mario.rossi", raw)
        self.assertTrue(self.events()[0]["decision"]["declared_reason_hash"].startswith("sha256:"))

    def test_a_renewed_request_is_not_a_second_request(self) -> None:
        gate.request("clodia", "clodia-320", "web.post", chat=CHAT)
        gate.request("clodia", "clodia-320", "web.post", chat=CHAT)
        self.assertEqual(self.types(), ["gate.request"])

    def test_rejection_records_who_said_no(self) -> None:
        gate.request("clodia", "clodia-320", "web.post", chat=CHAT)
        gate.resolve_request("clodia", "clodia-320", "web.post", outcome="rejected",
                             decided_by="davide", decided_by_role="owner")
        dec = self.events()[-1]
        self.assertEqual(dec["event"]["type"], "gate.decision")
        self.assertEqual(dec["event"]["action"], "reject")
        self.assertEqual(dec["authorization"]["result"], "rejected")
        self.assertEqual(dec["actor"], {"type": "human", "id": "davide", "role": "owner"})

    def test_nobody_answered_is_an_event(self) -> None:
        gate.request("clodia", "clodia-320", "web.post", chat=CHAT)
        gate.resolve_request("clodia", "clodia-320", "web.post", outcome="timeout")
        self.assertEqual(self.types()[-1], "gate.expire")
        self.assertEqual(self.events()[-1]["authorization"]["result"], "unanswered")

    def test_a_stale_request_expires_as_an_event(self) -> None:
        gate.request("clodia", "clodia-320", "web.post", chat=CHAT)
        with patch.object(gate.time, "time", return_value=time.time() + gate._REQ_TTL + 5):
            gate.list_requests()
        self.assertEqual(self.types(), ["gate.request", "gate.expire"])

    def test_end_of_spawn_revokes_copybrain_as_revoke_not_consume(self) -> None:
        for seed in ("avvocato", "commercialista"):
            gate.grant("clodia", "clodia-320", f"copybrain:{seed}", f"copybrain:{seed}",
                       decided_by="davide", decided_by_role="admin")
        gate.revoke_instance("clodia", "clodia-320", gate.COPYBRAIN_PREFIX)
        self.assertEqual(self.types(), ["gate.decision", "gate.decision",
                                        "gate.revoke", "gate.revoke"])
        self.assertEqual(self.events()[0]["authorization"]["scope"], "spawn")
        self.assertEqual({e["authorization"]["result"] for e in self.events()[2:]}, {"revoked"})

    def test_a_batch_of_approvals_is_one_event_per_item(self) -> None:
        verbs = ["web.post", "email.send", "gdrive.upload"]
        for v in verbs:
            gate.grant("clodia", "clodia-320", v, v, decided_by="davide")
        decisions = [e for e in self.events() if e["event"]["type"] == "gate.decision"]
        self.assertEqual(sorted(e["event"]["resource"] for e in decisions), sorted(verbs))


class ApiTests(_Env):
    def _client(self) -> TestClient:
        return TestClient(Starlette(routes=gate_api.routes))

    def test_deny_endpoint_records_the_human_and_role_from_the_token(self) -> None:
        gate.request("clodia", "clodia-320", "web.post", chat=CHAT)
        payload = {"principal": "davide", "human_role": "admin", "on_behalf": True}
        with patch.object(gate_api, "verify_session_token", return_value=payload), \
                patch.object(gate_api.internal_auth, "refuse_if_revoked", return_value=None):
            r = self._client().post("/internal/gate/deny",
                                    headers={"authorization": "Bearer x"},
                                    json={"agent": "clodia", "instance": "clodia-320",
                                          "verb": "web.post"})
        self.assertEqual(r.status_code, 200)
        dec = self.events()[-1]
        self.assertEqual(dec["authorization"]["result"], "rejected")
        self.assertEqual(dec["authorization"]["actor"], "davide")
        self.assertEqual(dec["authorization"]["role"], "admin")

    def test_grant_endpoint_records_the_approval(self) -> None:
        payload = {"principal": "davide", "human_role": "owner", "on_behalf": True}
        with patch.object(gate_api, "verify_session_token", return_value=payload), \
                patch.object(gate_api.internal_auth, "refuse_if_revoked", return_value=None):
            r = self._client().post("/internal/gate/grant",
                                    headers={"authorization": "Bearer x"},
                                    json={"agent": "clodia", "instance": "clodia-320",
                                          "verb": "web.post", "token": "web.post"})
        self.assertEqual(r.status_code, 200, r.text)
        dec = self.events()[-1]
        self.assertEqual((dec["event"]["type"], dec["authorization"]["role"]),
                         ("gate.decision", "owner"))


if __name__ == "__main__":
    unittest.main()

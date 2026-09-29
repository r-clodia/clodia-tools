"""clodia-platform#441 — the actor of an event comes from the verified claims.

`ClaimsContext` carries the identity of a request whose token signature was
already checked. These tests hold the audit trail to it: a gateway module that
names someone else cannot write that name as the actor, a person acting through
the platform is the actor (not the carrier), and the certificate that
authenticated the call is on the event.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

from .. import audit
from ..claims import ClaimsContext

AGENT_TOKEN = {"agent": "clodia", "execution_id": "clodia-320", "principal": "davide",
               "chat": "chan:SEAL-2:titulon-tech:clodia", "origin": ["davide", "clodia"]}
HUMAN_TOKEN = {"agent": "clodia", "principal": "davide", "on_behalf": True,
               "human_role": "admin", "principal_kind": "human", "scope_tier": "SEAL-1"}


def _write_cert(path: Path, cn: str) -> int:
    key = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
            .sign(key, None))
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert.serial_number


class IdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        self.root = base / "audit"
        certs = base / "certs"
        certs.mkdir()
        self.serial = _write_cert(certs / "clodia.crt", "clodia")
        env = patch.dict(os.environ, {"CLODIA_AUDIT_DIR": str(self.root),
                                      "CLODIA_AUDIT_KEY_DIR": str(base / "key"),
                                      "CLODIA_PKI_CERTS": str(certs)})
        env.start()
        self.addCleanup(env.stop)

    def last(self) -> dict:
        seg = sorted(self.root.glob("events-*.jsonl"))[-1]
        return json.loads(seg.read_text().splitlines()[-1])

    def test_a_caller_cannot_name_someone_else_as_the_actor(self) -> None:
        with ClaimsContext(AGENT_TOKEN, "t"):
            audit.emit("tool.call", actor={"type": "agent", "id": "avvocato"},
                       agent={"seed": "avvocato"})
        ev = self.last()
        self.assertEqual(ev["actor"]["id"], "clodia-320")
        self.assertEqual(ev["actor"]["source"], "claims")
        self.assertEqual(ev["actor"]["caller_claimed"], "avvocato")
        self.assertEqual(ev["agent"]["seed"], "clodia")

    def test_agent_event_carries_spawn_on_behalf_scope_origin_and_certificate(self) -> None:
        with ClaimsContext(AGENT_TOKEN, "t"):
            audit.emit("tool.call")
        ev = self.last()
        self.assertEqual(ev["actor"], {"type": "agent", "id": "clodia-320",
                                       "on_behalf": "davide", "source": "claims"})
        self.assertEqual(ev["agent"]["spawn"], "clodia-320")
        self.assertEqual(ev["agent"]["origin"], ["davide", "clodia"])
        self.assertEqual(ev["agent"]["cert_serial"], format(self.serial, "x"))
        self.assertTrue(ev["agent"]["cert_fingerprint"].startswith("sha256:"))
        self.assertEqual(ev["scope"], {"tier": "SEAL-2", "topic": "titulon-tech"})

    def test_a_person_acting_through_the_platform_is_the_actor(self) -> None:
        with ClaimsContext(HUMAN_TOKEN, "t"):
            audit.emit("control.change")
        ev = self.last()
        self.assertEqual(ev["actor"]["type"], "human")
        self.assertEqual(ev["actor"]["id"], "davide")
        self.assertEqual(ev["actor"]["role"], "admin")
        self.assertEqual(ev["actor"]["via"], "clodia")
        self.assertEqual(ev["scope"], {"tier": "SEAL-1"})

    def test_without_claims_the_callers_identity_is_marked_as_such(self) -> None:
        audit.emit("tool.call", actor={"type": "service", "id": "clodia-tools"})
        self.assertEqual(self.last()["actor"]["source"], "caller")

    def test_explicit_identity_is_kept_even_inside_a_request(self) -> None:
        with ClaimsContext(AGENT_TOKEN, "t"):
            audit.emit("gate.expire", identity="explicit",
                       actor={"type": "service", "id": "clodia-tools"})
        self.assertEqual(self.last()["actor"], {"type": "service", "id": "clodia-tools",
                                                "source": "caller"})

    def test_unknown_identity_mode_is_a_programming_error(self) -> None:
        with self.assertRaises(audit.RecordError):
            audit.emit("tool.call", identity="whatever")


if __name__ == "__main__":
    unittest.main()

"""PWA pairing tokens are refused by the gateway verifier (clodia-platform#657).

A pairing token was a `ckt1` session token signed IN THE BROWSER with the
principal's masterkey (clodia-web `mintPairingToken` → `signToken`), 30 days
long. Its claims are those of a WebUI session (12 h): only the lifetime tells
them apart. Same rule as clodia-logic `server/colony/pki.py`.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import delegation, pki_mint, pki_verify

HOUR = 3600


class PairingTokenTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        env = patch.dict(os.environ, {
            "CLODIA_SECRETS_DIR": str(base / "secrets"),
            "CLODIA_CA_CRT": str(base / "secrets" / "ca" / "ca.crt"),
            "CLODIA_PKI_CERTS": str(base / "pki" / "certs"),
            "CLODIA_PKI_REVOKED": str(base / "pki" / "revoked.json"),
            "CLODIA_DATA": str(base / "data"),
            "CLODIA_AUDIT_DIR": str(base / "audit"),
            "CLODIA_AUDIT_KEY_DIR": str(base / "k"),
        })
        env.start()
        self.addCleanup(env.stop)
        pki_mint.init_ca()
        # A human principal: the key stays in the browser, the gateway holds
        # only the certificate.
        self.key = Ed25519PrivateKey.generate()
        pki_mint.issue_cert_for_pubkey("davide", self.key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode())

    def _browser_token(self, ttl: int, **extra) -> str:
        """What clodia-web `signToken(principal, mk, ttl)` produces."""
        now = int(time.time())
        payload = {"agent": "davide", "execution_id": "", "iat": now,
                   "exp": now + ttl, "aud": pki_verify.TOKEN_AUDIENCE, **extra}
        body = pki_mint._b64e(json.dumps(payload).encode())
        sig = pki_mint._b64e(self.key.sign(body.encode()))
        return f"{pki_verify.TOKEN_PREFIX}.{body}.{sig}"

    def test_a_pairing_token_is_refused(self):
        with self.assertRaisesRegex(PermissionError, "#657"):
            pki_verify.verify_session_token(self._browser_token(30 * 24 * HOUR))

    def test_just_over_the_margin_is_refused(self):
        with self.assertRaises(PermissionError):
            pki_verify.verify_session_token(self._browser_token(24 * HOUR + 1))

    def test_a_webui_session_still_works(self):
        for ttl in (600, 12 * HOUR, 24 * HOUR):
            with self.subTest(ttl=ttl):
                p = pki_verify.verify_session_token(self._browser_token(ttl))
                self.assertEqual(p["agent"], "davide")

    def test_a_long_delegation_still_verifies(self):
        # clodia-web `signDelegation`: `typ` + `scope`, its own lifetime.
        token = self._browser_token(30 * 24 * HOUR, typ="delegation",
                                    scope={"verb": "email.send"})
        self.assertEqual(delegation.verify(token)["principal"], "davide")

    def test_a_human_mcp_client_token_still_verifies(self):
        # `human_mcp.issue`: days long, but signed by the carrier with
        # `principal`, `on_behalf`, `chat` and an execution id.
        pki_mint.issue_agent_identity("clodia")
        token = pki_mint.mint_session_token(
            "clodia", execution_id="mcp_abc", ttl_seconds=30 * 24 * HOUR,
            principal="davide", on_behalf=True, human_role="user",
            chat="chan:SEAL-1:room:davide", principal_kind="human")
        self.assertEqual(pki_verify.verify_session_token(token)["principal"], "davide")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

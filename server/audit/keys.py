"""The audit signing key.

A dedicated ed25519 key, not the CA key and not an agent identity key:
separation of duty, and a key that signs nothing but audit events and
checkpoints. It lives in the gateway STATE directory (`CLODIA_TOOLS_STATE_DIR`,
a volume the agent-server does not mount — clodia-platform#80), NOT under
`CLODIA_SECRETS_DIR`: on a deployment where the secrets directory sits on the
shared datadir, a key there would be readable by the process whose actions it
certifies (#425 §1.6, "independence").

The public key is written next to the events (`audit.pub.pem`) so that a
verifier needs nothing but the store directory and, for truncation evidence,
the exported checkpoints.
"""
from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)

PUB_NAME = "audit.pub.pem"


def _raw_pub(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def key_id_of(pub: Ed25519PublicKey) -> str:
    return hashlib.sha256(_raw_pub(pub)).hexdigest()[:16]


def load_public(pem: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("audit public key is not ed25519")
    return key


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Signer:
    """Loads the key from `key_dir`, creating it (0600) on first use."""

    def __init__(self, key_dir: Path, pub_dir: Path):
        self.key_path = key_dir / "audit.key"
        if self.key_path.is_file():
            key = serialization.load_pem_private_key(self.key_path.read_bytes(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError(f"{self.key_path}: expected an ed25519 key")
        else:
            key_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(key_dir, 0o700)
            key = Ed25519PrivateKey.generate()
            pem = key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(pem)
        self._key = key
        self.public = key.public_key()
        self.key_id = key_id_of(self.public)
        pub_dir.mkdir(parents=True, exist_ok=True)
        pub_pem = self.public.public_bytes(serialization.Encoding.PEM,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)
        pub_path = pub_dir / PUB_NAME
        if not pub_path.is_file() or pub_path.read_bytes() != pub_pem:
            pub_path.write_bytes(pub_pem)

    def sign(self, data: bytes) -> str:
        return b64(self._key.sign(data))


def verify(pub: Ed25519PublicKey, data: bytes, signature: str) -> bool:
    try:
        pub.verify(unb64(signature), data)
        return True
    except Exception:  # noqa: BLE001 - any failure is "not verified"
        return False

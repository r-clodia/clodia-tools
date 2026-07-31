"""Client gateway del canale cifrato su volume /shared."""
from __future__ import annotations

import base64
import os
import tempfile
import time
import uuid
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .transfer_crypto import decrypt_file, encrypt_file, public_b64, public_from_b64

SHARED_ROOT = Path(os.environ.get("CLODIA_SHARED_ROOT", "/shared"))
EXCHANGES = SHARED_ROOT / "exchanges"
GATEWAY_PUBLIC = SHARED_ROOT / "gateway.pub"
MAX_BYTES = int(os.environ.get("CLODIA_TRANSFER_MAX_BYTES", str(256 * 1024 * 1024)))
TTL_SECONDS = int(os.environ.get("CLODIA_TRANSFER_TTL_SECONDS", "900"))
AGENT_SERVER_URL = os.environ.get("AGENT_SERVER_URL", "http://agent-server:7842")


def _private_path() -> Path:
    root = Path(os.environ.get("CLODIA_SECRETS_DIR", "/datadir/secrets"))
    return root / "transfer" / "gateway.x25519"


def _gateway_private() -> X25519PrivateKey:
    path = _private_path()
    if path.is_file():
        return X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(path.read_text("ascii")))
    key = X25519PrivateKey.generate()
    raw = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(base64.urlsafe_b64encode(raw).decode("ascii"), encoding="ascii")
    os.chmod(path, 0o600)
    return key


def _publish_gateway_public(key: X25519PrivateKey) -> None:
    SHARED_ROOT.mkdir(parents=True, exist_ok=True)
    value = public_b64(key.public_key())
    if not GATEWAY_PUBLIC.is_file() or GATEWAY_PUBLIC.read_text("ascii").strip() != value:
        GATEWAY_PUBLIC.write_text(value, encoding="ascii")


def _headers() -> dict[str, str]:
    secret = (os.environ.get("CLODIA_ORCHESTRATOR_SECRET") or "").strip()
    if not secret:
        raise RuntimeError("CLODIA_ORCHESTRATOR_SECRET richiesto per il transfer cifrato")
    return {"X-Orchestrator-Secret": secret}


def _post(path: str, body: dict) -> dict:
    with httpx.Client(timeout=httpx.Timeout(connect=4, read=60, write=60, pool=4)) as client:
        response = client.post(f"{AGENT_SERVER_URL}{path}", headers=_headers(), json=body)
        response.raise_for_status()
        return response.json()


def _exchange_path(exchange_id: str) -> Path:
    return EXCHANGES / f"{uuid.UUID(exchange_id)}.clx"


def cleanup_expired() -> None:
    cutoff = time.time() - TTL_SECONDS
    if not EXCHANGES.is_dir():
        return
    for path in EXCHANGES.glob("*.clx"):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
        except OSError:
            pass


def fetch_to_agent(data: bytes, *, chat_id: str, dest: str, sender: str) -> dict:
    if len(data) > MAX_BYTES:
        raise ValueError(f"file oltre il limite di {MAX_BYTES} byte")
    cleanup_expired()
    recipient = _post("/internal/transfers/public-key", {"chat_id": chat_id})
    exchange_id = str(uuid.uuid4())
    envelope = _exchange_path(exchange_id)
    with tempfile.NamedTemporaryFile() as clear:
        clear.write(data)
        clear.flush()
        encrypt_file(Path(clear.name), envelope, recipient=recipient["recipient"], sender=sender,
                     recipient_key=public_from_b64(recipient["public_key"]))
    try:
        return _post("/internal/transfers/deliver", {
            "chat_id": chat_id, "exchange_id": exchange_id, "dest": dest,
        })
    finally:
        envelope.unlink(missing_ok=True)


def put_from_agent(*, chat_id: str, src: str) -> bytes:
    cleanup_expired()
    private = _gateway_private()
    _publish_gateway_public(private)
    collected = _post("/internal/transfers/collect", {"chat_id": chat_id, "src": src})
    envelope = _exchange_path(collected["exchange_id"])
    with tempfile.NamedTemporaryFile() as clear:
        try:
            decrypt_file(envelope, Path(clear.name), recipient="gateway", private_key=private,
                         max_bytes=MAX_BYTES, max_age_seconds=TTL_SECONDS)
            clear.seek(0)
            return clear.read()
        finally:
            envelope.unlink(missing_ok=True)

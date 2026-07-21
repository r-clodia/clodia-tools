"""pki_mint — minting lato GATEWAY (trust-anchor).

Il gateway è l'unico detentore delle chiavi private: le **identity key** degli
agenti (`${CLODIA_SECRETS_DIR}/agents/<agent>/identity.key`) e la **CA key**
(`${CLODIA_SECRETS_DIR}/ca/ca.key`). Firma qui i token di sessione (ckt1, con
l'identity key dell'agente) e i capability sudo (ccap1, con la CA). L'orchestrator
(agent-server) NON tiene più chiavi: chiede al gateway di coniare via
`/internal/mint` (autenticato dal secret di bootstrap, vedi mint_api.py).

Rispecchia byte-per-byte il formato di `clodia-logic/server/colony/pki.py`
(stesso prefix, audience, base64, payload) così i token restano verificabili da
`pki_verify.py` senza modifiche. Divergere qui = token non verificabili.
"""
from __future__ import annotations

import base64
import json
import os
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Costanti condivise col verificatore/minter storico (NON cambiare).
TOKEN_PREFIX = "ckt1"
TOKEN_AUDIENCE = "keystore"
SESSION_TTL_SECONDS = 45 * 60
CAP_PREFIX = "ccap1"


def _secrets_dir() -> Path:
    return Path(os.environ.get("CLODIA_SECRETS_DIR", "/datadir/secrets"))


def _agent_key_path(agent: str) -> Path:
    return _secrets_dir() / "agents" / agent / "identity.key"


def _ca_key_path() -> Path:
    return _secrets_dir() / "ca" / "ca.key"


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _load_private(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path}: attesa chiave ed25519")
    return key


def mint_session_token(agent: str, execution_id: str = "",
                       ttl_seconds: int = SESSION_TTL_SECONDS,
                       principal: str | None = None,
                       clearance: str | None = None,
                       on_behalf: bool = False,
                       human_role: str | None = None,
                       chat: str | None = None) -> str:
    """Conia un token di sessione ckt1 firmato con l'identity key dell'agente.
    Identico a colony.pki.mint_session_token, ma le chiavi stanno QUI (gateway)."""
    key_path = _agent_key_path(agent)
    if not key_path.is_file():
        raise PermissionError(f"agent '{agent}' senza identità (nessuna identity.key nel gateway)")
    key = _load_private(key_path)
    now = int(time.time())
    payload = {
        "agent": agent, "execution_id": execution_id,
        "iat": now, "exp": now + int(ttl_seconds), "aud": TOKEN_AUDIENCE,
    }
    if principal:
        payload["principal"] = principal
    if clearance:
        payload["clearance"] = clearance
    if chat:
        payload["chat"] = chat
    if on_behalf:
        payload["on_behalf"] = True
        payload["human_role"] = human_role or "user"
    body = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64e(key.sign(body.encode()))
    return f"{TOKEN_PREFIX}.{body}.{sig}"


def mint_capability(agent: str, instance: str, minutes: int, by: str,
                    cap: str = "sudo") -> dict:
    """Conia un capability sudo ccap1 firmato con la CA (prova dell'approvazione
    umana `by`). Identico a colony.pki.mint_capability."""
    import secrets as _secrets
    ca_key = _load_private(_ca_key_path())
    now = int(time.time())
    minutes = max(1, min(int(minutes or 15), 120))
    jti = _secrets.token_hex(8)
    payload = {
        "cap": cap, "agent": agent, "instance": instance or "-",
        "jti": jti, "iat": now, "exp": now + minutes * 60, "by": by,
    }
    body = _b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64e(ca_key.sign(body.encode()))
    return {"token": f"{CAP_PREFIX}.{body}.{sig}", "jti": jti, "exp": payload["exp"]}

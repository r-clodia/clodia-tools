"""Verifica self-contained dei session-token PKI (ckt1) a CHIAVE PUBBLICA.

Il microservizio clodia-tools NON conia token e NON tiene chiavi private: per
autenticare gli agenti gli basta verificare la firma con i certificati
PUBBLICI (CA + cert dell'agente). Replica fedelmente lo schema di
``agent-server/server/colony/pki.py`` (mint_session_token/verify_session_token)
senza importarlo (i due pacchetti si chiamano entrambi ``server``).

Path dei cert (override via env, utili nel container):
  CLODIA_CA_CRT       default <bundle>/secrets/ca/ca.crt
  CLODIA_PKI_CERTS    default <bundle>/pki/certs
  CLODIA_PKI_REVOKED  default <bundle>/pki/revoked.json
"""
from __future__ import annotations

import base64
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.x509.oid import NameOID

TOKEN_PREFIX = "ckt1"
TOKEN_AUDIENCE = "keystore"  # costante condivisa col minter (pki.py)

# Default di fallback per i path PKI (usati solo se le env non sono settate).
# In produzione CLODIA_CA_CRT / CLODIA_PKI_CERTS / CLODIA_PKI_REVOKED sono
# sempre forniti dall'orchestratore. _BUNDLE = root del repo (robusto: nel repo
# clodia-tools pki_verify.py sta in server/, quindi parents[1] = root).
_BUNDLE = Path(__file__).resolve().parents[1]


def _ca_crt() -> Path:
    return Path(os.environ.get("CLODIA_CA_CRT", str(_BUNDLE / "secrets" / "ca" / "ca.crt")))


def _certs_dir() -> Path:
    return Path(os.environ.get("CLODIA_PKI_CERTS", str(_BUNDLE / "pki" / "certs")))


def _revoked_file() -> Path:
    return Path(os.environ.get("CLODIA_PKI_REVOKED", str(_BUNDLE / "pki" / "revoked.json")))


def _b64d(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _is_revoked(agent: str) -> bool:
    f = _revoked_file()
    if not f.is_file():
        return False
    try:
        return agent in set(json.loads(f.read_text()).get("revoked", []))
    except Exception:
        return False


def _agent_public_key(agent: str) -> Ed25519PublicKey:
    """Carica il cert pubblico dell'agente e ne verifica firma CA, validità,
    CN e revoca. Ritorna la chiave pubblica."""
    cert_path = _certs_dir() / f"{agent}.crt"
    if not cert_path.is_file():
        raise PermissionError(f"nessun certificato per agent '{agent}'")
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if cn != agent:
        raise PermissionError(f"certificato CN '{cn}' != agent '{agent}'")
    ca_path = _ca_crt()
    if not ca_path.is_file():
        raise PermissionError("CA cert non disponibile")
    ca_pub = x509.load_pem_x509_certificate(ca_path.read_bytes()).public_key()
    if not isinstance(ca_pub, Ed25519PublicKey):
        raise PermissionError("CA non ed25519")
    ca_pub.verify(cert.signature, cert.tbs_certificate_bytes)  # raises se non firma CA
    now = datetime.now(timezone.utc)
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        raise PermissionError(f"certificato di '{agent}' scaduto o non valido")
    if _is_revoked(agent):
        raise PermissionError(f"certificato di '{agent}' REVOCATO")
    pub = cert.public_key()
    if not isinstance(pub, Ed25519PublicKey):
        raise PermissionError(f"chiave di '{agent}' non ed25519")
    return pub


def verify_session_token(token: str) -> dict:
    """Valida un token ckt1 e ritorna il payload {agent, execution_id, iat,
    exp, aud}. Solleva PermissionError su qualsiasi problema."""
    try:
        prefix, body, sig = token.strip().split(".")
        if prefix != TOKEN_PREFIX:
            raise ValueError("prefisso token sconosciuto")
        payload = json.loads(_b64d(body))
        agent = str(payload.get("agent") or "")
        if not agent:
            raise ValueError("token senza agent")
    except PermissionError:
        raise
    except Exception as e:
        raise PermissionError(f"token malformato: {e}")
    pub = _agent_public_key(agent)
    try:
        pub.verify(_b64d(sig), body.encode())
    except Exception:
        raise PermissionError(f"firma token non valida per '{agent}'")
    if payload.get("aud") != TOKEN_AUDIENCE:
        raise PermissionError("audience token errata")
    if int(payload.get("exp", 0)) < time.time():
        raise PermissionError("token scaduto")
    return payload

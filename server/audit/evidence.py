"""Evidence store: the CONTENT the trail references by hash (clodia-platform#445).

The trail holds metadata and hashes only, so it can be handed to an auditor
who is not cleared for the data. The contents live here: content-addressed
(`sha256` of the exact bytes the trail hashed), one directory per tier,
encrypted at rest with AES-256-GCM under a key that sits next to the audit
signing key on the gateway-only state volume.

    keep(data, tier)  → "sha256:<hex>"   (the same value as `content_hash(data)`)
    fetch(h, tier, clearance) → bytes    (only if clearance ≥ tier)

An auditor verifies that evidence matches the trail by recomputing the hash
of what `fetch` returns. A reader without clearance gets nothing, not even
whether the object exists.

`CLODIA_AUDIT_EVIDENCE`: `on` (default) keeps content up to
`CLODIA_AUDIT_EVIDENCE_MAX_BYTES` (1 MiB) per object; `off` keeps nothing
(hashes still go on the trail). Larger objects keep their hash and a marker,
not a truncated copy: a truncated copy would not match its hash.
"""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


DEFAULT_MAX = 1 << 20
_HEX64 = re.compile(r"[0-9a-f]{64}")
_TIERS = ("SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4")


class EvidenceDenied(PermissionError):
    pass


def enabled() -> bool:
    return (os.environ.get("CLODIA_AUDIT_EVIDENCE") or "on").strip().lower() not in (
        "0", "off", "false", "no")


def max_bytes() -> int:
    try:
        return int(os.environ.get("CLODIA_AUDIT_EVIDENCE_MAX_BYTES") or DEFAULT_MAX)
    except ValueError:
        return DEFAULT_MAX


def root() -> Path:
    """Next to the trail (`<state>/audit-evidence` in production)."""
    explicit = (os.environ.get("CLODIA_AUDIT_EVIDENCE_DIR") or "").strip()
    if explicit:
        return Path(explicit)
    from . import root_dir
    return root_dir().parent / "audit-evidence"


def _key() -> bytes:
    from . import key_dir
    kd = key_dir()
    p = kd / "evidence.key"
    if p.is_file():
        return p.read_bytes()
    kd.mkdir(parents=True, exist_ok=True)
    key = AESGCM.generate_key(bit_length=256)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return key


def _known(tier: str | None) -> str | None:
    t = str(tier or "").upper().strip()
    if t.startswith("P") and t[1:].isdigit():
        t = f"SEAL-{t[1:]}"
    return t if t in _TIERS else None


def norm_tier(tier: str | None) -> str:
    """The tier an object is FILED under: an unknown tier is the most
    restrictive. Never use it for a clearance (see `clearance_rank`)."""
    return _known(tier) or "SEAL-4"


def _rank(tier: str | None) -> int:
    return _TIERS.index(norm_tier(tier))


def clearance_rank(clearance: str | None) -> int:
    """The rank a CLEARANCE grants. Unknown or empty grants nothing (-1):
    below SEAL-0, so it reads no evidence at all. The opposite of
    `norm_tier`, on purpose — for the object unknown means «most
    restrictive», for the reader it means «not cleared»."""
    k = _known(clearance)
    return _TIERS.index(k) if k else -1


def valid_clearance(clearance: str | None) -> bool:
    return _known(clearance) is not None


def max_tier(*tiers: str | None) -> str | None:
    """The most restrictive of the given tiers; None if the first (the
    channel) is unknown, so that the object is filed as SEAL-4."""
    if not tiers or _known(tiers[0]) is None:
        return None
    known = [k for k in (_known(t) for t in tiers) if k]
    return max(known, key=_TIERS.index)


def _path(hexdigest: str, tier: str) -> Path:
    return root() / norm_tier(tier) / hexdigest[:2] / hexdigest


def keep(data: bytes | str, tier: str | None) -> str:
    """Store `data` (if enabled and small enough) and return its content hash."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    hexd = hashlib.sha256(data).hexdigest()
    if not enabled():
        return "sha256:" + hexd
    p = _path(hexd, tier)
    if p.exists():
        # Already kept: refresh its mtime. Retention prunes on mtime
        # (retention.py), so without this an object first seen more than a
        # retention ago and referenced again today would be deleted while the
        # newest trail events still point at it.
        try:
            os.utime(p, None)
        except OSError:
            pass
        return "sha256:" + hexd
    p.parent.mkdir(parents=True, exist_ok=True)
    if len(data) > max_bytes():
        blob = b"TOO-LARGE:" + str(len(data)).encode()
    else:
        nonce = os.urandom(12)
        blob = b"GCM1" + nonce + AESGCM(_key()).encrypt(nonce, data, hexd.encode())
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(blob)
    os.replace(tmp, p)
    return "sha256:" + hexd


def fetch(content_hash: str, tier: str | None, clearance: str | None) -> bytes:
    """The content of `content_hash`, if `clearance` covers `tier`.

    Raises `EvidenceDenied` without saying whether the object exists, and
    `FileNotFoundError` only to a cleared reader."""
    if clearance_rank(clearance) < _rank(tier):
        raise EvidenceDenied("clearance insufficient for this evidence")
    hexd = content_hash.split(":", 1)[-1]
    if not _HEX64.fullmatch(hexd):
        # Not a sha256: nothing can be stored under it. A 404, not a 500 —
        # and never a path built from what the caller typed.
        raise FileNotFoundError("evidence not found")
    blob = _path(hexd, tier).read_bytes()
    if blob.startswith(b"TOO-LARGE:"):
        raise FileNotFoundError(f"evidence not kept: object larger than the limit ({blob[10:].decode()} bytes)")
    if not blob.startswith(b"GCM1"):
        raise ValueError("unknown evidence format")
    data = AESGCM(_key()).decrypt(blob[4:16], blob[16:], hexd.encode())
    if hashlib.sha256(data).hexdigest() != hexd:
        raise ValueError("evidence does not match its hash")
    return data


def kept(tier: str | None) -> int:
    d = root() / norm_tier(tier)
    return sum(1 for _ in d.rglob("*") if _.is_file()) if d.is_dir() else 0

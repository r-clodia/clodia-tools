"""Who acted, from the VERIFIED claims of the request (clodia-platform#441).

`ClaimsContext` (`server/claims.py`) sets, for every gateway door, contextvars
from a `ckt1` token whose signature has already been checked against the
agent's certificate: carrier agent, spawn (`execution_id`), principal,
on_behalf, human role, chat, origin chain, unattended. This module turns them
into the `actor` / `agent` / `scope` blocks of the canonical record.

The rule that matters: **when claims are present, identity comes from them and
not from the caller**. A gateway module that passes `actor={"id": "someone"}`
while serving a signed request cannot write "someone" into the trail. When
there are no claims (gateway-internal work: a timer, a prune, a boot), the
caller's identity is kept, and `actor.source` says so, because the two are
evidence of different weight.
"""
from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path


def _wl():
    from .. import whitelist
    return whitelist


def claims_present() -> bool:
    return bool(_wl()._CURRENT_AGENT.get())


@lru_cache(maxsize=256)
def _cert_info(path: str, mtime: float) -> dict | None:
    try:
        from cryptography import x509
        cert = x509.load_pem_x509_certificate(Path(path).read_bytes())
        from cryptography.hazmat.primitives import serialization
        der = cert.public_bytes(serialization.Encoding.DER)
        return {"serial": format(cert.serial_number, "x"),
                "fingerprint": "sha256:" + hashlib.sha256(der).hexdigest()}
    except Exception:  # noqa: BLE001 - a missing cert is reported as absent
        return None


def cert_of(agent: str) -> dict | None:
    """Serial and fingerprint of the certificate that authenticates `agent`."""
    try:
        from ..pki_verify import _certs_dir
        p = _certs_dir() / f"{agent}.crt"
        return _cert_info(str(p), p.stat().st_mtime) if p.is_file() else None
    except Exception:  # noqa: BLE001
        return None


def _scope_from_chat(chat: str | None) -> dict | None:
    parts = str(chat or "").split(":")
    if len(parts) >= 3 and parts[0] == "chan":
        return {"tier": parts[1], "topic": parts[2]}
    return None


def from_claims() -> dict:
    """{actor, agent, scope} from the verified request context ({} if none)."""
    wl = _wl()
    carrier = wl._CURRENT_AGENT.get()
    if not carrier:
        return {}
    principal = wl.current_principal()
    on_behalf = wl.is_on_behalf()
    role = wl.current_human_role()
    spawn = wl.current_spawn()
    chat = wl.current_chat()
    cert = cert_of(carrier)
    agent = {"seed": carrier, "spawn": spawn,
             "cert_serial": (cert or {}).get("serial"),
             "cert_fingerprint": (cert or {}).get("fingerprint"),
             "origin": list(wl.current_origin()) or None,
             "unattended": True if wl.is_unattended() else None}
    if on_behalf and principal:
        # A person acting through the platform (webui, own MCP client): the
        # carrier is the vehicle, the person is the actor.
        actor = {"type": "human", "id": principal, "role": role,
                 "kind": wl.current_principal_kind(), "via": carrier, "source": "claims"}
    else:
        actor = {"type": "agent", "id": spawn or carrier, "on_behalf": principal,
                 "source": "claims"}
    scope = _scope_from_chat(chat)
    if scope is None and wl.current_scope_tier():
        scope = {"tier": wl.current_scope_tier()}
    return {"actor": actor, "agent": agent, "scope": scope}


def merge(fields: dict) -> dict:
    """Put the claims' identity into `fields`, overriding the caller's.

    Non-identity keys the caller adds to `actor`/`agent`/`scope` (e.g. a gate
    decision's `role` when there are no claims) survive; identity keys do not.
    """
    c = from_claims()
    out = dict(fields)
    if not c:
        for k in ("actor",):
            if isinstance(out.get(k), dict):
                out[k] = {**out[k], "source": out[k].get("source") or "caller"}
        return out
    for k in ("actor", "agent", "scope"):
        claimed = c.get(k)
        if claimed is None:
            continue
        given = out.get(k) if isinstance(out.get(k), dict) else {}
        out[k] = {**given, **{kk: vv for kk, vv in claimed.items() if vv is not None}}
        known = {claimed.get("id"), (c.get("agent") or {}).get("seed"),
                 (c.get("agent") or {}).get("spawn"), claimed.get("via")}
        if k == "actor" and given.get("id") and given.get("id") not in known:
            # Recorded, not obeyed: a caller named someone else.
            out[k]["caller_claimed"] = given.get("id")
    return out

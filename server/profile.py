"""Profilo dati personali per-agent (PII) con ACL — backed dal VAULT del gateway.

Ogni agent (umano o AI) può avere un profilo `profile_<agent>` con dati personali
(email, iban, domicilio, codice_fiscale, telefono, pec, …). Sono PII → vivono nel
vault (segregato, mai nell'agent registry pubblico) e l'accesso passa SOLO da qui
(reference monitor), con ACL per-profilo (tutto/niente):

  - READ  profilo di X: se caller==X (self) · caller in _ADMINS · caller ha grant su X
  - WRITE / GRANT / REVOKE: solo self o admin

L'ACL riusa il sistema di grant del vault (set_grant/grants_for): un grant 'fetch'
sul cred `profile_<X>` = "può leggere il profilo di X". Ogni lettura è auditata.
"""
from __future__ import annotations

import os
import re

from . import vault

_PREFIX = "profile_"
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")
# Admin che possono gestire qualsiasi profilo (oltre al self). Super-agent di
# default; estendibile via env (es. l'admin umano "davide").
_ADMINS = {"clodia", "ophelia", *(
    a.strip() for a in os.environ.get("CLODIA_PROFILE_ADMINS", "").split(",") if a.strip()
)}


def _cred(agent: str) -> str:
    return f"{_PREFIX}{agent}"


def _check_name(agent: str) -> None:
    if not _NAME_RE.match(agent or ""):
        raise ValueError(f"nome agent non valido: {agent!r}")


def is_admin(caller: str | None) -> bool:
    return (caller or "") in _ADMINS


def can_read(caller: str | None, target: str) -> bool:
    if not caller:
        return False
    if caller == target or is_admin(caller):
        return True
    return _cred(target) in vault.grants_for(caller)


def can_write(caller: str | None, target: str) -> bool:
    return bool(caller) and (caller == target or is_admin(caller))


# ── operazioni ───────────────────────────────────────────────────────────────
def get(caller: str, target: str) -> dict:
    """Profilo di `target` se `caller` è autorizzato. PermissionError altrimenti."""
    _check_name(target)
    if not can_read(caller, target):
        raise PermissionError(f"'{caller}' non autorizzato a leggere il profilo di '{target}'")
    if not vault.has_credential(_cred(target)):
        return {"agent": target, "fields": {}, "grants": [], "exists": False}
    bundle = vault.read_internal(_cred(target))  # lettura interna (ACL già fatta sopra)
    return {
        "agent": target,
        "fields": bundle.get("fields", {}),
        "grants": vault.agents_with_grant(_cred(target)),
        "exists": True,
    }


def set_fields(caller: str, target: str, fields: dict) -> dict:
    """Crea/aggiorna i campi del profilo di `target`. Solo self o admin."""
    _check_name(target)
    if not can_write(caller, target):
        raise PermissionError(f"'{caller}' non autorizzato a modificare il profilo di '{target}'")
    if not isinstance(fields, dict):
        raise ValueError("fields dev'essere un oggetto")
    existing = vault.read_internal(_cred(target)) if vault.has_credential(_cred(target)) else {}
    merged = {**existing.get("fields", {}), **fields}
    # rimuove le chiavi esplicitamente svuotate (valore null)
    merged = {k: v for k, v in merged.items() if v is not None}
    # deposit preserva i grant esistenti (vault.deposit non li rimuove); self ha sempre
    # accesso via can_read(self). grant_agents=[] = nessun grant aggiunto qui.
    vault.deposit(_cred(target), {"fields": merged, "tier": existing.get("tier", "SEAL-2")},
                  cred_type="pii_profile", grant_agents=[])
    return get(caller, target)


def grant(caller: str, target: str, grantee: str, granted: bool = True) -> dict:
    """Concede/revoca a `grantee` la lettura del profilo di `target`. Self o admin."""
    _check_name(target)
    _check_name(grantee)
    if not can_write(caller, target):
        raise PermissionError(f"'{caller}' non autorizzato a gestire i grant del profilo di '{target}'")
    if not vault.has_credential(_cred(target)):
        raise ValueError(f"profilo di '{target}' inesistente: crealo prima")
    vault.set_grant(_cred(target), grantee, granted, actions=["fetch"])
    return get(caller, target)

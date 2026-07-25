"""Deleghe firmate per lo sblocco dei gate — modello unico: **delega → verifica
firma (CA) → check grant/scope → unlock**.

Una delega è un token ckt1 firmato dal PRINCIPAL UMANO che approva, con claim:
  typ="delegation", scope={verb, agent?, job?}, exp (TTL lungo per l'async·A).
Il gateway la verifica con la STESSA macchina dei session token (firma dell'utente
vs il suo cert emesso dalla CA), poi controlla che lo scope copra l'azione gated.

- **Sync**: la webui/pwa firma la delega CLIENT-SIDE con la masterkey dell'utente
  (come già per i session token) al click su Approva.
- **Async · A (permanente)**: delega pre-firmata con scope+scadenza, che copre i run
  ricorrenti di un job (firma reale dell'utente, data in anticipo). Scoped → un
  agente compromesso NON può uscire dallo scope (il resto resta gated → async·B).

`_mint` qui è SOLO per test/CLI: in produzione firma l'utente, il gateway verifica.
"""
from __future__ import annotations

import json
import time

from . import pki_verify as _pv


def verify(token: str) -> dict | None:
    """Verifica una delega firmata → {principal, scope, exp} oppure None se non
    valida (firma/CA/scadenza/typ). Riusa la verifica dei session token."""
    try:
        p = _pv.verify_session_token(token)  # firma vs cert CA del principal + aud + exp
    except Exception:  # noqa: BLE001
        return None
    if p.get("typ") != "delegation":
        return None
    return {"principal": str(p.get("agent") or ""),
            "scope": p.get("scope") or {},
            "exp": int(p.get("exp", 0))}


def covers(deleg: dict, agent: str, verb: str) -> bool:
    """Lo scope della delega autorizza l'azione (agent, verb)? Lo scope è
    RESTRITTIVO: `verb` deve combaciare (o '*'), e se `agent` è indicato deve
    combaciare l'agente che esegue. Tutto ciò che esce dallo scope resta gated."""
    sc = (deleg or {}).get("scope") or {}
    if sc.get("verb") not in (verb, "*"):
        return False
    if sc.get("agent") and sc.get("agent") != agent:
        return False
    return True


def _mint(signer: str, scope: dict, ttl: int = 90 * 24 * 3600) -> str:
    """SOLO test/CLI: conia una delega firmata con la chiave di `signer` (in prod
    firma l'utente client-side). `scope` es. {"verb": "settings.backup_run"}."""
    from . import pki_mint as _pm
    key = _pm._load_private(_pm._agent_key_path(signer))
    now = int(time.time())
    payload = {"agent": signer, "typ": "delegation", "scope": scope,
               "iat": now, "exp": now + int(ttl), "aud": _pv.TOKEN_AUDIENCE}
    body = _pm._b64e(json.dumps(payload, separators=(",", ":")).encode())
    sig = _pm._b64e(key.sign(body.encode()))
    return f"{_pv.TOKEN_PREFIX}.{body}.{sig}"

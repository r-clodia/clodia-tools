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
import os
import pathlib
import time

from . import pki_verify as _pv

# Store delle deleghe PERMANENTI (async·A): token raw, ri-verificati al lookup
# (così scadenza/revoca/tamper vengono colti). Gateway datadir.
_STORE = pathlib.Path(os.environ.get("CLODIA_DATA") or "/datadir") / "delegations" / "active.jsonl"


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


def register(token: str) -> dict | None:
    """Registra una delega permanente (async·A). Ritorna {principal, scope, exp}
    se valida, altrimenti None. Il token grezzo è ri-verificato a ogni lookup."""
    v = verify(token)
    if not v:
        return None
    _STORE.parent.mkdir(parents=True, exist_ok=True)
    with _STORE.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"token": token, "principal": v["principal"],
                            "scope": v["scope"]}, ensure_ascii=False) + "\n")
    return v


def find_covering(agent: str, verb: str) -> dict | None:
    """Prima delega permanente VALIDA (firma+scadenza ok) il cui scope copre
    (agent, verb). None se nessuna. Chiamato dal gate: se presente → unlock."""
    try:
        lines = _STORE.read_text("utf-8").splitlines()
    except FileNotFoundError:
        return None
    for ln in lines:
        try:
            tok = json.loads(ln).get("token")
        except Exception:  # noqa: BLE001
            continue
        d = verify(tok)  # ri-verifica → scaduta/manomessa scartata
        if d and covers(d, agent, verb):
            return d
    return None


def list_active() -> list[dict]:
    """Deleghe permanenti VALIDE (firma+scadenza ok) → [{principal, scope, exp}]."""
    out: list[dict] = []
    try:
        lines = _STORE.read_text("utf-8").splitlines()
    except FileNotFoundError:
        return out
    for ln in lines:
        try:
            tok = json.loads(ln).get("token")
        except Exception:  # noqa: BLE001
            continue
        d = verify(tok)
        if d:
            out.append(d)
    return out


def revoke(principal: str, verb: str) -> bool:
    """Rimuove le deleghe di `principal` che coprono `verb` (revoca lato store).
    Ritorna True se ne ha tolta almeno una."""
    try:
        lines = _STORE.read_text("utf-8").splitlines()
    except FileNotFoundError:
        return False
    kept, removed = [], False
    for ln in lines:
        try:
            row = json.loads(ln)
        except Exception:  # noqa: BLE001
            continue
        d = verify(row.get("token") or "")
        if d and d.get("principal") == principal and (d.get("scope") or {}).get("verb") == verb:
            removed = True
            continue
        kept.append(ln)
    if removed:
        _STORE.write_text("\n".join(kept) + ("\n" if kept else ""), "utf-8")
    return removed


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

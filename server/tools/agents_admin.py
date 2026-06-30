"""Namespace nativo `agents.*` — amministrazione delle capability degli agent.

Permette a un agent autorizzato (super, o con `agents.*`) di dotare ALTRI agent
EDITABILI di skill/tool/rules, in chat, senza UI né edit a mano dei file.

Modello di sicurezza (deciso con l'owner, 30 giu 2026):
- I super-agent (clodia/ophelia) e gli agent con flag `immutable: true` (es.
  Wainston) sono IMMUTABILI a runtime: nessuna scrittura, da nessuno. Si
  cambiano solo via codice/rebuild dei seed.
- Le SCRITTURE passano dal backend (`PATCH /api/agents/{name}/caps`), che
  riverifica l'autorizzazione per principal-agent (token ckt1 INOLTRATO dal
  gateway) e l'immutabilità del target — difesa in profondità.
- Le LETTURE (lista agent/skill/rule/tool) sono metadati: GET anonimi sulla rete
  interna, come il resto dell'introspezione runtime.

Il gateway NON conia token: per le scritture inoltra al backend il token grezzo
del caller (whitelist.current_token), che il backend verifica con la sua CA.
"""
from __future__ import annotations

import os

import httpx

from .. import whitelist

AGENT_SERVER_URL = os.environ.get("AGENT_SERVER_URL", "http://agent-server:7842")
_TIMEOUT = httpx.Timeout(connect=4.0, read=15.0, write=10.0, pool=4.0)


def _get(path: str):
    with httpx.Client(timeout=_TIMEOUT) as c:
        r = c.get(f"{AGENT_SERVER_URL}{path}")
        r.raise_for_status()
        return r.json()


def _patch_caps(name: str, body: dict) -> dict:
    """PATCH /api/agents/{name}/caps inoltrando il token del caller. Propaga gli
    errori del backend (403 immutabile/non autorizzato, 400 ref sconosciuto)."""
    tok = whitelist.current_token()
    headers = {"Authorization": f"Bearer {tok}"} if tok else {}
    with httpx.Client(timeout=_TIMEOUT) as c:
        r = c.patch(f"{AGENT_SERVER_URL}/api/agents/{name}/caps", json=body, headers=headers)
        if r.status_code >= 400:
            try:
                detail = r.json().get("detail") or r.text
            except Exception:  # noqa: BLE001
                detail = r.text
            if r.status_code == 403:
                raise PermissionError(detail)
            raise ValueError(detail)
        return r.json()


def _all_agents() -> list[dict]:
    d = _get("/api/agents")
    return d.get("agents", []) if isinstance(d, dict) else (d or [])


def _find(name: str) -> dict | None:
    return next((a for a in _all_agents() if a.get("name") == name), None)


def _immutable(a: dict) -> bool:
    return a.get("type") == "super" or bool(a.get("immutable"))


# ── letture (metadati) ────────────────────────────────────────────────────
def list_agents() -> dict:
    """Tutti gli agent con tipo e immutabilità (per scegliere un target)."""
    out = [{"name": a.get("name"), "type": a.get("type"),
            "display_name": a.get("display_name"), "immutable": _immutable(a)}
           for a in _all_agents()]
    return {"count": len(out), "agents": out}


def show(name: str) -> dict:
    """Capability correnti di un agent (skill/rules/tool) + immutabilità."""
    a = _find(name)
    if a is None:
        raise ValueError(f"agent '{name}' non trovato")
    return {"name": name, "type": a.get("type"), "immutable": _immutable(a),
            "capabilities": a.get("capabilities", []) or [],
            "rules": a.get("rules", []) or [],
            "tool_permissions": a.get("tool_permissions", []) or []}


def list_skills() -> dict:
    """Nomi delle skill disponibili nel catalogo (assegnabili come capabilities)."""
    return {"skills": [s.get("name") for s in _get("/clodia/skills") if s.get("name")]}


def list_rules() -> dict:
    """Nomi delle rule disponibili nel catalogo."""
    return {"rules": [s.get("name") for s in _get("/clodia/rules") if s.get("name")]}


# ── scritture (delta su lista, calcolato qui; set completo inviato al backend) ─
def _modify(name: str, field: str, add: list[str] | None = None,
            remove: list[str] | None = None) -> dict:
    a = _find(name)
    if a is None:
        raise ValueError(f"agent '{name}' non trovato")
    if _immutable(a):
        raise PermissionError(
            f"agent '{name}' è immutabile (super o protetto): si modifica solo via "
            "codice/rebuild del seed")
    cur = list(a.get(field, []) or [])
    if remove:
        rm = set(remove)
        cur = [x for x in cur if x not in rm]
    if add:
        for x in add:
            if x not in cur:
                cur.append(x)
    res = _patch_caps(name, {field: cur})
    return {"ok": True, "name": name, field: res.get(field, cur)}


def grant_skill(name: str, skill: str) -> dict:
    return _modify(name, "capabilities", add=[skill])


def revoke_skill(name: str, skill: str) -> dict:
    return _modify(name, "capabilities", remove=[skill])


def grant_tool(name: str, tool: str) -> dict:
    return _modify(name, "tool_permissions", add=[tool])


def revoke_tool(name: str, tool: str) -> dict:
    return _modify(name, "tool_permissions", remove=[tool])


def grant_rule(name: str, rule: str) -> dict:
    return _modify(name, "rules", add=[rule])


def revoke_rule(name: str, rule: str) -> dict:
    return _modify(name, "rules", remove=[rule])

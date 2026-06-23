"""Runtime introspection — tool MCP read-only che danno a un agent una vista del
sistema in cui gira: altri agent, jobs, skill, chat aperte, topic, server MCP
disponibili e provider di inferenza.

Aggrega da due sorgenti:
  - agent-server (clodia-logic) via REST: agents, jobs, chats, skills, providers
  - gateway stesso: topics (TopicService) + server MCP (whitelist/native)

SICUREZZA (Prima Legge): SOLO metadati, MAI segreti. I provider espongono
id/nome/meccanismo/stato di connessione, mai chiavi/token. I topic di tier P3
(Restricted) sono esclusi di default dall'introspezione generica. Le chat
espongono id/kind/titolo/stato, non il contenuto.
"""
from __future__ import annotations

import os

import httpx

from .. import whitelist

# agent-server è un container distinto: si raggiunge per service-name sulla rete
# compose (non 127.0.0.1). Override via env per dev locale (es. 127.0.0.1:7842).
AGENT_SERVER_URL = os.environ.get("AGENT_SERVER_URL", "http://agent-server:7842")

_TIMEOUT = httpx.Timeout(connect=4.0, read=15.0, write=10.0, pool=4.0)


def _get(path: str):
    with httpx.Client(timeout=_TIMEOUT) as c:
        r = c.get(f"{AGENT_SERVER_URL}{path}")
        r.raise_for_status()
        return r.json()


def _pick(d: dict, keys: tuple[str, ...]) -> dict:
    return {k: d.get(k) for k in keys if k in d}


def agents() -> dict:
    """Gli agent definiti nell'istanza (con provider effettivo e stato)."""
    data = _get("/api/agents")
    rows = data.get("agents", []) if isinstance(data, dict) else data
    out = [_pick(a, ("name", "display_name", "type", "role", "agent_sdk", "model",
                     "provider", "providers", "provider_connected", "paused"))
           for a in rows]
    return {"count": len(out), "agents": out}


def jobs() -> dict:
    """I job schedulati (cron/intervallo) e il loro stato."""
    data = _get("/clodia/jobs")
    rows = data if isinstance(data, list) else data.get("jobs", [])
    out = [_pick(j, ("id", "job_id", "name", "agent", "kind", "schedule",
                     "cron", "enabled", "next_run", "last_run"))
           for j in rows]
    return {"count": len(out), "jobs": out}


def chats() -> dict:
    """Le chat aperte (solo metadati, non il contenuto)."""
    data = _get("/clodia/chats")
    rows = data if isinstance(data, list) else data.get("chats", [])
    out = [_pick(c, ("chat_id", "id", "kind", "title", "status", "last_activity"))
           for c in rows]
    return {"count": len(out), "chats": out}


def skills() -> dict:
    """Le skill nel catalogo (per pack)."""
    data = _get("/clodia/skills")
    rows = data if isinstance(data, list) else data.get("skills", [])
    out = [_pick(s, ("name", "pack", "description", "available_packs")) for s in rows]
    return {"count": len(out), "skills": out}


def providers() -> dict:
    """I provider di inferenza (id/nome/meccanismo/stato). MAI segreti."""
    data = _get("/api/providers")
    rows = data.get("providers", []) if isinstance(data, dict) else data
    out = [_pick(p, ("id", "name", "mechanism", "sdk", "connected", "via")) for p in rows]
    return {"count": len(out), "providers": out}


def topics(include_restricted: bool = False) -> dict:
    """I topic di cui l'agente chiamante è owner o partecipante (metadati). Un
    agente non autorizzato NON vede i topic altrui. P3 esclusi di default."""
    from ..topics_api import _service
    try:
        me = whitelist.agent_name()
    except Exception:  # noqa: BLE001
        me = None
    rows = _service().list(tier=None)
    rows = [t for t in rows
            if me and (me == t.get("owner") or me in (t.get("participants") or []))]
    if not include_restricted:
        rows = [t for t in rows if t.get("tier") != "P3"]
    return {"count": len(rows), "topics": rows}


def current_user() -> dict:
    """L'utente umano con cui l'agent sta interagendo.

    F2a: se la chat porta un **principal verificato** (claim del token ckt1,
    propagato dall'utente loggato in clodia-web), è QUELLO l'utente connesso —
    anche non-admin. In assenza di login (anonimo) fa fallback all'owner/
    superadmin dell'istanza. Il principal è verificato dalla CA → non spoofabile."""
    data = _get("/api/agents")
    rows = data.get("agents", []) if isinstance(data, dict) else data
    humans = [a for a in rows if a.get("type") == "human"]
    by_name = {a.get("name"): a for a in rows}
    shape = ("name", "display_name", "role")

    principal = whitelist.current_principal()
    if principal:
        p = by_name.get(principal)
        user = _pick(p, shape) if p else {"name": principal}
        return {"user": user, "authenticated": True,
                "humans": [_pick(h, shape) for h in humans]}

    # anonimo (nessuna login): fallback all'owner
    owner = next((h for h in humans if h.get("role") == "superadmin"),
                 humans[0] if humans else None)
    return {
        "user": _pick(owner, shape) if owner else None,
        "authenticated": False,
        "humans": [_pick(h, shape) for h in humans],
        "note": "nessun utente loggato: mostrato l'owner. Con la login l'utente connesso reale è nel claim verificato.",
    }


def mcp_servers() -> dict:
    """I server MCP disponibili: i backend montati (Add-MCP) + i namespace nativi."""
    backends = whitelist.CONFIG.get("mcp_backends") or []
    mounted = [_pick(b, ("name", "label", "transport")) for b in backends]
    native = ["fs", "agent", "email", "topic", "runtime"]
    return {"native": native, "mcp_backends": mounted, "count": len(mounted)}

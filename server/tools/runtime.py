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


def _post(path: str, payload: dict, *, auth: bool = False):
    # auth=True: inoltra il session token ckt1 del chiamante corrente, così
    # agent-server verifica l'identità firmata (via _principal_from_request) e
    # non deve fidarsi di un campo auto-dichiarato nel body.
    headers = {}
    if auth:
        token = whitelist.current_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
    with httpx.Client(timeout=_TIMEOUT) as c:
        r = c.post(f"{AGENT_SERVER_URL}{path}", json=payload, headers=headers)
        r.raise_for_status()
        return r.json()


def suggest_team(tier: str, description: str) -> dict:
    """Proxy all'agent-server: proposta di squadra per un topic (read-only)."""
    return _post("/clodia/channels/suggest-team",
                 {"tier": tier or "SEAL-0", "description": description or ""})


def propose_job(name: str, prompt: str, requested_by: str,
                schedule_text: str | None = None, cron_expr: str | None = None,
                agent: str = "clodia", enabled: bool = True) -> dict:
    """Proxy: PROPONE un job (l'owner approva via gate). Non crea nulla subito."""
    return _post("/clodia/jobs/propose", {
        "name": name, "prompt": prompt, "schedule_text": schedule_text,
        "cron_expr": cron_expr, "agent": agent, "enabled": enabled,
        "requested_by": requested_by,
    })


def restart_agent(agent: str) -> dict:
    """Proxy: RIAVVIA le sessioni vive di un agente (ferma i subprocess; la chat
    rimaterializza il seed al prossimo messaggio). Ops di sysadmin per sbloccare
    un agente col runtime impuntato. I dati persistono."""
    return _post("/clodia/runtime/restart-agent", {"agent": agent})


def inspect_topic(tier: str, name: str, by: str) -> dict:
    """Proxy: introspezione di UN topic per uno steward (sysadmin) chiamato dal
    widget. Metadati + agenti + ultimi messaggi, MA solo entro la clearance del
    chiamante: topic sopra la sua SEAL → 403 (invisibile). L'asse participant è
    bypassato (lo steward non è partecipante), quello clearance NO."""
    return _post("/clodia/runtime/inspect-topic",
                 {"tier": tier, "name": name, "by": by})


def channel_trigger(tier: str, name: str, text: str, by: str) -> dict:
    """Proxy: innesca il risponditore del topic su un messaggio appena iniettato
    (di norma con @menzione → il responder è l'agente taggato). Fire-and-forget
    lato agent-server."""
    return _post(f"/clodia/channels/{tier}/{name}/trigger/internal",
                 {"text": text, "by": by})


def set_participant(tier: str, name: str, agent: str, by: str, add: bool) -> dict:
    """Proxy: aggiunge/rimuove un partecipante da un canale, per conto dell'agente
    `by` (autorizzazione lato agent-server: owner|partecipante|super)."""
    return _post(f"/clodia/channels/{tier}/{name}/participants/internal",
                 {"agent": agent, "by": by, "add": add})


def _pick(d: dict, keys: tuple[str, ...]) -> dict:
    return {k: d.get(k) for k in keys if k in d}


def agents() -> dict:
    """Gli agent dell'istanza con il quadro COMPLETO per decidere in autonomia
    (chi coinvolgere, chi è idoneo a un tier, chi costa meno): identità, ruolo,
    dominio (expertise), skill e knowledge (rag_read), clearance SEAL, provider
    effettivo + il suo SEAL, modello, stato. Solo metadati, MAI segreti — la
    decisione spetta all'agente, non al tool."""
    data = _get("/api/agents")
    rows = data.get("agents", []) if isinstance(data, dict) else data
    out = [_pick(a, (
        "name", "display_name", "type", "role", "agent_sdk", "model",
        "provider", "providers", "provider_connected", "provider_seal",
        "paused", "clearance", "expertise", "skills", "capabilities",
        "rag_read", "rag_write", "rank_label",
    )) for a in rows]
    return {"count": len(out), "agents": out}


def rag_grants(agent: str) -> dict[str, set[str]]:
    """Grant RAG autorevoli dell'AgentSpec nel core.

    L'enforcement non deve leggere la whitelist locale del gateway: quella
    descrive tool e filesystem, mentre rag_read/rag_write sono capability
    amministrate dal core. La query resta live per rendere immediate le revoche.
    """
    data = _get("/api/agents")
    rows = data.get("agents", []) if isinstance(data, dict) else data
    row = next(
        (item for item in (rows or [])
         if isinstance(item, dict) and item.get("name") == agent),
        None,
    )
    if row is None:
        raise PermissionError(
            f"impossibile risolvere i grant RAG dell'agent '{agent}'")

    def _collections(key: str) -> set[str]:
        values = row.get(key) or []
        if not isinstance(values, (list, tuple, set)):
            raise PermissionError(
                f"grant RAG '{key}' non valido per l'agent '{agent}'")
        return {value.strip() for value in values
                if isinstance(value, str) and value.strip()}

    return {
        "rag_read": _collections("rag_read"),
        "rag_write": _collections("rag_write"),
    }


#: Esiti che un agente può dichiarare per il proprio run. Copia dell'insieme che
#: l'agent-server valida in `scheduler/run_status.py`: la validazione autorevole è
#: là, questa serve a rifiutare senza fare un giro di rete per uno stato che
#: verrebbe rifiutato comunque — e a poter elencare i valori giusti nell'errore.
#: `failed` non c'è: lo constata l'infrastruttura quando il turno muore.
_REPORTABLE = ("success", "error", "fatal")


def report_run_status(*, chat_id: str, status: str, detail: str | None = None,
                      agent: str = "") -> dict:
    """Proxy: l'agente DICHIARA l'esito del run schedulato che sta eseguendo.

    `chat_id` arriva dal claim firmato della sessione, non dagli argomenti del
    verbo: vedi il commento nel dispatch. Qui si valida solo la forma.
    """
    s = str(status or "").strip().lower()
    if s not in _REPORTABLE:
        raise ValueError(
            f"status '{status}' non valido; ammessi: {', '.join(_REPORTABLE)}. "
            "'failed' non è dichiarabile: descrive un turno morto, e lo constata "
            "l'infrastruttura")
    # `strip()` PRIMA del test di vuoto, non dopo: `"   "` supera un controllo
    # `not in (None, "")` e diventa `""`, cioè un dettaglio vuoto che lo storico
    # mostrerebbe come se fosse una spiegazione.
    d = (str(detail).strip() or None) if detail is not None else None
    return _post("/clodia/jobs/report-status/internal", {
        "chat_id": chat_id, "status": s, "detail": d, "agent": agent,
    })


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
        rows = [t for t in rows if t.get("tier") not in ("P3", "SEAL-3", "SEAL-4")]
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

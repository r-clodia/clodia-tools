"""M-sudo (Fase 1) — least-privilege per i super-agent (clodia/ophelia).

Modello: clodia/ophelia girano in modalità BASE (least-privilege). I tool della
classe "super-only" (che terraformano/distruggono la piattaforma) richiedono un
grant SUDO **time-boxed E instance-boxed** (una sola istanza dell'agente in una
chat viene promossa, non l'agente globale), approvato da un umano ADMIN.

Questa Fase 1 è NON-breaking: definisce il tiering + il grant-store + gli helper.
L'enforcement (flip di `_is_super`) e il flusso di approvazione arrivano dopo.

Store persistente: `$CLODIA_DATA/clodia-tools-sudo.json` — mappa
`"<agent>|<instance>" -> {exp: epoch, scope: [...], by: <admin>, at: epoch}`.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional

# Gruppo SUDOER: agenti ELEGGIBILI a escalation sudo. NON sono super permanenti:
# in base sono least-privilege; possono elevare (con approvazione admin) alle
# operazioni super-only. Configurabile via env (CSV). Default: clodia, ophelia,
# sysadmin. Sostituisce il concetto di "_SUPER_AGENTS" (bypass permanente).
SUDOERS = {"clodia", "ophelia", "sysadmin", *(
    a.strip() for a in os.environ.get("CLODIA_SUDOERS", "").split(",") if a.strip()
)}

# APPROVATORI: umani (principal) autorizzati a concedere sudo. Interim "admin
# singolo" (bootstrap): l'owner/superadmin. Multi-admin arriverà col bootstrap-auth.
APPROVERS = {"davide", "owner", "superadmin", *(
    a.strip() for a in os.environ.get("CLODIA_SUDO_APPROVERS", "").split(",") if a.strip()
)}


def is_sudoer(agent: Optional[str]) -> bool:
    """True se l'agente è nel gruppo sudoer (eleggibile a escalation)."""
    return (agent or "") in SUDOERS


def is_approver(principal: Optional[str]) -> bool:
    """True se il principal UMANO può approvare/concedere sudo (admin)."""
    return (principal or "") in APPROVERS


# Namespace/prefissi dei tool "super-only": mutazioni irreversibili o ad alto
# privilegio della piattaforma. Tutto il resto è BASE (lavoro quotidiano).
SUPER_ONLY_PREFIXES = (
    "packs.",        # install/remove pack (esegue codice terzi)
    "providers.",    # aggiungi/pausa provider (egress dati)
    "mcp.",          # aggiungi MCP server (nuova superficie di codice)
    "agents.",       # amministra capability di altri agenti
    "settings.",     # settings di piattaforma (mutazioni)
    "pki.", "ca.",   # emissione identità PKI / operazioni CA
)
# Verbi specifici super-only anche fuori dai prefissi sopra (es. delete espliciti).
SUPER_ONLY_EXACT = frozenset({
    "workflows.terminate",
})

_GRACE = 0  # nessun grace: alla scadenza il potere decade netto


def is_super_only(tool: str) -> bool:
    """True se il tool richiede sudo (classe super-only)."""
    t = tool or ""
    if t in SUPER_ONLY_EXACT:
        return True
    return any(t.startswith(p) for p in SUPER_ONLY_PREFIXES)


def _store_path() -> Path:
    return Path(os.environ.get("CLODIA_DATA", "/datadir")) / "clodia-tools-sudo.json"


def _load() -> dict:
    p = _store_path()
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def _save(d: dict) -> None:
    p = _store_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
    tmp.replace(p)


def _key(agent: str, instance: str) -> str:
    return f"{agent}|{instance or '-'}"


def _prune(d: dict, now: float) -> bool:
    """Rimuove i grant scaduti. Ritorna True se ha modificato d."""
    dead = [k for k, v in d.items() if float((v or {}).get("exp", 0)) <= now]
    for k in dead:
        d.pop(k, None)
    return bool(dead)


def grant(agent: str, instance: str, minutes: int, by: str,
          scope: Optional[list] = None) -> dict:
    """Concede sudo a (agent, instance) per `minutes`. `by` = admin approvante.
    Idempotente: sovrascrive un grant esistente per la stessa coppia."""
    minutes = max(1, min(int(minutes or 15), 120))  # cap 2h
    now = time.time()
    d = _load()
    _prune(d, now)
    entry = {"exp": now + minutes * 60, "by": by, "at": now,
             "scope": list(scope) if scope else []}
    d[_key(agent, instance)] = entry
    _save(d)
    return {"agent": agent, "instance": instance, "expires_in_s": minutes * 60,
            "by": by, "scope": entry["scope"]}


def revoke(agent: str, instance: str) -> bool:
    d = _load()
    k = _key(agent, instance)
    if k in d:
        d.pop(k, None)
        _save(d)
        return True
    return False


def active(agent: str, instance: str) -> bool:
    """True se (agent, instance) ha un grant sudo attivo e non scaduto."""
    now = time.time()
    d = _load()
    if _prune(d, now):
        _save(d)
    v = d.get(_key(agent, instance))
    return bool(v) and float(v.get("exp", 0)) > now


def status(agent: Optional[str] = None) -> list:
    """Grant attivi (opz. filtrati per agent), per la UI/audit."""
    now = time.time()
    d = _load()
    if _prune(d, now):
        _save(d)
    out = []
    for k, v in d.items():
        ag, inst = (k.split("|", 1) + ["-"])[:2]
        if agent and ag != agent:
            continue
        out.append({"agent": ag, "instance": inst,
                    "remaining_s": int(float(v.get("exp", 0)) - now),
                    "by": v.get("by"), "scope": v.get("scope", [])})
    return out


# ── Richieste di escalation (sudoer chiede → owner approva) ──────────────────
_REQ_TTL = 30 * 60  # una richiesta pending scade dopo 30'


def _req_path() -> Path:
    return Path(os.environ.get("CLODIA_DATA", "/datadir")) / "clodia-tools-sudo-requests.json"


def _req_load() -> dict:
    p = _req_path()
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def _req_save(d: dict) -> None:
    p = _req_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
    tmp.replace(p)


def request_sudo(agent: str, instance: str, reason: str, minutes: int,
                 human: Optional[str] = None) -> dict:
    """Un SUDOER chiede l'escalation. Crea/aggiorna una richiesta PENDING per la
    coppia (agent, instance). `human` = principal umano del turno (chi ha chiesto)."""
    if not is_sudoer(agent):
        raise PermissionError(f"'{agent}' non è nel gruppo sudoer")
    now = time.time()
    d = _req_load()
    # prune scadute
    for k in [k for k, v in d.items() if now - float((v or {}).get("at", 0)) > _REQ_TTL]:
        d.pop(k, None)
    entry = {"agent": agent, "instance": instance or "-",
             "reason": (reason or "").strip()[:300],
             "minutes": max(1, min(int(minutes or 15), 120)),
             "human": human, "at": now}
    d[_key(agent, instance)] = entry
    _req_save(d)
    return {"pending": True, **entry}


def list_requests() -> list:
    """Richieste pending non scadute (per il popup dell'owner)."""
    now = time.time()
    d = _req_load()
    dead = [k for k, v in d.items() if now - float((v or {}).get("at", 0)) > _REQ_TTL]
    if dead:
        for k in dead:
            d.pop(k, None)
        _req_save(d)
    return [{"agent": v["agent"], "instance": v.get("instance", "-"),
             "reason": v.get("reason", ""), "minutes": v.get("minutes", 15),
             "human": v.get("human"), "age_s": int(now - float(v.get("at", 0)))}
            for v in d.values()]


def resolve_request(agent: str, instance: str) -> bool:
    """Rimuove una richiesta pending (dopo approvazione o rifiuto)."""
    d = _req_load()
    k = _key(agent, instance)
    if k in d:
        d.pop(k, None)
        _req_save(d)
        return True
    return False

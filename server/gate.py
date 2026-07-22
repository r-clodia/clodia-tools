"""M-gate — supervisione umana sui verbi *gated* (sostituisce M-sudo).

Un verbo *gated* richiede una **conferma umana** a ogni esecuzione, chiunque la
inneschi. Il gate NON concede tool nuovi: è un checkpoint su azioni **già
permesse** dalla RBAC (chi non è autorizzato resta negato, nessun gate). Chi
approva presta la PROPRIA autorità → può approvare solo i verbi per cui la sua
RBAC lo autorizza (owner=tutto; utente=sottoinsieme). Vedi `m-gate.md`.

Questo modulo è la **policy** del gate. La macchina delle capability (ccap1
firmate dalla CA: grant/active/revoke/status/jti) è riusata da `sudo` (store
generico, non sudo-specifico) finché non la si rinomina. `is_gated` sostituisce
`is_super_only`; non esistono più gruppi SUDOERS/APPROVERS.
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

from . import pki_verify

LOG = logging.getLogger("clodia-tools.gate")

# Verbi/prefissi GATED: default ≈ i vecchi super-only (mutazioni di piattaforma).
# Configurabile via env CLODIA_GATED_VERBS (CSV di prefissi/verbi; un prefisso
# finisce con '.'). Vuoto = usa i default.
_DEFAULT_GATED_PREFIXES = (
    "packs.", "providers.", "mcp.", "agents.", "settings.", "pki.", "ca.",
)
_DEFAULT_GATED_EXACT = frozenset({
    "workflows.terminate", "workflows.start", "workflows.cancel", "workflows.delete",
})


def _configured():
    raw = [x.strip() for x in os.environ.get("CLODIA_GATED_VERBS", "").split(",") if x.strip()]
    if not raw:
        return _DEFAULT_GATED_PREFIXES, _DEFAULT_GATED_EXACT
    prefixes = tuple(x for x in raw if x.endswith("."))
    exact = frozenset(x for x in raw if not x.endswith("."))
    return prefixes, exact


def is_gated(verb: str) -> bool:
    """True se `verb` è nell'insieme gated → richiede conferma umana."""
    t = verb or ""
    prefixes, exact = _configured()
    if t in exact:
        return True
    return any(t.startswith(p) for p in prefixes)


def gated_verbs_spec() -> dict:
    """Per la UI/introspezione: l'insieme gated effettivo."""
    prefixes, exact = _configured()
    return {"prefixes": list(prefixes), "exact": sorted(exact)}


# ── Store dei CONSENSI (capability ccap1 firmate dalla CA) ───────────────────
# Un consenso è per (agent, instance, verb): l'umano approva l'uso di QUEL verbo
# da parte di QUELL'istanza. Riusa la stessa macchina crittografica di M-sudo
# (ccap1 + jti + revoca) ma scoped al verbo (cap = "gate:<verb>").
def _data() -> Path:
    return Path(os.environ.get("CLODIA_DATA", "/datadir"))


def _store_path() -> Path:
    return _data() / "clodia-tools-gate.json"


def _revoked_path() -> Path:
    return _data() / "clodia-tools-gate-revoked.json"


def _load(p: Path) -> dict:
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001
        return {}


def _save(p: Path, d: dict) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps(d, ensure_ascii=False), encoding="utf-8")
    tmp.replace(p)


def _key(agent: str, instance: str, verb: str) -> str:
    return f"{agent}|{instance or '-'}|{verb}"


def cap_for(verb: str) -> str:
    """Etichetta `cap` della capability per un verbo gated."""
    return f"gate:{verb}"


def _revoked() -> set:
    return set(_load(_revoked_path()).get("jti", []))


def _revoke_jti(jti: str) -> None:
    if not jti:
        return
    s = _revoked()
    s.add(jti)
    _save(_revoked_path(), {"jti": sorted(s)})


def grant(agent: str, instance: str, verb: str, token: str) -> dict:
    """Registra un consenso per (agent, instance, verb) da una capability ccap1
    firmata dalla CA. Verifica firma + agente + `cap`=gate:<verb>. Memorizza jti+exp
    autoritativi dal payload firmato."""
    payload = pki_verify.verify_capability(token)  # solleva se firma/scadenza KO
    if payload.get("agent") != agent:
        raise PermissionError("capability intestata ad altro agente")
    if str(payload.get("cap") or "") != cap_for(verb):
        raise PermissionError("capability non per questo verbo")
    d = _load(_store_path())
    now = time.time()
    d = {k: v for k, v in d.items() if float((v or {}).get("exp", 0)) > now}  # prune
    d[_key(agent, instance, verb)] = {
        "exp": float(payload.get("exp", 0)), "jti": str(payload.get("jti") or ""),
        "by": str(payload.get("by") or ""), "token": token, "at": now}
    _save(_store_path(), d)
    return {"agent": agent, "instance": instance, "verb": verb,
            "expires_in_s": int(float(payload.get("exp", 0)) - now)}


def active(agent: str, instance: str, verb: str) -> bool:
    """True se esiste un consenso valido per (agent, instance, verb): ri-verifica
    firma CA + scadenza + jti non revocato + cap=gate:<verb>."""
    d = _load(_store_path())
    v = d.get(_key(agent, instance, verb))
    if not v:
        return False
    tok = v.get("token")
    if not tok:
        return False
    try:
        payload = pki_verify.verify_capability(tok)
    except PermissionError as e:
        LOG.warning("consenso gate %s@%s:%s non valido: %s", agent, instance, verb, e)
        return False
    if payload.get("agent") != agent or str(payload.get("cap") or "") != cap_for(verb):
        return False
    if str(payload.get("jti") or "") in _revoked():
        return False
    return True


def consume(agent: str, instance: str, verb: str) -> None:
    """Consuma (revoca) il consenso dopo l'uso: il gate è per-azione, non un
    lasciapassare riusabile. Idempotente."""
    d = _load(_store_path())
    k = _key(agent, instance, verb)
    v = d.pop(k, None)
    if v:
        _revoke_jti(str(v.get("jti") or ""))
        _save(_store_path(), d)


# ── Richieste di gate (qualunque agente → approva l'umano in-contesto) ───────
_REQ_TTL = 30 * 60


def _req_path() -> Path:
    return _data() / "clodia-tools-gate-requests.json"


def request(agent: str, instance: str, verb: str, *, context: Optional[str] = None,
            human: Optional[str] = None, chat: Optional[str] = None,
            mode: str = "sync", reason: str = "") -> dict:
    """Crea/aggiorna una richiesta di gate PENDING per (agent, instance, verb).
    Nessuna restrizione su CHI richiede: il gate è sul verbo (che il richiedente
    ha già). `chat`/`context` = dove approvare; `mode` = sync|async."""
    d = _load(_req_path())
    now = time.time()
    d = {k: v for k, v in d.items() if now - float((v or {}).get("at", 0)) <= _REQ_TTL}
    rid = _key(agent, instance, verb)
    d[rid] = {"agent": agent, "instance": instance or "-", "verb": verb,
              "context": context, "human": human, "chat": chat, "mode": mode,
              "reason": (reason or "")[:300], "at": now}
    _save(_req_path(), d)
    return {"pending": True, "id": rid, **d[rid]}


def list_requests() -> list:
    d = _load(_req_path())
    now = time.time()
    live = {k: v for k, v in d.items() if now - float((v or {}).get("at", 0)) <= _REQ_TTL}
    if len(live) != len(d):
        _save(_req_path(), live)
    return [{"id": k, "agent": v["agent"], "instance": v.get("instance", "-"),
             "verb": v["verb"], "context": v.get("context"), "human": v.get("human"),
             "chat": v.get("chat"), "mode": v.get("mode", "sync"),
             "reason": v.get("reason", ""), "age_s": int(now - float(v.get("at", 0)))}
            for k, v in live.items()]


def resolve_request(agent: str, instance: str, verb: str) -> bool:
    d = _load(_req_path())
    k = _key(agent, instance, verb)
    if k in d:
        d.pop(k, None)
        _save(_req_path(), d)
        return True
    return False


def request_pending(agent: str, instance: str, verb: str) -> bool:
    """True se la richiesta per (agent, instance, verb) è ancora PENDING (non
    ancora decisa). Usato dal block-and-wait per distinguere 'in attesa' da
    'negata' (resolve senza consenso)."""
    now = time.time()
    v = _load(_req_path()).get(_key(agent, instance, verb))
    return bool(v and now - float(v.get("at", 0)) <= _REQ_TTL)

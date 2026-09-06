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


def _request(method: str, path: str, body: dict | None = None) -> dict:
    tok = whitelist.current_token()
    headers = {"Authorization": f"Bearer {tok}"} if tok else {}
    with httpx.Client(timeout=_TIMEOUT) as c:
        r = c.request(method, f"{AGENT_SERVER_URL}{path}", json=body, headers=headers)
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
def _archseed_card() -> dict:
    """La scheda dell'ARCISEED, costruita dalla sua definizione nel gateway.

    Non è un seed del pack, e questo è deliberato: l'autorità dev'essere
    irraggiungibile dal suo soggetto (§3.5), e i seed del pack vivono nella
    datadir, che l'agent-server scrive. Come codice sul volume del gateway, «i
    due livelli esistono» è vero su ogni istanza invece di dipendere da un file
    che qualcuno deve aver creato.

    Ma non essere un file non è una ragione per essere **invisibile**: si vedeva
    che un verbo veniva dall'arciseed e non si poteva aprire l'arciseed. La §1.4
    chiede che l'insieme risolto sia leggibile, e un antenato che non si ispeziona
    lascia metà della domanda senza risposta.

    `immutable` e `source: gateway` dicono la cosa che serve a chi la legge: non
    si modifica da qui, e non perché sia protetto — perché non è un file.
    """
    from .. import whitelist as _wl
    verbi = list(_wl.archseed_tools())
    return {
        "name": _wl.ARCHSEED,
        "type": "archseed",
        "display_name": "Archseed",
        "description": ("Antenato astratto di ogni seed: tiene i verbi base — la "
                        "propria memoria, la lettura dello scope in cui lo spawn "
                        "sta, e la parola. Non si spawna."),
        "immutable": True,
        "abstract": True,
        "source": "gateway",
        "capabilities": [],
        "rules": [],
        "tool_permissions": verbi,
        "verbs": {v: _wl.ARCHSEED for v in verbi},
    }


def list_agents() -> dict:
    """Tutti gli agent con tipo e immutabilità (per scegliere un target).

    L'arciseed compare in testa: è l'antenato di tutti, e un elenco che lo omette
    fa sembrare che i verbi base vengano dal nulla.
    """
    from .. import whitelist as _wl
    out = [{"name": _wl.ARCHSEED, "type": "archseed",
            "display_name": "Archseed", "immutable": True, "abstract": True}]
    out += [{"name": a.get("name"), "type": a.get("type"),
             "display_name": a.get("display_name"), "immutable": _immutable(a)}
            for a in _all_agents()]
    return {"count": len(out), "agents": out}


def show(name: str) -> dict:
    """Capability correnti di un agent (skill/rules/tool) + immutabilità."""
    from .. import whitelist as _wl
    if str(name or "") == _wl.ARCHSEED:
        return _archseed_card()
    a = _find(name)
    if a is None:
        raise ValueError(f"agent '{name}' non trovato")
    # `tool_permissions` è ciò che il seed DICHIARA; `verbs` è ciò che vale
    # davvero, con l'origine di ogni riga (§1.4). Convivono di proposito: senza
    # la prima non si sa cosa toccare per cambiare, senza la seconda non si sa
    # cosa l'agente può fare — e con l'ereditarietà le due cose hanno smesso di
    # coincidere.
    from .. import whitelist as _wl
    try:
        verbs = _wl.tools_with_provenance(name)
    except Exception:  # noqa: BLE001 — la scheda si apre anche se la risoluzione fallisce
        verbs = {}
    return {"name": name, "type": a.get("type"), "immutable": _immutable(a),
            "capabilities": a.get("capabilities", []) or [],
            "rules": a.get("rules", []) or [],
            "tool_permissions": a.get("tool_permissions", []) or [],
            "verbs": verbs,
            "abstract": bool(_wl.is_abstract(name))}


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


# ── l'esito si MISURA, non si dichiara ───────────────────────────────────────
#
# `grant_tool` rispondeva `{"ok": true}` avendo scritto la datadir, che non è
# dove si decide: l'autorizzazione si legge da `allowed_tools` nella config del
# gateway (clodia-platform#304). Un permesso concesso restava negato a ogni
# chiamata e — direzione peggiore — una revoca non toglieva niente.
#
# La correzione ha due metà, e questa è la seconda: la prima fa arrivare la
# modifica dove si decide (`patch_agent_caps` registra nel gateway), questa
# verifica che ci sia arrivata. Serve anche quando la prima c'è: un verbo può
# restare attivo perché lo eredita da un antenato o da un wildcard, e toglierlo
# dai `tool_permissions` propri non lo toglie affatto.
#
# La verifica usa `origin.agent_may`, cioè la funzione dell'ENFORCEMENT. Non una
# lettura scritta per l'occasione: tre lettori disallineati della stessa matrice
# sono già costati un verbo concesso da un percorso e negato da un altro.
def _covering(name: str, tool: str) -> tuple[str | None, str | None]:
    """La riga che copre `tool` fra i verbi effettivi, e la sua ORIGINE.

    Esatta, poi `ns.*`, poi `*`: un permesso ereditato da un wildcard non compare
    come voce propria, ed è precisamente il caso in cui una revoca sembra fatta e
    non toglie niente.
    """
    from .. import whitelist as _wl
    try:
        prov = _wl.tools_with_provenance(name)
    except Exception:  # noqa: BLE001
        return None, None
    ns = tool.split(".", 1)[0] if "." in tool else ""
    for riga in (tool, f"{ns}.*" if ns else None, "*"):
        if riga and riga in prov:
            return riga, prov[riga]
    return None, None


def _measure(name: str, tool: str, atteso: bool) -> dict:
    """Stato REALE del verbo dopo la scrittura, con la ragione se non combacia."""
    from .. import whitelist as _wl
    from .. import origin as _origin
    try:
        _wl.reload_config()          # la registrazione può essere appena arrivata
        effettivo = bool(_origin.agent_may(name, tool))
    except Exception as e:  # noqa: BLE001
        # Non si finge un esito: «non ho potuto misurare» è un caso esplicito, e
        # va detto con le stesse lettere maiuscole di un rifiuto.
        return {"ok": False, "effective": None, "verified": False,
                "detail": f"verifica non riuscita ({type(e).__name__}): l'esito "
                          f"di questa operazione NON è stato confermato"}
    riga, origine = _covering(name, tool)
    out: dict = {"ok": effettivo == atteso, "effective": effettivo,
                 "verified": True, "granted_by": riga, "inherited_from": origine}
    if effettivo == atteso:
        # La durata si dice SEMPRE, anche quando è andata bene: un grant
        # d'istanza torna indietro al primo Update del pack, e scoprirlo due
        # update dopo è lo stesso difetto di prima con un ritardo più lungo.
        out["persistence"] = "instance"
        out["note"] = ("vale su QUESTA istanza; un Update del pack riscrive il "
                       "seed e la registrazione: per renderla permanente serve "
                       "modificare i `tool_permissions` del seed nel pack")
        return out
    if not atteso and effettivo:
        if riga and origine and origine != "own":
            out["detail"] = (
                f"'{tool}' è ANCORA attivo per '{name}': non veniva dai suoi "
                f"`tool_permissions` ma da '{riga}' ereditato da '{origine}'. "
                f"Toglierlo dalla propria lista non lo toglie: la sottrazione di "
                f"un verbo ereditato si fa con `denied_tools` nel seed, che batte "
                f"anche i wildcard.")
        elif riga and riga != tool:
            out["detail"] = (
                f"'{tool}' è ANCORA attivo per '{name}': lo copre il wildcard "
                f"'{riga}' nella sua lista. Va tolto quello, o sottratto con "
                f"`denied_tools` nel seed.")
        else:
            out["detail"] = (
                f"'{tool}' è ANCORA attivo per '{name}' dopo la revoca. La "
                f"scrittura sulla datadir non ha raggiunto la whitelist del "
                f"gateway, che è dove si decide: la revoca NON è applicata.")
        return out
    if atteso and not effettivo:
        if _wl.agent_denies(tool, name):
            out["detail"] = (
                f"'{tool}' resta NEGATO a '{name}': compare nei suoi "
                f"`denied_tools`, che battono ogni concessione. Il permesso è "
                f"scritto ma non ha effetto finché quel deny non viene tolto dal "
                f"seed.")
        else:
            out["detail"] = (
                f"'{tool}' NON è stato concesso a '{name}': la scrittura sulla "
                f"datadir non ha raggiunto la whitelist del gateway, che è dove "
                f"si decide. Il permesso è dichiarato e inerte.")
    return out


def grant_tool(name: str, tool: str) -> dict:
    res = _modify(name, "tool_permissions", add=[tool])
    return {**res, "tool": tool, **_measure(name, tool, atteso=True)}


def revoke_tool(name: str, tool: str) -> dict:
    res = _modify(name, "tool_permissions", remove=[tool])
    return {**res, "tool": tool, **_measure(name, tool, atteso=False)}


def grant_rule(name: str, rule: str) -> dict:
    return _modify(name, "rules", add=[rule])


def revoke_rule(name: str, rule: str) -> dict:
    return _modify(name, "rules", remove=[rule])


def grant_scoped(name: str, body: dict, approval_token: str) -> dict:
    payload = dict(body)
    payload.pop("agent", None)
    if not payload.get("scope_id"):
        chat = whitelist.current_chat() or ""
        if payload.get("scope_kind", "topic") == "topic" and chat.startswith("chan:"):
            parts = chat.split(":")
            if len(parts) >= 3:
                payload["scope_id"] = f"{parts[1]}/{parts[2]}"
        elif payload.get("scope_kind") == "chat" and chat:
            payload["scope_id"] = chat
    if not payload.get("scope_id"):
        raise ValueError("scope_id richiesto fuori da una chat di canale")
    payload.setdefault("scope_kind", "topic")
    payload["approval_token"] = approval_token
    return _request("POST", f"/api/agents/{name}/scoped-overrides", payload)


def list_scoped(name: str) -> dict:
    return _request("GET", f"/api/agents/{name}/scoped-overrides")


def revoke_scoped(name: str, override_id: str, approval_token: str) -> dict:
    return _request(
        "DELETE", f"/api/agents/{name}/scoped-overrides/{override_id}",
        {"approval_token": approval_token},
    )

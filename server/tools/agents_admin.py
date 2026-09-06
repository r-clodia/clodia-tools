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

SCRIVERE NON È AUTORIZZARE (clodia-platform#304). Per i `tool_permissions` la
datadir è la DICHIARAZIONE; l'autorizzazione è la whitelist del gateway, che
l'agent-server non raggiunge per progetto (§3.5) e che si sincronizza dal seed
del pack. Le due possono divergere, e finché `grant_tool` rispondeva solo
`{"ok": true}` la divergenza era invisibile: il permesso compariva nel file e
ogni chiamata veniva rifiutata. Da qui `_authority_report`, che dopo la scrittura
verifica e lo dice.
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


# ── l'autorizzazione EFFETTIVA, che non è quella che questo verbo scrive ──────
#
# `_patch_caps` scrive nella DATADIR. L'autorizzazione si legge dalla whitelist
# del GATEWAY, che per progetto è irraggiungibile dall'agent-server (§3.5) e si
# sincronizza dal seed del pack. Le due cose non coincidono, e finché la risposta
# diceva solo `{"ok": true}` la differenza era invisibile: il permesso compariva
# nel file, l'agente lo vedeva in lista, e ogni chiamata veniva rifiutata con un
# messaggio che sembrava un problema di ruolo (clodia-platform#304).
#
# Qui non si CONCEDE dal gateway — sarebbe la seconda via della issue, e apre una
# decisione che non è dello sviluppatore (cosa succede quando la sincronizzazione
# dal seed sovrascrive un grant d'istanza). Qui si VERIFICA e si dice com'è
# andata, che è meno comodo e più onesto.

#: Dove sta l'autorità, e per che via si cambia. Va scritto in chiaro nella
#: risposta: senza, un «non ha funzionato» costa un'altra indagine.
_AUTHORITY = ("l'autorità è la whitelist del gateway (`allowed_tools` in "
              "clodia-tools-config.yaml), che questo verbo non tocca e che si "
              "sincronizza dal seed del pack.")
_ROUTE_ADD = (f"{_AUTHORITY} Per renderlo effettivo: aggiungi il verbo ai "
              "`tool_permissions` del seed NEL PACK e aggiorna il pack (`packs.*`) "
              "— un grant di sola istanza tornerebbe comunque indietro al primo "
              "Update.")
_ROUTE_DEL = (f"{_AUTHORITY} Per toglierlo davvero: togli il verbo dai "
              "`tool_permissions` del seed NEL PACK e aggiorna il pack (`packs.*`).")


def _may(agent: str, verb: str) -> bool:
    """Il verbo è autorizzato per l'agente? Stessa funzione che decide al
    dispatch: un secondo lettore della matrice direbbe prima o poi una cosa
    diversa da quella che vale davvero (è già successo, `whitelist.effective_tools`).
    """
    from .. import origin
    return origin._agent_may(agent, verb)


def _origin_of(agent: str, verb: str) -> str | None:
    """Da dove arriva il verbo: `own`, il seed che lo eredita, o `archseed`.

    Serve alla revoca, e non è un dettaglio: un verbo proprio si toglie
    dall'agente, uno ereditato si sottrae con `denied_tools`. Sono due rimedi
    diversi, e sbagliarli significa modificare un file e vedere che non cambia
    niente. Il wildcard va risolto qui: la provenienza è chiavata sul pattern
    dichiarato (`topic.*`), non sul verbo puntuale che si sta revocando.
    """
    prov = whitelist.tools_with_provenance(agent) or {}
    ns = f"{verb.split('.', 1)[0]}.*" if "." in verb else None
    for k in (verb, ns, "*"):
        if k and k in prov:
            return str(prov[k])
    return None


def _authority_report(agent: str, verb: str, granting: bool) -> dict:
    """Cosa vale davvero dopo la scrittura, e cosa fare se non è quel che si
    voleva. `effective`/`still_authorized` a `None` è il terzo stato — «non ho
    potuto controllare» — e non va nascosto dentro un `true`: sarebbe la stessa
    bugia rimessa dov'era."""
    key = "effective" if granting else "still_authorized"
    route = _ROUTE_ADD if granting else _ROUTE_DEL
    try:
        may = bool(_may(agent, verb))
    except Exception as e:  # noqa: BLE001 — il verbo ha già scritto: non si rialza
        return {"ok": True, key: None,
                "detail": (f"«{verb}» è stato scritto nella datadir di «{agent}», ma "
                           f"l'autorizzazione effettiva non è verificabile da qui "
                           f"({type(e).__name__}): {route}")}
    if granting and not may:
        if whitelist.agent_denies(verb, agent):
            why = (f"«{verb}» è nella `denied_tools` di «{agent}»: il deny vince su "
                   "ogni allow, inclusi i wildcard, quindi va tolto di lì e "
                   f"aggiungerlo altrove non lo riporta indietro. Per il resto, {route}")
        else:
            why = (f"«{verb}» è stato scritto nei `tool_permissions` di «{agent}» "
                   f"nella datadir, ma NON è autorizzato: {route}")
        return {"ok": False, key: False, "detail": why}
    if not granting and may:
        prov = _origin_of(agent, verb) or "sconosciuta"
        eredita = prov not in ("own", "sconosciuta")
        rimedio = (
            f"Arriva da «{prov}»: toglierlo dall'agente non toglie ciò che eredita, "
            "va sottratto con `denied_tools` nel suo seed."
            if eredita else
            f"Origine: {prov}. {route} Se invece risultasse ereditato da un antenato, "
            "il rimedio è un altro: si sottrae con `denied_tools` nel seed.")
        return {"ok": False, key: True, "detail": (
            f"«{verb}» è stato tolto dai `tool_permissions` di «{agent}» nella "
            f"datadir, ma resta AUTORIZZATO. {rimedio}")}
    return {"ok": True, key: may if granting else False}


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
    out = {"ok": True, "name": name, field: res.get(field, cur)}
    # Solo per i verbi: skill e rule le consuma l'agent-server dalla datadir,
    # cioè proprio dove questa scrittura arriva, e un avviso lì sarebbe un falso
    # allarme. La verifica sta QUI, nell'unico punto che scrive, e non nei sei
    # wrapper: tre letture parallele della stessa matrice hanno già divergito una
    # volta (whitelist.effective_tools).
    if field == "tool_permissions":
        verbo = (add or remove or [None])[0]
        if verbo:
            out["written"] = True
            out.update(_authority_report(name, str(verbo), granting=bool(add)))
    return out


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

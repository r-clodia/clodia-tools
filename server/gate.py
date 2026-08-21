"""M-gate — supervisione umana sui verbi *gated*.

Un verbo *gated* richiede una **conferma umana** a ogni esecuzione, chiunque la
inneschi. Il gate NON concede tool nuovi: è un checkpoint su azioni **già
permesse** dalla RBAC (chi non è autorizzato resta negato, nessun gate). Chi
approva presta la PROPRIA autorità → può approvare solo i verbi per cui la sua
RBAC lo autorizza (owner=tutto; utente=sottoinsieme). Vedi `m-gate.md`.

Questo modulo contiene sia la **policy** sia la macchina delle capability ccap1
firmate dalla CA (grant/active/revoke/status/jti). Non esistono gruppi di agenti
eleggibili all'elevazione: il controllo è sempre scoped al verbo.
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

from . import pki_verify, state_paths

LOG = logging.getLogger("clodia-tools.gate")

# Verbi/prefissi GATED: default ≈ i vecchi super-only (mutazioni di piattaforma).
# Configurabile via env CLODIA_GATED_VERBS (CSV di prefissi/verbi; un prefisso
# finisce con '.'). Vuoto = usa i default.
# Gate SOLO i verbi MUTANTI (non le letture). Prefissi per famiglie in cui ogni
# verbo è sensibile (settings/pki/ca); elenco esatto per le famiglie che hanno
# anche letture (agents/mcp/packs/providers → list/show NON gated).
# ── La REGOLA, invece della lista ────────────────────────────────────────────
#
# Un gate non è una proprietà del verbo: è ciò che accade quando un'azione
# ATTRAVERSA un confine, o quando chi la chiede non ne ha titolo
# (system-notebook 23, emendata dalla 26).
#
# Fino al 7 ago 2026 questa era una lista piatta di nomi. La lista funzionava,
# ma la REGOLA non si vedeva: ogni verbo nuovo obbligava un umano a indovinare
# in quale secchio andasse, ed è così che i meccanismi di gating sono diventati
# quattro. Classificarli non cambia il comportamento — cambia che la regola sia
# leggibile e che un verbo nuovo abbia un posto ovvio.
#
# Tre classi, misurate sui 28 verbi della lista il 6 ago:
#
#   SYSTEM    cambiano le REGOLE del sistema, non una risorsa di uno scope.
#             Oggi 16 + tre prefissi. Quando esisterà il topic di configurazione
#             (voce 22) diventeranno scritture in quello scope, e questa classe
#             si dissolverà nelle altre due.
#   WALLS     cambiano chi sta in uno scope o quanto è largo. Il gate va
#             all'OWNER dello scope (voce 24), non a un admin qualunque.
#   OUTWARD   attraversano il confine verso fuori.
#
# Non esiste una quarta classe «usa una risorsa del tuo scope»: la riga era vuota
# quando l'ho misurata, e deve restarlo. Se un verbo finisse lì, sarebbe un gate
# sul lavoro dentro la stanza — cioè la cosa che la voce 23 dice di non fare.
GATE_SYSTEM = "system"
GATE_WALLS = "walls"
GATE_OUTWARD = "outward"

_GATE_CLASS = {
    # SYSTEM — cambiano le regole
    "agents.grant_rule": GATE_SYSTEM, "agents.grant_skill": GATE_SYSTEM,
    "agents.grant_tool": GATE_SYSTEM, "agents.revoke_rule": GATE_SYSTEM,
    "agents.revoke_skill": GATE_SYSTEM, "agents.revoke_tool": GATE_SYSTEM,
    "agents.grant_scoped": GATE_SYSTEM, "agents.revoke_scoped": GATE_SYSTEM,
    "mcp.add": GATE_SYSTEM, "mcp.remove": GATE_SYSTEM,
    "packs.import_url": GATE_SYSTEM, "packs.remove": GATE_SYSTEM,
    "packs.install_pip": GATE_SYSTEM, "packs.install_npm": GATE_SYSTEM,
    "providers.pause": GATE_SYSTEM, "providers.resume": GATE_SYSTEM,
    # WALLS — chi sta nello scope, o quanto è largo
    "topic.add_participant": GATE_WALLS,
    # Collegare un gruppo Telegram porta la stanza FUORI: le menzioni, e con
    # `excerpt` anche una riga di testo, arrivano a persone che nel topic non
    # entrano. È un atto sui muri, come aggiungere un partecipante — e infatti
    # è la stessa cosa vista dall'altro lato.
    "topic.telegram_bind": GATE_WALLS, "topic.telegram_unbind": GATE_WALLS,
    "topic.set_portable": GATE_WALLS, "topic.remove_participant": GATE_WALLS,
    "topic.remote_add": GATE_WALLS, "topic.remote_enable": GATE_WALLS,
    "topic.remote_disable": GATE_WALLS,
    # OUTWARD — verso fuori
    "web.post": GATE_OUTWARD,
    # `github.push` e `github.pull_request` portano FUORI il lavoro fatto nella
    # scratch: il codice esce dallo scope e, sulla pull request, titolo e corpo
    # diventano leggibili sul repository. `github.clone` e `github.pull` portano
    # DENTRO, e non sono gated per la stessa ragione per cui non lo è
    # `remote_pull`: tirare dentro non sposta il confine — è già la lista dei
    # repository approvati a dire da dove si può tirare.
    "github.push": GATE_OUTWARD, "github.pull_request": GATE_OUTWARD,
    "egress.allow": GATE_OUTWARD, "ingress.allow": GATE_OUTWARD,
    "topic.save_agents_md": GATE_WALLS,
}

_PREFIX_CLASS = {
    "settings.": GATE_SYSTEM, "pki.": GATE_SYSTEM, "ca.": GATE_SYSTEM,
    # `egress:<tipo>:<destinazione>` — la chiave di un gate per DESTINAZIONE, non
    # per verbo (`egress.gate_key`). Non era classificata, e il 10 ago 2026 la
    # card l'ha detto: «attraversa un confine che il gateway non ha
    # classificato». Il messaggio era corretto e la lacuna vera — chiedere a
    # qualcuno di approvare un'uscita senza dirgli che È un'uscita è la cosa che
    # la classificazione esiste per evitare.
    #
    # È `outward` per definizione: una destinazione nuova è esattamente il
    # momento in cui qualcosa lascia la stanza.
    "egress:": GATE_OUTWARD,
}


def gate_class(verb: str) -> str | None:
    """In quale classe cade questo verbo? `None` se non è gated."""
    if verb in _GATE_CLASS:
        return _GATE_CLASS[verb]
    for pref, cls in _PREFIX_CLASS.items():
        if verb.startswith(pref):
            return cls
    return None


_DEFAULT_GATED_PREFIXES = (
    "settings.", "pki.", "ca.",
)
_DEFAULT_GATED_EXACT = frozenset({
    # agents: mutazioni delle capability (grant/revoke); list/show/list_* NON gated
    "agents.grant_rule", "agents.grant_skill", "agents.grant_tool",
    "agents.revoke_rule", "agents.revoke_skill", "agents.revoke_tool",
    "agents.grant_scoped", "agents.revoke_scoped",
    # mcp: add/remove nuova superficie di codice; mcp.list NON gated
    "mcp.add", "mcp.remove",
    # packs: install/remove esegue codice terzi; packs.list/show NON gated.
    # install_pip/install_npm eseguono il codice del pacchetto (setup.py /
    # postinstall) nel gateway → stesso rischio di import_url, quindi gated.
    # check_command è read-only (verifica presenza binario) → NON gated.
    "packs.import_url", "packs.remove",
    "packs.install_pip", "packs.install_npm",
    # providers: pausa/ripresa (egress dati); providers.list NON gated
    "providers.pause", "providers.resume",
    # gestione partecipanti di un topic (auto-invito / confused-deputy)
    "topic.add_participant", "topic.set_portable", "topic.remove_participant",
    "topic.telegram_bind", "topic.telegram_unbind",
    # Il remote Drive di un topic È il suo perimetro di accesso (la cartella del
    # remote è la radice del confine per le chiamate dentro quel canale). Quindi
    # impostarlo, cambiarlo o TOGLIERLO non è una preferenza: è una dichiarazione
    # di autorità, e va autorizzata come tale — per un umano un verbo gated
    # richiede il ruolo admin.
    #
    # `remote_disable` è nella lista per la ragione meno ovvia: disabilitare il
    # remote fa ricadere gli accessi sulle radici d'ACCOUNT, che possono essere
    # più larghe. Togliere il perimetro è un allargamento.
    #
    # `remote_status` e `remote_pull` NON sono gated: leggere lo stato e tirare
    # dentro i contenuti non spostano il confine.
    "topic.remote_add", "topic.remote_enable", "topic.remote_disable",
    # Le istruzioni di scope entrano nel contesto di OGNI agente della stanza a
    # OGNI turno: scriverle è un atto di autorità, non una preferenza. Finché il
    # gate non sarà rivolto all'owner dello scope (modello «titolo», voci 23-25
    # del system-notebook) qui vale la regola generale — per un umano un verbo
    # gated richiede il ruolo admin.
    "topic.save_agents_md",
    # HTTP egress mutante: consenso umano obbligatorio per ogni singola POST.
    "web.post",
    # Uscita di codice dallo scope. Il perimetro (la lista dei repository) dice
    # DOVE si può spingere; il gate dice che spingere è un atto, non un dettaglio
    # del lavoro.
    #
    # Erano due controlli indipendenti, e dal 17 ago 2026 non lo sono più: verso
    # una destinazione CENSITA il gate non chiede (`needs_consent`), perché
    # sarebbe la stessa decisione presa due volte — otto card per `create_branch`
    # in un giorno solo. Restano gated i push FUORI dal perimetro, che è dove il
    # confine si sposta. Chi rimette il gate incondizionato qui riapre #254.
    "github.push", "github.pull_request",
    # Allargamento delle whitelist: `allow` rende silenziosa una destinazione o
    # una fonte da lì in avanti, quindi è più privilegiato di qualunque singola
    # invocazione che consentirebbe. `revoke` e `list` NON sono gated: togliere
    # autorità e leggerla non richiedono un consenso.
    "egress.allow", "ingress.allow",
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


#: Verbi `outward` a cui il perimetro NON risponde, benché una destinazione ce
#: l'abbiano. `web.post` è l'unico: `egress._http()` riduce la destinazione a
#: `schema://host/` e BUTTA il path, quindi «host censito» non promette quello
#: che promette «repository censito» — e ciò che una POST porta a un host
#: approvato, su un path che nessuno ha guardato, è un corpo arbitrario.
_PERIMETER_BLIND = frozenset({"web.post"})


def perimeter_answers(verb: str) -> bool:
    """Il perimetro (la whitelist di destinazioni) risponde alla domanda di
    QUESTO gate?

    Solo per la classe `outward`. Un gate `system` chiede «devono cambiare le
    regole?» e uno `walls` «chi sta nella stanza?»: sono domande su cui una
    lista di destinazioni non ha nulla da dire, e farle tacere con essa
    sarebbe un controllo che spegne un altro controllo.
    """
    if (verb or "") in _PERIMETER_BLIND:
        return False
    return gate_class(verb) == GATE_OUTWARD


def needs_consent(verb: str, *, globally_gated: bool, agent_gated: bool,
                  off_profile: bool, perimeter_ok: bool) -> bool:
    """Questa chiamata deve passare da un umano?

    Tre ragioni indipendenti per chiederlo, e restano distinte nel testo della
    card perché chiedono di valutare cose diverse:

        globally_gated  il verbo è pericoloso per CHIUNQUE (`is_gated`)
        agent_gated     è pericoloso per QUESTO agente (`gated_tools`, §8)
        off_profile     lo raggiunge ma non lo dichiara (`profile_tools`)

    Una sola di esse chiede «dove sta andando questa roba», e a quella la
    whitelist ha già risposto — regola dell'owner del 17 ago 2026: una
    destinazione censita È perimetro e non è un segnale che fa scattare il gate.
    Applicarla al solo gate globale la lasciava inefficace proprio dove l'attrito
    si misura: `clodia` non dichiara `github.push` nel profilo e un dev può avere
    ancora `github.*` nei propri `gated_tools` nella copia del gateway, quindi la
    card tornava a ogni pubblicazione verso un repository già approvato
    (clodia-platform#254). Fuori dal perimetro il gate resta, ed è lì che serve.

    Funzione PURA: i tre booleani li calcola il dispatch, che sa chi chiama;
    qui sta la regola, in un punto solo, perché due copie della stessa
    condizione divergono.
    """
    if not (globally_gated or agent_gated or off_profile):
        return False
    if perimeter_ok and perimeter_answers(verb):
        return False
    return True


# ── Store dei CONSENSI (capability ccap1 firmate dalla CA) ───────────────────
# Un consenso è per (agent, instance, verb): l'umano approva l'uso di QUEL verbo
# da parte di QUELL'istanza, con ccap1 + jti + revoca e scope sul verbo
# (cap = "gate:<verb>").
# I consensi (e le revoche) sono stato DECISIONALE: vivono sul volume del solo
# gateway, non sulla datadir condivisa con l'agent-server (clodia-platform#80).
def _store_path() -> Path:
    return state_paths.state_path("clodia-tools-gate.json")


def _revoked_path() -> Path:
    return state_paths.state_path("clodia-tools-gate-revoked.json")


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


def details(agent: str, instance: str, verb: str) -> dict | None:
    """Return a valid signed consent and payload, or None."""
    d = _load(_store_path())
    v = d.get(_key(agent, instance, verb))
    if not v:
        return None
    tok = v.get("token")
    if not tok:
        return None
    try:
        payload = pki_verify.verify_capability(tok)
    except PermissionError as e:
        LOG.warning("consenso gate %s@%s:%s non valido: %s", agent, instance, verb, e)
        return None
    if payload.get("agent") != agent or str(payload.get("cap") or "") != cap_for(verb):
        return None
    if str(payload.get("jti") or "") in _revoked():
        return None
    return {**v, "payload": payload}


def active(agent: str, instance: str, verb: str) -> bool:
    """True se esiste un consenso valido per (agent, instance, verb)."""
    return details(agent, instance, verb) is not None


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
    return state_paths.state_path("clodia-tools-gate-requests.json")


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
    # `class` viaggia con la richiesta perché l'autorità sulla classificazione è
    # QUI: chi approva sta in un altro servizio e non deve riderivarla: una
    # regola duplicata diverge (è la lezione del confronto `== "admin"`).
    # `chat` è registrato da noi al momento della richiesta, da `current_chat()`
    # — claim firmato. Chi approva NON deve dirci in quale stanza si trovava
    # l'azione: sarebbe la parola di chi chiede su dove si trova.
    return [{"id": k, "agent": v["agent"], "instance": v.get("instance", "-"),
             "verb": v["verb"], "context": v.get("context"), "human": v.get("human"),
             "class": gate_class(v["verb"]),
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

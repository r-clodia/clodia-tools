"""The verbs a ROOM enables, and the ones enabled outside a room
(clodia-platform#604 · R1 #605).

Verbs are granted per seed, and a seed cannot know what a given channel will
need: in October alone fact-checker, sales-rep and officer were each blocked in
a room for a verb their seed lacked. #590 moved DATA authority to the room;
this module moves TOOL authority there too.

    meta["tools"] = {"enabled": ["email.*", "github.clone"],
                     "except": {"fact-checker": ["email.send"]}}

What an agent reaches in the room of the SIGNED claim:

- every ``topic.*`` verb, for every participant (epic decision 2). Included is
  not ungated: the verbs that move the room's walls (ingress/egress,
  participants, folders) keep their gates, and ``artifact.render`` is not a
  ``topic.`` verb — it does not ride in on this;
- the room's toolbox, minus that agent's own exceptions.

**Additive in R1** (owner's decision, 23 Oct 2026): this is added to the
resolved seed, the scoped grants and the data verbs of #590 — nothing is taken
away here. Reducing the seeds' ``tool_permissions`` to role/governance is #610.

Outside a room (a DM, a job not bound to a topic) there is no room to read the
list from: the owner's list is the instance's ``dm_tools``.

Modelled on `topic_data`: a declaration of the topic that moves an authority
the gateway already decides call by call. The gate, the deny list, the origin
chain, the egress PDP and taint are untouched — a verb enabled here still meets
every one of them.

LIMITE NOTO, lo stesso che ha #590. `origin._agent_may` misura l'autorità di un
anello della catena sul SEED risolto (`effective_tools`), senza la stanza:
con `CLODIA_ORIGIN_ENFORCE=on` una delega che passa per un agente a cui il
verbo arriva solo dalla toolbox verrebbe rifiutata. Oggi l'enforcement è
`report`, quindi il rifiuto è osservato e non applicato. Allineare l'origin ai
verbi della stanza vale per questa toolbox E per i verbi-dato di #590 insieme —
una correzione sola, in un follow-up, non due letture che divergono.
"""
from __future__ import annotations

import logging

LOG = logging.getLogger("clodia-tools.room_tools")

#: Where the toolbox lives in a topic's meta, and the instance key for the DM one.
FIELD = "tools"
DM_KEY = "dm_tools"

#: The namespace every participant gets in every room (epic decision 2).
TOPIC_NS = "topic"

WILDCARD = "*"


class ToolboxError(ValueError):
    pass


# ---------------------------------------------------------------- what is enablable

_GOVERNANCE = ("verbo di governance della piattaforma (vault, pack, job, liste "
               "globali, amministrazione): resta sul ruolo del seed")
_PER_SEED = "strumento del singolo agente, non della stanza: resta sul seed"
_ROOM_FLOOR = "già incluso in ogni stanza per ogni partecipante"
_PERSONAL = "memoria personale dell'agente: non è della stanza"
_BY_DATA = "lo concedono i dati importati nella stanza (#590), non la toolbox"

#: UNA lista sola di ciò che una stanza non abilita, con il perché — che è anche
#: il testo del rifiuto. Derivare «abilitabile» per sottrazione da ciò che il
#: gateway sa servire, invece di elencare gli ammessi, è quello che fa entrare da
#: sé un connettore nuovo: una seconda lista di ammessi sarebbe rimasta indietro
#: al primo pack installato.
_NOT_ENABLABLE: dict[str, str] = {
    # governance / ruolo (decisione 4 dell'epic)
    "agents": _GOVERNANCE,
    "egress": _GOVERNANCE,
    "ingress": _GOVERNANCE,
    "integrations": _GOVERNANCE,
    "jobs": _GOVERNANCE,
    "logs": _GOVERNANCE,
    "mcp": _GOVERNANCE,
    "native": _GOVERNANCE,
    "packs": _GOVERNANCE,
    "profile": _GOVERNANCE,
    "providers": _GOVERNANCE,
    "runtime": _GOVERNANCE,
    "settings": _GOVERNANCE,
    # strumenti del singolo agente
    "copybrain": _PER_SEED,
    "fs": _PER_SEED,
    "memory": _PERSONAL,
    # già della stanza, o governati altrove
    "topic": _ROOM_FLOOR,
    "datastore": _BY_DATA,
    "eu_corpus": _BY_DATA,
    "rag": _BY_DATA,
}


def _catalogue() -> dict[str, set[str]]:
    """Namespace → the verbs this gateway can actually serve there.

    Natives, the verbs of the loaded pack components (#558), the namespaces of
    the first-party packs' connectors (`_packaged_namespaces()`, the manifest —
    so `email.*` stays enablable through a restart in which the component has
    not been loaded yet) and the mounted MCP backends, whose verbs are the
    backend's to name. The last two appear with an EMPTY set, which reads
    «namespace known, verbs not enumerable from here».
    """
    out: dict[str, set[str]] = {}
    try:
        from . import main
        tools = list(main._all_native_tools()) + list(main._component_tools())
    except Exception as e:  # noqa: BLE001 — in doubt, nothing is enablable
        LOG.warning("catalogo dei verbi non disponibile (%s)", type(e).__name__)
        return out
    for t in tools:
        ns, _, _verb = str(getattr(t, "name", "")).partition(".")
        if ns and _verb:
            out.setdefault(ns, set()).add(t.name)
    for ns in main._packaged_namespaces():
        out.setdefault(str(ns), set())
    try:
        from .proxy import _backends
        for b in _backends():
            out.setdefault(str(b), set())
    except Exception:  # noqa: BLE001 — a backend list that does not load adds nothing
        pass
    return out


def enablable() -> dict[str, list[str]]:
    """`{namespace: [verbi]}` che l'owner può abilitare in una stanza.

    Per il pannello di #609 e per il rifiuto della rotta: una sola derivazione,
    così la UI non può proporre ciò che la rotta rifiuta.
    """
    return {ns: sorted(verbs) for ns, verbs in sorted(_catalogue().items())
            if ns not in _NOT_ENABLABLE}


def check(entry: str) -> str:
    """Normalizza una voce da abilitare, o la rifiuta DICENDO perché."""
    e = " ".join(str(entry or "").split())
    ns, sep, verb = e.partition(".")
    if not ns or not sep or not verb:
        raise ToolboxError(f"'{entry}': serve `namespace.verbo` oppure `namespace.*`")
    why = _NOT_ENABLABLE.get(ns)
    if why:
        raise ToolboxError(f"'{e}' non si abilita per stanza — {why}")
    cat = _catalogue()
    if ns not in cat:
        raise ToolboxError(f"namespace sconosciuto: '{ns}'")
    # Un backend MCP montato non espone qui i propri verbi: il namespace basta.
    if verb != WILDCARD and cat[ns] and e not in cat[ns]:
        raise ToolboxError(f"verbo sconosciuto: '{e}'")
    return e


def check_exception(entry: str) -> str:
    """Normalizza un'eccezione, o la rifiuta DICENDO perché.

    Si toglie ciò che la stanza dà: la toolbox e il pavimento `topic.*`. Un
    namespace che la stanza non dà mai (governance, per-seed, dati) non ha nulla
    da togliere — accettarlo mostrerebbe all'owner un divieto senza effetto.
    """
    e = _exceptable(entry)
    if e is None:
        raise ToolboxError(f"'{entry}': serve `namespace.verbo`, `namespace.*` oppure `*`")
    if e == WILDCARD:
        return e
    ns, _, verb = e.partition(".")
    if ns != TOPIC_NS and ns in _NOT_ENABLABLE:
        raise ToolboxError(f"'{e}' non lo dà la stanza, quindi non si toglie qui — "
                           f"{_NOT_ENABLABLE[ns]}")
    cat = _catalogue()
    if ns not in cat:
        raise ToolboxError(f"namespace sconosciuto: '{ns}'")
    if verb != WILDCARD and cat[ns] and e not in cat[ns]:
        raise ToolboxError(f"verbo sconosciuto: '{e}'")
    return e


def gated_of(enablable: dict[str, list[str]]) -> list[str]:
    """I verbi abilitabili che POSSONO chiedere una conferma (#609): il
    pannello li marca, perché abilitare non è togliere il gate (decisione 3
    dell'epic #604). «Possono», non «chiedono sempre»: `needs_consent` decide
    per chiamata (un push verso un repository censito non chiede), e i gate
    per agente non sono qui."""
    from . import gate
    return sorted(v for verbs in enablable.values() for v in verbs if gate.is_gated(v))


# ---------------------------------------------------------------- the room's toolbox

def _shape(entry) -> str | None:
    """`ns.verbo` o `ns.*`, normalizzato; `None` per qualunque altra forma.

    Un `*` nudo, un namespace vuoto o un verbo che contiene spazi non sono una
    voce di toolbox: nessuna delle due rotte li scrive, quindi se compaiono nel
    meta li ha scritti qualcun altro (review #429, B1).
    """
    e = " ".join(str(entry or "").split())
    ns, sep, verb = e.partition(".")
    if not ns or not sep or not verb or WILDCARD in ns or " " in e:
        return None
    if WILDCARD in verb and verb != WILDCARD:
        return None
    return e


def _grantable(entry) -> str | None:
    """Una voce che la stanza può davvero DARE: la forma giusta e un namespace
    abilitabile. Filtro di LETTURA, indipendente da `check()` alla scrittura:
    il meta non è scritto solo dalle rotte di questo modulo, e una voce
    `packs.*` o `*` arrivata da un'altra porta non deve concedere nulla."""
    e = _shape(entry)
    if e is None or e.partition(".")[0] in _NOT_ENABLABLE:
        return None
    return e


def _exceptable(entry) -> str | None:
    """Un'eccezione: `ns.verbo`, `ns.*` o `*` (tutto ciò che la stanza dà)."""
    e = " ".join(str(entry or "").split())
    return WILDCARD if e == WILDCARD else _shape(e)


def toolbox(meta: dict) -> dict:
    """Il contenuto di `meta["tools"]`, ridotto a ciò che una stanza può dare.

    Letto come `topic_data.imports`: voci che non si capiscono vengono scartate,
    non interpretate — una toolbox illeggibile non deve diventare permissiva.
    """
    raw = (meta or {}).get(FIELD)
    raw = raw if isinstance(raw, dict) else {}
    lst = raw.get("enabled") if isinstance(raw.get("enabled"), list) else []
    enabled = sorted({e for e in map(_grantable, lst) if e})
    exc_raw = raw.get("except") if isinstance(raw.get("except"), dict) else {}
    exc: dict[str, list[str]] = {}
    for agent, lst in exc_raw.items():
        if not isinstance(lst, list):
            continue
        verbs = sorted({v for v in map(_exceptable, lst) if v})
        if verbs:
            exc[str(agent)] = verbs
    return {"enabled": enabled, "except": exc}


def _bites(verb: str, excepted: set[str]) -> bool:
    """Un'eccezione colpisce `verb` per nome esatto, per `ns.*` o per `*`."""
    ns = verb.partition(".")[0]
    return (WILDCARD in excepted or verb in excepted
            or f"{ns}.{WILDCARD}" in excepted)


def _minus(entries: set[str], excepted: set[str]) -> set[str]:
    """`entries` meno le eccezioni di QUESTO agente.

    Un'eccezione morde per nome, per namespace (`web.*`) o su tutto (`*`). Fino
    alla review di #429 si sottraeva come stringa: `web.*` tra le eccezioni
    lasciava passare `web.fetch`, e il pannello mostrava un divieto che non
    c'era.

    Un `ns.*` abilitato si mangerebbe un'eccezione puntuale — `email.*`
    continua ad ammettere `email.send` — quindi un wildcard il cui namespace è
    toccato da un'eccezione puntuale viene ESPANSO nei verbi che il gateway
    serve, e la sottrazione morde su quelli. Se il catalogo non sa nominarli (un
    backend MCP montato, verbi non enumerabili da qui) il wildcard viene TOLTO:
    un dono che non si può tagliare dove l'owner ha chiesto non si fa.
    """
    if not excepted:
        return entries
    touched = {v.partition(".")[0] for v in excepted if v != WILDCARD}
    cat = None
    out: set[str] = set()
    for e in entries:
        ns, _, verb = e.partition(".")
        if _bites(e, excepted):
            continue
        if verb != WILDCARD or ns not in touched:
            out.add(e)
            continue
        if cat is None:
            cat = _catalogue()
        verbs = cat.get(ns) or set()
        if not verbs:
            LOG.warning("toolbox: '%s' tolto — c'è un'eccezione su '%s' e i suoi "
                        "verbi non sono enumerabili da qui", e, ns)
            continue
        out |= {v for v in verbs if not _bites(v, excepted)}
    return out


def _svc():
    from . import main
    return main._topics()


def verbs_for(agent: str | None, scope: str | None) -> set[str]:
    """I verbi che `agent` raggiunge in `scope` grazie alla STANZA (#605).

    Request-local come un grant scoped: il seed, il punteggio statico della
    trifecta e le altre stanze non cambiano. Fuori da una stanza vale la lista
    dei DM. Chi non partecipa non prende niente: il «qui» viene dal claim
    firmato, mai da un argomento.
    """
    agent = str(agent or "").strip()
    if not agent:
        return set()
    if not scope:
        return dm_verbs()
    tier, sep, name = str(scope).partition("/")
    if not (tier and sep and name):
        return set()
    try:
        meta = _svc()._read_meta(tier, name)[0]
    except Exception:  # noqa: BLE001 — no room, no verbs
        return set()
    svc = _svc()
    if agent not in svc.participants_map(meta):
        return set()
    tb = toolbox(meta)
    entries = {f"{TOPIC_NS}.{WILDCARD}"}
    # Una stanza archiviata tiene il pavimento (leggerla resta possibile) ma non
    # dà più la toolbox: nessuno lavora più lì (review #429, N2).
    if str(meta.get("status") or "").strip().lower() != "archived":
        entries |= set(tb["enabled"])
    return _minus(entries, set(tb["except"].get(agent, ())))


# ---------------------------------------------------------------- mutations (owner)

def _write(tier: str, name: str, mutate):
    svc = _svc()
    meta, ver = svc._read_meta(tier, name)
    tb = toolbox(meta)
    out = mutate(meta, tb)
    meta[FIELD] = {"enabled": sorted(set(tb["enabled"])),
                   "except": {a: sorted(set(v)) for a, v in tb["except"].items() if v}}
    svc._write_meta(tier, name, meta, base_version=ver)
    return out


def enable(tier: str, name: str, verb: str, on: bool = True) -> dict:
    """Abilita (o disabilita) un verbo nella stanza. Solo l'owner, via rotta."""
    v = check(verb) if on else " ".join(str(verb or "").split())

    def mutate(meta, tb):
        have = set(tb["enabled"])
        if on:
            have.add(v)
        else:
            have.discard(v)
        tb["enabled"] = sorted(have)
        return {"ok": True, "enabled": tb["enabled"]}
    return _write(tier, name, mutate)


def exception(tier: str, name: str, agent: str, verb: str, on: bool = True) -> dict:
    """«Tutti tranne X per questo verbo»: aggiunge o toglie un'eccezione.

    L'eccezione sottrae dal dono della STANZA, non dal seed: in R1 la
    raggiungibilità è additiva, quindi un agente che quel verbo lo ha già nel
    proprio seed continua ad averlo. Toglierlo è #610.
    """
    a = " ".join(str(agent or "").split())
    v = check_exception(verb) if on else " ".join(str(verb or "").split())
    if not a:
        raise ToolboxError("serve l'agente dell'eccezione")
    if not v:
        raise ToolboxError("serve il verbo dell'eccezione")

    def mutate(meta, tb):
        if on and a not in _svc().participants_map(meta):
            raise ToolboxError(f"'{a}' non partecipa a {tier}/{name}: non ha nulla da togliere")
        have = set(tb["except"].get(a, ()))
        have.add(v) if on else have.discard(v)
        if have:
            tb["except"][a] = sorted(have)
        else:
            tb["except"].pop(a, None)
        return {"ok": True, "except": {k: list(x) for k, x in tb["except"].items()}}
    return _write(tier, name, mutate)


# ---------------------------------------------------------------- outside a room

def dm_toolbox() -> list[str]:
    """I verbi abilitati FUORI da una stanza (decisione 5 dell'epic).

    Sta in `clodia-tools-config.yaml` come `data_access` di #596: è stato
    decisionale del gateway, in una directory che l'agent-server non monta
    (#80). Non è un file nuovo di proposito — lo stato che decide va dove il
    resto dello stato che decide è già protetto.
    """
    from . import whitelist as _wl
    raw = (_wl.CONFIG or {}).get(DM_KEY)
    if not isinstance(raw, list):
        return []
    return sorted({e for e in map(_grantable, raw) if e})


def dm_verbs() -> set[str]:
    return set(dm_toolbox())


def set_dm(verb: str, on: bool = True) -> dict:
    """`reload_config()` PRIMA di mutare, come `set_gdrive_roots`: mutare un
    CONFIG stantio riscrive sopra ciò che un altro processo ha cambiato."""
    v = check(verb) if on else " ".join(str(verb or "").split())
    from . import whitelist as _wl
    _wl.reload_config()
    have = set(dm_toolbox())
    have.add(v) if on else have.discard(v)
    _wl.CONFIG[DM_KEY] = sorted(have)
    _wl.save_config()
    return {"ok": True, DM_KEY: sorted(have)}

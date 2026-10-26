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


def gated_of(enablable: dict[str, list[str]]) -> list[str]:
    """I verbi abilitabili che POSSONO chiedere una conferma (#609): il
    pannello li marca, perché abilitare non è togliere il gate (decisione 3
    dell'epic #604). «Possono», non «chiedono sempre»: `needs_consent` decide
    per chiamata (un push verso un repository censito non chiede), e i gate
    per agente non sono qui."""
    from . import gate
    return sorted(v for verbs in enablable.values() for v in verbs if gate.is_gated(v))


# ---------------------------------------------------------------- MCPs (#620)

#: A pack whose connectors are ONE MCP for the owner (decision 3 of #620):
#: Drive, Docs, Sheets and Calendar are «Google», not four switches.
_PACK_AS_ONE: dict[str, tuple[str, str]] = {"google-pack": ("google", "Google Workspace")}

EFFECTS = ("allow", "ask", "deny")


def _registry():
    try:
        from .connectors import resolved as _c
        return _c.registry()
    except Exception as e:  # noqa: BLE001 — no registry, no connector MCPs
        LOG.warning("registro dei connettori non disponibile (%s)", type(e).__name__)
        return None


def _backend_verbs(ns: str) -> set[str]:
    """The verbs of a mounted MCP backend, if discovery has listed them."""
    try:
        from . import proxy
        return {t.name for t in proxy._TOOL_CACHE.get(ns) or []}
    except Exception:  # noqa: BLE001
        return set()


def _is_write(verb: str) -> bool:
    from . import authz_shadow as _s
    try:
        return _s.facts(verb, {})["kind"] != "read"
    except Exception:  # noqa: BLE001 — in doubt a verb writes
        return True


def _groups() -> dict[str, dict]:
    """`{mcp id: {label, kind, namespaces, connectors}}`: which namespaces make
    one MCP. A connector that `extends` another (Gmail as a provider of `mail`)
    adds a provider, not an MCP."""
    out: dict[str, dict] = {}
    reg = _registry()
    for c in (getattr(reg, "connectors", None) or ()):
        if getattr(c, "extends", ""):
            continue
        mid, label = _PACK_AS_ONE.get(c.pack, (c.namespace, c.label or c.namespace))
        g = out.setdefault(mid, {"label": label, "kind": "connector",
                                 "namespaces": set(), "connectors": set()})
        if c.namespace:
            g["namespaces"].add(c.namespace)
        g["connectors"].add(c.id)
    return out


def mcp_catalogue() -> dict[str, dict]:
    """Every MCP a room can authorise (#620), with what the panel needs.

    `verbs` and `write` as far as the gateway can name them (a backend's only
    once discovery has listed it: `enumerable` says so); `schemes` are the
    resource kinds the MCP's verbs reach, from the connector manifests, each
    with its direction and verbs — the rows of the resource panel.
    """
    cat = {ns: set(v) for ns, v in _catalogue().items() if ns not in _NOT_ENABLABLE}
    try:
        from .connectors import resolved as _c
        transports = set(_c.transport_backends())
    except Exception:  # noqa: BLE001
        transports = set()
    groups = _groups()
    owner: dict[str, str] = {}
    for mid, g in groups.items():
        for ns in g["namespaces"]:
            owner[ns] = mid
    out: dict[str, dict] = {}
    for ns, verbs in sorted(cat.items()):
        if ns in transports and ns not in owner:
            # A provider transport is a socket of the gateway, never an MCP —
            # unless a connector owns the namespace (it-pack's GitHub: the
            # backend is its transport AND `github.*` is the MCP), 26 Oct.
            continue
        mid = owner.get(ns, ns)
        g = groups.get(mid)
        e = out.setdefault(mid, {
            "id": mid, "label": (g or {}).get("label") or ns,
            "kind": (g or {}).get("kind") or ("native" if verbs else "mcp"),
            "namespaces": [], "verbs": [], "write": [], "schemes": [],
            "enumerable": True})
        e["namespaces"].append(ns)
        vv = set(verbs) or _backend_verbs(ns)
        if not vv or ns in transports:
            # Served through a transport (GitHub): the verbs the gateway can
            # name are a part of them, not the list — say so, so a «read»
            # level takes it all instead of cutting by a partial list.
            e["enumerable"] = False
        e["verbs"] = sorted(set(e["verbs"]) | vv)
    reg = _registry()
    for mid, e in out.items():
        e["write"] = sorted(v for v in e["verbs"] if _is_write(v))
        schemes: dict[tuple, set] = {}
        for c in (getattr(reg, "connectors", None) or ()):
            if c.namespace not in e["namespaces"]:
                continue
            for m in c.verbs:
                if m.scheme:
                    # A prefix mapping (`github.create_`) names a family: `*`.
                    v = f"{m.verb}*" if getattr(m, "prefix", False) else m.verb
                    schemes.setdefault((m.scheme, m.direction), set()).add(v)
        e["schemes"] = [{"scheme": sc, "direction": d, "verbs": sorted(v)}
                        for (sc, d), v in sorted(schemes.items())]
    return out


def _mcp_entries(meta: dict) -> dict:
    """The authorised MCPs and their rows as written in the meta, read
    defensively: an entry that does not parse grants nothing."""
    raw = (meta or {}).get(FIELD)
    raw = raw if isinstance(raw, dict) else {}
    mcp_raw = raw.get("mcp") if isinstance(raw.get("mcp"), dict) else {}
    mcp: dict[str, dict] = {}
    for mid, val in mcp_raw.items():
        rows = []
        for r in ((val or {}).get("resources") if isinstance(val, dict) else None) or []:
            if not isinstance(r, dict):
                continue
            uri = " ".join(str(r.get("uri") or "").split())
            eff = str(r.get("effect") or "").strip().lower()
            if ":" not in uri or eff not in EFFECTS:
                continue
            row = {"uri": uri, "effect": eff}
            if isinstance(r.get("verbs"), list):
                row["verbs"] = sorted({str(v) for v in r["verbs"] if str(v).strip()})
            rows.append(row)
        mcp[str(mid)] = {"resources": rows}
    return mcp


def _compile_mcp(meta: dict) -> set[str]:
    """The MCP form in the toolbox's own terms: `ns.*` per authorised MCP."""
    mcp = _mcp_entries(meta)
    if not mcp:
        return set()
    cat = mcp_catalogue()
    return {f"{ns}.{WILDCARD}" for mid in mcp
            for ns in (cat.get(mid) or {}).get("namespaces") or ()}


def resources(meta: dict) -> dict[str, list[dict]]:
    """The resource rows per authorised MCP."""
    return {mid: v["resources"] for mid, v in _mcp_entries(meta).items()}


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


def toolbox(meta: dict) -> dict:
    """What the room gives, both forms compiled together (`_legacy` + MCP)."""
    tb = _legacy(meta)
    m_enabled = _compile_mcp(meta)
    if m_enabled:
        tb["enabled"] = sorted(set(tb["enabled"]) | m_enabled)
    return tb


def _legacy(meta: dict) -> dict:
    """Il contenuto di `meta["tools"]`, ridotto a ciò che una stanza può dare.

    Letto come `topic_data.imports`: voci che non si capiscono vengono scartate,
    non interpretate — una toolbox illeggibile non deve diventare permissiva.
    """
    raw = (meta or {}).get(FIELD)
    raw = raw if isinstance(raw, dict) else {}
    lst = raw.get("enabled") if isinstance(raw.get("enabled"), list) else []
    enabled = sorted({e for e in map(_grantable, lst) if e})
    # Per-agent exceptions were removed (owner, 26 Oct 2026): the room gives
    # the same tools to every participant. A stored `except` is ignored.
    return {"enabled": enabled}


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
    return entries


# ---------------------------------------------------------------- mutations (owner)

def _write(tier: str, name: str, mutate):
    """Mutate the LEGACY lists; the MCP form (#620) is carried over as is."""
    svc = _svc()
    meta, ver = svc._read_meta(tier, name)
    tb = _legacy(meta)
    mcp = _mcp_entries(meta)
    out = mutate(meta, tb)
    meta[FIELD] = _serialise(tb, mcp)
    svc._write_meta(tier, name, meta, base_version=ver)
    return out


def _serialise(tb: dict, mcp: dict) -> dict:
    out = {"enabled": sorted(set(tb["enabled"]))}
    if mcp:
        out["mcp"] = {m: {"resources": v["resources"]} for m, v in sorted(mcp.items())}
    return out


def _write_mcp(tier: str, name: str, mutate):
    """Mutate the MCP form; the legacy lists are carried over as is."""
    svc = _svc()
    meta, ver = svc._read_meta(tier, name)
    tb = _legacy(meta)
    mcp = _mcp_entries(meta)
    out = mutate(meta, mcp)
    meta[FIELD] = _serialise(tb, mcp)
    svc._write_meta(tier, name, meta, base_version=ver)
    return out


def _known_mcp(mid: str) -> dict:
    e = mcp_catalogue().get(str(mid or "").strip())
    if not e:
        raise ToolboxError(f"'{mid}' non è un MCP che una stanza può autorizzare")
    return e


def enable_mcp(tier: str, name: str, mid: str, on: bool = True) -> dict:
    """Authorise (or revoke) a whole MCP in the room (#620, decision 1).
    Revoking drops its resource rows."""
    mid = str(mid or "").strip()
    if on:
        _known_mcp(mid)

    def mutate(meta, mcp):
        if on:
            mcp.setdefault(mid, {"resources": []})
        else:
            mcp.pop(mid, None)
        return {"ok": True, "mcp": sorted(mcp)}
    return _write_mcp(tier, name, mutate)


def set_resource(tier: str, name: str, mid: str, uri: str, effect: str | None,
                 verbs: list[str] | None = None) -> dict:
    """Add, change (`effect`) or remove (`effect=None`) one resource row of an
    authorised MCP. The URI's scheme must be one the MCP's verbs reach; the
    form is the canonical one the PDP compares."""
    e = _known_mcp(mid)
    from . import egress as _eg
    raw = " ".join(str(uri or "").split())
    u = _eg.canonical(raw) if raw else ""
    scheme = u.partition(":")[0]
    reach = {x["scheme"] for x in e["schemes"]}
    if effect is not None:
        if effect not in EFFECTS:
            raise ToolboxError(f"effetto non valido: {effect} (ammessi: {', '.join(EFFECTS)})")
        if not u or ":" not in u or scheme not in reach:
            raise ToolboxError(f"'{raw}' non è una risorsa di {e['label']} "
                               f"(schemi: {', '.join(sorted(reach)) or 'nessuno'})")
        if verbs:
            bad = sorted(set(verbs) - set(e["verbs"]))
            if bad:
                raise ToolboxError(f"verbi non di {e['label']}: {', '.join(bad)}")

    def mutate(meta, mcp):
        if mid not in mcp:
            raise ToolboxError(f"{e['label']} non è autorizzato in questa stanza")
        rows = [r for r in mcp[mid]["resources"] if r["uri"] != u]
        if effect is not None:
            row = {"uri": u, "effect": effect}
            if verbs:
                row["verbs"] = sorted(set(verbs))
            rows.append(row)
        mcp[mid]["resources"] = sorted(rows, key=lambda r: r["uri"])
        return {"ok": True, "resources": mcp[mid]["resources"]}
    return _write_mcp(tier, name, mutate)


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

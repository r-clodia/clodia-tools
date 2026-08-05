"""Per-agent whitelist enforcement."""
from contextvars import ContextVar
from pathlib import Path
import os
import yaml

from . import state_paths

TOOL_ROOT = Path(__file__).resolve().parent.parent
# Default BAKED nell'immagine (repo): è il SEED dei base-agent.
_DEFAULT_CONFIG_PATH = TOOL_ROOT / "config.yaml"
# Config RUNTIME sul volume dello STATO DECISIONALE del gateway: persiste ai
# rebuild dell'immagine, così le registrazioni a runtime (connettori, backend
# MCP via Add-MCP, responder confinati dei canali) non vengono azzerate a ogni
# deploy del gateway. La whitelist è la decisione di autorizzazione del
# reference monitor: vive su un volume che l'agent-server NON monta
# (`CLODIA_TOOLS_STATE_DIR`, issue clodia-platform#80); senza quella env resta
# in CLODIA_DATA come prima. In locale (nessuna delle due) coincide col default
# baked → nessun cambiamento.
CONFIG_FILENAME = "clodia-tools-config.yaml"
CONFIG_PATH = (state_paths.state_path(CONFIG_FILENAME)
               if state_paths.configured() else _DEFAULT_CONFIG_PATH)


def _read_yaml(p: Path) -> dict:
    try:
        with open(p) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}


def _load_config() -> dict:
    base = _read_yaml(_DEFAULT_CONFIG_PATH)
    if not CONFIG_PATH.exists():
        # Prima esecuzione sul volume: seed dal default baked.
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            yaml.safe_dump(base, f, sort_keys=False, allow_unicode=True)
        return base
    cfg = _read_yaml(CONFIG_PATH)
    # Merge non distruttivo: porta i BASE agent NUOVI del default (es. un nuovo
    # seed agent aggiunto in un release) senza sovrascrivere le entry runtime
    # esistenti (connettori, cloni). I base-agent già presenti restano come sono.
    c_agents = cfg.setdefault("agents", {})
    changed = False
    for name, spec in (base.get("agents") or {}).items():
        if name not in c_agents:
            c_agents[name] = spec
            changed = True
    cfg.setdefault("workspace_root", base.get("workspace_root"))
    cfg.setdefault("mcp_backends", base.get("mcp_backends", []))
    if changed:
        with open(CONFIG_PATH, "w") as f:
            yaml.safe_dump(cfg, f, sort_keys=False, allow_unicode=True)
    return cfg


CONFIG = _load_config()


def reload_config() -> dict:
    """Ricarica config.yaml MUTANDO il dict CONFIG in-place, così tutti gli
    importatori (`from .whitelist import CONFIG`) vedono i nuovi valori."""
    fresh = _load_config()
    CONFIG.clear()
    CONFIG.update(fresh)
    return CONFIG


def save_config() -> None:
    """Persiste CONFIG su config.yaml (usato da Add-MCP per registrare backend)."""
    with open(CONFIG_PATH, "w") as f:
        yaml.safe_dump(CONFIG, f, sort_keys=False, allow_unicode=True)


def set_gdrive_roots(account: str, folders: list[str]) -> list[str]:
    """Imposta (o rimuove, con lista vuota) il confinamento Drive di un account.

    `reload_config()` PRIMA di mutare, non per prudenza: `save_config()` scrive
    l'intero CONFIG in memoria, quindi mutare un dict stantio riscrive sopra
    tutto ciò che qualcun altro ha cambiato nel frattempo. È il difetto che
    stamattina ha azzerato i gate di clodia, e questo campo è della stessa
    natura — chi lo riscrive per sbaglio apre un Drive.
    """
    reload_config()
    roots = CONFIG.setdefault("gdrive_roots", {})
    if not isinstance(roots, dict):
        roots = {}
        CONFIG["gdrive_roots"] = roots
    clean = []
    for f in folders or []:
        f = str(f).strip()
        if f and f not in clean:
            clean.append(f)
    if clean:
        roots[account] = clean
    else:
        roots.pop(account, None)
    save_config()
    return clean


def gdrive_roots_all() -> dict:
    """Confinamenti configurati, per account. Sola lettura."""
    raw = CONFIG.get("gdrive_roots") or {}
    return {k: (v if isinstance(v, list) else [v]) for k, v in raw.items()} \
        if isinstance(raw, dict) else {}


def set_agent_tool(agent: str, tool: str, present: bool) -> None:
    """Aggiunge/rimuove un tool (o wildcard '<ns>.*') dalla whitelist di `agent`
    e persiste. Usato per delegare connettori MCP per-agent."""
    agents = CONFIG.setdefault("agents", {})
    spec = agents.setdefault(agent, {})
    tools = spec.setdefault("allowed_tools", [])
    if present and tool not in tools:
        tools.append(tool)
    elif not present and tool in tools:
        tools.remove(tool)
    save_config()


def agent_has_tool(agent: str, tool: str) -> bool:
    spec = (CONFIG.get("agents") or {}).get(agent) or {}
    return tool in (spec.get("allowed_tools") or [])


def upsert_agent(agent: str, allowed_tools: list | None = None,
                 allowed_paths: list | None = None,
                 gated_tools: list | None = None,
                 gated_in_channel: list | None = None) -> dict:
    """Registra/aggiorna un agent nella whitelist del gateway e persiste. Serve
    all'auto-provisioning dei responder confinati (clone per-topic): senza una
    entry in config.yaml la sessione MCP dell'agent non può aprirsi (agent_name).
    Non tocca gli altri campi se l'agent esiste già (merge non distruttivo)."""
    # RILETTURA prima della scrittura. `save_config()` serializza l'INTERO CONFIG
    # in memoria: se un altro processo ha modificato il file da quando questo lo ha
    # caricato, salvare senza rileggere sovrascrive le sue modifiche con una copia
    # stantia. È già successo, e in silenzio: un `profile_tools` scritto da uno
    # script è sparito al primo upsert del gateway, cioè un vincolo di sicurezza è
    # stato rimosso da un'operazione che non c'entrava (l'update di un pack).
    #
    # Non è un lock — due scritture simultanee restano un problema teorico — ma
    # elimina il caso reale, che è "modificato altrove minuti fa".
    reload_config()
    agents = CONFIG.setdefault("agents", {})
    spec = agents.setdefault(agent, {})
    spec.setdefault("allowed_paths", allowed_paths or ["."])
    spec.setdefault("allowed_shell_cmds", [])
    spec.setdefault("denied_shell_patterns", [])
    if allowed_tools is not None:
        spec["allowed_tools"] = list(allowed_tools)
    else:
        spec.setdefault("allowed_tools", [])
    # `gated_tools`: dichiarati nel seed, custoditi QUI. `None` significa «il
    # chiamante non si pronuncia» e NON azzera: un chiamante vecchio, o una
    # registrazione parziale, non deve poter togliere i gate per omissione — è
    # la direzione d'errore silenziosa.
    if gated_tools is not None:
        spec["gated_tools"] = list(gated_tools)
    # `gated_in_channel`: stessa custodia e stessa regola sul `None`. Un
    # chiamante che non si pronuncia non deve poter togliere il gate del canale
    # per omissione — è la direzione d'errore silenziosa, e su `gated_tools` è
    # già accaduta una volta oggi.
    if gated_in_channel is not None:
        spec["gated_in_channel"] = list(gated_in_channel)
    save_config()
    return spec
# Override portabile: rispetta CLODIA_WORKSPACE_ROOT se settato
# (utile dentro al container Docker dove il path differisce dal Mac).
WORKSPACE_ROOT = Path(os.environ.get("CLODIA_WORKSPACE_ROOT", CONFIG["workspace_root"])).resolve()


# Identità dell'agente per la richiesta corrente. Nel transport HTTP
# (microservizio multi-agente) la setta l'auth middleware per-richiesta dal
# token PKI; nello stdio legacy (un agente per processo) resta None e si usa
# MCP_AGENT_NAME. I contextvar sono task-local → sicuri in concorrenza HTTP.
_CURRENT_AGENT: ContextVar[str | None] = ContextVar("mcp_current_agent", default=None)
# Principal UMANO della richiesta corrente (claim `principal` del token ckt1):
# l'utente della chat per conto del quale l'agent opera. Letto da runtime.current_user.
_CURRENT_PRINCIPAL: ContextVar[str | None] = ContextVar("mcp_current_principal", default=None)


def set_current_agent(name: str | None) -> object:
    """Imposta l'agente della richiesta corrente; ritorna il token di reset."""
    return _CURRENT_AGENT.set(name)


def reset_current_agent(token: object) -> None:
    _CURRENT_AGENT.reset(token)  # type: ignore[arg-type]


def set_current_principal(name: str | None) -> object:
    return _CURRENT_PRINCIPAL.set(name)


def reset_current_principal(token: object) -> None:
    _CURRENT_PRINCIPAL.reset(token)  # type: ignore[arg-type]


def current_principal() -> str | None:
    """Principal umano della richiesta corrente, o None se anonimo."""
    return _CURRENT_PRINCIPAL.get()


# ── RBAC umana (unificazione PDP) ────────────────────────────────────────────
# Quando la chiamata è ON-BEHALF di un UMANO (webui → agent-server → gateway),
# il gateway autorizza sul RUOLO dell'umano, non sull'agent-carrier. `on_behalf`
# distingue questo caso; `human_role` è il ruolo firmato (admin|user). Entrambi
# provengono da claim firmati dall'agent-server (trusted): un modello non può
# forgiarli.
_CURRENT_ON_BEHALF: ContextVar[bool] = ContextVar("mcp_current_on_behalf", default=False)
_CURRENT_HUMAN_ROLE: ContextVar[str | None] = ContextVar("mcp_current_human_role", default=None)


def set_current_on_behalf(v: bool) -> object:
    return _CURRENT_ON_BEHALF.set(bool(v))


def reset_current_on_behalf(token: object) -> None:
    _CURRENT_ON_BEHALF.reset(token)  # type: ignore[arg-type]


def is_on_behalf() -> bool:
    """True se la richiesta è ON-BEHALF di un umano (autorizzare per ruolo)."""
    return _CURRENT_ON_BEHALF.get()


def set_current_human_role(r: str | None) -> object:
    return _CURRENT_HUMAN_ROLE.set(r)


def reset_current_human_role(token: object) -> None:
    _CURRENT_HUMAN_ROLE.reset(token)  # type: ignore[arg-type]


def current_human_role() -> str | None:
    """Ruolo umano firmato (admin|user) della richiesta on-behalf, o None."""
    return _CURRENT_HUMAN_ROLE.get()


# chat_id della sessione dell'agente chiamante (dal claim `chat` del token) — per
# postare in chat le decisioni sudo (approvato/negato).
_CURRENT_CHAT: ContextVar[str | None] = ContextVar("mcp_current_chat", default=None)
_CURRENT_SCOPED_TOOLS: ContextVar[tuple[str, ...]] = ContextVar(
    "mcp_current_scoped_tools", default=())


def set_current_chat(c: str | None) -> object:
    return _CURRENT_CHAT.set(c)


def reset_current_chat(token: object) -> None:
    _CURRENT_CHAT.reset(token)  # type: ignore[arg-type]


def current_chat() -> str | None:
    return _CURRENT_CHAT.get()


#: Sessione NON PRESIDIATA: aperta da un job schedulato, nessun umano davanti al
#: turno. Viene dal claim firmato nel token, quindi l'agente non può negarla.
_CURRENT_UNATTENDED: ContextVar[bool] = ContextVar("clodia_unattended", default=False)


def set_current_unattended(v: bool) -> object:
    return _CURRENT_UNATTENDED.set(bool(v))


def reset_current_unattended(token: object) -> None:
    _CURRENT_UNATTENDED.reset(token)  # type: ignore[arg-type]


def is_unattended() -> bool:
    return _CURRENT_UNATTENDED.get()


def set_current_scoped_tools(tools: list[str] | None) -> object:
    return _CURRENT_SCOPED_TOOLS.set(tuple(dict.fromkeys(tools or [])))


def reset_current_scoped_tools(token: object) -> None:
    _CURRENT_SCOPED_TOOLS.reset(token)  # type: ignore[arg-type]


def current_scoped_tools() -> tuple[str, ...]:
    return _CURRENT_SCOPED_TOOLS.get()


# Token ckt1 grezzo della richiesta corrente. Serve per INOLTRARLO al backend
# quando il gateway deve compiere, per conto del caller, un'operazione che il
# backend autorizza per principal-agent (es. agents.* → PATCH /api/agents/*/caps).
# Il gateway non conia token: riusa quello già verificato in ingresso.
_CURRENT_TOKEN: ContextVar[str | None] = ContextVar("mcp_current_token", default=None)


def set_current_token(token: str | None) -> object:
    return _CURRENT_TOKEN.set(token)


def reset_current_token(token: object) -> None:
    _CURRENT_TOKEN.reset(token)  # type: ignore[arg-type]


def current_token() -> str | None:
    """Token ckt1 grezzo della richiesta corrente (da inoltrare al backend)."""
    return _CURRENT_TOKEN.get()


# Clearance (SEAL-N) del caller, dal claim firmato nel token — per l'enforcement
# clearance≥tier sull'accesso ai topic (asse livello). None → default SEAL-0.
_CURRENT_CLEARANCE: ContextVar[str | None] = ContextVar("mcp_current_clearance", default=None)


def set_current_clearance(c: str | None) -> object:
    return _CURRENT_CLEARANCE.set(c)


def reset_current_clearance(token: object) -> None:
    _CURRENT_CLEARANCE.reset(token)  # type: ignore[arg-type]


def current_clearance() -> str | None:
    return _CURRENT_CLEARANCE.get()


def agent_name() -> str:
    """Agente chiamante: prima il contextvar (HTTP per-richiesta), poi l'env
    MCP_AGENT_NAME (stdio legacy)."""
    name = (_CURRENT_AGENT.get() or os.environ.get("MCP_AGENT_NAME", "")).strip()
    if not name:
        raise PermissionError("identità agente non impostata (né contextvar né MCP_AGENT_NAME)")
    if name not in CONFIG.get("agents", {}):
        raise PermissionError(f"agent '{name}' not declared in config.yaml")
    return name


def agent_config(name: str | None = None) -> dict:
    return CONFIG["agents"][name or agent_name()]


def _listed(verb: str, patterns: set) -> bool:
    """Match ESATTO o per namespace (`ns.*`). Deliberatamente NON riusa
    `_tool_allowed` di main.py: quello ha una scorciatoia per i namespace
    universali che ritorna True indipendentemente dall'insieme passato. Usarlo
    per un DENY negherebbe verbi che nessuno ha elencato — la direzione d'errore
    peggiore per una lista che serve a togliere.
    """
    v = (verb or "").strip()
    if not v or not patterns:
        return False
    if v in patterns:
        return True
    if "." in v and f"{v.split('.', 1)[0]}.*" in patterns:
        return True
    return False


def agent_denies(verb: str, name: str | None = None) -> bool:
    """True se `verb` è nella `denied_tools` dell'agente.

    Serve a ritagliare eccezioni da un `*` (clodia-platform#104 §8): il wildcard
    resta — l'enumerazione renderebbe il punteggio stale, misurato in #119 — ma
    alcuni verbi non sono operazioni da turno di chat (`settings.backup_run`,
    `mcp.add`, `packs.install_*`) e vanno tolti per sottrazione invece che
    ricostruendo l'insieme per addizione.

    Il DENY vince sempre sull'allow, inclusi i super-agent: è l'unico ordine che
    rende la lista utile — se un `*` potesse sovrascriverla non toglierebbe nulla.
    """
    try:
        cfg = agent_config(name)
    except KeyError:
        return False
    return _listed(verb, set(cfg.get("denied_tools") or []))


def agent_gates(verb: str, name: str | None = None) -> bool:
    """True se `verb` è gated PER QUESTO agente (`gated_tools` nella sua config).

    La lista globale in gate.py dice «questo verbo è pericoloso per chiunque». La
    §8 chiede qualcosa di diverso: «le SCRITTURE di impiegato-tomato sono gated»,
    «le scritture github di fullstack-dev sono gated». Sono gli stessi verbi che
    per altri agenti restano liberi, quindi la granularità non può essere globale.
    """
    try:
        cfg = agent_config(name)
    except KeyError:
        return False
    return _listed(verb, set(cfg.get("gated_tools") or []))


def in_channel() -> bool:
    """True se la chiamata corrente arriva dal turno di un CANALE di topic.

    Il discriminante è il claim `chat` del token di sessione, che per un canale
    vale `chan:<tier>:<topic>:<agente>`. È **firmato** dall'agent-server: un
    agente non può dichiararsi fuori da un canale per sfuggire a un gate, né
    dichiararne uno altrui. Senza questa proprietà la condizione sarebbe
    un'autodichiarazione, cioè niente.
    """
    c = current_chat() or ""
    return c.startswith("chan:")


def current_channel() -> str | None:
    """`<tier>/<topic>` del canale corrente, per i messaggi di gate. None fuori."""
    c = current_chat() or ""
    if not c.startswith("chan:"):
        return None
    parts = c[len("chan:"):].split(":")
    return f"{parts[0]}/{parts[1]}" if len(parts) >= 2 else None


def agent_gates_in_channel(verb: str, name: str | None = None) -> bool:
    """True se `verb` è gated per questo agente **solo dentro un canale**.

    Perché una terza lista invece di allargare `gated_tools`. Per un postino
    spedire non è un'anomalia: fuori da un canale — la posta in arrivo che
    smista, una conversazione diretta con l'owner — è il suo mestiere, e chiedere
    ogni volta renderebbe il gate un riflesso, che è il modo in cui un gate
    smette di essere letto. Dentro un canale cambia una cosa sola: chi può
    chiedere. I partecipanti non sono l'owner, e il contenuto che possono far
    uscire è tutto quello che sta nella stanza.

    Quindi la condizione non è sul verbo né sull'agente: è sul CONTESTO. Solo un
    admin può approvare un gate (`_can_approve` lato agent-server), ed è
    esattamente il «grant dall'admin» che questo serve a ottenere.
    """
    if not in_channel():
        return False
    try:
        cfg = agent_config(name)
    except KeyError:
        return False
    return _listed(verb, set(cfg.get("gated_in_channel") or []))


def outside_profile(verb: str, name: str | None = None) -> bool:
    """True se `verb` è RAGGIUNGIBILE ma fuori dal profilo dichiarato dell'agente.

    Il profilo (`profile_tools`) è l'insieme che l'agente dichiara come proprio
    mestiere: quello che mostra nella sua scheda e che usa senza chiedere. Ciò che
    il suo grant copre e che il profilo NON dichiara resta raggiungibile, ma passa
    da un consenso umano.
    
    Sposta la least authority dalla RIMOZIONE alla SUPERVISIONE, ed è la ragione
    per cui esiste: un verbo tolto a clodia è un verbo che deve fare Davide a mano;
    un verbo fuori profilo è un verbo che clodia fa con la sua approvazione. Stesso
    umano coinvolto, ma niente si rompe — e togliere verbi a un super per
    disciplina si è già rotto addosso una volta (a un postino, levandogli
    `post_message`, cioè il mestiere).

    Profilo vuoto o assente → nessun vincolo: un agente che non dichiara un profilo
    non è un agente senza mestiere, è un agente che non l'ha ancora dichiarato, e
    trattarlo come «tutto gated» renderebbe la piattaforma inservibile al primo
    aggiornamento incompleto.
    """
    try:
        cfg = agent_config(name)
    except KeyError:
        return False
    profile = [str(x) for x in (cfg.get("profile_tools") or [])]
    if not profile:
        return False
    return not _listed(verb, set(profile))


def resolve_safe_path(rel_or_abs: str) -> Path:
    """Resolve a path and verify it's inside one of the agent's allowed_paths."""
    cfg = agent_config()
    p = Path(rel_or_abs)
    if not p.is_absolute():
        p = WORKSPACE_ROOT / p
    p = p.resolve()
    allowed = [(WORKSPACE_ROOT / Path(a)).resolve() for a in cfg["allowed_paths"]]
    for base in allowed:
        try:
            p.relative_to(base)
            return p
        except ValueError:
            continue
    raise PermissionError(
        f"path '{rel_or_abs}' not in allowed_paths of agent '{agent_name()}'"
    )


# Super-agent: bypassano la whitelist (coerente con main.py call_tool). Estendibile
# via env CLODIA_SUPER_AGENTS (CSV).
import os as _os
_SUPER_AGENTS = {"clodia", "ophelia", *(
    a.strip() for a in _os.environ.get("CLODIA_SUPER_AGENTS", "").split(",") if a.strip()
)}


def tool_allowed(tool_name: str) -> None:
    """Gate a livello adapter, coerente con main.py: super-agent bypassano; il
    wildcard `<ns>.*` concede tutti i tool di un namespace. Senza questo, un tool
    nuovo (es. email.get_attachment) o un wildcard veniva bloccato qui anche se
    main.py lo consentiva (doppio gate incoerente)."""
    ag = agent_name()
    if ag in _SUPER_AGENTS:
        return
    allowed = agent_config().get("allowed_tools", [])
    if tool_name in allowed:
        return
    if "." in tool_name and f"{tool_name.split('.', 1)[0]}.*" in allowed:
        return
    raise PermissionError(
        f"tool '{tool_name}' not in allowed_tools of agent '{ag}'"
    )

"""Per-agent whitelist enforcement."""
from contextvars import ContextVar
from pathlib import Path
import logging
import os
import yaml

from . import state_paths

_log = logging.getLogger("clodia-tools.whitelist")

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


#: Il default BAKED non si riscrive mai. `yaml.safe_dump` perde i commenti, e
#: quel file ne ha 109 righe che spiegano `gdrive_roots`, il wildcard dei super e
#: il resto — cioè la documentazione operativa del gateway.
#:
#: È già successo, il 7 ago 2026: eseguire il caricamento della config in un test
#: locale ha riscritto `config.yaml` spogliato, e `git add -A` l'ha portato in una
#: PR che parlava d'altro. Il file si scrive SOLO sul volume di stato
#: (`CONFIG_PATH`), che è generato e non ha commenti da perdere.
_DEFAULT_IS_READ_ONLY = True


def _load_config() -> dict:
    base = _read_yaml(_DEFAULT_CONFIG_PATH)
    if not CONFIG_PATH.exists():
        # Prima esecuzione sul volume: seed dal default baked. Mai il contrario —
        # vedi `_DEFAULT_IS_READ_ONLY`.
        if CONFIG_PATH.resolve() == _DEFAULT_CONFIG_PATH.resolve():
            return base
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


#: Copia di CONFIG come era all'ultimo caricamento. Serve a `save_config` per
#: sapere COSA ha cambiato questo processo, invece di riversare tutto.
#:
#: Popolata anche al PRIMO caricamento, non solo su `reload_config`: un processo
#: che carica all'import e salva senza aver mai ricaricato ricadrebbe altrimenti
#: sul comportamento vecchio — cioè proprio il caso che ha riportato i verbi di
#: clodia da 53 a 130 su venere.
_LOADED: dict = {}

CONFIG = _load_config()
import copy as _copy
_LOADED.update(_copy.deepcopy(CONFIG))


def reload_config() -> dict:
    """Ricarica config.yaml MUTANDO il dict CONFIG in-place, così tutti gli
    importatori (`from .whitelist import CONFIG`) vedono i nuovi valori."""
    import copy
    fresh = _load_config()
    CONFIG.clear()
    CONFIG.update(fresh)
    _LOADED.clear()
    _LOADED.update(copy.deepcopy(fresh))
    return CONFIG


def _merge_my_changes(disco: dict) -> dict:
    """Riporta sullo stato SU DISCO solo ciò che questo processo ha cambiato.

    «Cambiato» = differente rispetto a `_LOADED`, la copia scattata all'ultimo
    caricamento. Tutto il resto arriva dal disco, quindi le modifiche di un altro
    processo sopravvivono.

    `agents` si fonde per-agente e non in blocco: due processi che toccano due
    agenti diversi non devono sovrascriversi, ed è precisamente quello che è
    successo — un processo con la lista di clodia in memoria da prima ha riversato
    la propria copia su un'altra scritta nel frattempo.
    """
    import copy
    out = copy.deepcopy(disco)
    for k, v in CONFIG.items():
        if k == "agents" and isinstance(v, dict) and isinstance(out.get("agents"), dict):
            base = _LOADED.get("agents") or {}
            for nome, spec in v.items():
                if spec != base.get(nome):
                    out["agents"][nome] = copy.deepcopy(spec)
            for nome in list(out["agents"]):
                if nome in base and nome not in v:
                    out["agents"].pop(nome, None)   # rimosso da questo processo
            continue
        if v != _LOADED.get(k):
            out[k] = copy.deepcopy(v)
    for k in list(out):
        if k in _LOADED and k not in CONFIG:
            out.pop(k, None)                        # chiave rimossa da questo processo
    return out


def save_config() -> None:
    """Persiste su config.yaml SOLO le modifiche di questo processo.

    Perché non scrive più `CONFIG` così com'è. `save_config` serializzava l'intero
    dict in memoria, quindi un processo che aveva caricato la config e la salvava
    più tardi riversava la propria copia STANTIA su tutto ciò che era cambiato nel
    frattempo. Non è teorico: il 6 ago l'insieme di verbi di clodia su venere è
    tornato da 53 a 130 — misurato, `config.yaml` riscritto alle 17:14 con i
    valori di prima delle 13:00, dal processo del gateway che li aveva in memoria
    dall'avvio.
    #
    Avevo già visto questa classe di difetto e l'avevo corretta in DUE chiamanti
    (`upsert_agent`, `set_gdrive_roots`) mettendoci un `reload_config()` davanti.
    Ma i chiamanti sono nove, e far dipendere la correttezza dalla disciplina di
    nove punti significa che il decimo la rompe. La correzione appartiene qui.

    Rilettura + merge del solo delta, non un lock: due scritture simultanee
    restano un problema teorico. Elimina il caso reale, che è «un altro processo
    ha scritto fra il mio load e il mio save».
    """
    import copy
    try:
        disco = _load_config()
    except Exception:                                # noqa: BLE001
        disco = copy.deepcopy(_LOADED)
    finale = _merge_my_changes(disco) if _LOADED else dict(CONFIG)
    if CONFIG_PATH.resolve() == _DEFAULT_CONFIG_PATH.resolve():
        # Il default baked è di sola lettura (`_DEFAULT_IS_READ_ONLY`): scriverlo
        # significa perderne i commenti, ed è già costato 109 righe di
        # documentazione il 7 ago. In locale, senza volume di stato, i due path
        # coincidono — ed è esattamente lì che è successo.
        _log.warning("save_config: il default baked non si riscrive (nessun "
                     "volume di stato configurato); modifiche non persistite")
        return
    with open(CONFIG_PATH, "w") as f:
        yaml.safe_dump(finale, f, sort_keys=False, allow_unicode=True)
    # Da qui in avanti «cambiato» si misura da ciò che è appena stato scritto.
    CONFIG.clear()
    CONFIG.update(finale)
    _LOADED.clear()
    _LOADED.update(copy.deepcopy(finale))


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
                 profile_tools: list | None = None) -> dict:
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
    # `profile_tools`: il MESTIERE dichiarato. Non aveva nessuna catena — non era
    # nel modello del seed, non lo trasportava la registrazione, non lo custodiva
    # questa funzione: viveva solo nella config live, quindi un rebuild o una
    # nuova istanza si ritrovavano clodia senza profilo e niente gated per
    # mestiere. Una dichiarazione che nessuno trasporta è un controllo che sembra
    # esserci: terza volta in un giorno, dopo `gated_tools` e un terzo campo.
    if profile_tools is not None:
        spec["profile_tools"] = list(profile_tools)
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


_CURRENT_SPAWN: ContextVar = ContextVar("clodia_current_spawn", default=None)


def set_current_spawn(v):
    return _CURRENT_SPAWN.set(v)


def reset_current_spawn(token: object) -> None:
    _CURRENT_SPAWN.reset(token)  # type: ignore[arg-type]


def current_spawn() -> str | None:
    """Lo SPAWN chiamante (`clodia-1`), dal claim `execution_id` FIRMATO.

    `agent_name()` dice il seed; questo dice l'istanza. La differenza è quella
    fra «un clodia» e «questo clodia», ed è ciò che permette di esigere che uno
    spawn scriva nel PROPRIO scratch invece che in quello di un altro.

    `None` quando il token non lo porta — un chiamante vecchio, o un percorso
    interno. Dedurlo da un argomento sarebbe la parola dell'agente su chi è.
    """
    v = _CURRENT_SPAWN.get()
    return str(v) if v else None


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



# ─────────────────────────── L'ARCISEED ────────────────────────────────────
#
# Un seed ASTRATTO, che non si può spawnare, da cui ogni seed discende. Tiene i
# verbi base; il resto è mestiere, e il mestiere è del seed (specification §1.3).
#
# Sta QUI e non nella datadir per la regola della §3.5: l'autorità dev'essere
# irraggiungibile dal suo soggetto. La datadir la scrive l'agent-server; questo
# volume no. Ed essendo nel codice, «i due livelli esistono» è vero su ogni
# istanza invece che dipendere da un file che qualcuno deve aver creato.
#
# La regola di appartenenza: un verbo sta nell'arciseed quando il suo BERSAGLIO è
# l'agente stesso o la stanza in cui lo spawn già si trova. Tutto il resto
# attraversa qualcosa, e attraversare è mestiere.
ARCHSEED = "archseed"

#: PAVIMENTO DI BOOTSTRAP, non la definizione. La definizione è il seed
#: `agents/archseed/agent.yaml` del base-pack; questa lista serve solo prima che
#: il pack sia materializzato, e tenerla allineata a mano sarebbe una seconda
#: verità — è deliberatamente minima e il suo uso viene loggato.
_ARCHSEED_TOOLS = (
    # la propria memoria, confinata alla propria cartella
    "memory.*",
    # il pavimento di LETTURA dello scope corrente
    "topic.open", "topic.files", "topic.read_file", "topic.read_document",
    "topic.search", "topic.list", "topic.fetch",
    # parlare non è mutare: uno spawn che non può parlare nella propria stanza
    # non può fare niente (specification §2.9)
    "topic.post_message",
)

#: Profondità massima della catena `parents`. Un ciclo non deve diventare un
#: gateway che non risponde: si tronca e si logga.
_MAX_ANCESTRY = 8


def archseed_tools() -> list:
    """I verbi dell'arciseed, letti dal SUO SEED.

    L'arciseed è un seed del base-pack come gli altri — `agents/archseed/` — e
    si legge dallo stesso posto da cui si legge il seed di un umano:
    `/datadir/agents/`, che è `drwx------ root` mentre gli spawn girano
    unprivileged. Il confine lo mette il kernel, non logica applicativa, ed è la
    ragione per cui leggere di lì è sound (§3.5).

    Tre fonti, in ordine, e la terza NON è una seconda verità:

    1. **il seed** — la fonte. Un seed è un file, si legge, si diffa, si revisiona
       in una PR;
    2. **`config.yaml`** — override d'istanza, per chi vuole un pavimento diverso
       senza toccare il pack;
    3. **il built-in** — solo quando il pack non è ancora materializzato, cioè al
       primo avvio di un'istanza nuova. Senza, ogni agente resterebbe senza verbi
       base finché qualcuno non installa il pack, e «i due livelli esistono»
       sarebbe falso proprio nel momento in cui l'istanza nasce. Si logga, perché
       trovarlo in uso dopo il bootstrap significa che il seed è sparito.
    """
    try:
        from . import human as _seedreader
        d = _seedreader._seed(ARCHSEED)
        tp = d.get("tool_permissions")
        if isinstance(tp, list) and tp:
            return [str(x) for x in tp]
    except Exception as e:  # noqa: BLE001
        _log.warning("seed dell'arciseed illeggibile (%s)", type(e).__name__)
    over = (CONFIG or {}).get("archseed")
    if isinstance(over, dict) and isinstance(over.get("allowed_tools"), list):
        return [str(x) for x in over["allowed_tools"]]
    _log.warning("arciseed non trovato fra i seed: uso il pavimento built-in "
                 "(atteso solo prima che il base-pack sia materializzato)")
    return list(_ARCHSEED_TOOLS)


def is_abstract(name: str) -> bool:
    """Un seed astratto non si spawna. Dichiararlo non basta: va imposto, perché
    un arciseed spawnato per errore è un agente con i verbi base e nessun
    mestiere — e funziona abbastanza da non farsene accorgere."""
    if str(name or "") == ARCHSEED:
        return True
    try:
        if bool(agent_config(name).get("abstract")):
            return True
    except KeyError:
        pass
    # Anche dal seed: `abstract` è una dichiarazione del seed, e un seed che non
    # è registrato nella config del gateway resterebbe altrimenti spawnabile
    # nonostante si dichiari astratto.
    try:
        from . import human as _seedreader
        return bool(_seedreader._seed(str(name or "")).get("abstract"))
    except Exception:  # noqa: BLE001
        return False


def parents_of(name: str) -> list:
    """Antenati dichiarati da un seed. L'arciseed è antenato di TUTTI, e non va
    dichiarato: se lo fosse, un seed potrebbe non dichiararlo e uscire dal
    modello senza che si veda."""
    try:
        raw = agent_config(name).get("parents") or []
    except KeyError:
        raw = []
    out = [str(x).strip() for x in raw if str(x).strip()]
    if name != ARCHSEED and ARCHSEED not in out:
        out.append(ARCHSEED)
    return out


def effective_tools(name: str | None) -> set:
    """Verbi EFFETTIVI di un principal: i propri PIÙ quelli ereditati.

    Un punto solo, e questa è la ragione per cui esiste. La matrice era letta in
    **tre** posti — `main._declared_tools`, `origin._agent_may` e
    `ensure_tool_allowed` — e i tre non erano d'accordo: il terzo non consultava
    nemmeno i `denied_tools`. Con l'ereditarietà innestata in uno solo, un verbo
    sarebbe stato concesso da un percorso e negato da un altro, e il difetto
    sarebbe stato invisibile perché nessuno confronta i tre esiti.

    Il genitore è un DEFAULT, non un tetto (specification §1.4): quello che si
    eredita è un pavimento, e il contenimento viene dai gate, dalle liste dello
    scope e dall'intersezione della catena — mai dall'antenato.

    La SOTTRAZIONE resta ai `denied_tools`, che battono tutto: è il verso in cui
    un seed più stretto del proprio genitore si dichiara tale, ed è ciò che
    impedisce all'arciseed di allargare chi era stretto di proposito.
    """
    n = str(name or "")
    if not n:
        return set()
    visti: set = set()
    fuori: set = set()
    coda = [(n, 0)]
    while coda:
        chi, prof = coda.pop(0)
        if chi in visti or prof > _MAX_ANCESTRY:
            if prof > _MAX_ANCESTRY:
                _log.warning("catena `parents` troppo profonda a '%s': troncata", chi)
            continue
        visti.add(chi)
        if chi == ARCHSEED:
            fuori.update(archseed_tools())
            continue
        try:
            fuori.update(str(x) for x in (agent_config(chi).get("allowed_tools") or []))
        except KeyError:
            if chi == n:
                # principal non registrato (umano, clone per-topic): il suo seed
                # sulla datadir è la fonte. Senza, l'intersezione lo azzererebbe.
                from . import human as _seedreader
                d = _seedreader._seed(chi)
                fuori.update(str(x) for x in (d.get("tool_permissions") or []))
        for g in parents_of(chi):
            coda.append((g, prof + 1))
    return fuori



def tools_with_provenance(name: str | None) -> dict:
    """Ogni verbo effettivo con la sua ORIGINE: `own`, il seed che lo eredita, o
    `archseed`.

    Terza condizione della §1.4, e senza di essa l'ereditarietà sarebbe un
    cattivo affare: prima si leggeva un file e si sapeva cosa un agente potesse
    fare; con l'ereditarietà non più. Una duplicazione la vedi, un'opacità no —
    quindi l'insieme risolto deve dire da dove viene ogni pezzo.

    Serve anche a una cosa pratica: capire se un verbo si toglie togliendolo
    dall'agente, o se va sottratto con `denied_tools` perché arriva da un
    antenato. Sono due rimedi diversi, e sbagliarli significa modificare un file
    e vedere che non cambia niente.
    """
    n = str(name or "")
    out: dict = {}
    if not n:
        return out
    visti: set = set()
    coda = [(n, 0)]
    while coda:
        chi, prof = coda.pop(0)
        if chi in visti or prof > _MAX_ANCESTRY:
            continue
        visti.add(chi)
        if chi == ARCHSEED:
            for v in archseed_tools():
                out.setdefault(str(v), ARCHSEED)
            continue
        try:
            propri = agent_config(chi).get("allowed_tools") or []
        except KeyError:
            propri = []
            if chi == n:
                from . import human as _seedreader
                propri = _seedreader._seed(chi).get("tool_permissions") or []
        for v in propri:
            out.setdefault(str(v), "own" if chi == n else chi)
        for g in parents_of(chi):
            coda.append((g, prof + 1))
    # Il deny non toglie la riga: la MARCA. Un verbo che sparisce dall'elenco
    # lascia chi legge a chiedersi se non sia mai stato ereditato — e la risposta
    # («c'è, ed è stato sottratto qui») è quella che serve per intervenire.
    for v in list(out):
        if agent_denies(v, n):
            out[v] = f"{out[v]} · negato"
    return out


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


_CURRENT_ORIGIN: ContextVar[tuple | None] = ContextVar("mcp_current_origin",
                                                      default=None)


def set_current_origin(chain) -> object:
    return _CURRENT_ORIGIN.set(tuple(chain) if chain else None)


def reset_current_origin(token: object) -> None:
    _CURRENT_ORIGIN.reset(token)


def current_origin() -> tuple:
    """Catena d'origine del turno, dal claim FIRMATO. Vuota se non dichiarata.

    Firmata per la stessa ragione di `chat`: se un agente potesse comporla,
    l'intersezione sarebbe la sua parola su sé stesso. Vuota ≠ permessa — chi la
    legge deve trattarla come «sconosciuta», che è un caso esplicito.
    """
    return _CURRENT_ORIGIN.get() or ()


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
# `clodia` rimossa anche qui: questo è il SECONDO insieme super (gate a livello
# adapter), e toglierla da uno solo l'avrebbe lasciata bypassare dall'altro.
# Estendibile via env: chi rimette `clodia` in `CLODIA_SUPER_AGENTS` annulla la
# modifica, ed è deliberato che sia possibile — ma va saputo.
_SUPER_AGENTS = {"ophelia", *(
    a.strip() for a in _os.environ.get("CLODIA_SUPER_AGENTS", "").split(",") if a.strip()
)}


def tool_allowed(tool_name: str) -> None:
    """Gate a livello adapter, coerente con main.py: super-agent bypassano; il
    wildcard `<ns>.*` concede tutti i tool di un namespace. Senza questo, un tool
    nuovo (es. email.get_attachment) o un wildcard veniva bloccato qui anche se
    main.py lo consentiva (doppio gate incoerente)."""
    ag = agent_name()
    # Il DENY per primo, e prima mancava del tutto qui: questo percorso rispondeva
    # «consentito» su un verbo che gli altri due negavano. Tre lettori della
    # stessa matrice con tre risposte possibili — invisibile, perché nessuno
    # confronta i tre esiti.
    if agent_denies(tool_name, ag):
        raise PermissionError(
            f"tool '{tool_name}' negato esplicitamente all'agente '{ag}'")
    if ag in _SUPER_AGENTS:
        return
    allowed = effective_tools(ag)          # propri + ereditati (arciseed incluso)
    if tool_name in allowed:
        return
    if "." in tool_name and f"{tool_name.split('.', 1)[0]}.*" in allowed:
        return
    if "*" in allowed:
        return
    raise PermissionError(
        f"tool '{tool_name}' not in allowed_tools of agent '{ag}'"
    )

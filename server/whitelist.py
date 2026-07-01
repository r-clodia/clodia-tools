"""Per-agent whitelist enforcement."""
from contextvars import ContextVar
from pathlib import Path
import os
import yaml

TOOL_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = TOOL_ROOT / "config.yaml"


def _load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


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
                 allowed_paths: list | None = None) -> dict:
    """Registra/aggiorna un agent nella whitelist del gateway e persiste. Serve
    all'auto-provisioning dei responder confinati (clone per-topic): senza una
    entry in config.yaml la sessione MCP dell'agent non può aprirsi (agent_name).
    Non tocca gli altri campi se l'agent esiste già (merge non distruttivo)."""
    agents = CONFIG.setdefault("agents", {})
    spec = agents.setdefault(agent, {})
    spec.setdefault("allowed_paths", allowed_paths or ["."])
    spec.setdefault("allowed_shell_cmds", [])
    spec.setdefault("denied_shell_patterns", [])
    if allowed_tools is not None:
        spec["allowed_tools"] = list(allowed_tools)
    else:
        spec.setdefault("allowed_tools", [])
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

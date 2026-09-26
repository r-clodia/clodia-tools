"""`copybrain` — uno spawn prende in prestito i verbi di un altro seed
(clodia-platform#393).

Decisione di Davide (26 set 2026): clodia non tiene i verbi dei mestieri altrui
(`contabilita.*`, `leads.*`, `normattiva.*`, `sedia.*`), ma può, previo gate,
assumere i verbi di un seed a sua scelta per lo spawn che sta usando.

È un'ECCEZIONE deliberata al principio del M-gate («il gate supervisiona, non
concede verbi nuovi»), e i suoi confini sono ciò che la rende accettabile:

- **per spawn**: il consenso è `(agent, spawn, copybrain:<seed>)`, con lo spawn
  preso dal claim `execution_id` FIRMATO (`whitelist.current_spawn`). Senza quel
  claim si nega: un consenso non scopabile varrebbe per il seed intero;
- **fino a fine spawn**: non si consuma all'uso; lo chiude la revoca che
  l'agent-server manda alla pulizia del workspace (`gate.revoke_instance`), con
  il tetto di 24 ore della capability come rete;
- **deciso dall'utente in contesto**: classe `walls` (`gate._PREFIX_CLASS`),
  cioè l'owner della stanza in cui lo spawn lavora; fuori stanza un admin;
- **mai ricordato**: nessuna delega permanente, nessun «approva sempre» — un
  consenso ricordato coprirebbe gli spawn futuri, cioè il seed;
- **nessuna scorciatoia**: i verbi in prestito entrano in `effective_tools`
  (l'unico risolutore della matrice) e `copybrain.call` rientra in `call_tool`,
  quindi deny, gate del verbo, taint ed egress si applicano come sempre. Il
  prestito non concatena: si prende la matrice dichiarata del seed copiato, mai
  i suoi prestiti.

Perché `copybrain.call` e non solo il permesso: Claude Code legge l'elenco dei
tool MCP all'avvio della sessione e il gateway non emette
`tools/list_changed`, quindi un verbo concesso a metà sessione non comparirebbe
fra quelli che il modello può invocare.
"""
from __future__ import annotations

import logging
import re

from mcp.types import Tool

LOG = logging.getLogger("clodia-tools.copybrain")

_SEED_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}(?:\.[a-z0-9][a-z0-9_-]{0,63})?$")

TOOLS: list[Tool] = [
    Tool(
        name="copybrain.assume",
        description=(
            "Assume i verbi di un altro seed per QUESTO spawn, fino alla sua fine. "
            "Chiede un gate: decide l'owner della stanza (fuori stanza un admin). "
            "Approvato, restituisce i verbi presi in prestito con i loro schemi: "
            "si invocano con copybrain.call. Usalo quando il compito richiede il "
            "mestiere di un altro agente e farlo tu è più sensato che delegarlo."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "seed": {"type": "string",
                         "description": "Nome del seed di cui assumere i verbi (es. commercialista)."},
                "reason": {"type": "string",
                           "description": "Perché ti serve: lo legge chi deve approvare."},
            },
            "required": ["seed", "reason"],
            "additionalProperties": False,
        },
    ),
    Tool(
        name="copybrain.call",
        description=(
            "Esegue un verbo preso in prestito con copybrain.assume. Tutti i controlli "
            "del verbo restano validi (gate, destinazioni, fonti)."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "verb": {"type": "string", "description": "Il verbo da eseguire (es. contabilita.list)."},
                "arguments": {"type": "object", "description": "Argomenti del verbo, secondo il suo schema."},
            },
            "required": ["verb"],
            "additionalProperties": False,
        },
    ),
    Tool(
        name="copybrain.release",
        description="Restituisce subito i verbi presi in prestito da un seed (prima della fine dello spawn).",
        inputSchema={
            "type": "object",
            "properties": {"seed": {"type": "string"}},
            "required": ["seed"],
            "additionalProperties": False,
        },
    ),
]

NAMES = frozenset(t.name for t in TOOLS)


def gate_key(seed: str) -> str:
    from . import gate as _gate
    return f"{_gate.COPYBRAIN_PREFIX}{seed}"


def _norm_seed(raw: object) -> str:
    seed = str(raw or "").strip().lower().lstrip("@")
    if not _SEED_RE.fullmatch(seed):
        raise ValueError(f"copybrain: nome di seed non valido: {raw!r}")
    return seed


def _seed_exists(seed: str) -> bool:
    from . import whitelist as W
    try:
        W.agent_config(seed)
        return True
    except KeyError:
        pass
    try:
        from . import human as _seedreader
        return bool(_seedreader._seed(seed))
    except Exception:  # noqa: BLE001 — seed illeggibile = seed assente
        return False


def _caller_and_spawn() -> tuple[str, str]:
    from .whitelist import agent_name, current_spawn, is_on_behalf
    if is_on_behalf():
        raise PermissionError(
            "copybrain è un verbo di agente: una persona usa i verbi del proprio ruolo")
    agent = agent_name()
    spawn = current_spawn()
    if not spawn:
        raise PermissionError(
            "copybrain: nessuna identità di spawn firmata (execution_id) in questo "
            "token — il prestito non è scopabile allo spawn, quindi è negato.")
    return agent, spawn


def borrowed_catalog(agent: str, seed: str, catalog: list[Tool]) -> list[dict]:
    """I verbi che `seed` ha e `agent` no, con schema, presi dal catalogo VERO
    (nativi + backend montati): un wildcard `ns.*` si espande nei tool esistenti."""
    from . import main as M
    from . import whitelist as W
    own = W._resolved_tools(agent)
    theirs = W._resolved_tools(seed)
    out = []
    for t in catalog:
        if t.name in NAMES:
            continue
        if M._tool_allowed(t.name, theirs) and not M._tool_allowed(t.name, own) \
                and not W.agent_denies(t.name, agent):
            out.append({"name": t.name,
                        "description": " ".join((t.description or "").split())[:400],
                        "inputSchema": t.inputSchema})
    return sorted(out, key=lambda d: d["name"])


async def assume(arguments: dict, catalog: list[Tool]) -> dict:
    from . import main as M
    agent, spawn = _caller_and_spawn()
    seed = _norm_seed(arguments.get("seed"))
    if seed == agent:
        raise ValueError("copybrain: non puoi assumere i verbi del tuo stesso seed")
    if not _seed_exists(seed):
        raise ValueError(f"copybrain: seed '{seed}' non trovato fra gli agenti dell'istanza")
    reason = str(arguments.get("reason") or "").strip()
    await M._require_gate_consent(
        agent, gate_key(seed), consume=False, allow_delegation=False,
        reason=(f"assumere i verbi di @{seed} per lo spawn {spawn}"
                + (f" — {reason}" if reason else "")))
    verbs = borrowed_catalog(agent, seed, catalog)
    LOG.info("COPYBRAIN %s@%s ha assunto i verbi di %s (%d verbi)", agent, spawn, seed, len(verbs))
    return {
        "assumed": seed, "spawn": spawn, "until": "fine dello spawn",
        "verbs": verbs,
        "how": "invoca ogni verbo con copybrain.call(verb, arguments); "
               "copybrain.release(seed) li restituisce prima",
    }


def check_call(arguments: dict) -> tuple[str, dict]:
    """Valida una `copybrain.call` e restituisce (verbo, argomenti) da eseguire."""
    from . import main as M
    from . import whitelist as W
    agent, _spawn = _caller_and_spawn()
    verb = str(arguments.get("verb") or "").strip()
    if not verb or verb.startswith("copybrain."):
        raise ValueError("copybrain.call: serve il nome di un verbo preso in prestito")
    if not M._tool_allowed(verb, W.borrowed_tools(agent)):
        raise PermissionError(
            f"copybrain.call: '{verb}' non è fra i verbi presi in prestito da questo "
            "spawn — chiedili prima con copybrain.assume(seed, reason)")
    args = arguments.get("arguments") or {}
    if not isinstance(args, dict):
        raise ValueError("copybrain.call: 'arguments' deve essere un oggetto")
    return verb, args


def release(arguments: dict) -> dict:
    from . import gate as _gate
    agent, spawn = _caller_and_spawn()
    seed = _norm_seed(arguments.get("seed"))
    had = _gate.active(agent, spawn, gate_key(seed))
    _gate.consume(agent, spawn, gate_key(seed))
    LOG.info("COPYBRAIN %s@%s ha restituito i verbi di %s", agent, spawn, seed)
    return {"released": seed, "spawn": spawn, "was_active": had}

"""Claim del token → contesto della richiesta, per ogni porta del gateway."""
from __future__ import annotations

import logging

from . import whitelist

LOG = logging.getLogger("clodia-tools.claims")


def _spawn_of(payload: dict) -> str | None:
    """Lo spawn dal claim `execution_id`, se è uno spawn.

    I client MCP di una PERSONA portano anch'essi un `execution_id`, nella forma
    `mcp_*` (`human_mcp`): è l'id del client, non uno spawn, e trattarlo come
    tale farebbe scambiare una persona per uno spawn nel confine dello scratch.
    """
    v = str(payload.get("execution_id") or "")
    if not v or v.startswith("mcp_"):
        return None
    return v


class ClaimsContext:
    """Imposta i contextvar della richiesta dai claim del token e li resetta.

    UNA tabella per tutte le porte del gateway (clodia-platform#398). Prima
    erano due: questa, per gli endpoint interni, e una lista scritta a mano nel
    middleware di `/mcp`. Il docstring diceva «identici a `_AuthMiddleware`», e
    non lo erano più: `/mcp` — la porta di OGNI agente — non impostava lo spawn
    (`execution_id`) né lo `scope_tier`. Così `current_spawn()` era sempre
    `None` proprio dove serviva: `copybrain` e `crosstopic` negati, e il
    confine dello scratch di uno spawn saltato perché si applicava solo «se lo
    spawn è noto». Una sola tabella non può più divergere da sé stessa."""

    # I token si tengono per NOME, non per posizione.
    #
    # Erano una lista rilasciata per indice, e il 5 ago 2026 l'aggiunta di
    # `origin` per la catena di delega ha spostato tutto di uno: `__exit__`
    # passava il token di `origin` al reset di `scoped_tools` — che solleva
    # `ValueError: was created by a different ContextVar` — e `origin` non veniva
    # rilasciato affatto.
    #
    # L'effetto visibile era irriconoscibile dalla causa: `/internal/authorize`
    # DECIDEVA correttamente e poi esplodeva in uscita, rispondendo 500. Il
    # chiamante traduce ogni non-200 in «negato», e all'utente arrivava
    # «azione riservata agli admin» — mandando a cercare un problema di permessi
    # per tre giri. Un difetto di teardown travestito da rifiuto di autorizzazione.
    #
    # Con un dizionario di (setter, resetter) aggiungere una variabile non può
    # più disallineare nulla: non c'è più un ordine da tenere a mente.
    _VARS = (
        ("agent", "set_current_agent", "reset_current_agent",
         lambda p, t: str(p.get("agent") or "")),
        # Lo SPAWN, non il seed: `execution_id` esisteva nel token e nessuno lo
        # riempiva. Aggiungere una riga qui è sicuro perché la tabella ha
        # (nome, setter, resetter): è la struttura nata dal difetto opposto.
        ("spawn", "set_current_spawn", "reset_current_spawn",
         lambda p, t: _spawn_of(p)),
        ("scope_tier", "set_current_scope_tier", "reset_current_scope_tier",
         lambda p, t: p.get("scope_tier") or None),
        ("principal", "set_current_principal", "reset_current_principal",
         lambda p, t: p.get("principal") or None),
        ("token", "set_current_token", "reset_current_token",
         lambda p, t: t or None),
        ("clearance", "set_current_clearance", "reset_current_clearance",
         lambda p, t: p.get("clearance") or None),
        ("on_behalf", "set_current_on_behalf", "reset_current_on_behalf",
         lambda p, t: bool(p.get("on_behalf"))),
        ("principal_kind", "set_current_principal_kind",
         "reset_current_principal_kind", lambda p, t: p.get("principal_kind") or None),
        ("human_role", "set_current_human_role", "reset_current_human_role",
         lambda p, t: p.get("human_role") or None),
        ("chat", "set_current_chat", "reset_current_chat",
         lambda p, t: p.get("chat") or None),
        ("origin", "set_current_origin", "reset_current_origin",
         lambda p, t: p.get("origin") or None),
        ("scoped_tools", "set_current_scoped_tools", "reset_current_scoped_tools",
         lambda p, t: p.get("scoped_tools") or None),
        # Il middleware di `/mcp` lo impostava e questa tabella no: l'unione delle
        # due, non una delle due.
        ("unattended", "set_current_unattended", "reset_current_unattended",
         lambda p, t: bool(p.get("unattended"))),
    )

    def __init__(self, payload: dict, token: str):
        self.payload, self.token, self._toks = payload, token, {}

    def __enter__(self):
        p = self.payload
        for nome, setter, _res, val in self._VARS:
            self._toks[nome] = getattr(whitelist, setter)(val(p, self.token))
        return self

    def __exit__(self, *exc):
        # In ordine inverso, e ogni reset protetto: un rilascio che solleva non
        # deve impedire i successivi, altrimenti un contextvar resta impostato
        # per la richiesta seguente sullo stesso task.
        for nome, _set, resetter, _val in reversed(self._VARS):
            tok = self._toks.get(nome)
            if tok is None:
                continue
            try:
                getattr(whitelist, resetter)(tok)
            except Exception:  # noqa: BLE001
                LOG.warning("ctx: reset di '%s' fallito", nome, exc_info=True)
        self._toks.clear()
        return False

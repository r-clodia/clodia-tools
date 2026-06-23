"""Backend interno del gateway per le credenziali dei PROVIDER di inferenza.

Le credenziali dei provider (token OAuth abbonamento Anthropic via claude.ai,
bundle codex OpenAI, o API key) NON vivono più nel datadir di clodia-logic ma
nella **vault** del gateway (Fase 4). clodia-logic resta il consumatore (è lui
che fa inferenza) e mantiene la logica di login/refresh; lo **storage** è qui.

A differenza di `/mcp` (canale tool→modello), questi endpoint sono chiamati dal
**runner** di clodia-logic (un processo, non un LLM): il bundle del provider non
transita mai da un modello. Auth ckt1 come `/mcp`, ma ristretta a un **principal
privilegiato** (default `clodia`, il trusted-core): le credenziali provider sono
infrastruttura, non grant esposti ai singoli agenti — perciò usano
`vault.deposit(..., grant_agents=[])` / `vault.read_internal` e l'autorizzazione
è il principal di questo router, non un grant per-agente.

  GET    /internal/providers          → {ids: [...]} pid con credenziale nel vault
  GET    /internal/providers/{pid}    → bundle | 404
  PUT    /internal/providers/{pid}    → deposita/aggiorna bundle (login + refresh)
  DELETE /internal/providers/{pid}    → rimuove (disconnect)

Prima Legge: il valore del bundle è restituito SOLO al runner trusted-core di
clodia-logic, mai a un modello, e non viene loggato.
"""
from __future__ import annotations

import logging
import os
import re

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import vault
from .pki_verify import verify_session_token

LOG = logging.getLogger("clodia-tools.providers")

# Principal autorizzati a leggere/scrivere le credenziali provider. Default: il
# solo trusted-core `clodia`. Override via env (CSV) per scenari multi-core.
_PRINCIPALS = {
    p.strip() for p in (os.environ.get("CLODIA_PROVIDER_PRINCIPALS") or "clodia").split(",")
    if p.strip()
}

# pid ammessi: slug semplice (evita path traversal nel nome credenziale).
_PID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")

# Prefisso del nome credenziale nello store del vault.
_CRED_PREFIX = "provider_"


def _cred(pid: str) -> str:
    return f"{_CRED_PREFIX}{pid}"


def _authorize(request: Request) -> tuple[str | None, JSONResponse | None]:
    """Verifica il Bearer ckt1 e che il principal sia tra quelli privilegiati.
    Ritorna (agent, None) se ok, altrimenti (None, JSONResponse di errore)."""
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    try:
        payload = verify_session_token(token)
    except PermissionError as e:
        LOG.warning("providers auth fallita: %s", e)
        return None, JSONResponse({"error": "unauthorized"}, status_code=401)
    agent = str(payload.get("agent") or "")
    if agent not in _PRINCIPALS:
        LOG.warning("providers: principal '%s' non autorizzato", agent)
        return None, JSONResponse({"error": "forbidden"}, status_code=403)
    return agent, None


def _valid_pid(pid: str) -> bool:
    return bool(_PID_RE.match(pid or ""))


async def list_providers(request: Request):
    agent, err = _authorize(request)
    if err:
        return err
    ids = [n[len(_CRED_PREFIX):] for n in vault.store_names() if n.startswith(_CRED_PREFIX)]
    return JSONResponse({"ids": sorted(ids)})


async def get_provider(request: Request):
    agent, err = _authorize(request)
    if err:
        return err
    pid = request.path_params["pid"]
    if not _valid_pid(pid):
        return JSONResponse({"error": "bad_pid"}, status_code=400)
    if not vault.has_credential(_cred(pid)):
        return JSONResponse({"error": "not_found"}, status_code=404)
    try:
        bundle = vault.read_internal(_cred(pid))
    except vault.VaultDenied:
        return JSONResponse({"error": "not_found"}, status_code=404)
    return JSONResponse(bundle)


async def put_provider(request: Request):
    agent, err = _authorize(request)
    if err:
        return err
    pid = request.path_params["pid"]
    if not _valid_pid(pid):
        return JSONResponse({"error": "bad_pid"}, status_code=400)
    try:
        bundle = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    if not isinstance(bundle, dict) or not bundle:
        return JSONResponse({"error": "bundle non è un oggetto JSON non vuoto"},
                            status_code=400)
    # Infra: nessun grant per-agente (accesso solo via questo router privilegiato).
    vault.deposit(_cred(pid), bundle, cred_type="provider", grant_agents=[])
    LOG.info("provider '%s' depositato nel vault (by %s)", pid, agent)
    return JSONResponse({"ok": True, "id": pid})


async def delete_provider(request: Request):
    agent, err = _authorize(request)
    if err:
        return err
    pid = request.path_params["pid"]
    if not _valid_pid(pid):
        return JSONResponse({"error": "bad_pid"}, status_code=400)
    removed = vault.remove(_cred(pid))
    LOG.info("provider '%s' rimosso dal vault=%s (by %s)", pid, removed, agent)
    return JSONResponse({"ok": True, "id": pid, "removed": removed})


routes = [
    Route("/internal/providers", list_providers, methods=["GET"]),
    Route("/internal/providers/{pid}", get_provider, methods=["GET"]),
    Route("/internal/providers/{pid}", put_provider, methods=["PUT"]),
    Route("/internal/providers/{pid}", delete_provider, methods=["DELETE"]),
]

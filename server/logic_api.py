"""logic_api — esecuzione di VERBI per i JOB LOGICI (agentico→logico).

Un job "logico" esegue un piano deterministico di tool-call SENZA turno LLM. Lo
scheduler (agent-server) chiama `POST /internal/logic-run {verb, args}` per ogni
step. Autenticazione: **secret orchestrator condiviso** (`CLODIA_ORCHESTRATOR_SECRET`,
header `X-Orchestrator-Secret`) — server-to-server, non raggiungibile dagli spawn.

SICUREZZA (Prima Legge): NIENTE M-gate qui (il job è già stato approvato dall'owner
alla creazione → l'esecuzione ricorrente è pre-autorizzata). Per NON aprire un
bypass generico di verbi gated, l'esecuzione è ristretta a una **ALLOWLIST** esplicita
di verbi sicuri per l'esecuzione non presidiata. Espandere l'allowlist è un atto
deliberato (nuovo deploy), non runtime.
"""
from __future__ import annotations

import hmac
import logging
import os

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

LOG = logging.getLogger("clodia-tools.logic")


def _authorized(request: Request) -> bool:
    expected = (os.environ.get("CLODIA_ORCHESTRATOR_SECRET") or "").strip()
    if not expected:
        return False  # fail-closed
    got = (request.headers.get("x-orchestrator-secret") or "").strip()
    return bool(got) and hmac.compare_digest(got, expected)


def _verb_backup_run(_args: dict) -> dict:
    from . import backup
    return backup.run_backup()


def _verb_backup_restore_test(_args: dict) -> dict:
    from . import backup
    return backup.restore_test()


# ALLOWLIST verbo → callable(args)->dict. Solo verbi sicuri per esecuzione
# non presidiata dentro un job logico pre-autorizzato.
_ALLOWED = {
    "settings.backup_run": _verb_backup_run,
    "settings.backup_restore_test": _verb_backup_restore_test,
}


async def logic_run(request: Request):
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        b = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "bad request"}, status_code=400)
    verb = (b.get("verb") or "").strip()
    args = b.get("args") or {}
    fn = _ALLOWED.get(verb)
    if fn is None:
        return JSONResponse(
            {"error": f"verbo '{verb}' non ammesso nei job logici (allowlist)"},
            status_code=403)
    try:
        result = fn(args if isinstance(args, dict) else {})
        LOG.info("logic-run verb=%s ok", verb)
        return JSONResponse({"ok": True, "verb": verb, "result": result})
    except Exception as e:  # noqa: BLE001
        LOG.error("logic-run verb=%s fallito: %s", verb, e)
        return JSONResponse({"ok": False, "verb": verb, "error": str(e)[:400]},
                            status_code=500)


routes = [
    Route("/internal/logic-run", logic_run, methods=["POST"]),
]

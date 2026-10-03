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
    """Backup notturno + sorveglianza del restore-test settimanale.

    Il controllo di freschezza sta QUI e non dentro `backup.py` perché è una
    politica del job, non una proprietà del repository: `run_backup()` continua
    a rispondere «il repository è integro?», e chi lo esegue ogni notte decide
    cosa fare dell'informazione «l'ultimo restore-test riuscito è di 14 giorni
    fa». È il notturno a doversene accorgere: il settimanale che non parte non
    può notificare di non essere partito (clodia-platform#422).
    """
    from . import backup
    res = dict(backup.run_backup())
    fr = backup.restore_test_freshness(write_baseline=True)
    res["restore_test"] = fr
    if fr.get("overdue"):
        res["ok"] = False
        res["error"] = (f"restore-test: nessun esito riuscito da {fr.get('days')} "
                        f"giorni (limite {fr.get('max_days')})")
    return res


def _verb_backup_restore_test(_args: dict) -> dict:
    from . import backup
    return backup.restore_test()


# ALLOWLIST verbo → callable(args)->dict. Solo verbi sicuri per esecuzione
# non presidiata dentro un job logico pre-autorizzato.
#
# Il criterio di ammissione non è «è utile», è «cosa può fare di diverso se
# nessuno guarda»: nessuna destinazione e nessun testo che arrivino dal
# chiamante, e una superficie di argomenti troppo piccola perché controllare il
# chiamante serva a qualcosa. È la ragione per cui questa lista esiste come
# lista e non come regola: si valuta un verbo per volta.
_ALLOWED = {
    "settings.backup_run": _verb_backup_run,
    "settings.backup_restore_test": _verb_backup_restore_test,
}


def _motivo(result: dict) -> str:
    """Il perché del fallimento, in forma leggibile nella notifica all'owner."""
    if result.get("error"):
        return str(result["error"])[:400]
    codici = {k: v for k, v in result.items()
              if k.endswith("_rc") and v not in (0, None)}
    return (", ".join(f"{k}={v}" for k, v in sorted(codici.items()))
            or "esito non riuscito")[:400]


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
        if isinstance(result, dict) and result.get("ok") is False:
            # Un verbo che torna `ok: false` ha FALLITO, e lo step con lui.
            # Senza questa riga il job registrava `last_status: ok` su un
            # `{"ok": false, "check_rc": 11}` e la notifica d'errore non
            # partiva: 14 notti di backup non verificati, nessuno avvisato
            # (clodia-platform#422). La risposta resta **200**: lo scheduler fa
            # `raise_for_status()` prima di guardare il corpo, e un 500 gli
            # lascerebbe in mano «500 Server Error» al posto del motivo vero.
            motivo = _motivo(result)
            LOG.error("logic-run verb=%s esito non ok: %s", verb, motivo)
            return JSONResponse({"ok": False, "verb": verb, "error": motivo,
                                 "result": result})
        LOG.info("logic-run verb=%s ok", verb)
        return JSONResponse({"ok": True, "verb": verb, "result": result})
    except Exception as e:  # noqa: BLE001
        LOG.error("logic-run verb=%s fallito: %s", verb, e)
        return JSONResponse({"ok": False, "verb": verb, "error": str(e)[:400]},
                            status_code=500)


routes = [
    Route("/internal/logic-run", logic_run, methods=["POST"]),
]

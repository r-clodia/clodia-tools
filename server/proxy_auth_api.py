"""`POST /proxy/token` — l'unica rotta del gateway che nasce SENZA autenticazione.

E non è una deroga: **l'asserzione è l'autenticazione**. Chiedere un token
mostrando una firma è la stessa cosa che `_authorize` fa per le rotte interne,
solo che qui la prova arriva dal richiedente invece che da un segreto condiviso
di rete. Una rotta protetta da un secret non servirebbe a niente: il sistema
terzo quel secret non ce l'ha — è precisamente ciò che sta cercando di ottenere.

Gli errori tornano **400 con il motivo intatto**. È deliberato: chi collega un
sistema esterno sta scrivendo codice, e «unauthorized» senza altro lo lascia a
indovinare fra orologio, chiave, audience e collegamento revocato — quattro
rimedi diversi. Non c'è nulla da proteggere in quei messaggi: dicono cosa non
torna in ciò che il chiamante ha appena mandato, mai cosa esiste dall'altra
parte.
"""
from __future__ import annotations

import logging

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import proxy_auth

LOG = logging.getLogger("clodia-tools.proxy_auth_api")


async def proxy_token(request: Request):
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "bad_json"}, status_code=400)
    assertion = (body.get("assertion") or "").strip()
    if not assertion:
        return JSONResponse(
            {"error": "assertion mancante: firma un'asserzione cpa1 con la "
                      "chiave del proxy e mandala qui"}, status_code=400)
    try:
        return JSONResponse(proxy_auth.token_for(assertion))
    except PermissionError as e:
        # Loggato per NOME del principal quando si riesce a leggerlo: un
        # tentativo fallito ripetuto è la traccia di una chiave che non combacia
        # o di qualcuno che riprova una firma vecchia, e senza il nome nel log
        # sono indistinguibili.
        LOG.warning("proxy token rifiutato: %s", str(e)[:200])
        return JSONResponse({"error": str(e)[:400]}, status_code=400)


routes = [Route("/proxy/token", proxy_token, methods=["POST"])]

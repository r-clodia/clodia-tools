"""mint_api — endpoint interno di minting (trust-anchor lato gateway).

`POST /internal/mint` conia un token per conto dell'orchestrator (agent-server),
che NON tiene più chiavi private. Autenticazione via **secret di bootstrap**
condiviso (`CLODIA_ORCHESTRATOR_SECRET`, header `X-Orchestrator-Secret`), NON via
ckt1: sarebbe circolare (per coniare servirebbe già un token). Il secret vive
solo nell'ENV dei due servizi trusted (gateway + orchestrator), mai su un volume
montato dagli spawn né nel loro child-env → un agente sandboxato non può
raggiungerlo e quindi non può farsi coniare identità arbitrarie.

Body JSON:
  {"kind":"session"|"capability", "agent":..., "principal":..., "clearance":...,
   "on_behalf":bool, "human_role":..., "chat":..., "ttl_seconds":int,
   "execution_id":..., "instance":..., "minutes":int, "by":..., "cap":...}
"""
from __future__ import annotations

import hmac
import logging
import os

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import pki_mint

LOG = logging.getLogger("clodia-tools.mint")


def _bootstrap_secret() -> str:
    return (os.environ.get("CLODIA_ORCHESTRATOR_SECRET") or "").strip()


def _authorized(request: Request) -> bool:
    expected = _bootstrap_secret()
    if not expected:
        # Nessun secret configurato → endpoint disabilitato (fail-closed): il
        # minting resta locale all'orchestrator finché non si abilita il flag.
        return False
    got = (request.headers.get("x-orchestrator-secret") or "").strip()
    return bool(got) and hmac.compare_digest(got, expected)


async def mint(request: Request):
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        b = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "bad request"}, status_code=400)
    kind = (b.get("kind") or "session").strip()
    agent = (b.get("agent") or "").strip()
    if not agent:
        return JSONResponse({"error": "agent mancante"}, status_code=400)
    try:
        if kind == "session":
            token = pki_mint.mint_session_token(
                agent,
                execution_id=b.get("execution_id") or "",
                ttl_seconds=int(b.get("ttl_seconds") or pki_mint.SESSION_TTL_SECONDS),
                principal=b.get("principal") or None,
                clearance=b.get("clearance") or None,
                on_behalf=bool(b.get("on_behalf")),
                human_role=b.get("human_role") or None,
                chat=b.get("chat") or None,
            )
            return JSONResponse({"token": token})
        if kind == "capability":
            res = pki_mint.mint_capability(
                agent, b.get("instance") or "-", int(b.get("minutes") or 15),
                by=b.get("by") or "", cap=b.get("cap") or "sudo")
            return JSONResponse(res)
        return JSONResponse({"error": f"kind ignoto: {kind}"}, status_code=400)
    except PermissionError as e:
        LOG.warning("mint negato per %s: %s", agent, e)
        return JSONResponse({"error": str(e)}, status_code=403)
    except Exception as e:  # noqa: BLE001
        LOG.error("mint fallito per %s: %s", agent, e)
        return JSONResponse({"error": "mint failed"}, status_code=500)


routes = [
    Route("/internal/mint", mint, methods=["POST"]),
]

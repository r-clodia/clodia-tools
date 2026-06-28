"""Router privilegiato per i profili PII (chiamato dall'agent-server per la UI).

Auth ckt1: il token porta il `principal` (l'utente/agent che opera). L'enforcement
ACL (self/admin/grant) è in `profile.py`. I valori non transitano mai da un modello.
"""
from __future__ import annotations

import logging

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import profile
from .pki_verify import verify_session_token

LOG = logging.getLogger("clodia-tools.profile")


def _principal(request: Request) -> tuple[str | None, JSONResponse | None]:
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    try:
        payload = verify_session_token(token)
    except PermissionError as e:
        LOG.warning("profile auth fallita: %s", e)
        return None, JSONResponse({"error": "unauthorized"}, status_code=401)
    return str(payload.get("agent") or ""), None


def _err(e: Exception) -> JSONResponse:
    code = 403 if isinstance(e, PermissionError) else 400
    return JSONResponse({"error": str(e)[:200]}, status_code=code)


async def get_profile(request: Request):
    caller, err = _principal(request)
    if err:
        return err
    try:
        return JSONResponse(profile.get(caller, request.path_params["agent"]))
    except Exception as e:  # noqa: BLE001
        return _err(e)


async def put_profile(request: Request):
    caller, err = _principal(request)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    try:
        return JSONResponse(profile.set_fields(caller, request.path_params["agent"],
                                               body.get("fields", {})))
    except Exception as e:  # noqa: BLE001
        return _err(e)


async def grant_profile(request: Request):
    caller, err = _principal(request)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    try:
        return JSONResponse(profile.grant(caller, request.path_params["agent"],
                                          body["grantee"], bool(body.get("granted", True))))
    except Exception as e:  # noqa: BLE001
        return _err(e)


routes = [
    Route("/internal/profile/{agent}", get_profile, methods=["GET"]),
    Route("/internal/profile/{agent}", put_profile, methods=["PUT"]),
    Route("/internal/profile/{agent}/grant", grant_profile, methods=["POST"]),
]

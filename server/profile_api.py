"""Router privilegiato per i profili PII (chiamato dall'agent-server per la UI).

Auth ckt1: il token porta il `principal` (l'utente/agent che opera). L'enforcement
ACL (self/admin/grant) è in `profile.py`. I valori non transitano mai da un modello.
"""
from __future__ import annotations

import base64
import logging

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from . import internal_auth, profile
from .pki_verify import verify_session_token

LOG = logging.getLogger("clodia-tools.profile")


# Servizi fidati (agent-server) che possono dichiarare il principal effettivo via
# header — necessario per gli UMANI, che non hanno chiave server-side per coniare
# un token a proprio nome. Solo i super-agent sono ammessi come servizio.
_TRUSTED_SERVICES = {"clodia", "ophelia"}


def _principal(request: Request) -> tuple[str | None, JSONResponse | None]:
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    try:
        payload = verify_session_token(token)
    except PermissionError as e:
        LOG.warning("profile auth fallita: %s", e)
        return None, JSONResponse({"error": "unauthorized"}, status_code=401)
    err = internal_auth.refuse_if_revoked(payload, log=LOG)
    if err:
        return None, err
    # L'identità di servizio dell'agent-server è un token NUDO sul principal
    # (`clodia-logic/server/api/profile.py:_headers`). Un token `on_behalf` o
    # *scoped* porta lo stesso claim `agent` — è il carrier — ma non è quel
    # servizio: senza questa riga un token di proxy stretto a quattro verbi di
    # chat dichiarava nell'header il principal che voleva e leggeva i PII di
    # chiunque, perché l'ACL di `profile.py` si applica al principal DICHIARATO
    # (clodia-platform#261).
    if payload.get("on_behalf") or payload.get("scoped_tools"):
        LOG.warning("profile: sessione non di servizio rifiutata (principal=%s)",
                    payload.get("principal"))
        return None, JSONResponse({"error": "forbidden"}, status_code=403)
    agent = str(payload.get("agent") or "")
    # Un servizio fidato può agire per conto del principal reale (header).
    declared = request.headers.get("x-clodia-principal", "")
    if declared and agent in _TRUSTED_SERVICES:
        return declared, None
    return agent, None


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



async def list_files(request: Request):
    caller, err = _principal(request)
    if err:
        return err
    try:
        return JSONResponse({"files": profile.list_files(caller, request.path_params["agent"])})
    except Exception as e:  # noqa: BLE001
        return _err(e)


async def upload_file(request: Request):
    caller, err = _principal(request)
    if err:
        return err
    try:
        body = await request.json()
        data = base64.b64decode(body["data_b64"])
        return JSONResponse(profile.put_file(caller, request.path_params["agent"],
                                             body["filename"], data))
    except Exception as e:  # noqa: BLE001
        return _err(e)


async def download_file(request: Request):
    caller, err = _principal(request)
    if err:
        return err
    try:
        data = profile.read_file(caller, request.path_params["agent"],
                                 request.path_params["filename"])
        return Response(data, media_type="application/octet-stream")
    except Exception as e:  # noqa: BLE001
        return _err(e)


async def delete_file(request: Request):
    caller, err = _principal(request)
    if err:
        return err
    try:
        return JSONResponse(profile.delete_file(caller, request.path_params["agent"],
                                                request.path_params["filename"]))
    except Exception as e:  # noqa: BLE001
        return _err(e)


routes = [
    Route("/internal/profile/{agent}", get_profile, methods=["GET"]),
    Route("/internal/profile/{agent}", put_profile, methods=["PUT"]),
    Route("/internal/profile/{agent}/grant", grant_profile, methods=["POST"]),
    Route("/internal/profile/{agent}/files", list_files, methods=["GET"]),
    Route("/internal/profile/{agent}/files", upload_file, methods=["POST"]),
    Route("/internal/profile/{agent}/files/{filename}", download_file, methods=["GET"]),
    Route("/internal/profile/{agent}/files/{filename}", delete_file, methods=["DELETE"]),
]

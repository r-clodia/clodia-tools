"""Backend interno del gateway per la lettura di credenziali GIT dal vault.

Serve al runner di clodia-logic (workflow): per clonare/pushare un repo privato
(es. tomatoblue-next) il backend ha bisogno del PAT, che vive nel vault del
gateway. Come `providers_api`, è ckt1 ristretto al trusted-core e SCOPATO:
restituisce SOLO credenziali di tipo `mcp_secret` (i PAT/token dei tool) —
MAI provider di inferenza, backup_config, chiavi dei topic o altro. Il valore
è per il runner, mai per un modello, e non viene loggato.

  GET /internal/vault/{name}  → {value: "..."} | 404 (assente/non ammessa)
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

LOG = logging.getLogger("clodia-tools.vault_api")

_PRINCIPALS = {
    p.strip() for p in (os.environ.get("CLODIA_PROVIDER_PRINCIPALS") or "clodia").split(",")
    if p.strip()
}
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,60}$")
# SOLO i segreti dei tool (PAT git, token MCP). Esclude provider_*, backup_config,
# chiavi topic, ecc. → superficie minima.
_ALLOWED_TYPES = {"mcp_secret"}


def _authorize(request: Request) -> JSONResponse | None:
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    try:
        payload = verify_session_token(token)
    except PermissionError:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if str(payload.get("agent") or "") not in _PRINCIPALS:
        return JSONResponse({"error": "forbidden"}, status_code=403)
    return None


async def get_vault_credential(request: Request):
    err = _authorize(request)
    if err:
        return err
    name = request.path_params["name"]
    if not _NAME_RE.match(name or "") or not vault.has_credential(name):
        return JSONResponse({"error": "not_found"}, status_code=404)
    # scope: solo credenziali di tipo ammesso (mcp_secret)
    ctype = None
    try:
        policy = vault._load_policy()  # noqa: SLF001 — lettura del tipo dichiarato
        ctype = ((policy.get("credentials") or {}).get(name) or {}).get("type")
    except Exception:  # noqa: BLE001
        ctype = None
    if ctype not in _ALLOWED_TYPES:
        LOG.warning("vault_api: credenziale '%s' (tipo %s) non ammessa", name, ctype)
        return JSONResponse({"error": "not_found"}, status_code=404)
    try:
        bundle = vault.read_internal(name)
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "not_found"}, status_code=404)
    # non logghiamo il valore
    return JSONResponse({"value": bundle.get("value") or bundle.get("token") or ""})


routes = [Route("/internal/vault/{name}", get_vault_credential, methods=["GET"])]

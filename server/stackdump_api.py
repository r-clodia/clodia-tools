"""GET /internal/diagnostics/stacks — the gateway's thread and task stacks,
redacted (clodia-platform#710). See `stackdump` for what is in the dump.

Who: the agent-server's service role (`role: agent-server`, for the webui and
the operator's tooling) or an admin person's on-behalf session. Never an
agent: a spawn's token, the bare carrier token and a non-admin person are
refused — the dump says which code the gateway is running, and where it waits,
which is the operator's business.
"""
from __future__ import annotations

import logging

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import internal_auth, stackdump

LOG = logging.getLogger("clodia-tools.stackdump_api")


def _admin_or_service(payload: dict) -> bool:
    from .human import _ADMIN_ROLES
    from .pki_mint import ROLE_AGENT_SERVER
    if payload.get("role") == ROLE_AGENT_SERVER:
        return True
    from . import human_mcp
    return bool(payload.get("on_behalf")
                and human_mcp.principal_kind_of(payload) == "human"
                and (payload.get("human_role") or "") in _ADMIN_ROLES)


async def stacks_route(request: Request):
    payload, err = internal_auth.authorize(request, allow_on_behalf=True, log=LOG)
    if err:
        return err
    if not _admin_or_service(payload):
        LOG.warning("stack dump refused to %s (not admin, not the service role)",
                    payload.get("principal") or payload.get("agent"))
        return JSONResponse({"error": "reserved to admins and the agent-server"},
                            status_code=403)
    # On the loop on purpose: the asyncio tasks are read from the running loop,
    # and the dump is a walk of in-memory frames (milliseconds).
    return JSONResponse(stackdump.dump())


routes = [Route("/internal/diagnostics/stacks", stacks_route, methods=["GET"])]

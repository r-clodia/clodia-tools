"""GET /internal/diagnostics/tool-calls — per verb/backend tool-call
telemetry of the gateway (clodia-platform#550). See `tool_calls`.

Who: the agent-server's service role (`role: agent-server`, for the webui and
the operator's tooling) or an admin person's on-behalf session. Never an
agent: a spawn's token, the bare carrier token and a non-admin person are
refused. The table holds verb names and numbers only, but which verbs the
colony uses, how often and how they fail is the operator's business.

`?top=N` keeps the N busiest verbs (the backends are always all listed).
"""
from __future__ import annotations

import logging

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import internal_auth, tool_calls

LOG = logging.getLogger("clodia-tools.tool_calls_api")


def _admin_or_service(payload: dict) -> bool:
    from .human import _ADMIN_ROLES
    from .pki_mint import ROLE_AGENT_SERVER
    if payload.get("role") == ROLE_AGENT_SERVER:
        return True
    from . import human_mcp
    return bool(payload.get("on_behalf")
                and human_mcp.principal_kind_of(payload) == "human"
                and (payload.get("human_role") or "") in _ADMIN_ROLES)


async def tool_calls_route(request: Request):
    payload, err = internal_auth.authorize(request, allow_on_behalf=True, log=LOG)
    if err:
        return err
    if not _admin_or_service(payload):
        LOG.warning("tool-call telemetry refused to %s (not admin, not the service role)",
                    payload.get("principal") or payload.get("agent"))
        return JSONResponse({"error": "reserved to admins and the agent-server"},
                            status_code=403)
    top = request.query_params.get("top")
    try:
        top_n = int(top) if top not in (None, "") else None
    except ValueError:
        return JSONResponse({"error": "top: an integer"}, status_code=400)
    # In memory, on the loop: a copy of a bounded table.
    return JSONResponse(tool_calls.snapshot(top=top_n))


routes = [Route("/internal/diagnostics/tool-calls", tool_calls_route, methods=["GET"])]

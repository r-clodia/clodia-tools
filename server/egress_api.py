"""egress_api — read-only view of the egress confinement, for the agent-server.

Why an endpoint at all. The trifecta score is computed in the agent-server, but
the destination whitelist lives in the GATEWAY's config, on a volume the
agent-server deliberately does not mount (clodia-platform#80: whoever can rewrite
the whitelist self-grants destinations). So the score cannot read the data it now
needs, and the only correct way across that boundary is the existing
server-to-server channel.

Authentication: `CLODIA_ORCHESTRATOR_SECRET` (`X-Orchestrator-Secret`), the same
as `/internal/logic-run` and `/internal/mint`. Not reachable from a spawn.

What it returns is metadata only — the mode and, per agent, which destination
types have rules and how many. **Never the destinations themselves**: an
address book is private data, and the score does not need it to tell arbitrary
egress from circumscribed egress. Sending the list would put the owner's
contacts into the context of whatever renders the score.
"""
from __future__ import annotations

import hmac
import logging
import os

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

LOG = logging.getLogger("clodia-tools.egress-api")


def _authorized(request: Request) -> bool:
    expected = (os.environ.get("CLODIA_ORCHESTRATOR_SECRET") or "").strip()
    if not expected:
        return False  # fail-closed
    got = (request.headers.get("x-orchestrator-secret") or "").strip()
    return bool(got) and hmac.compare_digest(got, expected)


def _scope(rules) -> str:
    """How constrained the egress of one type is.

    `wide` covers the explicit `*` opt-out: a rule set of `["*"]` is declared but
    constrains nothing, and reporting it as circumscribed would be the one
    direction of error this measure cannot afford.
    """
    if rules is None:
        return "none"          # no rules declared → the type denies (§7 prop. 6)
    if not rules:
        return "muted"         # declared empty → denies (§7 prop. 1)
    if any(str(r).strip() == "*" for r in rules):
        return "wide"
    return "listed"


async def profile(request: Request):
    """GET /internal/egress → mode + per-agent shape of the whitelist."""
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from . import egress
    from .whitelist import CONFIG
    agents = {}
    for name, spec in (CONFIG.get("agents") or {}).items():
        allow = (spec or {}).get("egress_allow") or {}
        agents[name] = {t: {"scope": _scope(r), "count": len(r or [])}
                        for t, r in allow.items()}
    return JSONResponse({"mode": egress.mode(), "agents": agents})


routes = [Route("/internal/egress", profile, methods=["GET"])]

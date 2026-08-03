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


async def observations(request: Request):
    """GET /internal/observations?since=<epoch> → gate che SAREBBERO scattati.

    Alimenta il feedback effimero nel footer della webui: in modalità di
    osservazione l'owner lavora come prima, e questo è l'unico modo in cui vede
    che un controllo *avrebbe* chiesto qualcosa. Senza, l'osservazione è muta e
    l'unico modo di leggerla sarebbe aprire il registro a mano.

    Solo metadati, come il registro da cui legge.
    """
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        since = int(request.query_params.get("since") or 0)
    except ValueError:
        since = 0
    limit = 50
    from . import observe, telemetry
    rows = []
    try:
        p = telemetry._path()
        if p.is_file():
            import json as _j
            for line in p.read_text(encoding="utf-8").splitlines()[-2000:]:
                try:
                    r = _j.loads(line)
                except ValueError:
                    continue
                if r.get("outcome") in ("would_gate", "would_deny") \
                        and int(r.get("at") or 0) > since:
                    rows.append(r)
    except OSError as e:
        return JSONResponse({"error": str(e)[:120], "observations": []})
    return JSONResponse({"observing": observe.skipping(),
                         "observations": rows[-limit:]})


async def whitelist_view(request: Request):
    """GET /internal/egress/whitelist → le destinazioni, per agente e per tipo.

    Diverso da `/internal/egress`, che ritorna solo la FORMA: là il consumatore è
    il punteggio, che non ha bisogno degli indirizzi e non deve averli. Qui il
    consumatore è l'owner nelle impostazioni, che ha tutto il diritto di vedere
    la propria rubrica — è la sua. Stessa auth server-to-server: la webui passa
    dall'agent-server, non parla al gateway.
    """
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from . import egress
    from .whitelist import CONFIG
    agents = {}
    for name, spec in (CONFIG.get("agents") or {}).items():
        allow = (spec or {}).get("egress_allow") or {}
        if allow:
            agents[name] = {t: list(r or []) for t, r in allow.items()}
    return JSONResponse({"mode": egress.mode(), "agents": agents,
                         "types": sorted({t for t, _ in egress._SPECS.values()}
                                         | {"github"})})


routes = [Route("/internal/egress", profile, methods=["GET"]),
          Route("/internal/egress/whitelist", whitelist_view, methods=["GET"]),
          Route("/internal/observations", observations, methods=["GET"])]

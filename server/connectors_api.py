"""connectors_api — the connectors of this instance, generically.

clodia-platform#519. Until now every connector had its own routes, one family
per vendor (`tg-link`, `mailbox-link`, `drive-folder`, `/tools/google/*`,
`/tools/telegram/*`). The registry of #518 made that unnecessary for the
READING side: what a connector is, which schemes it speaks, which button it adds
to a topic and which credential it needs is declared in its manifest, so one
route can serve all of them and a connector arriving with a pack appears without
a deploy.

Two routes here, and neither writes anything:

    GET  /internal/connectors           what is installed, for the webui (#520)
    POST /internal/connectors/validate  what a candidate block would do

The second is the install-time half: `pack_import` in clodia-logic asks before
registering a pack, the way it already asks `/flow-allow` for the flow
declarations. The verdict is computed in `connectors/validate.py` — see there
for why a refusal and an «ignored because the gateway still implements it» are
two different answers, and only the first stops an installation.

**No secret is ever returned.** A provider is described by the NAME of its vault
entry and by whether something is stored under it, never by its contents.
"""
from __future__ import annotations

import logging

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import instance_profile
from .connectors import resolved as _resolved
from .connectors import validate as _validate

LOG = logging.getLogger("clodia-tools.connectors-api")


def _authorize(request: Request):
    """The ADMIN check of the Tools routes (`tools_api._authorized`).

    Review of #359: `internal_auth.authorize(allow_on_behalf=True)` let ANY
    human session through. The real callers are an admin at the Tools page
    (on-behalf with `human_role: admin`) and `pack_import` in clodia-logic,
    which mints a plain session token for its principal (`clodia`) — both pass
    here, a non-admin session does not.
    """
    from . import tools_api
    if not tools_api._authorized(request):
        LOG.warning("connectors: richiesta non autorizzata (serve un admin)")
        return {}, JSONResponse({"error": "unauthorized"}, status_code=401)
    return {}, None


def _allowed(cid: str) -> bool:
    """The instance profile decides which connectors exist here at all.

    Asked per connector rather than filtering a list afterwards, so a connector
    that the profile excludes is missing from the listing for the same reason it
    is refused at the Tools page: one rule, one place (`connector_check`).
    """
    try:
        instance_profile.connector_check(cid)
        return True
    except PermissionError:
        return False


async def list_connectors(request: Request):
    """GET /internal/connectors → the installed connectors, from the registry.

    Includes the ones the gateway still implements itself (`builtin: true`):
    from the outside they are connectors like the others, which is the point of
    declaring them in the same grammar. `problems` is not an error field — it
    says why the list may be shorter than the packs installed, and an empty
    registry with no reason shown is the failure that looks like «no packs».
    """
    _payload, err = _authorize(request)
    if err:
        return err
    reg = _resolved.registry()
    rows = [_validate.summary(c) for c in reg.connectors if _allowed(c.id)]
    return JSONResponse({
        "connectors": rows,
        "schemes": {"egress": list(reg.scheme_names("egress")),
                    "source": list(reg.scheme_names("source"))},
        "problems": list(_resolved.problems()),
        "ignored": list(reg.refused),
    })


async def validate_connectors(request: Request):
    """POST /internal/connectors/validate {pack, connectors} → verdict, no write.

    Called by `pack_import` before it registers a pack. Answers `ok: false` only
    for what is wrong wherever and whenever it is asked; a declaration that is
    merely inert on this instance today comes back in `ignored`, with `ok: true`
    — a pack must not become uninstallable because the gateway has not finished
    its own migration.
    """
    _payload, err = _authorize(request)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "bad_json"}, status_code=400)
    body = body or {}
    out = _validate.validate(str(body.get("pack") or ""), body.get("connectors"))
    if out["errors"]:
        LOG.warning("connectors: blocco rifiutato per il pack '%s': %s",
                    out["pack"], out["errors"][0])
    return JSONResponse(out)


routes = [
    Route("/internal/connectors", list_connectors, methods=["GET"]),
    Route("/internal/connectors/validate", validate_connectors, methods=["POST"]),
]

"""HTTP side of gateway components (clodia-platform#558).

    GET|POST|… /tools/<pack>/<path>         a route a component registered
    GET        /internal/components         status of every gateway component
    POST       /internal/components/<pack>/refresh
                                            re-fetch that pack's components

Component routes require a human admin or the trusted core, whether the
component declared `owner` or `admin` (only `owner` routes may write the
component's config): there is no public component route. They are mounted AFTER every core route,
so a core path under `/tools/…` always wins.

`refresh` re-resolves the pack's default-branch head upstream and reloads; it
requires a HUMAN admin (or the trusted core's UI token), like `auth="admin"`
and `auth="owner"` component routes — never a super-agent or the agent-server's
service role. `{"allow_downgrade": true}` lowers the floor: the owner's
decision. Every component route call and every refresh is audited
(`control.component`).
"""
from __future__ import annotations

import asyncio
import logging

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from . import components
from .components.host import OWNER_REQUEST

LOG = logging.getLogger("clodia-tools.components")

_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]


def _auth_ok(request: Request, level: str) -> bool:
    """`owner` and `admin` both need a HUMAN admin (or the trusted core's UI
    token): never a super-agent, never the agent-server's service role. They
    differ in what the route may do — only an owner route may write the
    component's config (`host.set_config`). `status` is a read for the
    services that already read `/internal/connectors`."""
    from . import tools_api
    if level in ("owner", "admin"):
        return tools_api._authorized_owner(request)
    return tools_api._authorized(request)


def _audit_route(request: Request, spec, status: int) -> None:
    """Every component route call is a control-plane record: who, which
    component, which path, with what outcome. Never the body."""
    try:
        from .audit import control as _control
        from . import tools_api
        principal = ""
        hdr = request.headers.get("authorization", "")
        if tools_api._UI_TOKEN and hdr == f"Bearer {tools_api._UI_TOKEN}":
            principal = "trusted-core"
        elif hdr.lower().startswith("bearer "):
            try:
                from .pki_verify import verify_session_token
                p = verify_session_token(hdr[7:])
                principal = str(p.get("principal") or p.get("agent") or "")
            except Exception:  # noqa: BLE001 — unparsable: recorded without
                principal = ""
        _control.safe(_control.emit, "component", request.method.lower(),
                      f"/tools/{spec.pack}/{spec.path}", component=spec.component,
                      auth=spec.auth, status=status, principal=principal or None)
    except Exception as e:  # noqa: BLE001
        LOG.error("components: route audit not recorded (%s)", type(e).__name__)


def _core_answer(request: Request) -> Response:
    """What the app answered before the catch-all existed: 405 when a core
    route has this path with other methods (Starlette prefers our full match
    over its partial one), else 404."""
    from starlette.routing import Match
    scope = dict(request.scope)
    for r in getattr(request.app, "routes", []) or []:
        if getattr(r, "endpoint", None) is component_route:
            continue
        try:
            match, _ = r.matches(scope)
        except Exception:  # noqa: BLE001
            continue
        if match == Match.PARTIAL:
            return JSONResponse({"error": "method not allowed"}, status_code=405)
    return JSONResponse({"error": "not found"}, status_code=404)


async def component_route(request: Request):
    pack = request.path_params["pack"]
    path = request.path_params["rest"]
    spec = components.route(pack, path)
    if spec is None:
        return _core_answer(request)
    if not _auth_ok(request, spec.auth):
        resp = JSONResponse({"error": "unauthorized"}, status_code=401)
    elif request.method not in spec.methods:
        resp = JSONResponse({"error": "method not allowed"}, status_code=405)
    else:
        resp = await _run(request, spec)
    await asyncio.to_thread(_audit_route, request, spec, resp.status_code)
    return resp


async def _run(request: Request, spec) -> Response:
    tok = OWNER_REQUEST.set(spec.auth == "owner")
    try:
        if asyncio.iscoroutinefunction(spec.handler):
            out = await spec.handler(request)
        else:
            out = await asyncio.to_thread(spec.handler, request)
    except PermissionError as e:
        return JSONResponse({"error": str(e)}, status_code=403)
    except Exception as e:  # noqa: BLE001 — a component error is a 500, not a crash
        LOG.error("components: route %s/%s failed: %s", spec.pack, spec.path, e)
        return JSONResponse({"error": f"{type(e).__name__}"}, status_code=500)
    finally:
        OWNER_REQUEST.reset(tok)
    if isinstance(out, Response):
        return out
    return JSONResponse(out)


async def components_status(request: Request):
    if not _auth_ok(request, "read"):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return JSONResponse({"components": components.status(),
                         "problems": components.problems()})


async def components_refresh(request: Request):
    # A HUMAN admin (or the trusted core): moving code inside the reference
    # monitor is not something a super-agent or a service token decides.
    if not _auth_ok(request, "owner"):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    pack = request.path_params["pack"]
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 — empty body: defaults
        body = {}
    allow_downgrade = bool((body or {}).get("allow_downgrade"))
    try:
        from .audit import control as _control
        _control.safe(_control.emit, "component", "refresh", pack,
                      allow_downgrade=allow_downgrade or None)
    except Exception:  # noqa: BLE001
        pass
    rows = await asyncio.to_thread(components.reconcile, refresh_pack=pack,
                                   allow_downgrade=allow_downgrade)
    return JSONResponse({"components": [r for r in rows if r["pack"] == pack]})


#: Core routes first (`/internal/...`), the catch-all LAST.
internal_routes = [
    Route("/internal/components", components_status, methods=["GET"]),
    Route("/internal/components/{pack}/refresh", components_refresh, methods=["POST"]),
]
catch_all_routes = [
    Route("/tools/{pack}/{rest:path}", component_route, methods=_METHODS),
]

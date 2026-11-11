"""The Databases page's internal routes (clodia-platform#671).

    GET  /internal/databases                                       catalogue
    POST /internal/databases  {action: create_datastore | create_collection
                               | delete | restore, ...}           admins
    GET  /internal/databases/datastore/{pack}/{name}/tables        ?scope=
    GET  /internal/databases/datastore/{pack}/{name}/rows          ?table&limit&offset&q&scope
    POST /internal/databases/datastore/{pack}/{name}/rows          {op, table, rowid?, values?, scope?}
    POST /internal/databases/datastore/{pack}/{name}/schema        {op, ...}   admins
    GET  /internal/databases/collection/{name}/documents           ?scope=
    GET  /internal/databases/collection/{name}/chunks              ?doc&version&limit&offset&scope
    POST /internal/databases/collection/{name}/upload              ?filename&doc_name&version&scope, raw body
    POST /internal/databases/collection/{name}/remove              {doc_name, version?, scope?}

Only a PERSON's on-behalf session passes (the agent-server mints it with the
person's signed role and clearance): agents reach data through their verbs
and the scope of their signed claim, never through this door. `scope` is the
room the person is working from: a non-admin reaches content only through a
scope that imports it (`databases.authorize_person`).
"""
from __future__ import annotations

import asyncio
import logging

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import databases, datastores, human_mcp, internal_auth

LOG = logging.getLogger("clodia-tools.databases_api")


def _person(request: Request):
    """`((who, is_admin, clearance), None)` or `(None, error response)`."""
    from .human import _ADMIN_ROLES
    payload, err = internal_auth.authorize(request, allow_on_behalf=True, log=LOG)
    if err:
        return None, err
    if not payload.get("on_behalf") or not payload.get("principal") \
            or human_mcp.principal_kind_of(payload) != "human":
        return None, JSONResponse({"error": "riservato alle persone (sessione on-behalf)"},
                                  status_code=403)
    request.state.auth_payload = payload
    return (str(payload["principal"]), (payload.get("human_role") or "") in _ADMIN_ROLES,
            payload.get("clearance")), None


def _error(e: Exception) -> JSONResponse:
    if isinstance(e, PermissionError):
        return JSONResponse({"error": str(e)[:300]}, status_code=403)
    if isinstance(e, (databases.NotFound, LookupError, KeyError)):
        return JSONResponse({"error": str(e)[:300]}, status_code=404)
    if isinstance(e, ValueError):
        return JSONResponse({"error": str(e)[:300]}, status_code=400)
    LOG.error("databases: %s: %s", type(e).__name__, str(e)[:300])
    return JSONResponse({"error": str(e)[:300] or type(e).__name__}, status_code=502)


def _audit(action: str, resource: str, who: str, **details) -> None:
    from .audit import control as _control
    _control.safe(_control.emit, "databases", action, resource, by=who, **details)


async def _json(request: Request) -> dict:
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        raise ValueError("corpo JSON non valido") from None
    if not isinstance(body, dict):
        raise ValueError("corpo JSON: atteso un oggetto")
    return body


def _scope(request: Request, body: dict | None = None) -> str | None:
    s = (body or {}).get("scope") if body else None
    s = s or request.query_params.get("scope")
    return str(s).strip() or None if s else None


def _datastore(request: Request) -> tuple[str, dict]:
    pack, name = request.path_params["pack"], request.path_params["name"]
    key = f"{pack}/{name}"
    entry = datastores.find(pack, name)
    if entry is None:
        raise databases.NotFound(f"datastore '{key}' sconosciuto")
    return key, entry


# ── Catalogue and containers ─────────────────────────────────────────────────

async def catalogue_route(request: Request):
    me, err = _person(request)
    if err:
        return err
    who, admin, clearance = me
    if request.method == "GET":
        try:
            out = await asyncio.to_thread(databases.catalogue, who=who, is_admin=admin,
                                          clearance=clearance)
        except Exception as e:  # noqa: BLE001
            return _error(e)
        return JSONResponse(out)
    if not admin:
        return JSONResponse({"error": "creare ed eliminare datastore e collection è "
                             "riservato agli admin"}, status_code=403)
    try:
        body = await _json(request)
        action = body.get("action")
        name = str(body.get("name") or "").strip()
        if action == "create_datastore":
            out = await asyncio.to_thread(
                databases.create_datastore, name, purpose=str(body.get("purpose") or ""),
                tier=str(body.get("tier") or ""), pii=bool(body.get("pii")), by=who)
        elif action == "create_collection":
            out = await asyncio.to_thread(
                databases.create_collection, name, tier=str(body.get("tier") or ""),
                description=str(body.get("description") or ""), by=who)
        elif action == "delete":
            kind = str(body.get("kind") or "")
            # The typed-name confirmation travels to the server too: a client
            # that skips the dialog does not skip the check.
            if str(body.get("confirm") or "") != name:
                raise ValueError("conferma: scrivi esattamente il nome della risorsa")
            out = await asyncio.to_thread(databases.delete, kind, name, by=who)
        elif action == "restore":
            out = await asyncio.to_thread(databases.restore, str(body.get("kind") or ""),
                                          name, by=who)
        else:
            raise ValueError("azione: create_datastore | create_collection | delete | restore")
    except Exception as e:  # noqa: BLE001
        return _error(e)
    _audit(str(action), name or "*", who, resource_kind=body.get("kind"), tier=body.get("tier"),
           export=out.get("export_dir"))
    return JSONResponse(out)


# ── Datastore content ────────────────────────────────────────────────────────

async def tables_route(request: Request):
    me, err = _person(request)
    if err:
        return err
    who, admin, clearance = me
    from .tools import datastore_sql
    try:
        key, entry = _datastore(request)
        databases.authorize_person("datastore", key, write=False, who=who, is_admin=admin,
                                   clearance=clearance, scope=_scope(request))
        out = await asyncio.to_thread(datastore_sql.tables, entry, agent=f"human:{who}")
    except Exception as e:  # noqa: BLE001
        return _error(e)
    return JSONResponse(out)


async def rows_route(request: Request):
    me, err = _person(request)
    if err:
        return err
    who, admin, clearance = me
    from .tools import datastore_sql
    try:
        key, entry = _datastore(request)
        if request.method == "GET":
            qp = request.query_params
            databases.authorize_person("datastore", key, write=False, who=who, is_admin=admin,
                                       clearance=clearance, scope=_scope(request))
            out = await asyncio.to_thread(
                datastore_sql.rows, entry, str(qp.get("table") or ""),
                limit=int(qp.get("limit") or 50), offset=int(qp.get("offset") or 0),
                q=str(qp.get("q") or ""), agent=f"human:{who}")
            return JSONResponse(out)
        body = await _json(request)
        databases.authorize_person("datastore", key, write=True, who=who, is_admin=admin,
                                   clearance=clearance, scope=_scope(request, body))
        op = str(body.get("op") or "")
        out = await asyncio.to_thread(
            datastore_sql.row_op, entry, op, str(body.get("table") or ""),
            rowid=body.get("rowid"), values=body.get("values"), agent=f"human:{who}")
    except Exception as e:  # noqa: BLE001
        return _error(e)
    _audit(f"row_{op}", key, who, table=body.get("table"), rowid=body.get("rowid"))
    return JSONResponse(out)


async def schema_route(request: Request):
    me, err = _person(request)
    if err:
        return err
    who, admin, clearance = me
    if not admin:
        return JSONResponse({"error": "le modifiche dello schema sono riservate agli admin"},
                            status_code=403)
    from .tools import datastore_sql
    try:
        key, entry = _datastore(request)
        databases.authorize_person("datastore", key, write=True, who=who, is_admin=True,
                                   clearance=clearance, scope=None)
        body = await _json(request)
        out = await asyncio.to_thread(datastore_sql.ddl, entry, body, agent=f"human:{who}")
    except Exception as e:  # noqa: BLE001
        return _error(e)
    _audit("schema", key, who, op=body.get("op"), table=body.get("table"))
    return JSONResponse(out)


# ── Collection content ───────────────────────────────────────────────────────

async def documents_route(request: Request):
    me, err = _person(request)
    if err:
        return err
    who, admin, clearance = me
    name = request.path_params["name"]
    from .tools import eu_corpus
    try:
        databases.authorize_person("rag", name, write=False, who=who, is_admin=admin,
                                   clearance=clearance, scope=_scope(request))
        out = await asyncio.to_thread(eu_corpus.list_documents, name)
    except Exception as e:  # noqa: BLE001
        return _error(e)
    return JSONResponse(out)


async def chunks_route(request: Request):
    me, err = _person(request)
    if err:
        return err
    who, admin, clearance = me
    name = request.path_params["name"]
    qp = request.query_params
    from .tools import eu_corpus
    try:
        doc = str(qp.get("doc") or "").strip()
        if not doc:
            raise ValueError("parametro 'doc' richiesto")
        databases.authorize_person("rag", name, write=False, who=who, is_admin=admin,
                                   clearance=clearance, scope=_scope(request))
        out = await asyncio.to_thread(
            eu_corpus.list_chunks, name, doc, qp.get("version") or None,
            int(qp.get("limit") or 50), int(qp.get("offset") or 0))
    except Exception as e:  # noqa: BLE001
        return _error(e)
    return JSONResponse(out)


async def upload_route(request: Request):
    me, err = _person(request)
    if err:
        return err
    who, admin, clearance = me
    name = request.path_params["name"]
    qp = request.query_params
    limit = databases._upload_max()
    try:
        databases.authorize_person("rag", name, write=True, who=who, is_admin=admin,
                                   clearance=clearance, scope=_scope(request))
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > limit:
            raise ValueError(f"file troppo grande: {declared} byte (max {limit})")
        data = bytearray()
        async for chunk in request.stream():
            data += chunk
            if len(data) > limit:
                raise ValueError(f"file troppo grande (max {limit} byte)")
        out = await asyncio.to_thread(
            databases.upload, name, str(qp.get("filename") or ""), bytes(data),
            doc_name=str(qp.get("doc_name") or ""), version=str(qp.get("version") or "1"),
            who=who, clearance=clearance)
    except Exception as e:  # noqa: BLE001
        _audit("upload", name, who, result="refused", error=str(e)[:200],
               filename=qp.get("filename"))
        return _error(e)
    _audit("upload", name, who, result="ok", filename=qp.get("filename"),
           document=out.get("document"), bytes=out.get("bytes"), chunks=out.get("chunks"))
    return JSONResponse(out)


async def remove_route(request: Request):
    me, err = _person(request)
    if err:
        return err
    who, admin, clearance = me
    name = request.path_params["name"]
    from .tools import eu_corpus
    try:
        body = await _json(request)
        doc = str(body.get("doc_name") or "").strip()
        if not doc:
            raise ValueError("doc_name richiesto")
        databases.authorize_person("rag", name, write=True, who=who, is_admin=admin,
                                   clearance=clearance, scope=_scope(request, body))
        out = await asyncio.to_thread(eu_corpus.remove, doc, body.get("version") or None, name)
    except Exception as e:  # noqa: BLE001
        return _error(e)
    _audit("remove_document", name, who, document=doc, version=body.get("version"))
    return JSONResponse(out)


routes = [
    Route("/internal/databases", catalogue_route, methods=["GET", "POST"]),
    Route("/internal/databases/datastore/{pack}/{name}/tables", tables_route, methods=["GET"]),
    Route("/internal/databases/datastore/{pack}/{name}/rows", rows_route, methods=["GET", "POST"]),
    Route("/internal/databases/datastore/{pack}/{name}/schema", schema_route, methods=["POST"]),
    Route("/internal/databases/collection/{name}/documents", documents_route, methods=["GET"]),
    Route("/internal/databases/collection/{name}/chunks", chunks_route, methods=["GET"]),
    Route("/internal/databases/collection/{name}/upload", upload_route, methods=["POST"]),
    Route("/internal/databases/collection/{name}/remove", remove_route, methods=["POST"]),
]

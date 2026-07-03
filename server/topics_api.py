"""Endpoint interni dei topic (Topic System v2, P5-min) — per i flussi *owner*
del backend (la pagina Topics della webui), non per un modello.

Come providers_api/imagegen_api: auth ckt1 ristretta al principal privilegiato
(default clodia), chiamato dal runner di clodia-logic che fa da proxy per la
webui. Espone in lettura la stessa vista dei verbi MCP topic.list/open.

  GET /internal/topics?classification=&include_archived=   → {topics: [...]}
  GET /internal/topics/{cls}/{name}                        → open() | 404
"""
from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import tarfile
from pathlib import Path

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .pki_verify import verify_session_token
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicError, TopicService

LOG = logging.getLogger("clodia-tools.topics")

_PRINCIPALS = {
    p.strip() for p in (os.environ.get("CLODIA_PROVIDER_PRINCIPALS") or "clodia").split(",")
    if p.strip()
}
_ROOT = os.environ.get("CLODIA_TOPICS_ROOT", "/datadir/clodia-vault/topics-store")
_svc: TopicService | None = None


def _service() -> TopicService:
    global _svc
    if _svc is None:
        _svc = TopicService(LocalFsStorage(_ROOT))
    return _svc


def _authorize(request: Request):
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    try:
        payload = verify_session_token(token)
    except PermissionError as e:
        LOG.warning("topics auth fallita: %s", e)
        return None, JSONResponse({"error": "unauthorized"}, status_code=401)
    if str(payload.get("agent") or "") not in _PRINCIPALS:
        return None, JSONResponse({"error": "forbidden"}, status_code=403)
    return payload.get("agent"), None


async def list_topics(request: Request):
    _, err = _authorize(request)
    if err:
        return err
    tier = request.query_params.get("tier") or None
    inc = request.query_params.get("include_archived", "").lower() in ("1", "true", "yes")
    return JSONResponse({"topics": _service().list(tier, include_archived=inc)})


async def open_topic(request: Request):
    _, err = _authorize(request)
    if err:
        return err
    tier = request.path_params["tier"]
    name = request.path_params["name"]
    try:
        return JSONResponse(_service().open(tier, name))
    except TopicError:
        return JSONResponse({"error": "not_found"}, status_code=404)


async def open_file(request: Request):
    _, err = _authorize(request)
    if err:
        return err
    tier = request.path_params["tier"]
    name = request.path_params["name"]
    path = request.query_params.get("path", "")
    try:
        data = await asyncio.to_thread(_service().read_file, tier, name, path)
    except TopicError:
        return JSONResponse({"error": "not_found"}, status_code=404)
    except Exception:  # noqa: BLE001 — file assente / illeggibile
        return JSONResponse({"error": "not_found"}, status_code=404)
    import mimetypes
    from starlette.responses import Response
    ct = mimetypes.guess_type(path)[0] or "application/octet-stream"
    return Response(content=data, media_type=ct)


async def archive_topic(request: Request):
    _, err = _authorize(request)
    if err:
        return err
    try:
        meta = _service().archive(request.path_params["tier"], request.path_params["name"])
        return JSONResponse({"archived": True, "meta": meta})
    except TopicError as e:
        return JSONResponse({"error": str(e)}, status_code=400)


async def set_status(request: Request):
    _, err = _authorize(request)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = {}
    try:
        res = _service().set_status(request.path_params["tier"],
                                    request.path_params["name"],
                                    (body or {}).get("status", ""))
        return JSONResponse(res)
    except TopicError as e:
        return JSONResponse({"error": str(e)}, status_code=400)


async def create_topic(request: Request):
    _, err = _authorize(request)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    name = (body.get("name") or "").strip()
    tier = body.get("tier") or None
    if not name:
        return JSONResponse({"error": "name_required"}, status_code=400)
    try:
        meta = _service().new(tier, name, body.get("meta") or {})
        return JSONResponse({"created": True, "meta": meta})
    except TopicError as e:
        return JSONResponse({"error": str(e)}, status_code=400)


async def list_messages(request: Request):
    _, err = _authorize(request)
    if err:
        return err
    tier = request.path_params["tier"]; name = request.path_params["name"]
    limit = int(request.query_params.get("limit", "200") or 200)
    try:
        return JSONResponse({"messages": _service().list_messages(tier, name, limit=limit)})
    except TopicError:
        return JSONResponse({"error": "not_found"}, status_code=404)


async def post_message(request: Request):
    _, err = _authorize(request)
    if err:
        return err
    tier = request.path_params["tier"]; name = request.path_params["name"]
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    author = (body.get("author") or "").strip()
    if not author:
        return JSONResponse({"error": "author_required"}, status_code=400)
    try:
        msg = _service().post_message(tier, name, author, body.get("text") or "",
                                      kind=body.get("kind", "human"),
                                      attachments=body.get("attachments") or [])
        return JSONResponse(msg)
    except TopicError:
        return JSONResponse({"error": "not_found"}, status_code=404)


async def set_channel(request: Request):
    """POST /internal/topics/{tier}/{name}/channel {channel} → configura il
    channel dei messaggi (telegram) del topic; {} o null → rimuove (webui)."""
    _, err = _authorize(request)
    if err:
        return err
    tier = request.path_params["tier"]; name = request.path_params["name"]
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    try:
        meta = _service().set_channel(tier, name, body.get("channel"))
        return JSONResponse({"ok": True, "channel": meta.get("channel")})
    except TopicError as e:
        return JSONResponse({"error": str(e)[:200]}, status_code=400)


async def remote(request: Request):
    """POST /internal/topics/{tier}/{name}/remote {action, ...} → verbi Remote.
    action: status|enable|disable|add|commit|push|pull."""
    _, err = _authorize(request)
    if err:
        return err
    tier = request.path_params["tier"]; name = request.path_params["name"]
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    svc = _service()
    action = body.get("action")
    try:
        if action == "status":
            return JSONResponse(svc.remote_status(tier, name))
        if action == "enable":
            return JSONResponse(svc.remote_enable(tier, name, body.get("type"), body.get("config")))
        if action == "disable":
            return JSONResponse(svc.remote_disable(tier, name))
        if action == "add":
            return JSONResponse(svc.remote_add(tier, name, body.get("path")))
        if action == "commit":
            return JSONResponse(svc.remote_commit(tier, name, body.get("message", "")))
        if action == "push":
            return JSONResponse(svc.remote_push(tier, name))
        if action == "pull":
            return JSONResponse(svc.remote_pull(tier, name))
        return JSONResponse({"error": f"azione sconosciuta: {action}"}, status_code=400)
    except TopicError as e:
        return JSONResponse({"error": str(e)[:200]}, status_code=400)
    except Exception as e:  # noqa: BLE001
        return JSONResponse({"error": str(e)[:200]}, status_code=502)


async def participants(request: Request):
    _, err = _authorize(request)
    if err:
        return err
    tier = request.path_params["tier"]; name = request.path_params["name"]
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    agent = (body.get("agent") or "").strip()
    if not agent:
        return JSONResponse({"error": "agent_required"}, status_code=400)
    svc = _service()
    try:
        if request.method == "DELETE":
            return JSONResponse(svc.remove_participant(tier, name, agent))
        return JSONResponse(svc.add_participant(tier, name, agent))
    except TopicError:
        return JSONResponse({"error": "not_found"}, status_code=404)


async def files(request: Request):
    _, err = _authorize(request)
    if err:
        return err
    tier = request.path_params["tier"]; name = request.path_params["name"]
    svc = _service()
    if request.method == "GET":
        subpath = request.query_params.get("path", "")
        try:
            return JSONResponse({"files": await asyncio.to_thread(svc.list_files, tier, name, subpath)})
        except TopicError as e:
            return JSONResponse({"error": str(e)}, status_code=404)
    # POST upload: {filename, content_b64}
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    fn = (body.get("filename") or "").strip()
    try:
        import base64 as _b64
        data = _b64.b64decode(body.get("content_b64") or "")
    except Exception:
        return JSONResponse({"error": "bad_content"}, status_code=400)
    try:
        return JSONResponse(await asyncio.to_thread(svc.put_file, tier, name, fn, data))
    except TopicError as e:
        return JSONResponse({"error": str(e)}, status_code=400)


async def export_topics(request: Request):
    """Esporta i topic (meta, summary, minutes/, files/, conversazioni .messages)
    in un tar.gz. `?topics=tier/name,tier/name` per selezionarne alcuni; assente
    → tutti. Nessun segreto: i topic non contengono credenziali."""
    _, err = _authorize(request)
    if err:
        return err
    sel_raw = request.query_params.get("topics", "").strip()
    selected = {s.strip() for s in sel_raw.split(",") if s.strip()} if sel_raw else None
    root = Path(_ROOT)
    svc = _service()
    topics = [t for t in svc.list(None, include_archived=True)
              if selected is None or f"{t['tier']}/{t['name']}" in selected]
    included = {f"{t['tier']}/{t['name']}" for t in topics}
    manifest = {"kind": "clodia-topics-snapshot", "version": 1,
                "count": len(topics), "topics": sorted(included)}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        mdata = json.dumps(manifest, ensure_ascii=False, indent=2).encode()
        ti = tarfile.TarInfo("manifest.json")
        ti.size = len(mdata)
        tar.addfile(ti, io.BytesIO(mdata))
        if root.is_dir():
            for p in sorted(root.rglob("*")):
                if not p.is_file():
                    continue
                rel = p.relative_to(root)
                parts = rel.parts
                if len(parts) >= 2 and f"{parts[0]}/{parts[1]}" in included:
                    tar.add(p, arcname="topics-store/" + str(rel))
    buf.seek(0)
    return Response(buf.read(), media_type="application/gzip",
                    headers={"Content-Disposition": 'attachment; filename="clodia-topics-snapshot.tgz"'})


async def import_topics(request: Request):
    """Importa i topic da un tar.gz prodotto da export. MERGE non-distruttivo:
    i topic GIÀ presenti (tier/name) vengono saltati, gli altri ripristinati."""
    _, err = _authorize(request)
    if err:
        return err
    body = await request.body()
    root = Path(_ROOT)
    root.mkdir(parents=True, exist_ok=True)
    existing = set()
    if root.is_dir():
        for tier_dir in root.iterdir():
            if tier_dir.is_dir():
                for t in tier_dir.iterdir():
                    if t.is_dir():
                        existing.add(f"{tier_dir.name}/{t.name}")
    added, skipped = set(), set()
    try:
        with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tar:
            for m in tar.getmembers():
                if not m.isfile() or m.name == "manifest.json":
                    continue
                if not m.name.startswith("topics-store/"):
                    continue
                rel = m.name[len("topics-store/"):]
                parts = rel.split("/")
                # anti-traversal + struttura attesa tier/name/...
                if rel.startswith("/") or ".." in parts or len(parts) < 3:
                    continue
                key = f"{parts[0]}/{parts[1]}"
                if key in existing:
                    skipped.add(key)
                    continue
                added.add(key)
                src = tar.extractfile(m)
                if src is None:
                    continue
                dest = root / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(src.read())
    except (tarfile.TarError, OSError) as e:
        return JSONResponse({"error": f"bundle non valido: {e}"}, status_code=400)
    return JSONResponse({"imported": sorted(added), "skipped": sorted(skipped),
                         "imported_count": len(added), "skipped_count": len(skipped)})


routes = [
    Route("/internal/topics/export", export_topics, methods=["GET"]),
    Route("/internal/topics/import", import_topics, methods=["POST"]),
    Route("/internal/topics", list_topics, methods=["GET"]),
    Route("/internal/topics", create_topic, methods=["POST"]),
    Route("/internal/topics/{tier}/{name}", open_topic, methods=["GET"]),
    Route("/internal/topics/{tier}/{name}/file", open_file, methods=["GET"]),
    Route("/internal/topics/{tier}/{name}/messages", list_messages, methods=["GET"]),
    Route("/internal/topics/{tier}/{name}/messages", post_message, methods=["POST"]),
    Route("/internal/topics/{tier}/{name}/archive", archive_topic, methods=["POST"]),
    Route("/internal/topics/{tier}/{name}/status", set_status, methods=["POST"]),
    Route("/internal/topics/{tier}/{name}/participants", participants, methods=["POST", "DELETE"]),
    Route("/internal/topics/{tier}/{name}/channel", set_channel, methods=["POST"]),
    Route("/internal/topics/{tier}/{name}/remote", remote, methods=["POST"]),
    Route("/internal/topics/{tier}/{name}/files", files, methods=["GET", "POST"]),
]

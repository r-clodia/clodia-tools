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

from . import instance_profile
from pathlib import Path

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .pki_verify import verify_session_token
from .topics.local_fs import LocalFsStorage
from .topics.service import SCHEMA_VERSION, TopicError, TopicService, normalize_meta_v2
from .topics.storage import VersionConflict

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


# Cache TTL brevissima della lista topic: la webui la polla di continuo e
# service.list() apre OGNI topic (costoso, CPU-bound su 78 topic). Con un TTL di
# pochi secondi N poll frequenti diventano 1 enumerazione, senza percepibile
# staleness. Chiave = (tier, include_archived). Invalida su qualunque scrittura.
_LIST_CACHE: dict = {}
_LIST_TTL = float(os.environ.get("TOPICS_LIST_TTL", "6"))


def _invalidate_list_cache() -> None:
    _LIST_CACHE.clear()


async def list_topics(request: Request):
    _, err = _authorize(request)
    if err:
        return err
    tier = request.query_params.get("tier") or None
    inc = request.query_params.get("include_archived", "").lower() in ("1", "true", "yes")
    key = (tier, inc)
    now = asyncio.get_event_loop().time()
    hit = _LIST_CACHE.get(key)
    if hit and (now - hit[0]) < _LIST_TTL:
        return JSONResponse({"topics": hit[1]})
    # list() apre ogni topic (I/O per topic): sincrono e ~O(topic). Offload su
    # thread per non bloccare l'event loop del gateway (che serve anche l'MCP).
    topics = await asyncio.to_thread(_service().list, tier, include_archived=inc)
    _LIST_CACHE[key] = (now, topics)
    return JSONResponse({"topics": topics})


async def open_topic(request: Request):
    _, err = _authorize(request)
    if err:
        return err
    tier = request.path_params["tier"]
    name = request.path_params["name"]
    try:
        data = await asyncio.to_thread(_service().open, tier, name)
        # Primo bit del vettore di contesto (#104 §4): «è entrato contenuto non
        # fidato». Vive nel gateway, e senza esporlo qui la UI mostra un punteggio
        # a due bit su tre — cioè lo stato *statico* del canale, che è quello che
        # non cambia mai. Il bit dinamico è l'unico che l'owner può azzerare, e
        # quindi l'unico su cui gli serve un'indicazione in tempo reale.
        from . import taint as _t
        st = _t.status(f"{tier}/{name}")
        data["taint"] = {"tainted": st["tainted"], "since": st.get("since"),
                         "sources": st.get("sources") or []}
        return JSONResponse(data)
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


async def telegram_binding(request: Request):
    """Collega/scollega il gruppo Telegram e aggiorna la mappa delle persone.

    Una rotta sola per le tre cose, perché nella UI sono un gesto solo: l'owner
    incolla l'id del gruppo e dice chi è chi. Separarle farebbe esistere lo
    stato intermedio «collegato ma senza nessuno mappato», che è il
    collegamento che sembra funzionare e non avvisa nessuno.
    """
    _, err = _authorize(request)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    tier = request.path_params["tier"]
    name = request.path_params["name"]
    svc = _service()
    try:
        if body.get("action") == "unbind":
            return JSONResponse(svc.telegram_unbind(tier, name, body.get("mount")))
        return JSONResponse(svc.telegram_bind(
            tier, name, body.get("chat_id") or "",
            mode=body.get("mode") or "excerpt",
            people=body.get("people") or {},
            mount_name=body.get("mount")))
    except TopicError as e:
        return JSONResponse({"error": str(e)}, status_code=400)


async def set_portable(request: Request):
    """Dichiara o revoca la portabilità di un topic.

    La portabilità è dichiarata dal TOPIC, non dall'agente (voce 28 emendata):
    se la dichiarasse l'agente, chiunque potesse scrivere la propria lista si
    darebbe da solo un canale verso i contenuti di una stanza.
    """
    _, err = _authorize(request)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    try:
        out = _service().set_portable(request.path_params["tier"],
                                      request.path_params["name"],
                                      bool(body.get("portable")))
        _invalidate_list_cache()
        return JSONResponse(out)
    except TopicError as e:
        return JSONResponse({"error": str(e)}, status_code=400)


async def archive_topic(request: Request):
    _, err = _authorize(request)
    if err:
        return err
    try:
        meta = _service().archive(request.path_params["tier"], request.path_params["name"])
        _invalidate_list_cache()
        return JSONResponse({"archived": True, "meta": meta})
    except TopicError as e:
        return JSONResponse({"error": str(e)}, status_code=400)


async def set_agents_md(request: Request):
    """Istruzioni di scope del topic. GET restituisce testo + versione, POST le
    riscrive in optimistic lock.

    Rotta separata da `files`, e non un caso particolare di quella, perché
    l'oggetto è di natura diversa: un file del topic è contenuto, questo è
    control-plane — entra nel contesto di ogni agente della stanza a ogni turno.
    Confonderli è come sono finite in `files/` in origine.
    """
    tier = request.path_params["tier"]
    name = request.path_params["name"]
    _, err = _authorize(request)
    if err:
        return err
    if request.method == "GET":
        try:
            info = _service().open(tier, name)
        except TopicError as e:
            return JSONResponse({"error": str(e)}, status_code=404)
        return JSONResponse({"text": info.get("agents_md"),
                             "version": info.get("agents_md_version"),
                             # `authoritative=False` = il testo viene ancora dalla
                             # posizione legacy in files/, dove QUALUNQUE
                             # partecipante poteva scriverlo. Chi lo inietta in un
                             # prompt deve poterlo sapere: è la differenza fra una
                             # nota di canale e una direttiva.
                             "authoritative": info.get("agents_md_version") is not None})
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = {}
    try:
        res = _service().save_agents_md(tier, name, (body or {}).get("text", ""),
                                        (body or {}).get("base_version"))
        return JSONResponse(res)
    except VersionConflict as e:
        return JSONResponse({"error": f"conflitto di versione: {e}"}, status_code=409)
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
        _invalidate_list_cache()
        return JSONResponse(res)
    except TopicError as e:
        return JSONResponse({"error": str(e)}, status_code=400)


async def set_deadline(request: Request):
    _, err = _authorize(request)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = {}
    try:
        res = _service().set_deadline(request.path_params["tier"],
                                      request.path_params["name"],
                                      (body or {}).get("deadline"))
        _invalidate_list_cache()
        return JSONResponse(res)
    except TopicError as e:
        return JSONResponse({"error": str(e)}, status_code=400)


async def create_topic(request: Request):
    principal, err = _authorize(request)
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
        # Profilo topics:single → solo il workspace unico (DM sempre permessi).
        instance_profile.topic_creation_check(name)
    except PermissionError as e:
        return JSONResponse({"error": str(e)}, status_code=403)
    try:
        hook_enabled = bool(body.get("hook_enabled", True))
        requested_meta = {**(body.get("meta") or {}), "hook_enabled": hook_enabled}
        meta = _service().new(tier, name, requested_meta)
        if hook_enabled and bool(body.get("ensure_hook", True)):
            from .tools import runtime
            await asyncio.to_thread(
                runtime.ensure_topic_hook, meta["tier"], name, principal or "platform")
        _invalidate_list_cache()
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
        msgs = await asyncio.to_thread(_service().list_messages, tier, name, limit=limit)
        return JSONResponse({"messages": msgs})
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
        msg = await asyncio.to_thread(
            _service().post_message, tier, name, author, body.get("text") or "",
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
        _invalidate_list_cache()
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
            return JSONResponse(svc.remote_status(tier, name, body.get("mount")))
        if action == "enable":
            return JSONResponse(svc.remote_enable(
                tier, name, body.get("type"), body.get("config"),
                confirm_hides_local=bool(body.get("confirm_hides_local")),
                credential=body.get("credential"),
                mount_name=body.get("mount")))
        if action == "set_credential":
            # Cambiare o togliere la credenziale di uno scope senza ricollegare
            # il remote: serve per la ROTAZIONE, che è il costo ricorrente di
            # questo disegno. Senza una via per ruotare, una credenziale per
            # topic si trasforma in N credenziali che nessuno rinnova più.
            # `kind` distingue le due credenziali di un mount. Il default resta
            # git: era l'unica quando questa azione è nata, e cambiarlo
            # silenziosamente rimuoverebbe token git credendo di toccare Drive.
            if (body.get("kind") or "git") == "drive":
                return JSONResponse(svc.set_drive_credential(
                    tier, name, body.get("credential") or None, body.get("mount")))
            return JSONResponse(svc.set_git_credential(
                tier, name, body.get("credential"), body.get("mount")))
        if action == "disable":
            return JSONResponse(svc.remote_disable(tier, name, body.get("mount")))
        if action == "add":
            return JSONResponse(svc.remote_add(tier, name, body.get("path"), body.get("mount")))
        if action == "unstage":
            return JSONResponse(svc.remote_unstage(tier, name, body.get("path") or "", body.get("mount")))
        if action == "commit":
            return JSONResponse(svc.remote_commit(tier, name, body.get("message", ""), body.get("mount")))
        if action == "push":
            return JSONResponse(svc.remote_push(tier, name, body.get("mount")))
        if action == "pull":
            return JSONResponse(svc.remote_pull(tier, name, body.get("mount")))
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
        # `role` opzionale: assente = `contributor`, che è ciò che «invitato» ha
        # significato finora. Serve anche a CAMBIARE il ruolo di chi è già dentro,
        # senza doverlo togliere e rimettere — un'operazione che nel frattempo lo
        # farebbe uscire dal canale.
        return JSONResponse(svc.add_participant(tier, name, agent,
                                                role=body.get("role")))
    except TopicError as e:
        # Un ruolo non valido è una richiesta malformata, non un topic assente:
        # rispondere 404 manderebbe a cercare il topic sbagliato.
        msg = str(e)
        if "ruolo" in msg or "owner" in msg:
            return JSONResponse({"error": msg[:200]}, status_code=400)
        return JSONResponse({"error": "not_found"}, status_code=404)


async def files(request: Request):
    who, err = _authorize(request)
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
    # Provenienza dichiarata dall'utente all'upload (#104 §3). È l'unico momento
    # in cui l'informazione esiste, e l'unico interlocutore che può risponderla è
    # lui. Default `untrusted`: se il client non la manda, non si assume il bene.
    prov = (body.get("provenance") or "untrusted").strip().lower()
    try:
        res = await asyncio.to_thread(svc.put_file, tier, name, fn, data, prov,
                                      who or "")
    except TopicError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    if prov != "trusted":
        # Il file untrusted CONTAMINA il canale. La lettura resta libera: è una
        # classificazione, non un blocco, e un file illeggibile spingerebbe
        # l'utente a dichiarare «trusted» per andare avanti — che è il modo di
        # rendere l'etichetta inutile.
        from . import taint  # noqa: PLC0415
        taint.mark(f"{tier}/{name}", "file", fn, who or "")
    return JSONResponse(res)


def _snapshot_meta_bytes(raw: bytes, tier: str) -> bytes:
    meta = normalize_meta_v2(json.loads(raw.decode("utf-8")), tier)
    return json.dumps(meta, ensure_ascii=False, indent=2).encode()


async def export_topics(request: Request):
    """Esporta i topic schema v2 (meta, summary, files/, conversazioni .messages)
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
    manifest = {"kind": "clodia-topics-snapshot", "version": SCHEMA_VERSION,
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
                    arcname = "topics-store/" + str(rel)
                    if len(parts) == 3 and parts[2] == "meta.json":
                        data = _snapshot_meta_bytes(p.read_bytes(), parts[0])
                        ti = tarfile.TarInfo(arcname)
                        ti.size = len(data)
                        tar.addfile(ti, io.BytesIO(data))
                    elif len(parts) >= 3 and parts[2] == "minutes":
                        continue
                    else:
                        tar.add(p, arcname=arcname)
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
            try:
                mf = tar.extractfile("manifest.json")
                manifest = json.loads((mf.read() if mf else b"{}").decode("utf-8"))
            except Exception:
                manifest = {}
            version = int(manifest.get("version") or 1)
            if version != SCHEMA_VERSION:
                return JSONResponse({
                    "error": "unsupported_snapshot_version",
                    "detail": f"snapshot v{version} non importabile: esegui prima la migrazione a v{SCHEMA_VERSION}",
                    "expected_version": SCHEMA_VERSION,
                    "found_version": version,
                }, status_code=400)
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
                data = src.read()
                if len(parts) == 3 and parts[2] == "meta.json":
                    data = _snapshot_meta_bytes(data, parts[0])
                if len(parts) >= 3 and parts[2] == "minutes":
                    continue
                dest.write_bytes(data)
    except (tarfile.TarError, OSError) as e:
        return JSONResponse({"error": f"bundle non valido: {e}"}, status_code=400)
    return JSONResponse({"imported": sorted(added), "skipped": sorted(skipped),
                         "imported_count": len(added), "skipped_count": len(skipped)})


async def mcp_clients(request: Request):
    """GET/POST /internal/topics/{tier}/{name}/mcp-clients → client MCP umani.

    GET elenca (senza token: il valore non si rilegge, si revoca). POST con
    `action: issue|revoke`. Chi può chiedere è deciso a monte, nella webui, dove
    si sa chi è l'owner: qui arriva già autorizzato, come per `telegram`.
    """
    _, err = _authorize(request)
    if err:
        return err
    tier = request.path_params["tier"]; name = request.path_params["name"]
    from . import human_mcp
    if request.method == "GET":
        return JSONResponse({"grants": human_mcp.list_grants(tier, name)})
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "bad_json"}, status_code=400)
    action = body.get("action") or "issue"
    try:
        if action == "revoke":
            return JSONResponse(human_mcp.revoke(body.get("id") or ""))
        res = human_mcp.issue(
            tier, name, body.get("principal") or "",
            provider=body.get("provider") or "",
            carrier=body.get("carrier") or "clodia",
            human_role=body.get("human_role") or "user",
            clearance=body.get("clearance") or None,
            ttl_days=int(body.get("ttl_days") or human_mcp.DEFAULT_TTL_DAYS),
            by=body.get("by") or "",
            tier_consent=bool(body.get("tier_consent")))
        base = (body.get("base_url") or "").strip()
        if base:
            res["config"] = human_mcp.client_config(base, res["token"], tier, name)
        return JSONResponse(res)
    except (PermissionError, ValueError) as e:
        # Il messaggio arriva intatto: dice QUALE delle condizioni ha fermato la
        # coniazione (tier troppo alto, provider non dichiarato, consenso
        # mancante), e ognuna ha un rimedio diverso.
        return JSONResponse({"error": str(e)[:400]}, status_code=400)


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
    Route("/internal/topics/{tier}/{name}/portable", set_portable, methods=["POST"]),
    Route("/internal/topics/{tier}/{name}/telegram", telegram_binding, methods=["POST"]),
    Route("/internal/topics/{tier}/{name}/status", set_status, methods=["POST"]),
    Route("/internal/topics/{tier}/{name}/agents-md", set_agents_md, methods=["GET", "POST"]),
    Route("/internal/topics/{tier}/{name}/deadline", set_deadline, methods=["POST"]),
    Route("/internal/topics/{tier}/{name}/participants", participants, methods=["POST", "DELETE"]),
    Route("/internal/topics/{tier}/{name}/channel", set_channel, methods=["POST"]),
    Route("/internal/topics/{tier}/{name}/remote", remote, methods=["POST"]),
    Route("/internal/topics/{tier}/{name}/mcp-clients", mcp_clients,
          methods=["GET", "POST"]),
    Route("/internal/topics/{tier}/{name}/files", files, methods=["GET", "POST"]),
]

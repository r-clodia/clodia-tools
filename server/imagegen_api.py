"""Endpoint interno di generazione immagini — usato dai flussi *owner* del
backend (es. generazione PFP nel dialog nuovo agente), non da un modello.

Come `providers_api`: auth ckt1 ristretta al principal privilegiato (default
`clodia`), chiamato dal runner di clodia-logic. Riceve un JSON (immagine di input
opzionale in base64, niente multipart → nessuna dipendenza extra) e ritorna i
**byte PNG** grezzi (il chiamante li scrive dove serve, es. `agent_dir/pfp.png`).

  POST /internal/imagegen
    body: {"prompt": str, "image_b64"?: str, "size"?, "background"?, "quality"?}
    200 → image/png (bytes)
    409 → integrazione OpenAI non attiva (nessuna key)
"""
from __future__ import annotations

import asyncio
import base64
import logging
import os

from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from .pki_verify import verify_session_token
from .tools import image as image_tool

LOG = logging.getLogger("clodia-tools.imagegen")

_PRINCIPALS = {
    p.strip() for p in (os.environ.get("CLODIA_PROVIDER_PRINCIPALS") or "clodia").split(",")
    if p.strip()
}


def _authorize(request: Request):
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    try:
        payload = verify_session_token(token)
    except PermissionError as e:
        LOG.warning("imagegen auth fallita: %s", e)
        return None, JSONResponse({"error": "unauthorized"}, status_code=401)
    agent = str(payload.get("agent") or "")
    if agent not in _PRINCIPALS:
        return None, JSONResponse({"error": "forbidden"}, status_code=403)
    return agent, None


def _strip_data_url(s: str) -> str:
    """Accetta sia base64 puro sia data URL (data:image/png;base64,...)."""
    if s.startswith("data:") and "," in s:
        return s.split(",", 1)[1]
    return s


async def generate_image(request: Request):
    agent, err = _authorize(request)
    if err:
        return err
    if not image_tool.has_key():
        return JSONResponse(
            {"error": "openai_not_connected",
             "detail": "attiva l'integrazione Image generation (OpenAI) nella sezione Integrazioni"},
            status_code=409)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_json"}, status_code=400)
    prompt = (body.get("prompt") or "").strip()
    image_b64 = body.get("image_b64")
    size = body.get("size") or "1024x1024"
    quality = body.get("quality") or "auto"
    background = body.get("background") or "auto"
    try:
        if image_b64:
            raw = base64.b64decode(_strip_data_url(image_b64))
            # to_thread: la chiamata OpenAI è sincrona e dura 10-30s → in un thread
            # non blocca l'event loop del gateway (altrimenti TUTTI gli agent/tool
            # si fermano durante la generazione).
            png = await asyncio.to_thread(image_tool.edit, prompt, raw,
                                          size=size, quality=quality, background=background)
        else:
            if not prompt:
                return JSONResponse({"error": "serve prompt o image_b64"}, status_code=400)
            png = await asyncio.to_thread(image_tool.generate, prompt,
                                          size=size, quality=quality, background=background)
    except image_tool.ImageGenError as e:
        LOG.warning("imagegen errore: %s", e)
        return JSONResponse({"error": "imagegen_failed", "detail": str(e)[:240]}, status_code=502)
    return Response(content=png, media_type="image/png")


routes = [
    Route("/internal/imagegen", generate_image, methods=["POST"]),
]

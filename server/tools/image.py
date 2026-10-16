"""Generazione immagini via OpenAI gpt-image — per la PFP degli agenti (flusso
owner) e, in prospettiva, come tool MCP per gli agenti.

La API key NON sta in `secrets/` editata a mano: è una **integrazione** attivata
dall'owner che la incolla nella sezione Integrazioni → depositata nel **vault**
come credenziale infra `openai_api_key` (grant vuoto: la legge solo il gateway
via `read_internal`). Fallback su env `OPENAI_API_KEY` per dev.

Due modalità (entrambe ritornano i byte PNG):
  - `generate(prompt)`        → text→image (endpoint /images/generations)
  - `edit(prompt, image)`     → image→image (endpoint /images/edits, multipart)

Lo **stile** (es. manga/ghibli per le PFP) NON è hardcoded qui: lo applica il
chiamante (il flusso PFP), così il tool resta generico e riusabile.
"""
from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request

from .. import vault

_GEN_URL = "https://api.openai.com/v1/images/generations"
_EDIT_URL = "https://api.openai.com/v1/images/edits"
DEFAULT_MODEL = "gpt-image-2"
CRED = "openai_api_key"  # nome credenziale nel vault (infra, no grant)

_TIMEOUT = 300


class ImageGenError(RuntimeError):
    """Errore di configurazione o di chiamata all'API immagini."""


def has_key() -> bool:
    """True se l'integrazione OpenAI è attiva (key nel vault o env)."""
    if os.environ.get("OPENAI_API_KEY", "").strip():
        return True
    return vault.has_credential(CRED)


def _api_key() -> str:
    k = os.environ.get("OPENAI_API_KEY", "").strip()
    if k:
        return k
    try:
        b = vault.read_internal(CRED)
    except vault.VaultDenied as e:
        raise ImageGenError(
            "OpenAI non collegato: attiva l'integrazione 'Image generation' "
            "(incolla la API key nella sezione Integrazioni)") from e
    k = (b.get("api_key") or "").strip()
    if not k:
        raise ImageGenError("credenziale 'openai_api_key' priva di api_key")
    return k


def _extract_png(result: dict) -> bytes:
    data = (result.get("data") or [])
    if not data:
        raise ImageGenError("risposta OpenAI senza immagine")
    d = data[0]
    b64 = d.get("b64_json")
    if b64:
        return base64.b64decode(b64)
    url = d.get("url")
    if url:
        with urllib.request.urlopen(url, timeout=120) as r:
            return r.read()
    raise ImageGenError("risposta OpenAI senza b64_json né url")


def _post_json(url: str, payload: dict) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {_api_key()}",
                 "Content-Type": "application/json"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8") if e.fp else str(e)
        raise ImageGenError(f"OpenAI {e.code}: {body[:240]}") from e
    except urllib.error.URLError as e:
        raise ImageGenError(f"OpenAI irraggiungibile: {e}") from e


def _multipart(fields: dict, files: dict) -> tuple[bytes, str]:
    """Encoder multipart/form-data minimale (no dipendenze)."""
    boundary = "----clodia" + base64.urlsafe_b64encode(os.urandom(12)).decode().rstrip("=")
    out = bytearray()
    for k, v in fields.items():
        out += f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n".encode()
    for k, (fn, content, ct) in files.items():
        out += (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{k}\"; "
                f"filename=\"{fn}\"\r\nContent-Type: {ct}\r\n\r\n").encode()
        out += content + b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return bytes(out), boundary


#: The connector whose transport `generate`/`edit` use in `pack` position.
CONNECTOR = "openai-images"


def _in_pack_position() -> bool:
    """`connectors: {openai-images: pack}` (clodia-platform#525). In doubt,
    `native`: `connector_mode` never raises and falls back to it itself."""
    from .. import instance_profile
    return instance_profile.connector_mode(CONNECTOR) == "pack"


def _via_transport(op: str, prompt: str, *, size: str, quality: str,
                   background: str, image_bytes: bytes | None = None) -> bytes:
    """One image operation through it-pack's provider transport (#525).

    The gateway keeps the decisions — who may call, which topic the PNG lands
    in (`main._dispatch_image`), the owner-only `/internal/imagegen` — and the
    pack does the HTTP call with the API key of THIS call only. Contract with
    it-pack: backend/tool from the manifest (`imagegen-transport`/`run`),
    arguments `{op, prompt, size, quality, background, image_b64?, api_key}`,
    result `{"png_b64": "<base64>"}`; a failure is a tool error (isError).

    Fail closed: no usable transport (pack connector not held, transport not
    declared or not the pack's own mount) is an error, never the in-process
    client — an owner who turned the switch would otherwise be verifying the
    wrong implementation on real traffic.
    """
    from .. import proxy
    from ..connectors import resolved
    transport = resolved.transport_for(CONNECTOR)
    if transport is None:
        raise ImageGenError(
            "image generation is handed to a pack on this instance "
            "(connectors: {openai-images: pack}) but its transport provider "
            "is not available: install/enable it-pack, or switch back to native")
    backend, tool = transport
    args = {"op": op, "prompt": prompt, "size": size, "quality": quality,
            "background": background, "api_key": _api_key()}
    if image_bytes is not None:
        args["image_b64"] = base64.b64encode(image_bytes).decode("ascii")
    try:
        text = proxy.call_backend_tool_sync(backend, tool, args, timeout=_TIMEOUT)
    except proxy.BackendToolError as e:
        # Never the arguments: they carry the key.
        raise ImageGenError(f"image transport: {str(e)[:240]}") from e
    try:
        out = json.loads(text)
        png = base64.b64decode(out["png_b64"], validate=True)
    except Exception as e:  # noqa: BLE001 — any other shape is a failed call
        raise ImageGenError("image transport: answer without a valid png_b64") from e
    if not png:
        raise ImageGenError("image transport: empty image")
    return png


def generate(prompt: str, *, size: str = "1024x1024", quality: str = "auto",
             background: str = "auto", model: str = DEFAULT_MODEL) -> bytes:
    """text→image. Ritorna i byte PNG."""
    if not (prompt or "").strip():
        raise ImageGenError("prompt vuoto")
    if _in_pack_position():
        return _via_transport("generate", prompt, size=size, quality=quality,
                              background=background)
    payload = {"model": model, "prompt": prompt, "n": 1, "size": size,
               "quality": quality, "background": background}
    return _extract_png(_post_json(_GEN_URL, payload))


def edit(prompt: str, image_bytes: bytes, *, size: str = "1024x1024",
         quality: str = "auto", background: str = "auto",
         model: str = DEFAULT_MODEL) -> bytes:
    """image→image (restyle dell'immagine fornita secondo il prompt). PNG out."""
    if not image_bytes:
        raise ImageGenError("immagine di input vuota")
    if _in_pack_position():
        return _via_transport("edit", prompt or "", size=size, quality=quality,
                              background=background, image_bytes=image_bytes)
    fields = {"model": model, "prompt": prompt or "", "n": "1", "size": size,
              "quality": quality, "background": background}
    body, boundary = _multipart(fields, {"image": ("input.png", image_bytes, "image/png")})
    req = urllib.request.Request(
        _EDIT_URL, data=body,
        headers={"Authorization": f"Bearer {_api_key()}",
                 "Content-Type": f"multipart/form-data; boundary={boundary}"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return _extract_png(json.loads(resp.read().decode("utf-8")))
    except urllib.error.HTTPError as e:
        b = e.read().decode("utf-8") if e.fp else str(e)
        raise ImageGenError(f"OpenAI edit {e.code}: {b[:240]}") from e
    except urllib.error.URLError as e:
        raise ImageGenError(f"OpenAI irraggiungibile: {e}") from e

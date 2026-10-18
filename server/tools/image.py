"""Image generation for the gateway's `image.generate` and the owner's agent
avatar flow (`/internal/imagegen`).

The gateway keeps the decisions — who may call, which topic the PNG lands in
(`main._dispatch_image`), the owner-only avatar route — and the HTTP call to
OpenAI is it-pack's GATEWAY COMPONENT's service `imagegen_run`
(clodia-platform#525/#558), which reads the key `openai_api_key` from the
vault itself. The in-process client and the MCP transport of it-pack ≤ 0.18
are gone: without the component there is no image generation, and the error
says why.

Two operations (both return PNG bytes):
  - `generate(prompt)`        → text→image
  - `edit(prompt, image)`     → image→image

The style (e.g. manga for avatars) is the caller's, not this module's.
"""
from __future__ import annotations

import base64

from .. import vault

CRED = "openai_api_key"  # vault credential (infra, no grant), read by the component

#: The connector whose component serves the calls.
CONNECTOR = "openai-images"


class ImageGenError(RuntimeError):
    """Configuration or call error of image generation."""


def has_key() -> bool:
    """True when the OpenAI Images integration has its key in the vault."""
    return vault.has_credential(CRED)


def _via_component(op: str, prompt: str, *, size: str, quality: str,
                   background: str, image_bytes: bytes | None = None) -> bytes:
    """One image operation through it-pack's component service (#525/#558).

    Contract: arguments `{op, prompt, size, quality, background, image_b64?}`,
    result `{"png_b64": "<base64>"}`. Fail closed: no serving component is an
    error naming its state, never another client."""
    from ..components import loader as _components
    svc = _components.service("it-pack", "imagegen_run")
    if svc is None:
        try:
            st = _components.state_of("it-pack")
        except Exception:  # noqa: BLE001
            st = None
        if st:
            raise ImageGenError(
                f"image generation is it-pack's, but its gateway component is "
                f"{st.get('status')}: {str(st.get('reason') or '')[:200]}")
        raise ImageGenError(
            "image generation is served by it-pack's gateway component "
            "(it-pack ≥ 0.19.0) with `connectors: {openai-images: pack}`; it is "
            "not installed, not enabled, or the switch is on `native`, which has "
            "no implementation any more")
    sargs = {"op": op, "prompt": prompt, "size": size, "quality": quality,
             "background": background}
    if image_bytes is not None:
        sargs["image_b64"] = base64.b64encode(image_bytes).decode("ascii")
    try:
        out = svc.handler(sargs)
        png = base64.b64decode((out or {})["png_b64"], validate=True)
    except Exception as e:  # noqa: BLE001 — never the arguments in the message
        raise ImageGenError(f"image component: {type(e).__name__}: {str(e)[:200]}") from e
    if not png:
        raise ImageGenError("image component: empty image")
    return png


def generate(prompt: str, *, size: str = "1024x1024", quality: str = "auto",
             background: str = "auto") -> bytes:
    """text→image. Returns the PNG bytes."""
    if not (prompt or "").strip():
        raise ImageGenError("prompt vuoto")
    return _via_component("generate", prompt, size=size, quality=quality,
                          background=background)


def edit(prompt: str, image_bytes: bytes, *, size: str = "1024x1024",
         quality: str = "auto", background: str = "auto") -> bytes:
    """image→image (restyle of the given image per the prompt). PNG out."""
    if not image_bytes:
        raise ImageGenError("immagine di input vuota")
    return _via_component("edit", prompt or "", size=size, quality=quality,
                          background=background, image_bytes=image_bytes)

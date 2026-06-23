"""Self-test imagegen + connettore OpenAI (Fase image-gen) — plain python.

    python3 -m server.test_imagegen_api

Vault temporanea + OpenAI monkeypatchato: nessuna chiamata reale né PKI reale.
"""
from __future__ import annotations

import importlib
import os
import tempfile
import warnings


def main() -> int:
    warnings.filterwarnings("ignore")
    tmp = tempfile.mkdtemp(prefix="clodia-imagegen-test-")
    os.environ["CLODIA_VAULT_DIR"] = tmp
    os.environ["CLODIA_PROVIDER_PRINCIPALS"] = "clodia"
    os.environ.pop("OPENAI_API_KEY", None)

    from . import vault as _vault
    importlib.reload(_vault)
    from .tools import image as image_tool
    importlib.reload(image_tool)
    from . import imagegen_api as iapi
    importlib.reload(iapi)
    from . import tools_api as tapi
    importlib.reload(tapi)

    # monkeypatch: niente PKI reale, niente OpenAI reale
    iapi.verify_session_token = lambda t: ({"agent": "clodia"} if t != "BAD"
                                           else (_ for _ in ()).throw(PermissionError("bad")))
    iapi._PRINCIPALS = {"clodia"}
    image_tool.generate = lambda prompt, **kw: b"PNGGEN:" + prompt.encode()
    image_tool.edit = lambda prompt, raw, **kw: b"PNGEDIT:" + raw

    from starlette.applications import Starlette
    from starlette.testclient import TestClient
    app = Starlette(routes=iapi.routes + tapi.routes)
    c = TestClient(app)
    H = {"Authorization": "Bearer ckt1.fake"}

    ok = 0
    fail = 0

    def check(name, cond):
        nonlocal ok, fail
        print(f"  {'✓' if cond else '✗'} {name}")
        ok += cond
        fail += (not cond)

    # auth
    check("401 senza token valido", c.post("/internal/imagegen", headers={"Authorization": "Bearer BAD"}, json={"prompt": "x"}).status_code == 401)

    # 409 finché la key non è nel vault
    r = c.post("/internal/imagegen", headers=H, json={"prompt": "un gatto"})
    check("409 senza key OpenAI", r.status_code == 409)

    # attiva il connettore (deposita la key nel vault)
    r = c.post("/tools/openai/connect", json={"api_key": "sk-test-123"})
    check("connect deposita key", r.status_code == 200 and r.json()["connected"] is True)
    check("key nel vault", _vault.has_credential("openai_api_key"))

    # list_tools mostra il connettore connesso
    r = c.get("/tools")
    conn = {x["id"]: x for x in r.json()["connectors"]}
    check("connettore openai-images connected", conn.get("openai-images", {}).get("connected") is True)

    # generate (text→image)
    r = c.post("/internal/imagegen", headers=H, json={"prompt": "un robot"})
    check("generate → png", r.status_code == 200 and r.content == b"PNGGEN:un robot"
          and r.headers["content-type"] == "image/png")

    # edit (image→image) con data URL
    import base64
    b64 = base64.b64encode(b"RAWIMG").decode()
    r = c.post("/internal/imagegen", headers=H, json={"prompt": "stile", "image_b64": f"data:image/png;base64,{b64}"})
    check("edit → png", r.status_code == 200 and r.content == b"PNGEDIT:RAWIMG")

    # 400 se né prompt né immagine
    r = c.post("/internal/imagegen", headers=H, json={})
    check("400 senza prompt né immagine", r.status_code == 400)

    # disconnect (key vuota) → rimuove
    c.post("/tools/openai/connect", json={"api_key": ""})
    check("disconnect rimuove key", not _vault.has_credential("openai_api_key"))

    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{ok} ok, {fail} fail")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

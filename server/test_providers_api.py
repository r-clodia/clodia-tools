"""Self-test del backend interno credenziali provider (Fase 4) — plain python.

Esegui con::

    python3 -m server.test_providers_api    # dalla root del repo

Usa una vault temporanea (CLODIA_VAULT_DIR) e monkeypatcha la verifica ckt1:
non tocca PKI reale né credenziali reali.
"""
from __future__ import annotations

import importlib
import os
import tempfile
import warnings


def main() -> int:
    warnings.filterwarnings("ignore")
    tmp = tempfile.mkdtemp(prefix="clodia-providers-test-")
    os.environ["CLODIA_VAULT_DIR"] = tmp
    os.environ["CLODIA_PROVIDER_PRINCIPALS"] = "clodia"

    # ricarica i moduli con l'env di test
    from . import vault as _vault
    importlib.reload(_vault)
    from . import providers_api as papi
    importlib.reload(papi)

    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    # monkeypatch della verifica token: il nostro test non ha PKI reale
    _fake_agent = {"v": "clodia"}

    def _fake_verify(token: str) -> dict:
        if token == "BAD":
            raise PermissionError("token non valido")
        return {"agent": _fake_agent["v"], "aud": "keystore"}

    papi.verify_session_token = _fake_verify

    app = Starlette(routes=papi.routes)
    c = TestClient(app)
    H = {"Authorization": "Bearer ckt1.fake"}

    ok = 0
    fail = 0

    def check(name: str, cond: bool) -> None:
        nonlocal ok, fail
        if cond:
            ok += 1
            print(f"  ✓ {name}")
        else:
            fail += 1
            print(f"  ✗ {name}")

    # 1. lista vuota all'inizio
    r = c.get("/internal/providers", headers=H)
    check("list vuota", r.status_code == 200 and r.json()["ids"] == [])

    # 2. get di un provider assente → 404
    r = c.get("/internal/providers/anthropic", headers=H)
    check("get assente → 404", r.status_code == 404)

    # 3. put deposita il bundle
    bundle = {"method": "subscription", "access_token": "tok-123",
              "refresh_token": "ref-456", "expires_at": 9999999999}
    r = c.put("/internal/providers/anthropic", headers=H, json=bundle)
    check("put ok", r.status_code == 200 and r.json()["id"] == "anthropic")

    # 4. il bundle è davvero nello store del vault
    check("bundle nel vault", _vault.has_credential("provider_anthropic"))

    # 5. get restituisce il bundle identico
    r = c.get("/internal/providers/anthropic", headers=H)
    check("get round-trip", r.status_code == 200 and r.json() == bundle)

    # 6. compare in lista
    r = c.get("/internal/providers", headers=H)
    check("list contiene anthropic", r.json()["ids"] == ["anthropic"])

    # 7. grant_agents vuoto → nessun agente può fetcharlo via get_secret
    try:
        _vault.get_secret("clodia", "provider_anthropic")
        check("no grant per-agente", False)
    except _vault.VaultDenied:
        check("no grant per-agente", True)

    # 8. update idempotente (refresh writeback)
    bundle2 = {**bundle, "access_token": "tok-NEW"}
    c.put("/internal/providers/anthropic", headers=H, json=bundle2)
    r = c.get("/internal/providers/anthropic", headers=H)
    check("update writeback", r.json()["access_token"] == "tok-NEW")

    # 9. delete rimuove
    r = c.delete("/internal/providers/anthropic", headers=H)
    check("delete ok", r.status_code == 200 and r.json()["removed"] is True)
    check("vault svuotato", not _vault.has_credential("provider_anthropic"))

    # 10. delete idempotente
    r = c.delete("/internal/providers/anthropic", headers=H)
    check("delete idempotente", r.status_code == 200 and r.json()["removed"] is False)

    # 11. token invalido → 401
    r = c.get("/internal/providers", headers={"Authorization": "Bearer BAD"})
    check("token invalido → 401", r.status_code == 401)

    # 12. principal non privilegiato → 403
    _fake_agent["v"] = "looper"
    r = c.get("/internal/providers", headers=H)
    check("principal non privilegiato → 403", r.status_code == 403)
    _fake_agent["v"] = "clodia"

    # 13. pid malformato → 400
    r = c.get("/internal/providers/..%2fetc", headers=H)
    check("pid malformato → 400/404", r.status_code in (400, 404))
    r = c.put("/internal/providers/bad pid", headers=H, json={"x": 1})
    check("pid con spazio → 400/404", r.status_code in (400, 404))

    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{ok} ok, {fail} fail")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

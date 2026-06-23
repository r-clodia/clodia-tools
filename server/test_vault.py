"""Self-test della vault — plain python, niente pytest.

Esegui con::

    python3 -m server.test_vault    # dalla root del repo

Usa una vault temporanea (CLODIA_VAULT_DIR) con una credenziale fittizia:
non tocca nulla di reale.
"""
from __future__ import annotations

import importlib
import json
import os
import shutil
import tempfile
from pathlib import Path


def main() -> int:
    d = tempfile.mkdtemp(prefix="vaulttest_")
    os.environ["CLODIA_VAULT_DIR"] = d
    from . import vault
    importlib.reload(vault)
    try:
        # deposit + grant
        vault.deposit(
            "gmail_demo",
            {"client_id": "cid", "client_secret": "csec", "refresh_token": "rtok",
             "email": "agency@example.com", "account": "demo"},
            cred_type="oauth2_google", grant_agents=["clodia"])

        # fetch autorizzato
        b = vault.get_secret("clodia", "gmail_demo")
        assert b["refresh_token"] == "rtok", "fetch deve restituire il bundle"

        # deny: agente senza grant
        try:
            vault.get_secret("looper", "gmail_demo")
            raise AssertionError("doveva negare 'looper'")
        except vault.VaultDenied:
            pass

        # deny: credenziale inesistente
        try:
            vault.get_secret("clodia", "inesistente")
            raise AssertionError("doveva negare credenziale inesistente")
        except vault.VaultDenied:
            pass

        # has_credential
        assert vault.has_credential("gmail_demo") is True
        assert vault.has_credential("inesistente") is False

        # materializzazione google oauth (3 file: oauth client, tokens, config)
        dest = Path(d) / "tmpmat"
        acct = vault.materialize_google_oauth("clodia", "gmail_demo", dest)
        assert acct == "demo"
        client = json.loads((dest / "google_oauth_client.json").read_text())
        assert set(client) == {"client_id", "client_secret"}, "client = solo id+secret"
        toks = json.loads((dest / "email_oauth_tokens.json").read_text())
        assert "demo" in toks and toks["demo"]["refresh_token"] == "rtok"
        cfg = json.loads((dest / "email_config.json").read_text())
        assert cfg["default"] == "demo"
        assert cfg["accounts"]["demo"]["auth"] == "oauth2"
        assert cfg["accounts"]["demo"]["imap_server"] == "imap.gmail.com"
        assert oct((dest / "google_oauth_client.json").stat().st_mode)[-3:] == "600"

        # list_for: solo nomi, filtrato per grant
        assert vault.list_for("clodia") == ["gmail_demo"]
        assert vault.list_for("looper") == []

        # audit: ogni accesso registrato (2 OK + 2 DENIED)
        lines = [json.loads(x) for x in (Path(d) / "audit.log").read_text().splitlines()]
        results = [r["result"] for r in lines]
        assert results.count("OK") == 2 and results.count("DENIED") == 2, results

        print("OK — vault self-test: tutti i check passati")
        return 0
    finally:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""seed_app_credential — deposita nella vault il **client OAuth dell'app**
(`app_google_oauth`) a partire dal JSON scaricato da Google Cloud.

È la credenziale d'infrastruttura del gateway (client_id + client_secret +
redirect_uri) che serve a costruire l'URL di consenso e a scambiare il code.
NON è esposta agli agenti: viene letta solo da `vault.read_internal`, quindi
si deposita SENZA grant.

Uso::

    python3 seed_app_credential.py /path/al/client_secret_*.json

Il client_secret non viene mai stampato: lo script lo legge dal file e lo
scrive nella vault (`$CLODIA_VAULT_DIR`, default ~/.clodia). Esegui sul Mac e
poi `scp` la vault al host (lo script stampa i comandi).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from server import google_oauth as go  # noqa: E402
from server import vault  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    c = go.parse_client_file(sys.argv[1])
    if not c.get("client_id") or not c.get("client_secret"):
        print("ERRORE: client_id/client_secret assenti nel file.", file=sys.stderr)
        return 1
    vault.deposit(
        go.APP_CREDENTIAL,
        {"client_id": c["client_id"], "client_secret": c["client_secret"],
         "redirect_uri": c["redirect_uri"]},
        cred_type="oauth2_google_app",
        grant_agents=[],   # infra: nessun agente può fetch-arla
    )
    print(f"✅ Client d'app depositato come '{go.APP_CREDENTIAL}' in {vault.vault_dir()} "
          f"(redirect {c['redirect_uri']}, nessun grant agente)")
    print("   Copia la vault sul host:")
    print(f"   scp {vault.vault_dir()}/store/{go.APP_CREDENTIAL}.json host:~/.clodia/store/")
    print(f"   scp {vault.vault_dir()}/vault-policy.yaml host:~/.clodia/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

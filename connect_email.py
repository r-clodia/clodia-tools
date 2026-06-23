#!/usr/bin/env python3
"""connect_email — acquisisce la credenziale OAuth2 di un account Gmail e la
DEPOSITA NELLA VAULT del gateway (non più in secrets/).

Flusso (loopback + code dall'URL, niente HTTPS — bootstrap "token-da-URL"):
  1. fornisci il client OAuth (client_id + client_secret) dell'app desktop
     Google: via `--client <file.json>` oppure ai prompt;
  2. apri l'URL di consenso stampato, consenti;
  3. Google redirige a http://127.0.0.1/?code=XXXX (pagina "impossibile
     connettersi": normale) → copia il valore di `code=`;
  4. incollalo → scambio code→refresh token → il bundle
     {client_id, client_secret, refresh_token, email, account} viene
     depositato nella vault come credenziale `gmail_<account>` con grant
     `fetch` a `clodia`.

Prerequisito: OAuth client "App desktop" (Gmail API, scope
https://mail.google.com/, app in Production). Il client_secret NON viene
scritto in secrets/: finisce solo nella vault.

La vault sta in $CLODIA_VAULT_DIR (default ~/.clodia). Dopo il deposito,
copia store/ + vault-policy.yaml sul host (~/.clodia) — è lì che gira il
gateway. La vault NON è sincronizzata in automatico.
"""
import argparse
import sys
import urllib.parse
from pathlib import Path

# importa i moduli del gateway
sys.path.insert(0, str(Path(__file__).resolve().parent))
from server import google_oauth as go  # noqa: E402
from server import vault  # noqa: E402

DEFAULT_REDIRECT = go.DEFAULT_REDIRECT


def load_client(args) -> tuple[str, str, str]:
    """Ritorna (client_id, client_secret, redirect_uri) dal file `--client`
    (formato annidato Google o piatto) o dai prompt."""
    if args.client:
        c = go.parse_client_file(args.client)
        cid, csec, redirect = c["client_id"], c["client_secret"], c["redirect_uri"]
    else:
        cid = input("client_id: ").strip()
        csec = input("client_secret: ").strip()
        redirect = input(f"redirect_uri [{DEFAULT_REDIRECT}]: ").strip() or DEFAULT_REDIRECT
    if not cid or not csec:
        sys.exit("ERRORE: client_id/client_secret mancanti.")
    return cid, csec, redirect


def main() -> int:
    ap = argparse.ArgumentParser(description="Acquisisce la credenziale OAuth Gmail nella vault")
    ap.add_argument("account", help="nome account (es. demo)")
    ap.add_argument("email", help="indirizzo email (es. agency@example.com)")
    ap.add_argument("--client", help="file JSON {client_id, client_secret} dell'OAuth client")
    ap.add_argument("--grant", action="append", default=None,
                    help="agente a cui concedere 'fetch' (ripetibile; default: clodia)")
    args = ap.parse_args()

    client_id, client_secret, redirect = load_client(args)

    print("\n1) Apri questo URL nel browser e consenti:\n")
    print("   " + go.consent_url(client_id, redirect) + "\n")
    print(f"2) Dopo il consenso il browser va su {redirect}/?code=...")
    print("   (pagina di errore: normale). Copia il valore di `code=`.\n")
    code = input("3) Incolla il code qui: ").strip()
    if code.startswith("http"):
        code = urllib.parse.parse_qs(urllib.parse.urlparse(code).query).get("code", [""])[0]

    res = go.exchange_code(client_id, client_secret, code, redirect)
    rt = res.get("refresh_token")
    if not rt:
        print("ERRORE: nessun refresh_token nella risposta. Verifica che l'app sia in "
              "'Production' e riprova con prompt=consent.", file=sys.stderr)
        print(json.dumps({k: v for k, v in res.items() if k != "access_token"}, indent=2),
              file=sys.stderr)
        return 1

    credential = f"gmail_{args.account}"
    vault.deposit(
        credential,
        {"client_id": client_id, "client_secret": client_secret,
         "refresh_token": rt, "email": args.email, "account": args.account},
        cred_type="oauth2_google",
        grant_agents=args.grant or ["clodia"],
    )
    print(f"\n✅ Credenziale '{credential}' depositata nella vault {vault.vault_dir()}")
    print(f"   grant 'fetch' → {args.grant or ['clodia']}")
    print("   Ora copia la vault sul host:")
    print(f"   scp {vault.vault_dir()}/store/{credential}.json host:~/.clodia/store/")
    print(f"   scp {vault.vault_dir()}/vault-policy.yaml host:~/.clodia/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

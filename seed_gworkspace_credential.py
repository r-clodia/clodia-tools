#!/usr/bin/env python3
"""Deposita nel vault le credenziali OAuth di Google Workspace per il backend
``gworkspace``, leggendole dai ``token.json`` esistenti dei client (gdrive /
gcalendar). NON stampa mai i valori segreti.

Uso (dentro il container del gateway, con i token montati/copiati):
    python3 seed_gworkspace_credential.py \
        --drive-token /path/gdrive/token.json \
        --calendar-token /path/gcalendar/token.json \
        --email agency@example.com

Il token.json (formato authorized_user di google-auth) contiene già
client_id / client_secret / refresh_token / scopes: li mappiamo sul bundle
``oauth2_google`` atteso dal vault. Grant di default: fetch a `clodia`.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from server import vault


def _bundle_from_token(path: str, email: str) -> dict:
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    missing = [k for k in ("client_id", "client_secret", "refresh_token") if not d.get(k)]
    if missing:
        sys.exit(f"token '{path}' incompleto: manca {missing}")
    return {
        "client_id": d["client_id"],
        "client_secret": d["client_secret"],
        "refresh_token": d["refresh_token"],
        "token_uri": d.get("token_uri", "https://oauth2.googleapis.com/token"),
        "scopes": d.get("scopes"),
        "email": email,
        "account": email.split("@")[0].replace(".", "_"),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--drive-token", required=True, help="path a gdrive/token.json (scope drive)")
    ap.add_argument("--calendar-token", help="path a gcalendar/token.json (scope calendar)")
    ap.add_argument("--email", required=True, help="email dell'account Google")
    ap.add_argument("--agent", default="clodia", help="agent a cui concedere fetch (default clodia)")
    args = ap.parse_args()

    vault.deposit("gworkspace_drive", _bundle_from_token(args.drive_token, args.email),
                  cred_type="oauth2_google", grant_agents=[args.agent])
    print("OK gworkspace_drive depositata (scope drive → Drive/Docs/Slides)")

    if args.calendar_token:
        vault.deposit("gworkspace_calendar", _bundle_from_token(args.calendar_token, args.email),
                      cred_type="oauth2_google", grant_agents=[args.agent])
        print("OK gworkspace_calendar depositata (scope calendar)")


if __name__ == "__main__":
    main()

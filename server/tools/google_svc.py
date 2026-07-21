"""google_svc — costruzione client Google API condivisa (Drive/Docs/Calendar).

Riusa la credenziale OAuth Workspace UNIFICATA già nel vault (`google_<account>`,
scope Drive+Docs+Calendar+Gmail) e la risoluzione account/credenziale di
`gdrive.py`, così Docs e Calendar NON duplicano la logica di credenziali. L'access
token è rinfrescato dalla libreria Google dal refresh_token; non tocca il modello.
Il grant sull'agente chiamante è verificato da `vault.get_secret` (VaultDenied).
"""
from __future__ import annotations

from typing import Optional

from .. import vault
from ..whitelist import agent_name

_TOKEN_URI = "https://oauth2.googleapis.com/token"


def build_service(api: str, version: str, account: Optional[str] = None):
    """Ritorna (service, account) per l'API Google `api`/`version` con la
    credenziale Workspace di `account` (o il primo disponibile). Timeout HTTP 30s
    così una chiamata stallata fallisce invece di bloccare l'event loop."""
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request as GoogleRequest
    from googleapiclient.discovery import build
    import httplib2
    from google_auth_httplib2 import AuthorizedHttp
    # risoluzione account + nome credenziale: unica fonte, quella di gdrive.
    from .gdrive import _resolve_account, _drive_cred

    acct = _resolve_account(account)
    b = vault.get_secret(agent_name(), _drive_cred(acct))  # VaultDenied se no grant
    creds = Credentials(
        token=None,
        refresh_token=b["refresh_token"],
        client_id=b["client_id"],
        client_secret=b["client_secret"],
        token_uri=_TOKEN_URI,
        scopes=(b.get("scope") or "").split(),
    )
    creds.refresh(GoogleRequest())
    authed = AuthorizedHttp(creds, http=httplib2.Http(timeout=30))
    return build(api, version, http=authed, cache_discovery=False), acct

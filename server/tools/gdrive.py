"""Google Drive tool exposed via MCP — export/import di file fra i topic e una
cartella Drive condivisa.

Riusa le credenziali OAuth Google Workspace già nel vault (`gworkspace_<account>`,
depositate dal flusso "Connetti Google Workspace": client_id/secret/refresh_token
+ scope `drive` pieno). Il segreto resta nel gateway: la libreria Google rinfresca
l'access token da sé, non raggiunge mai il modello.

Trasferimento file via **scratch** dell'agent (come topic.fetch/put): i byte non
transitano in base64 nel contesto. Flusso tipico orchestrato da clodia:
  export:  topic.fetch → gdrive.upload
  import:  gdrive.download → topic.put
"""
from __future__ import annotations

import io
from typing import Optional

from .. import vault
from ..whitelist import agent_name, tool_allowed

_TOKEN_URI = "https://oauth2.googleapis.com/token"
_FOLDER_MIME = "application/vnd.google-apps.folder"
# Export di default per i Google-native doc (non scaricabili con get_media).
_GOOGLE_EXPORT = {
    "application/vnd.google-apps.document": ("application/pdf", ".pdf"),
    "application/vnd.google-apps.spreadsheet":
        ("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", ".xlsx"),
    "application/vnd.google-apps.presentation": ("application/pdf", ".pdf"),
}
_FIELDS = "id, name, mimeType, modifiedTime, size, webViewLink, parents"


def gworkspace_accounts() -> list[str]:
    """Account Workspace disponibili = credenziali gworkspace_<account> nel vault."""
    return sorted(n[len("gworkspace_"):] for n in vault.store_names()
                  if n.startswith("gworkspace_"))


def _resolve_account(account: Optional[str]) -> str:
    accts = gworkspace_accounts()
    if not accts:
        raise RuntimeError(
            "nessun account Google Workspace nel vault: connettilo da "
            "Tools → Google Workspace")
    if account:
        if account not in accts:
            raise ValueError(f"account '{account}' sconosciuto; disponibili: {accts}")
        return account
    return accts[0]


def _service(account: Optional[str] = None):
    """Costruisce il client Drive v3 per `account`, con credenziali dal vault
    (grant-checked sull'agente chiamante). L'access token è rinfrescato dalla
    libreria Google a partire dal refresh_token."""
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request as GoogleRequest
    from googleapiclient.discovery import build

    acct = _resolve_account(account)
    b = vault.get_secret(agent_name(), f"gworkspace_{acct}")  # VaultDenied se no grant
    creds = Credentials(
        token=None,
        refresh_token=b["refresh_token"],
        client_id=b["client_id"],
        client_secret=b["client_secret"],
        token_uri=_TOKEN_URI,
        scopes=(b.get("scope") or "").split(),
    )
    creds.refresh(GoogleRequest())
    return build("drive", "v3", credentials=creds, cache_discovery=False), acct


def _clean(f: dict) -> dict:
    return {k: f.get(k) for k in ("id", "name", "mimeType", "modifiedTime",
                                  "size", "webViewLink") if f.get(k) is not None}


# ── Tool esposti via MCP ─────────────────────────────────────────────────────

def list_files(folder_id: Optional[str] = None, query: Optional[str] = None,
               limit: int = 50, account: Optional[str] = None) -> dict:
    """Elenca file/cartelle di Drive. `folder_id` per il contenuto di una cartella;
    `query` per una query Drive arbitraria (es. \"name contains 'report'\")."""
    tool_allowed("gdrive.list")
    svc, acct = _service(account)
    clauses = ["trashed = false"]
    if folder_id:
        clauses.append(f"'{folder_id}' in parents")
    if query:
        clauses.append(f"({query})")
    res = svc.files().list(
        q=" and ".join(clauses), pageSize=max(1, min(int(limit), 1000)),
        fields=f"files({_FIELDS})", orderBy="folder,name").execute()
    return {"account": acct, "files": [_clean(f) for f in res.get("files", [])]}


def search(name: str, limit: int = 20, account: Optional[str] = None) -> dict:
    """Cerca per nome (match parziale, case-insensitive)."""
    tool_allowed("gdrive.search")
    if not name:
        raise ValueError("'name' non può essere vuoto")
    svc, acct = _service(account)
    safe = name.replace("'", "\\'")
    res = svc.files().list(
        q=f"name contains '{safe}' and trashed = false",
        pageSize=max(1, min(int(limit), 1000)),
        fields=f"files({_FIELDS})", orderBy="folder,name").execute()
    return {"account": acct, "files": [_clean(f) for f in res.get("files", [])]}


def mkdir(name: str, parent_id: Optional[str] = None,
          account: Optional[str] = None) -> dict:
    """Crea una cartella (idempotenza non garantita: due chiamate → due cartelle).
    Cerca prima una cartella omonima nello stesso parent e la riusa se esiste."""
    tool_allowed("gdrive.mkdir")
    if not name:
        raise ValueError("'name' non può essere vuoto")
    svc, acct = _service(account)
    safe = name.replace("'", "\\'")
    q = (f"name = '{safe}' and mimeType = '{_FOLDER_MIME}' and trashed = false"
         + (f" and '{parent_id}' in parents" if parent_id else ""))
    existing = svc.files().list(q=q, fields=f"files({_FIELDS})").execute().get("files", [])
    if existing:
        return {"account": acct, "reused": True, **_clean(existing[0])}
    body = {"name": name, "mimeType": _FOLDER_MIME}
    if parent_id:
        body["parents"] = [parent_id]
    f = svc.files().create(body=body, fields=_FIELDS).execute()
    return {"account": acct, "reused": False, **_clean(f)}


def upload(src: str, name: Optional[str] = None, folder_id: Optional[str] = None,
           account: Optional[str] = None) -> dict:
    """Carica un file su Drive. `src` è un path locale (scratch dell'agent, già
    validato dal dispatch). `name` default = nome del file; `folder_id` = cartella
    di destinazione."""
    tool_allowed("gdrive.upload")
    from googleapiclient.http import MediaFileUpload
    import os
    svc, acct = _service(account)
    fname = name or os.path.basename(src)
    body = {"name": fname}
    if folder_id:
        body["parents"] = [folder_id]
    media = MediaFileUpload(src, resumable=False)
    f = svc.files().create(body=body, media_body=media, fields=_FIELDS).execute()
    return {"account": acct, "uploaded": True, **_clean(f)}


def download(file_id: str, dest: str, account: Optional[str] = None) -> dict:
    """Scarica un file di Drive in `dest` (path scratch dell'agent, già validato
    dal dispatch). I Google-native doc (Docs/Sheets/Slides) vengono esportati
    (PDF/xlsx)."""
    tool_allowed("gdrive.download")
    from googleapiclient.http import MediaIoBaseDownload
    svc, acct = _service(account)
    meta = svc.files().get(fileId=file_id, fields="id, name, mimeType").execute()
    mime = meta.get("mimeType", "")
    if mime in _GOOGLE_EXPORT:
        export_mime, _ext = _GOOGLE_EXPORT[mime]
        request = svc.files().export_media(fileId=file_id, mimeType=export_mime)
    elif mime.startswith("application/vnd.google-apps"):
        raise ValueError(f"tipo Google non esportabile: {mime}")
    else:
        request = svc.files().get_media(fileId=file_id)
    buf = io.BytesIO()
    downloader = MediaIoBaseDownload(buf, request)
    done = False
    while not done:
        _status, done = downloader.next_chunk()
    with open(dest, "wb") as fh:
        fh.write(buf.getvalue())
    return {"account": acct, "downloaded": True, "file_id": file_id,
            "name": meta.get("name"), "mimeType": mime, "local_path": dest,
            "size": buf.getbuffer().nbytes}


def share(file_id: str, email: str, role: str = "writer",
          account: Optional[str] = None) -> dict:
    """Condivide un file/cartella con un'email. role: writer (editor, default),
    reader, commenter. Notifica l'utente via email."""
    tool_allowed("gdrive.share")
    if "@" not in (email or ""):
        raise ValueError(f"email non valida: '{email}'")
    if role not in ("writer", "reader", "commenter"):
        raise ValueError("role deve essere writer | reader | commenter")
    svc, acct = _service(account)
    perm = svc.permissions().create(
        fileId=file_id, sendNotificationEmail=True,
        body={"type": "user", "role": role, "emailAddress": email},
        fields="id").execute()
    meta = svc.files().get(fileId=file_id, fields="id, name, webViewLink").execute()
    return {"account": acct, "shared": True, "permission_id": perm.get("id"),
            "email": email, "role": role, **_clean(meta)}

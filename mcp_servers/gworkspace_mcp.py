#!/usr/bin/env python3
"""gworkspace — backend MCP stdio per Google Workspace (Drive + Docs + Slides + Calendar).

First-party del gateway: invece di iniettare segreti nel config, legge le
credenziali OAuth **direttamente dal vault** (`read_internal`) e lascia che la
libreria Google rinfreschi l'access token da sola, in-process. Niente
`token.json` editato a mano.

Credenziali attese nel vault (depositate da `seed_gworkspace_credential.py`):
  - ``gworkspace_drive``     scope ``…/auth/drive``     → Drive + Docs + Slides
  - ``gworkspace_calendar``  scope ``…/auth/calendar``  → Calendar

Montato come backend ``gworkspace`` in config.yaml; i tool sono esposti agli
agenti namespaced ``gworkspace.<tool>`` dal proxy del gateway.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import uuid

# Il backend gira come subprocesso del proxy con cwd=/app: aggiungiamo la root
# del pacchetto al path per poter importare `server.vault`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

from server import vault  # noqa: E402

__version__ = "0.3.0"

CRED_DRIVE = "gworkspace_drive"
CRED_CALENDAR = "gworkspace_calendar"
_TOKEN_URI = "https://oauth2.googleapis.com/token"

app = Server("gworkspace")


def _creds(cred_name: str) -> Credentials:
    """Costruisce le Credentials dal bundle nel vault e rinfresca se scaduto.
    Il refresh_token non cambia: lavoriamo in-process, niente write-back."""
    b = vault.read_internal(cred_name)
    for k in ("client_id", "client_secret", "refresh_token"):
        if not b.get(k):
            raise RuntimeError(f"vault: bundle '{cred_name}' incompleto, manca '{k}'")
    c = Credentials(
        token=b.get("token"),
        refresh_token=b["refresh_token"],
        token_uri=b.get("token_uri", _TOKEN_URI),
        client_id=b["client_id"],
        client_secret=b["client_secret"],
        scopes=b.get("scopes"),
    )
    if not c.valid:
        c.refresh(Request())
    return c


def _drive():
    return build("drive", "v3", credentials=_creds(CRED_DRIVE), cache_discovery=False)


def _docs():
    return build("docs", "v1", credentials=_creds(CRED_DRIVE), cache_discovery=False)


def _slides():
    return build("slides", "v1", credentials=_creds(CRED_DRIVE), cache_discovery=False)


def _calendar():
    return build("calendar", "v3", credentials=_creds(CRED_CALENDAR), cache_discovery=False)


# ── Implementazioni ─────────────────────────────────────────────────────────

# Shared Drive / file condivisi da altri account: senza questi parametri le
# chiamate Drive danno 404 su tutto ciò che non è nel "My Drive" proprio
# (lezione retrospettiva 2026-03-21). `corpora=allDrives` fa spaziare la list
# anche sui Drive di team oltre che su "condivisi con me".
_LIST_ALL_DRIVES = {"supportsAllDrives": True, "includeItemsFromAllDrives": True,
                    "corpora": "allDrives"}


def drive_list(folder_id: str | None = None, limit: int = 25) -> dict:
    q = f"'{folder_id}' in parents and trashed=false" if folder_id else "trashed=false"
    res = _drive().files().list(
        q=q, pageSize=min(int(limit), 100),
        fields="files(id,name,mimeType,modifiedTime,size,webViewLink,driveId)",
        orderBy="modifiedTime desc", **_LIST_ALL_DRIVES,
    ).execute()
    return {"files": res.get("files", [])}


def drive_search(query: str, limit: int = 25) -> dict:
    res = _drive().files().list(
        q=f"name contains '{query}' and trashed=false", pageSize=min(int(limit), 100),
        fields="files(id,name,mimeType,modifiedTime,webViewLink,driveId)",
        orderBy="modifiedTime desc", **_LIST_ALL_DRIVES,
    ).execute()
    return {"files": res.get("files", [])}


def drive_get(file_id: str) -> dict:
    return _drive().files().get(
        fileId=file_id, supportsAllDrives=True,
        fields="id,name,mimeType,modifiedTime,size,webViewLink,parents,driveId,owners(emailAddress)",
    ).execute()


def docs_read(file_id: str) -> dict:
    """Esporta un Google Doc come testo semplice (via Drive export)."""
    data = _drive().files().export(fileId=file_id, mimeType="text/plain").execute()
    text = data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else str(data)
    return {"file_id": file_id, "text": text}


def docs_create(title: str, text: str = "", folder_id: str | None = None) -> dict:
    doc = _docs().documents().create(body={"title": title}).execute()
    doc_id = doc["documentId"]
    if text:
        _docs().documents().batchUpdate(
            documentId=doc_id,
            body={"requests": [{"insertText": {"location": {"index": 1}, "text": text}}]},
        ).execute()
    if folder_id:
        _drive().files().update(fileId=doc_id, addParents=folder_id,
                                supportsAllDrives=True, fields="id,parents").execute()
    return {"document_id": doc_id,
            "webViewLink": f"https://docs.google.com/document/d/{doc_id}/edit"}


def _docs_batch(doc_id: str, requests: list) -> dict:
    return _docs().documents().batchUpdate(
        documentId=doc_id, body={"requests": requests}).execute()


def docs_append(file_id: str, text: str, suggest: bool = False) -> dict:
    """Accoda testo in fondo al corpo del documento (endOfSegmentLocation)."""
    req: dict = {"insertText": {"endOfSegmentLocation": {}, "text": text}}
    if suggest:
        req["insertText"]["suggestedInsertionIds"] = [str(uuid.uuid4())[:8]]
    _docs_batch(file_id, [req])
    return {"document_id": file_id, "appended_chars": len(text), "suggest": suggest}


def docs_insert(file_id: str, text: str, index: int = 1, suggest: bool = False) -> dict:
    """Inserisce testo alla posizione `index` (1 = inizio del corpo)."""
    loc = {"insertText": {"location": {"index": int(index)}, "text": text}}
    if suggest:
        loc["insertText"]["suggestedInsertionIds"] = [str(uuid.uuid4())[:8]]
    _docs_batch(file_id, [loc])
    return {"document_id": file_id, "inserted_at": int(index),
            "inserted_chars": len(text), "suggest": suggest}


def docs_replace(file_id: str, find: str, replace: str, match_case: bool = False) -> dict:
    """Sostituisce tutte le occorrenze di `find` con `replace` (edit diretto)."""
    res = _docs_batch(file_id, [{
        "replaceAllText": {
            "containsText": {"text": find, "matchCase": bool(match_case)},
            "replaceText": replace,
        }}])
    changed = res.get("replies", [{}])[0].get("replaceAllText", {}).get("occurrencesChanged", 0)
    return {"document_id": file_id, "occurrences_changed": changed}


def slides_create(title: str, folder_id: str | None = None) -> dict:
    pres = _slides().presentations().create(body={"title": title}).execute()
    pid = pres["presentationId"]
    if folder_id:
        _drive().files().update(fileId=pid, addParents=folder_id,
                                supportsAllDrives=True, fields="id,parents").execute()
    return {"presentation_id": pid,
            "webViewLink": f"https://docs.google.com/presentation/d/{pid}/edit"}


def calendar_list(time_min: str | None = None, time_max: str | None = None,
                  limit: int = 20, calendar_id: str = "primary") -> dict:
    params = {"calendarId": calendar_id, "maxResults": min(int(limit), 100),
              "singleEvents": True, "orderBy": "startTime"}
    if time_min:
        params["timeMin"] = time_min
    if time_max:
        params["timeMax"] = time_max
    res = _calendar().events().list(**params).execute()
    items = [{"id": e.get("id"), "summary": e.get("summary"),
              "start": e.get("start"), "end": e.get("end"),
              "htmlLink": e.get("htmlLink")} for e in res.get("items", [])]
    return {"events": items}


def calendar_create(summary: str, start: str, end: str,
                    description: str | None = None, calendar_id: str = "primary",
                    attendees: list | None = None, location: str | None = None,
                    send_updates: str | None = None) -> dict:
    """Crea un evento. start/end in RFC3339 (es. 2026-06-20T10:00:00+02:00).
    `attendees`: lista di email da invitare. `send_updates`: 'all' | 'externalOnly'
    | 'none' (default 'all' se ci sono invitati, altrimenti 'none')."""
    body = {"summary": summary,
            "start": {"dateTime": start}, "end": {"dateTime": end}}
    if description:
        body["description"] = description
    if location:
        body["location"] = location
    if attendees:
        body["attendees"] = [{"email": e} for e in attendees]
    su = send_updates or ("all" if attendees else "none")
    ev = _calendar().events().insert(
        calendarId=calendar_id, body=body, sendUpdates=su).execute()
    return {"event_id": ev.get("id"), "htmlLink": ev.get("htmlLink"),
            "attendees": [a.get("email") for a in ev.get("attendees", [])],
            "send_updates": su}


# ── Wiring MCP ──────────────────────────────────────────────────────────────

_TOOLS: list[Tool] = [
    Tool(name="drive_list", description="List files in a Drive folder (default: root). Returns id/name/mimeType/link.",
         inputSchema={"type": "object", "properties": {
             "folder_id": {"type": "string", "description": "Drive folder id (optional; root if omitted)"},
             "limit": {"type": "integer", "description": "max files, default 25"}}}),
    Tool(name="drive_search", description="Search Drive files whose name contains the query.",
         inputSchema={"type": "object", "properties": {
             "query": {"type": "string"}, "limit": {"type": "integer"}}, "required": ["query"]}),
    Tool(name="drive_get", description="Get metadata of a Drive file by id (name, mimeType, webViewLink, parents, owner).",
         inputSchema={"type": "object", "properties": {"file_id": {"type": "string"}}, "required": ["file_id"]}),
    Tool(name="docs_read", description="Export a Google Doc as plain text by file id.",
         inputSchema={"type": "object", "properties": {"file_id": {"type": "string"}}, "required": ["file_id"]}),
    Tool(name="docs_create", description="Create a Google Doc with title and optional text body; optional folder_id.",
         inputSchema={"type": "object", "properties": {
             "title": {"type": "string"}, "text": {"type": "string"},
             "folder_id": {"type": "string"}}, "required": ["title"]}),
    Tool(name="docs_append", description="Append text at the end of an existing Google Doc (set suggest=true for a tracked suggestion).",
         inputSchema={"type": "object", "properties": {
             "file_id": {"type": "string"}, "text": {"type": "string"},
             "suggest": {"type": "boolean"}}, "required": ["file_id", "text"]}),
    Tool(name="docs_insert", description="Insert text at a character index in an existing Google Doc (index 1 = start of body).",
         inputSchema={"type": "object", "properties": {
             "file_id": {"type": "string"}, "text": {"type": "string"},
             "index": {"type": "integer"}, "suggest": {"type": "boolean"}},
             "required": ["file_id", "text"]}),
    Tool(name="docs_replace", description="Replace all occurrences of a string in an existing Google Doc; returns occurrences_changed.",
         inputSchema={"type": "object", "properties": {
             "file_id": {"type": "string"}, "find": {"type": "string"},
             "replace": {"type": "string"}, "match_case": {"type": "boolean"}},
             "required": ["file_id", "find", "replace"]}),
    Tool(name="slides_create", description="Create an empty Google Slides presentation with the given title; optional folder_id.",
         inputSchema={"type": "object", "properties": {
             "title": {"type": "string"}, "folder_id": {"type": "string"}}, "required": ["title"]}),
    Tool(name="calendar_list", description="List upcoming Calendar events (RFC3339 time_min/time_max optional).",
         inputSchema={"type": "object", "properties": {
             "time_min": {"type": "string"}, "time_max": {"type": "string"},
             "limit": {"type": "integer"}, "calendar_id": {"type": "string"}}}),
    Tool(name="calendar_create", description="Create a Calendar event. start/end in RFC3339, e.g. 2026-06-20T10:00:00+02:00. Optional attendees (emails) get an invite per send_updates.",
         inputSchema={"type": "object", "properties": {
             "summary": {"type": "string"}, "start": {"type": "string"}, "end": {"type": "string"},
             "description": {"type": "string"}, "calendar_id": {"type": "string"},
             "attendees": {"type": "array", "items": {"type": "string"},
                           "description": "email degli invitati"},
             "location": {"type": "string"},
             "send_updates": {"type": "string", "enum": ["all", "externalOnly", "none"],
                              "description": "notifiche di invito; default 'all' se ci sono attendees"}},
             "required": ["summary", "start", "end"]}),
]

_DISPATCH = {
    "drive_list": lambda a: drive_list(a.get("folder_id"), a.get("limit", 25)),
    "drive_search": lambda a: drive_search(a["query"], a.get("limit", 25)),
    "drive_get": lambda a: drive_get(a["file_id"]),
    "docs_read": lambda a: docs_read(a["file_id"]),
    "docs_create": lambda a: docs_create(a["title"], a.get("text", ""), a.get("folder_id")),
    "docs_append": lambda a: docs_append(a["file_id"], a["text"], a.get("suggest", False)),
    "docs_insert": lambda a: docs_insert(a["file_id"], a["text"], a.get("index", 1),
                                         a.get("suggest", False)),
    "docs_replace": lambda a: docs_replace(a["file_id"], a["find"], a["replace"],
                                           a.get("match_case", False)),
    "slides_create": lambda a: slides_create(a["title"], a.get("folder_id")),
    "calendar_list": lambda a: calendar_list(a.get("time_min"), a.get("time_max"),
                                             a.get("limit", 20), a.get("calendar_id", "primary")),
    "calendar_create": lambda a: calendar_create(a["summary"], a["start"], a["end"],
                                                 a.get("description"), a.get("calendar_id", "primary"),
                                                 a.get("attendees"), a.get("location"),
                                                 a.get("send_updates")),
}


@app.list_tools()
async def list_tools() -> list[Tool]:
    return _TOOLS


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    fn = _DISPATCH.get(name)
    if fn is None:
        return [TextContent(type="text", text=f"ERROR: unknown tool: {name}")]
    try:
        # Le chiamate google sono sincrone/bloccanti: eseguile in un thread.
        result = await asyncio.to_thread(fn, arguments)
        return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]
    except Exception as e:  # noqa: BLE001
        return [TextContent(type="text", text=f"ERROR: {type(e).__name__}: {e}")]


async def main():
    print(f"[gworkspace-mcp v{__version__}] up", file=sys.stderr)
    async with stdio_server() as (read, write):
        await app.run(read, write, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())

"""gdocs.* — Google Docs via MCP, sulla credenziale Workspace del vault.

Stessa credenziale di gdrive/gcalendar (scope `documents` già incluso). Verbi:
create, read (testo estratto), append_text, replace_text. Per creare dentro una
cartella specifica: create + gdrive.move. L'agente deve avere il grant Workspace.
"""
from __future__ import annotations

from typing import Optional

from .google_svc import build_service


def _svc(account: Optional[str]):
    return build_service("docs", "v1", account)


def create(title: str, text: Optional[str] = None, account: Optional[str] = None) -> dict:
    svc, acct = _svc(account)
    doc = svc.documents().create(body={"title": title}).execute()
    doc_id = doc.get("documentId")
    if text:
        svc.documents().batchUpdate(documentId=doc_id, body={"requests": [
            {"insertText": {"location": {"index": 1}, "text": text}}]}).execute()
    return {"account": acct, "document_id": doc_id, "title": title,
            "url": f"https://docs.google.com/document/d/{doc_id}/edit"}


def read(document_id: str, account: Optional[str] = None) -> dict:
    svc, acct = _svc(account)
    doc = svc.documents().get(documentId=document_id).execute()
    text = _extract_text(doc)
    return {"account": acct, "document_id": document_id,
            "title": doc.get("title"), "text": text, "chars": len(text)}


def append_text(document_id: str, text: str, account: Optional[str] = None) -> dict:
    """Aggiunge testo in fondo al documento."""
    svc, acct = _svc(account)
    doc = svc.documents().get(documentId=document_id).execute()
    end = _end_index(doc)
    svc.documents().batchUpdate(documentId=document_id, body={"requests": [
        {"insertText": {"location": {"index": max(1, end - 1)}, "text": text}}]}).execute()
    return {"account": acct, "document_id": document_id, "appended_chars": len(text), "ok": True}


def replace_text(document_id: str, find: str, replace: str,
                 match_case: bool = True, account: Optional[str] = None) -> dict:
    """Sostituisce TUTTE le occorrenze di `find` con `replace`."""
    svc, acct = _svc(account)
    res = svc.documents().batchUpdate(documentId=document_id, body={"requests": [
        {"replaceAllText": {"containsText": {"text": find, "matchCase": match_case},
                            "replaceText": replace}}]}).execute()
    occ = (res.get("replies", [{}])[0].get("replaceAllText", {}) or {}).get("occurrencesChanged", 0)
    return {"account": acct, "document_id": document_id, "occurrences": occ, "ok": True}


def _extract_text(doc: dict) -> str:
    out = []
    for el in doc.get("body", {}).get("content", []):
        para = el.get("paragraph")
        if not para:
            continue
        for pe in para.get("elements", []):
            tr = pe.get("textRun")
            if tr and tr.get("content"):
                out.append(tr["content"])
    return "".join(out)


def _end_index(doc: dict) -> int:
    content = doc.get("body", {}).get("content", [])
    return content[-1].get("endIndex", 1) if content else 1

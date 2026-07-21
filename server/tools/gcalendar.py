"""gcalendar.* — Google Calendar via MCP, sulla credenziale Workspace del vault.

Stessa credenziale di gdrive/gdocs (scope `calendar` già incluso). L'agente deve
avere un grant Workspace (`google_`/`gworkspace_`) — verificato dal vault.
Verbi: list_calendars, list_events, create_event, update_event, delete_event,
freebusy. Tutti gli orari sono ISO 8601 (RFC3339), es. 2026-07-22T15:00:00+02:00.
"""
from __future__ import annotations

from typing import Optional

from .google_svc import build_service


def _svc(account: Optional[str]):
    return build_service("calendar", "v3", account)


def list_calendars(account: Optional[str] = None) -> dict:
    svc, acct = _svc(account)
    items = svc.calendarList().list().execute().get("items", [])
    cals = [{"id": c.get("id"), "summary": c.get("summary"),
             "primary": c.get("primary", False), "accessRole": c.get("accessRole")}
            for c in items]
    return {"account": acct, "calendars": cals}


def list_events(calendar_id: str = "primary", time_min: Optional[str] = None,
                time_max: Optional[str] = None, query: Optional[str] = None,
                limit: int = 25, account: Optional[str] = None) -> dict:
    svc, acct = _svc(account)
    params = {"calendarId": calendar_id, "singleEvents": True, "orderBy": "startTime",
              "maxResults": max(1, min(int(limit or 25), 250))}
    if time_min:
        params["timeMin"] = time_min
    if time_max:
        params["timeMax"] = time_max
    if query:
        params["q"] = query
    res = svc.events().list(**params).execute()
    ev = [_clean_event(e) for e in res.get("items", [])]
    return {"account": acct, "calendar_id": calendar_id, "events": ev}


def create_event(summary: str, start: str, end: str, calendar_id: str = "primary",
                 description: Optional[str] = None, location: Optional[str] = None,
                 attendees: Optional[list] = None, all_day: bool = False,
                 account: Optional[str] = None) -> dict:
    svc, acct = _svc(account)
    body = {"summary": summary}
    if description:
        body["description"] = description
    if location:
        body["location"] = location
    if all_day:
        body["start"] = {"date": start}
        body["end"] = {"date": end}
    else:
        body["start"] = {"dateTime": start}
        body["end"] = {"dateTime": end}
    if attendees:
        body["attendees"] = [{"email": e} for e in attendees]
    e = svc.events().insert(calendarId=calendar_id, body=body).execute()
    return {"account": acct, "event": _clean_event(e)}


def update_event(event_id: str, calendar_id: str = "primary",
                 summary: Optional[str] = None, start: Optional[str] = None,
                 end: Optional[str] = None, description: Optional[str] = None,
                 location: Optional[str] = None, account: Optional[str] = None) -> dict:
    svc, acct = _svc(account)
    e = svc.events().get(calendarId=calendar_id, eventId=event_id).execute()
    if summary is not None:
        e["summary"] = summary
    if description is not None:
        e["description"] = description
    if location is not None:
        e["location"] = location
    if start is not None:
        key = "date" if "date" in e.get("start", {}) else "dateTime"
        e["start"] = {key: start}
    if end is not None:
        key = "date" if "date" in e.get("end", {}) else "dateTime"
        e["end"] = {key: end}
    upd = svc.events().update(calendarId=calendar_id, eventId=event_id, body=e).execute()
    return {"account": acct, "event": _clean_event(upd)}


def delete_event(event_id: str, calendar_id: str = "primary",
                 account: Optional[str] = None) -> dict:
    svc, acct = _svc(account)
    svc.events().delete(calendarId=calendar_id, eventId=event_id).execute()
    return {"account": acct, "deleted": event_id, "ok": True}


def freebusy(time_min: str, time_max: str, calendar_id: str = "primary",
             account: Optional[str] = None) -> dict:
    svc, acct = _svc(account)
    body = {"timeMin": time_min, "timeMax": time_max, "items": [{"id": calendar_id}]}
    res = svc.freebusy().query(body=body).execute()
    busy = res.get("calendars", {}).get(calendar_id, {}).get("busy", [])
    return {"account": acct, "calendar_id": calendar_id, "busy": busy}


def _clean_event(e: dict) -> dict:
    return {k: e.get(k) for k in ("id", "summary", "description", "location",
                                  "start", "end", "status", "htmlLink", "attendees")
            if e.get(k) is not None}

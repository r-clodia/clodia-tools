"""Trello tool (nostra implementazione) — wrapper MCP sui verbi principali del
client vendorizzato. Le credenziali arrivano dal vault (vault-first in
trello_client._creds), depositate da "Connetti Trello" nella sezione Tools.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

# Carica il client vendorizzato in modo robusto (indipendente da sys.path).
_p = Path(__file__).resolve().parents[2] / "vendor" / "trello_client.py"
_spec = importlib.util.spec_from_file_location("trello_client", _p)
_tc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_tc)  # type: ignore[union-attr]


def boards() -> list:
    return _tc._get("members/me/boards", fields="name,closed,url,shortLink")


def lists(board_id: str) -> list:
    return _tc._get(f"boards/{board_id}/lists", fields="name,closed", filter="open")


def cards(list_id: str) -> list:
    return _tc._get(f"lists/{list_id}/cards",
                    fields="name,desc,due,idList,url,shortLink,dateLastActivity")


def create_card(list_id: str, name: str, desc: str | None = None) -> dict:
    params: dict = {"idList": list_id, "name": name}
    if desc is not None:
        params["desc"] = desc
    return _tc._post("cards", **params)


def move_card(card_id: str, to_list: str) -> dict:
    card = _tc._get(f"cards/{card_id}", fields="idBoard,idList,name")
    target = _tc._resolve_list_id(card["idBoard"], to_list)
    if card["idList"] == target:
        return {"moved": False, "note": "già nella lista target", "card": card["name"]}
    _tc._put(f"cards/{card_id}", idList=target)
    return {"moved": True, "card": card["name"], "to": to_list}


def comment(card_id: str, text: str) -> dict:
    r = _tc._post(f"cards/{card_id}/actions/comments", text=text)
    return {"id": r.get("id"), "text": (r.get("data") or {}).get("text")}

#!/usr/bin/env python3
"""Trello CLI for the Clodia agent family.

Credentials are read from `secrets/trello-apikey` and `secrets/trello-token`,
never accepted as CLI arguments to avoid leaking to the inference engine.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

import httpx

__version__ = "0.5.0"

TOOL_ROOT = Path(__file__).resolve().parent
# Risoluzione portabile dei secret (container-aware): CLODIA_SECRETS_DIR ha la
# precedenza, poi CLODIA_WORKSPACE_ROOT/secrets, infine il default Mac (dev).
_WS = os.environ.get("CLODIA_WORKSPACE_ROOT")
SECRETS_DIR = Path(
    os.environ.get("CLODIA_SECRETS_DIR")
    or (f"{_WS}/secrets" if _WS else "/Users/erreclaudea/erre-claudia/secrets")
)
BASE_URL = "https://api.trello.com/1"

POLICY_PATH = TOOL_ROOT / "POLICY.md"


def _creds() -> tuple[str, str]:
    # Vault-first: la credenziale 'trello' depositata da "Connetti Trello" ha la
    # precedenza; fallback ai file legacy secrets/trello-apikey|token.
    try:
        from server import vault  # import lazy: vendor resta autonomo
        b = vault.read_internal("trello")
        if b.get("api_key") and b.get("token"):
            return b["api_key"], b["token"]
    except Exception:
        pass
    key = (SECRETS_DIR / "trello-apikey").read_text().strip()
    token = (SECRETS_DIR / "trello-token").read_text().strip()
    return key, token


def _auth_params() -> dict:
    key, token = _creds()
    return {"key": key, "token": token}


def _get(path: str, **params) -> dict | list:
    r = httpx.get(f"{BASE_URL}/{path.lstrip('/')}", params={**_auth_params(), **params}, timeout=15.0)
    r.raise_for_status()
    return r.json()


def _put(path: str, **params) -> dict:
    r = httpx.put(f"{BASE_URL}/{path.lstrip('/')}", params={**_auth_params(), **params}, timeout=15.0)
    r.raise_for_status()
    return r.json()


def _post(path: str, **params) -> dict:
    r = httpx.post(f"{BASE_URL}/{path.lstrip('/')}", params={**_auth_params(), **params}, timeout=15.0)
    r.raise_for_status()
    return r.json()


def _delete(path: str, **params) -> dict:
    r = httpx.delete(f"{BASE_URL}/{path.lstrip('/')}", params={**_auth_params(), **params}, timeout=15.0)
    r.raise_for_status()
    return r.json() if r.text else {}


_HEX24 = re.compile(r"^[0-9a-f]{24}$")


def _resolve_member_to_id(member: str) -> str:
    """Resolve a member alias / username / id to a Trello member id.

    Accepts (in order): 24-hex member id, Clodia-family alias (e.g. "ada"
    → username "demoada"), arbitrary Trello username.
    """
    m = member.strip()
    if not m:
        raise SystemExit("empty member identifier")
    if _HEX24.match(m):
        return m
    candidates = []
    if not m.startswith("demo"):
        candidates.append(f"demo{m}")
    candidates.append(m)
    for username in candidates:
        try:
            return _get(f"members/{username}", fields="id")["id"]
        except httpx.HTTPStatusError:
            continue
    raise SystemExit(f"cannot resolve trello member '{member}' (tried: {', '.join(candidates)})")


def _print_json(data) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def cmd_boards(args) -> int:
    data = _get("members/me/boards", fields="name,closed,url,shortLink")
    _print_json(data)
    return 0


def cmd_board(args) -> int:
    data = _get(f"boards/{args.board_id}", fields="name,closed,url,shortLink", lists="open")
    _print_json(data)
    return 0


def cmd_lists(args) -> int:
    data = _get(f"boards/{args.board_id}/lists", fields="name,closed", filter="open")
    _print_json(data)
    return 0


def cmd_cards(args) -> int:
    data = _get(
        f"lists/{args.list_id}/cards",
        fields="name,desc,labels,due,idMembers,idList,url,shortLink,dateLastActivity",
    )
    _print_json(data)
    return 0


def cmd_card(args) -> int:
    data = _get(
        f"cards/{args.card_id}",
        fields="name,desc,labels,due,idMembers,idList,idBoard,url,shortLink,dateLastActivity",
    )
    _print_json(data)
    return 0


def _resolve_list_id(board_id: str, name_or_id: str) -> str:
    lists = _get(f"boards/{board_id}/lists", fields="name", filter="open")
    for l in lists:
        if l["id"] == name_or_id or l["name"].lower() == name_or_id.lower():
            return l["id"]
    raise SystemExit(f"list '{name_or_id}' not found on board {board_id}")


def cmd_move_card(args) -> int:
    card = _get(f"cards/{args.card_id}", fields="idBoard,idList,name")
    target_list_id = _resolve_list_id(card["idBoard"], args.to)
    if card["idList"] == target_list_id:
        print(f"card '{card['name']}' already in target list, no-op")
        return 0
    result = _put(f"cards/{args.card_id}", idList=target_list_id)
    print(f"moved '{card['name']}' to list {args.to}")
    if args.verbose:
        _print_json(result)
    return 0


def cmd_comment(args) -> int:
    result = _post(f"cards/{args.card_id}/actions/comments", text=args.text)
    print(f"comment added on card {args.card_id}")
    if args.verbose:
        _print_json({"id": result.get("id"), "text": result.get("data", {}).get("text")})
    return 0


def cmd_archive_card(args) -> int:
    _put(f"cards/{args.card_id}", closed="true")
    print(f"archived card {args.card_id}")
    return 0


def cmd_unarchive_card(args) -> int:
    _put(f"cards/{args.card_id}", closed="false")
    print(f"unarchived card {args.card_id}")
    return 0


def cmd_list_comments(args) -> int:
    raw = _get(
        f"cards/{args.card_id}/actions",
        filter="commentCard",
        limit=args.limit,
    )
    comments = [
        {
            "id": a.get("id"),
            "date": a.get("date"),
            "member_id": a.get("idMemberCreator"),
            "member_username": (a.get("memberCreator") or {}).get("username"),
            "member_fullname": (a.get("memberCreator") or {}).get("fullName"),
            "text": (a.get("data") or {}).get("text"),
        }
        for a in raw
    ]
    _print_json(comments)
    return 0


def cmd_update_card(args) -> int:
    params = {}
    if args.name is not None:
        params["name"] = args.name
    if args.desc is not None:
        params["desc"] = args.desc
    if not params:
        print("nothing to update (use --name and/or --desc)", file=sys.stderr)
        return 1
    result = _put(f"cards/{args.card_id}", **params)
    print(f"updated card {args.card_id}: {', '.join(params.keys())}")
    if args.verbose:
        _print_json(result)
    return 0


def cmd_member(args) -> int:
    data = _get(f"members/{args.member_id}", fields="username,fullName,email")
    _print_json(data)
    return 0


def cmd_assign_card(args) -> int:
    member_id = _resolve_member_to_id(args.member)
    _post(f"cards/{args.card_id}/idMembers", value=member_id)
    print(f"assigned {args.member} ({member_id}) to card {args.card_id}")
    return 0


def cmd_unassign_card(args) -> int:
    member_id = _resolve_member_to_id(args.member)
    _delete(f"cards/{args.card_id}/idMembers/{member_id}")
    print(f"unassigned {args.member} ({member_id}) from card {args.card_id}")
    return 0


def cmd_create_card(args) -> int:
    params: dict = {"idList": args.list_id, "name": args.name}
    if args.desc is not None:
        params["desc"] = args.desc
    if args.pos is not None:
        params["pos"] = args.pos
    if args.due is not None:
        params["due"] = args.due
    if args.members:
        params["idMembers"] = ",".join(args.members)
    if args.labels:
        params["idLabels"] = ",".join(args.labels)
    result = _post("cards", **params)
    print(f"created card {result.get('id')}: {result.get('name')}")
    if args.verbose:
        _print_json(result)
    else:
        _print_json({"id": result.get("id"), "url": result.get("url"), "shortLink": result.get("shortLink")})
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="trello",
        description="Trello CLI for the Clodia agent family — read/update cards via API.",
    )
    p.add_argument("--version", action="version", version=f"trello {__version__}")
    p.add_argument("--policy", action="store_true", help="Print operational policy and exit")
    p.add_argument("-v", "--verbose", action="store_true")

    sub = p.add_subparsers(dest="cmd")

    p_boards = sub.add_parser("boards", help="List boards accessible to the token")
    p_boards.set_defaults(func=cmd_boards)

    p_board = sub.add_parser("board", help="Show details of a single board (with lists)")
    p_board.add_argument("board_id")
    p_board.set_defaults(func=cmd_board)

    p_lists = sub.add_parser("lists", help="List the open lanes of a board")
    p_lists.add_argument("board_id")
    p_lists.set_defaults(func=cmd_lists)

    p_cards = sub.add_parser("cards", help="List cards of a list (lane)")
    p_cards.add_argument("list_id")
    p_cards.set_defaults(func=cmd_cards)

    p_card = sub.add_parser("card", help="Show full details of a card")
    p_card.add_argument("card_id")
    p_card.set_defaults(func=cmd_card)

    p_move = sub.add_parser("move-card", help="Move a card to another lane (by name or id)")
    p_move.add_argument("card_id")
    p_move.add_argument("--to", required=True, help="target list name or id")
    p_move.set_defaults(func=cmd_move_card)

    p_comment = sub.add_parser("comment", help="Add a comment to a card")
    p_comment.add_argument("card_id")
    p_comment.add_argument("text")
    p_comment.set_defaults(func=cmd_comment)

    p_lc = sub.add_parser("list-comments", help="List comments of a card (most recent first)")
    p_lc.add_argument("card_id")
    p_lc.add_argument("--limit", type=int, default=50, help="max number of comments (default 50, Trello API max 1000)")
    p_lc.set_defaults(func=cmd_list_comments)

    p_arch = sub.add_parser("archive-card", help="Archive a card (closed=true, recoverable, NOT deletion)")
    p_arch.add_argument("card_id")
    p_arch.set_defaults(func=cmd_archive_card)

    p_unarch = sub.add_parser("unarchive-card", help="Unarchive a card (closed=false)")
    p_unarch.add_argument("card_id")
    p_unarch.set_defaults(func=cmd_unarchive_card)

    p_update = sub.add_parser("update-card", help="Update name and/or description of a card")
    p_update.add_argument("card_id")
    p_update.add_argument("--name")
    p_update.add_argument("--desc")
    p_update.set_defaults(func=cmd_update_card)

    p_member = sub.add_parser("member", help="Resolve a member id to username/fullName")
    p_member.add_argument("member_id")
    p_member.set_defaults(func=cmd_member)

    p_assign = sub.add_parser("assign-card", help="Assign a member to a card")
    p_assign.add_argument("card_id")
    p_assign.add_argument("member", help="member id (24-hex), family alias (ada/clodia/...), or full username")
    p_assign.set_defaults(func=cmd_assign_card)

    p_unassign = sub.add_parser("unassign-card", help="Remove a member from a card")
    p_unassign.add_argument("card_id")
    p_unassign.add_argument("member", help="member id (24-hex), family alias (ada/clodia/...), or full username")
    p_unassign.set_defaults(func=cmd_unassign_card)

    p_create = sub.add_parser("create-card", help="Create a new card on a list (lane)")
    p_create.add_argument("list_id", help="target list (lane) id")
    p_create.add_argument("--name", required=True, help="card title")
    p_create.add_argument("--desc", help="card description (markdown supported)")
    p_create.add_argument("--pos", help='card position: "top", "bottom", or a number')
    p_create.add_argument("--due", help="due date ISO 8601 (e.g. 2026-05-20T10:00:00.000Z)")
    p_create.add_argument("--member", dest="members", action="append", default=[], help="add member id (repeatable)")
    p_create.add_argument("--label", dest="labels", action="append", default=[], help="add label id (repeatable)")
    p_create.set_defaults(func=cmd_create_card)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.policy:
        print(POLICY_PATH.read_text() if POLICY_PATH.is_file() else "policy missing")
        return 0
    if not args.cmd:
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except httpx.HTTPStatusError as e:
        print(f"HTTP {e.response.status_code}: {e.response.text[:400]}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

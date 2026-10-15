"""Joining a Telegram group to a topic by link (clodia-platform#549).

A bot cannot join a group from an invite link: the Bot API has no such method,
only a member can add it. So the link goes the other way. An agent of the topic
asks for a `startgroup` deep link carrying a one-time token bound to the topic;
a human opens it and picks the group; Telegram adds the bot and delivers
`/start <token>` in that group. The gateway consumes the token and records a
**proposal** for the topic: "the bot is in chat X". Nothing is authorised yet.

The owner decides. The proposal shows up in the topic's Telegram action
(`telegram-link`, owner-only) as a ready value: approving it is the same
`connect` that writes ingress + egress `tg:<chat_id>` and the binding. So no one,
human or agent, ever types a chat id — the error behind "chat not found" with
`-4433615610` for `-1004433615610`.

State lives next to the Telegram state file: tokens (single use, short TTL) and
proposals per topic (longer TTL, dropped on connect).
"""
from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
from pathlib import Path

#: How long a link stays usable. Long enough to open Telegram and pick a group.
TOKEN_TTL = 3600
#: How long a proposal waits for the owner before it is forgotten.
PROPOSAL_TTL = 7 * 24 * 3600

_LOCK = threading.RLock()

# `startgroup` payloads: up to 64 chars of [A-Za-z0-9_-] (Telegram's rule).
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{16,64}")
# `/start <token>` or `/start@bot <token>` — what Telegram delivers on join.
_START_RE = re.compile(r"^/start(?:@([A-Za-z0-9_]+))?\s+([A-Za-z0-9_-]{16,64})\s*$")


def _path() -> Path:
    env = os.environ.get("CLODIA_TELEGRAM_JOIN")
    if env:
        return Path(env)
    from .telegram import _state_path
    return _state_path().parent / "telegram-join.json"


def _load() -> dict:
    p = _path()
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        d = {}
    d.setdefault("tokens", {})
    d.setdefault("proposals", {})
    return d


def _save(d: dict) -> None:
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, indent=2), encoding="utf-8")
    os.replace(tmp, p)


def _prune(d: dict, now: float) -> None:
    d["tokens"] = {k: v for k, v in d["tokens"].items()
                   if now - float(v.get("at", 0)) <= TOKEN_TTL}
    for scope in list(d["proposals"]):
        keep = [p for p in d["proposals"][scope]
                if now - float(p.get("at", 0)) <= PROPOSAL_TTL]
        if keep:
            d["proposals"][scope] = keep
        else:
            del d["proposals"][scope]


def _scope(tier: str, topic: str) -> str:
    from .. import egress as eg
    return eg._norm_scope_key(f"{tier}/{topic}")


def mint(tier: str, topic: str, *, by: str) -> dict:
    """A fresh one-time token bound to this topic and to who asked."""
    tok = secrets.token_urlsafe(24)[:32]
    now = time.time()
    with _LOCK:
        d = _load()
        _prune(d, now)
        d["tokens"][tok] = {"tier": tier, "topic": topic, "by": by, "at": now}
        _save(d)
    return {"token": tok, "expires_in": TOKEN_TTL}


def parse_start(text: str, bot_username: str | None) -> str | None:
    """The token of a `/start <token>` addressed to this bot, else None.

    A `/start@other_bot …` in a group is another bot's business and is left
    alone; a bare `/start` carries nothing to claim."""
    m = _START_RE.match(str(text or "").strip())
    if not m:
        return None
    target, tok = m.group(1), m.group(2)
    if target and bot_username and target.lower() != str(bot_username).lower():
        return None
    return tok


def claim(token: str, *, chat_id: str, chat_title: str, chat_type: str,
          added_by: str = "") -> dict | None:
    """Consume the token for this chat. Returns the proposal, or None.

    Unknown, expired and already-used tokens all answer None: the message is
    then an ordinary `/start` and nothing is recorded. Only groups qualify — a
    private chat cannot be "the group of a topic"."""
    if chat_type not in ("group", "supergroup") or not _TOKEN_RE.fullmatch(token or ""):
        return None
    now = time.time()
    with _LOCK:
        d = _load()
        _prune(d, now)
        t = d["tokens"].pop(token, None)
        if t is None:
            _save(d)
            return None
        scope = _scope(t["tier"], t["topic"])
        cid = str(chat_id)
        prop = {"chat_id": cid, "title": chat_title or cid, "at": now,
                "requested_by": t.get("by", ""), "added_by": added_by,
                "tier": t["tier"], "topic": t["topic"]}
        lst = [p for p in d["proposals"].get(scope, []) if p.get("chat_id") != cid]
        lst.append(prop)
        d["proposals"][scope] = lst
        _save(d)
    return prop


def proposals(tier: str, topic: str) -> list[dict]:
    """The chats the bot joined for this topic, waiting for the owner."""
    with _LOCK:
        d = _load()
        _prune(d, time.time())
        return [dict(p) for p in d["proposals"].get(_scope(tier, topic), [])]


def drop(tier: str, topic: str, chat_id: str) -> bool:
    """Forget a proposal (it was connected, or turned down)."""
    with _LOCK:
        d = _load()
        scope = _scope(tier, topic)
        lst = d["proposals"].get(scope, [])
        keep = [p for p in lst if p.get("chat_id") != str(chat_id)]
        if len(keep) == len(lst):
            return False
        if keep:
            d["proposals"][scope] = keep
        else:
            d["proposals"].pop(scope, None)
        _save(d)
        return True


def announce(prop: dict) -> None:
    """Tell the room that a group waits for its owner. Best effort."""
    try:
        from ..topics_api import _service
        _service().post_message(
            prop["tier"], prop["topic"], author="gate", kind="ai",
            text=(f"📨 The Telegram bot was added to the group «{prop['title']}» "
                  f"(`{prop['chat_id']}`) with this topic's link. Nothing is "
                  "connected yet: the topic owner decides. To approve, open the "
                  "Telegram button of this topic and pick the group — that "
                  "enables ingress and egress for it."))
    except Exception:  # noqa: BLE001 — the proposal stands even unannounced
        import logging
        logging.getLogger("clodia-tools.telegram").warning(
            "telegram join: proposal for %s/%s not announced",
            prop.get("tier"), prop.get("topic"))


def intercept(msg: dict, bot_username: str | None) -> bool:
    """Handle a `/start <token>` join message. True = consumed, do not relay.

    Called by both Telegram consumers (`poll_updates`, `_refresh`) on every
    message. A message that is not a join command is left untouched."""
    tok = parse_start(msg.get("text") or "", bot_username)
    if not tok:
        return False
    chat = msg.get("chat") or {}
    frm = msg.get("from") or {}
    from .telegram import _chat_title
    prop = claim(tok, chat_id=str(chat.get("id")), chat_title=_chat_title(chat),
                 chat_type=str(chat.get("type") or ""),
                 added_by=frm.get("username") or str(frm.get("id") or ""))
    if prop is None:
        return False
    announce(prop)
    return True

"""Mailboxes connected to a room (clodia-platform#734).

A room connects one or more of the instance's mailboxes the way it connects
an MCP: `meta.tools.mcp["mailbox:<account>"]`, through the room's 🔌 and the
usual `enable_mcp`. A connected mailbox is one the courier reads for the
room's declared senders and one the room may send with. The room's own
address on the colony mailbox (`local+CODE@`, #583) is not a connection: it
is always on and is not listed here.

Until #734 the same decision was an address in the room's lists
(`inbox:<addr>` / `outbox:<addr>`). `migrate()` turns those entries into
connections once, then removes them; the lists keep `mailfrom:` (senders) and
`mailto:` (recipients), which are not mailboxes.
"""
from __future__ import annotations

import logging

LOG = logging.getLogger("clodia-tools.room-mailboxes")

#: The prefix of a mailbox's key among the room's MCPs.
PREFIX = "mailbox:"

#: Config key recording that the list entries were migrated (#734).
MIGRATED_KEY = "room_mailboxes_migrated"


def key(account: str) -> str:
    return f"{PREFIX}{account}"


def connected_accounts(meta: dict) -> list[str]:
    """The accounts of the mailboxes the room connects, as stored (an account
    switched off or removed since is still listed here; `room_mailboxes`
    drops it)."""
    from .room_tools import _mcp_entries
    return sorted(m[len(PREFIX):] for m in _mcp_entries(meta) if m.startswith(PREFIX)
                  and len(m) > len(PREFIX))


def system_boxes() -> dict[str, dict]:
    """`{account: {email, send_only}}` of the instance's usable mailboxes:
    operational and switched on (#733). Never raises."""
    try:
        from .tools import mail_switch
        rows = mail_switch.system_mailboxes()
    except Exception:  # noqa: BLE001
        return {}
    return {str(r.get("account") or ""): {"email": str(r.get("email") or "").strip().lower(),
                                         "send_only": bool(r.get("send_only"))}
            for r in rows if r.get("account")}


def room_mailboxes(meta: dict, boxes: dict | None = None) -> dict[str, dict]:
    """The room's connected mailboxes that exist and are switched on:
    `{account: {email, send_only}}`."""
    boxes = system_boxes() if boxes is None else boxes
    return {a: boxes[a] for a in connected_accounts(meta) if a in boxes}


def _read_meta(tier: str, name: str) -> dict:
    from . import main
    return main._topics()._read_meta(tier, name)[0]


def scope_allows(direction: str, address: str, scope: str | None) -> bool:
    """Does the room `scope` connect the mailbox at `address`? A send-only
    mailbox is never read. False outside a room or for a room that cannot
    be read."""
    addr = (address or "").strip().lower()
    tier, _, name = str(scope or "").partition("/")
    if not (addr and tier and name):
        return False
    try:
        meta = _read_meta(tier, name)
    except Exception:  # noqa: BLE001
        return False
    for box in room_mailboxes(meta).values():
        if box["email"] == addr and not (direction == "inbox" and box["send_only"]):
            return True
    return False


def outbox_account(tier: str, name: str, meta: dict | None = None) -> list[str]:
    """The accounts the room may send with: its connected mailboxes."""
    meta = _read_meta(tier, name) if meta is None else meta
    return sorted(room_mailboxes(meta))


def reading_rooms() -> list[tuple[str, str, str, str]]:
    """`(tier, name, account, address)` for every room × connected mailbox
    the courier reads (receiving mailboxes only). One pass over the topics'
    metas — the same scan the message-box codes make every cycle."""
    from . import main
    svc = main._topics()
    boxes = system_boxes()
    out = []
    for tier, name in svc._meta_refs():
        try:
            meta, _ = svc._read_meta(tier, name)
        except Exception:  # noqa: BLE001
            continue
        if meta.get("status") == "archived":
            continue    # an archived room is no room the courier serves
        for acct, box in room_mailboxes(meta, boxes).items():
            if not box["send_only"] and box["email"]:
                out.append((tier, name, acct, box["email"]))
    return out


def forget(account: str) -> list[str]:
    """Disconnect the mailbox `account` from every room (it is being removed
    from the instance). Returns the rooms that changed."""
    from . import main, room_tools
    svc = main._topics()
    mid = key(account)
    changed = []
    for tier, name in svc._meta_refs():
        try:
            meta, _ = svc._read_meta(tier, name)
        except Exception:  # noqa: BLE001
            continue
        if mid in room_tools._mcp_entries(meta):
            try:
                room_tools.enable_mcp(tier, name, mid, False)
                changed.append(f"{tier}/{name}")
            except Exception as e:  # noqa: BLE001
                LOG.warning("room mailboxes: %s not disconnected from %s/%s (%s)",
                            account, tier, name, type(e).__name__)
    return changed


# ── the migration of the list entries (once) ──────────────────────────────

def plan(cfg: dict | None = None) -> dict:
    """What `migrate()` would do, computed without writing: per room, the
    accounts its `inbox:`/`outbox:` entries name, the entries of rooms that
    no longer exist, and the addresses that are no mailbox of the instance
    (left alone, reported)."""
    from . import egress, whitelist
    cfg = whitelist.CONFIG if cfg is None else cfg
    boxes = system_boxes()
    by_addr = {b["email"]: a for a, b in boxes.items() if b["email"]}
    scopes = set()
    for k in egress._SCOPE_KEYS.values():
        scopes |= set(cfg.get(k) or {})
    rooms: dict[str, dict] = {}
    for scope in sorted(scopes):
        norm = egress._norm_scope_key(str(scope))
        tier, _, name = norm.partition("/")
        if not (tier and name):
            continue
        entries = [u for d in ("ingress", "egress") for u in egress.scope_uris(d, norm, cfg)
                   if str(u).startswith(("inbox:", "outbox:"))]
        if not entries:
            continue
        accounts, unknown = set(), []
        for u in entries:
            addr = str(u).partition(":")[2].strip().lower()
            if addr in by_addr:
                accounts.add(by_addr[addr])
            else:
                unknown.append(u)
        rooms[norm] = {"entries": entries, "accounts": sorted(accounts), "unknown": unknown,
                       "exists": _exists(tier, name)}
    return {"rooms": rooms}


def _exists(tier: str, name: str) -> bool:
    """A room the courier serves: one the topics service opens. An ARCHIVED
    topic is not one (its meta is still readable): on terra the migration
    connected three mailboxes to an archived topic that the approved plan
    had listed as gone (25 Nov 2026)."""
    from .mail_courier_api import _topic_exists
    return _topic_exists(tier, name)


def migrate(*, dry_run: bool = False) -> dict:
    """Turn every room's `inbox:`/`outbox:` entries into connected mailboxes
    and remove the entries (clodia-platform#734). Once: the config records
    it, and a second call does nothing. A room that no longer exists only
    loses its entries. An address that is no mailbox of the instance is left
    in the list and reported — it is not ours to guess what it was."""
    from . import egress, room_tools, whitelist
    if whitelist.CONFIG.get(MIGRATED_KEY) and not dry_run:
        return {"done": False, "reason": "already migrated"}
    p = plan()
    if dry_run:
        return {"done": False, "plan": p}
    report = {"connected": {}, "dropped_rooms": [], "kept_unknown": {}, "failed": {}}
    for scope, r in p["rooms"].items():
        tier, _, name = scope.partition("/")
        if r["exists"]:
            try:
                for acct in r["accounts"]:
                    room_tools.enable_mcp(tier, name, key(acct), True)
            except Exception as e:  # noqa: BLE001 — this room keeps its entries
                report["failed"][scope] = type(e).__name__
                continue
            if r["accounts"]:
                report["connected"][scope] = r["accounts"]
        else:
            report["dropped_rooms"].append(scope)
        known = [u for u in r["entries"] if u not in r["unknown"]]
        for u in (r["entries"] if not r["exists"] else known):
            d = "ingress" if str(u).startswith("inbox:") else "egress"
            egress.scope_revoke(d, scope, u)
        if r["unknown"] and r["exists"]:
            report["kept_unknown"][scope] = r["unknown"]
    if not report["failed"]:
        from datetime import datetime, timezone
        whitelist.CONFIG[MIGRATED_KEY] = datetime.now(timezone.utc).isoformat()
    whitelist.save_config()
    LOG.info("room mailboxes: migration %s", report)
    return {"done": True, **report}

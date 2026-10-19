"""Internal routes of the deterministic mail courier (clodia-platform#531).

The agent-server's courier — code, never a model — moves inbound mail into the
topics whose room has a mailbox in its `inbox:` list: it posts the ENVELOPE
(sender, subject, date, attachment names) and stores the attachments in the
topic's files. It never receives a message body.

Same door as `/internal/telegram/*`: `internal_auth` restricted to a privileged
principal (the agent-server), not a per-agent MCP grant. Each call runs inside
the ROOM's claims, so comms-pack's component applies that room's rules exactly
as for an agent working there: the mailbox must be in the room's `inbox:`
list, and on a strict room (#503) only declared senders pass.

- `GET  /internal/mail/courier/rooms`       → `[{tier, name, account, address, strict}]`
- `POST /internal/mail/courier/envelopes`   {tier, name, account, folder?, limit?, skip?}
- `POST /internal/mail/courier/attachment`  {tier, name, account, email_id, filename, folder?}
- `POST /internal/mail/courier/eml`         {tier, name, account, email_id, folder?}

Only mail from a sender the room itself declares (`mailfrom:` among its OWN
ingress entries) is delivered (#576): a room with no declared sender gets
nothing, and `rooms()` says how many senders each room declares.
"""
from __future__ import annotations

import asyncio
import logging

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import internal_auth

LOG = logging.getLogger("clodia-tools.mail_courier")

#: How the courier's calls are told apart in the audit trail: the spawn id
#: (`execution_id`) of its calls. The agent is the authorized caller itself (a
#: privileged principal declared in the gateway's config), never a new one.
COURIER = "courier"


def _authorize(request: Request):
    payload, err = internal_auth.authorize(request, log=LOG)
    return payload, err


def _room_claims(tier: str, name: str, payload: dict) -> dict:
    """The claims of a courier call inside `tier/name`: the room comes from the
    route's arguments, checked to be an existing topic; the principal is the
    authorized caller's."""
    agent = str((payload or {}).get("agent") or "")
    return {"agent": agent, "chat": f"chan:{tier}:{name}:{agent}",
            "principal": (payload or {}).get("principal") or agent,
            "execution_id": f"{COURIER}-{tier}-{name}"}


def _topic_exists(tier: str, name: str) -> bool:
    try:
        from . import main
        main._topics().open(tier, name)
        return True
    except Exception:  # noqa: BLE001 — unknown or unreadable: not a room
        return False


def rooms() -> list[dict]:
    """The rooms with a mailbox in their OWN `inbox:` list, one row per
    mailbox the instance has. Global entries are not a room: the courier
    posts only where a room declared the mailbox."""
    from . import egress
    from . import whitelist
    from .tools import mail_switch
    boxes = {}
    for row in mail_switch.system_mailboxes():
        addr = str(row.get("email") or "").strip().lower()
        if addr and not row.get("send_only"):
            boxes[addr] = str(row.get("account") or "")
    out = []
    per_scope = (whitelist.CONFIG.get("scope_source_allow") or {})
    for scope in sorted(per_scope):
        tier, _, name = egress._norm_scope_key(str(scope)).partition("/")
        if not (tier and name) or not _topic_exists(tier, name):
            continue
        for uri in egress.scope_uris("ingress", f"{tier}/{name}"):
            if not str(uri).startswith("inbox:"):
                continue
            addr = str(uri)[len("inbox:"):].strip().lower()
            row = {"tier": tier, "name": name, "account": boxes.get(addr, ""),
                   "address": addr,
                   "strict": bool(egress.ingress_strict(f"{tier}/{name}")),
                   **_senders(f"{tier}/{name}")}
            if addr in boxes and row not in out:
                out.append(row)
    return out


def _senders(scope: str) -> dict:
    """How many `mailfrom:` entries the room declares, and a signature of the
    set (#576): when it changes the courier records what is already in the
    mailbox instead of delivering it — a sender added today brings its mail
    from today, like a mailbox linked today."""
    import hashlib
    from . import egress
    regole = sorted(str(r).strip().lower() for r in egress.room_sender_rules(scope))
    return {"senders": len(regole),
            "senders_sig": hashlib.sha256("\n".join(regole).encode()).hexdigest()[:16]}


def _in_room(tier: str, name: str, payload: dict, service: str, args: dict):
    from .claims import ClaimsContext
    from .tools import mail_switch
    with ClaimsContext(_room_claims(tier, name, payload), ""):
        return mail_switch.call(service, dict(args))


async def rooms_route(request: Request):
    payload, err = _authorize(request)
    if err:
        return err
    try:
        return JSONResponse({"rooms": await asyncio.to_thread(rooms)})
    except Exception as e:  # noqa: BLE001
        LOG.warning("courier rooms: %s", type(e).__name__)
        return JSONResponse({"error": str(e)[:200]}, status_code=502)


async def _room_call(request: Request, service: str, keys: tuple[str, ...]):
    payload, err = _authorize(request)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "bad_json"}, status_code=400)
    if not isinstance(body, dict):
        return JSONResponse({"error": "bad_json"}, status_code=400)
    tier, name = str(body.get("tier") or ""), str(body.get("name") or "")
    if not (tier and name and await asyncio.to_thread(_topic_exists, tier, name)):
        return JSONResponse({"error": "tier/name of an existing topic required"},
                            status_code=400)
    # Only a pair `rooms()` offers: the room's OWN `inbox:` list names the
    # mailbox. A global entry would let the caller pull a mailbox into any
    # room (review of #406).
    account = str(body.get("account") or "")
    offerte = await asyncio.to_thread(rooms)
    if not any(r["tier"] == tier and r["name"] == name and r["account"] == account
               for r in offerte):
        return JSONResponse({"error": f"mailbox '{account}' is not in the inbox: list "
                                      f"of {tier}/{name}"}, status_code=403)
    args = {k: body[k] for k in keys if k in body}
    if "limit" in args:
        try:
            args["limit"] = max(1, min(int(args["limit"]), 50))
        except (TypeError, ValueError):
            args.pop("limit")
    try:
        return JSONResponse(await asyncio.to_thread(_in_room, tier, name, payload,
                                                    service, args))
    except PermissionError as e:
        return JSONResponse({"error": str(e)[:300]}, status_code=403)
    except Exception as e:  # noqa: BLE001
        LOG.warning("courier %s: %s", service, type(e).__name__)
        return JSONResponse({"error": str(e)[:200]}, status_code=502)


async def envelopes_route(request: Request):
    return await _room_call(request, "courier_envelopes",
                            ("account", "folder", "limit", "skip", "keys_only"))


async def attachment_route(request: Request):
    return await _room_call(request, "courier_attachment",
                            ("account", "email_id", "filename", "folder"))


async def eml_route(request: Request):
    return await _room_call(request, "courier_eml", ("account", "email_id", "folder"))


routes = [
    Route("/internal/mail/courier/eml", eml_route, methods=["POST"]),
    Route("/internal/mail/courier/rooms", rooms_route, methods=["GET"]),
    Route("/internal/mail/courier/envelopes", envelopes_route, methods=["POST"]),
    Route("/internal/mail/courier/attachment", attachment_route, methods=["POST"]),
]

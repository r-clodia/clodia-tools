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
- `POST /internal/mail/courier/box`         {}  → `{account, tags: {CODE: [keys]}}`

The message box (#583/#585): one search per cycle on the colony mailbox lists
which codes have recent mail (`box`), so the courier calls `envelopes` only for
those rooms, and only for the keys the index named (`only`).

Only mail from a sender the room itself declares (`mailfrom:` among its OWN
ingress entries) is delivered (#576): a room with no declared sender gets
nothing, and `rooms()` says how many senders each room declares.
"""
from __future__ import annotations

import asyncio
import contextvars
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

#: The message-box tag of the courier call in progress (#583): set ONLY by
#: `_in_room` for a row `rooms()` offered with a tag, never from a token or an
#: argument. While it is set, and only then, the colony mailbox may be read for
#: that room — and comms-pack keeps only the mail addressed to `box+TAG@…`.
COURIER_TAG: contextvars.ContextVar[str] = contextvars.ContextVar(
    "courier_tag", default="")

#: The courier tag of the message-box INDEX call (#585): the colony mailbox,
#: read once per cycle for every code at once. Never a topic's code (codes are
#: drawn from an alphabet without `*`), so `_room_call` never accepts it.
BOX_INDEX_TAG = "*"

#: Config key naming the colony's mailbox (#583): an ACCOUNT of the instance's
#: mailboxes. An instance setting, never hard-coded — `devnullboxx` is the
#: owner's temporary choice, not a platform mailbox.
COLONY_KEY = "colony_mailbox"


def colony_mailbox() -> tuple[str, str]:
    """`(account, address)` of the colony mailbox, or `("", "")` when unset or
    not one of the instance's receiving mailboxes (feature off)."""
    from . import whitelist
    from .tools import mail_switch
    acct = str((whitelist.CONFIG.get(COLONY_KEY) or "")).strip()
    if not acct:
        return "", ""
    try:
        rows = mail_switch.system_mailboxes()
    except Exception:  # noqa: BLE001
        return "", ""
    for row in rows or []:
        if str(row.get("account") or "") == acct and not row.get("send_only"):
            return acct, str(row.get("email") or "").strip().lower()
    return "", ""


def message_box_address(code: str) -> str:
    """`local+CODE@domain` on the colony mailbox, "" when the feature is off."""
    _acct, addr = colony_mailbox()
    local, at, domain = addr.partition("@")
    if not (code and at):
        return ""
    return f"{local}+{code}@{domain}"


def _authorize(request: Request):
    """The courier is the AGENT-SERVER, never an agent: the routes require the
    service role (`role: agent-server`, clodia-platform#539 §1), which only
    the agent-server can mint behind the bootstrap secret. A spawn of
    `clodia` carries a token whose `agent` is `clodia` too — without the role
    it could pull any topic's whole message through `/eml` (review of #416)."""
    payload, err = internal_auth.authorize(request, log=LOG)
    if err:
        return payload, err
    from .pki_mint import ROLE_AGENT_SERVER
    if (payload or {}).get("role") != ROLE_AGENT_SERVER:
        LOG.warning("courier: richiesta senza il ruolo di servizio rifiutata (agent=%s)",
                    (payload or {}).get("agent"))
        return None, JSONResponse({"error": "forbidden"}, status_code=403)
    return payload, None


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
    out.extend(_colony_rooms(out))
    return out


def _colony_rooms(existing: list[dict]) -> list[dict]:
    """One row per topic reachable through the colony mailbox (#583): it has a
    message-box code and at least one sender, its own or global (#585). A room that
    already reads the colony mailbox through its own `inbox:` gets no second
    row (the same mail would arrive twice)."""
    from . import egress
    from . import main
    acct, addr = colony_mailbox()
    if not acct:
        return []
    # Only a comms-pack that FILTERS by tag may be handed a tagged row: an
    # older one would ignore the tag and deliver every declared sender's mail
    # of the colony mailbox to every topic (second review of #416). The
    # capability is a service only comms-pack ≥ 2.5.0 registers.
    try:
        from .components import loader as _components
        if _components.service("comms-pack", "courier_message_box") is None:
            return []
        # Global senders count on the message box (#585), but they make EVERY
        # topic with a code a row: only with the one-search index (comms-pack
        # ≥ 2.6.0) — without it each row is one IMAP search per cycle.
        indexed = _components.service("comms-pack", "courier_box_index") is not None
    except Exception:  # noqa: BLE001 — unknown → off
        return []
    already = {(r["tier"], r["name"]) for r in existing if r.get("address") == addr}
    out = []
    try:
        codes = main._topics().mailbox_codes()
    except Exception as e:  # noqa: BLE001
        LOG.warning("courier colony: codes unavailable (%s)", type(e).__name__)
        return []
    for code, (tier, name) in sorted(codes.items()):
        if (tier, name) in already:
            continue
        # Cheap check first: the senders are config, opening a topic is not.
        sig = _senders(f"{tier}/{name}", with_global=indexed)
        if not sig["senders"] or not _topic_exists(tier, name):
            continue
        out.append({"tier": tier, "name": name, "account": acct, "address": addr,
                    "strict": bool(egress.ingress_strict(f"{tier}/{name}")),
                    **sig, "tag": code, "indexed": indexed})
    return out


def _senders(scope: str, with_global: bool = False) -> dict:
    """How many `mailfrom:` entries the room declares, and a signature of the
    set (#576): when it changes the courier records what is already in the
    mailbox instead of delivering it — a sender added today brings its mail
    from today, like a mailbox linked today. `with_global` for a message-box
    row (#585): the global entries count there, so they are in the signature."""
    import hashlib
    from . import egress
    regole = sorted(str(r).strip().lower()
                    for r in egress.room_sender_rules(scope, with_global))
    return {"senders": len(regole),
            "senders_sig": hashlib.sha256("\n".join(regole).encode()).hexdigest()[:16]}


def _in_room(tier: str, name: str, payload: dict, service: str, args: dict,
             tag: str = ""):
    from .claims import ClaimsContext
    from .tools import mail_switch
    tok = COURIER_TAG.set(tag or "")
    try:
        with ClaimsContext(_room_claims(tier, name, payload), ""):
            return mail_switch.call(service, dict(args))
    finally:
        COURIER_TAG.reset(tok)


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
    tag = str(body.get("tag") or "")
    offerte = await asyncio.to_thread(rooms)
    # The tag is part of the pair: a colony row is offered WITH its topic's
    # code, and only that exact (room, mailbox, tag) is accepted (#583).
    if not any(r["tier"] == tier and r["name"] == name and r["account"] == account
               and str(r.get("tag") or "") == tag for r in offerte):
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
                                                    service, args, tag))
    except PermissionError as e:
        return JSONResponse({"error": str(e)[:300]}, status_code=403)
    except Exception as e:  # noqa: BLE001
        LOG.warning("courier %s: %s", service, type(e).__name__)
        return JSONResponse({"error": str(e)[:200]}, status_code=502)


async def envelopes_route(request: Request):
    return await _room_call(request, "courier_envelopes",
                            ("account", "folder", "limit", "skip", "keys_only", "only"))


def box_index(payload: dict) -> dict:
    """Which message-box codes have recent mail on the colony mailbox, and the
    keys of that mail (#585): ONE search for every topic, instead of one per
    topic. Keys only — hashes, never a sender, subject or body — to the
    agent-server, which then asks `envelopes` for the rooms named here."""
    from .claims import ClaimsContext
    from .tools import mail_switch
    acct, _addr = colony_mailbox()
    if not acct:
        return {"account": "", "tags": {}}
    claims = {"agent": str((payload or {}).get("agent") or ""), "chat": "courier-box",
              "principal": (payload or {}).get("principal") or "",
              "execution_id": f"{COURIER}-box"}
    tok = COURIER_TAG.set(BOX_INDEX_TAG)
    try:
        with ClaimsContext(claims, ""):
            out = mail_switch.call("courier_box_index", {"account": acct})
    finally:
        COURIER_TAG.reset(tok)
    tags = (out or {}).get("tags") if isinstance(out, dict) else None
    return {"account": acct,
            "tags": {str(k).upper(): [str(x) for x in (v or [])]
                     for k, v in (tags or {}).items()}}


async def box_route(request: Request):
    payload, err = _authorize(request)
    if err:
        return err
    try:
        from .components import loader as _components
        if _components.service("comms-pack", "courier_box_index") is None:
            return JSONResponse({"error": "comms-pack has no courier_box_index"},
                                status_code=404)
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "components unavailable"}, status_code=404)
    try:
        return JSONResponse(await asyncio.to_thread(box_index, payload))
    except PermissionError as e:
        return JSONResponse({"error": str(e)[:300]}, status_code=403)
    except Exception as e:  # noqa: BLE001
        LOG.warning("courier box: %s", type(e).__name__)
        return JSONResponse({"error": str(e)[:200]}, status_code=502)


async def attachment_route(request: Request):
    return await _room_call(request, "courier_attachment",
                            ("account", "email_id", "filename", "folder"))


async def eml_route(request: Request):
    return await _room_call(request, "courier_eml", ("account", "email_id", "folder"))


routes = [
    Route("/internal/mail/courier/eml", eml_route, methods=["POST"]),
    Route("/internal/mail/courier/box", box_route, methods=["POST"]),
    Route("/internal/mail/courier/rooms", rooms_route, methods=["GET"]),
    Route("/internal/mail/courier/envelopes", envelopes_route, methods=["POST"]),
    Route("/internal/mail/courier/attachment", attachment_route, methods=["POST"]),
]

"""Mail goes out through the courier (clodia-platform#736).

An agent in a room asks for a mail to be sent (`topic.mail_send`, or
`channel.deliver` to a `mailto:` destination). Nothing is sent during the
agent's turn: the message enters the courier's queue on the agent-server and
the verb returns at once with its number.

- A recipient already in the room's «Destinatari» or in the global list is
  `queued`: the courier sends it at its next pass.
- Any other recipient is `pending_gate`: an ASYNC gate request opens in the
  room (`egress:email:mailto:<addr>`, the key the egress PDP uses), with three
  answers — deny, authorise in this channel (the room's «Destinatari»),
  authorise in all channels (the global list, admin only). The request lives
  24 hours, as long as the queued message (owner, 25 Nov 2026).
- A room with no connected mailbox cannot send: refused at once.

At its pass the courier calls `send_now()` through
`/internal/mail/courier/send`, which checks again — mailbox and recipient —
and only then hands the message to the mail code. A recipient withdrawn in
the meantime is not mailed.
"""
from __future__ import annotations

import logging
import re

LOG = logging.getLogger("clodia-tools.courier-send")

#: One address, no display name, no list.
_ADDR = re.compile(r"^[^@\s,;<>]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def gate_key(addr: str) -> str:
    """The gate key of a recipient: the egress PDP's own, so an approval
    writes the same list entries an ordinary egress gate writes."""
    return f"egress:email:mailto:{addr.strip().lower()}"


def recipient(raw: str) -> str:
    a = str(raw or "").strip()
    if a.lower().startswith("mailto:"):
        a = a[len("mailto:"):].strip()
    if not _ADDR.match(a):
        raise ValueError(f"destinatario '{raw}' non valido: un solo indirizzo email")
    return a.lower()


def allowed(addr: str, scope: str) -> bool:
    """Is the recipient in the room's «Destinatari» or in the global list?"""
    from . import egress
    return bool(egress.destinations_already_allowed("email.send", {"to": addr}, scope))


def sender_account(tier: str, name: str, account: str = "") -> str:
    """The mailbox the room sends with: the one asked for, if the room
    connects it, else the room's only one. None connected → refused."""
    from . import main, room_mailboxes
    if account:
        if account not in room_mailboxes.outbox_account(tier, name):
            raise PermissionError(f"la casella '{account}' non è collegata a questo canale")
        return account
    return main._room_outbox_account(tier, name)


def _card(agent: str, addr: str, subject: str, account: str, qid: str) -> str:
    clean = lambda s: str(s or "").replace("<!--", "‹!--").replace("-->", "--›")[:200]
    return (f"📤 **{clean(agent)}** chiede di spedire una mail a **{clean(addr)}** "
            f"— «{clean(subject)}», dalla casella {clean(account)} (pratica {clean(qid)}). "
            f"Il destinatario non è ancora autorizzato: la mail resta in coda finché "
            f"non si decide, per 24 ore.")


def enqueue(*, tier: str, name: str, agent: str, chat: str, principal: str | None,
            to: str, subject: str, body: str, attachments: list[str] | None = None,
            account: str = "") -> dict:
    """Queue one mail on the courier; open the gate if its recipient is new.
    Returns `{queue_id, state, to, account}`. Runs off the event loop."""
    from . import gate, main, transfer_channel
    addr = recipient(to)
    if not str(body or "").strip():
        raise ValueError("il testo della mail non può essere vuoto")
    acct = sender_account(tier, name, str(account or "").strip())
    scope = f"{tier}/{name}"
    stato = "queued" if allowed(addr, scope) else "pending_gate"
    key = gate_key(addr)
    out = transfer_channel._post("/internal/courier/enqueue", {
        "tier": tier, "name": name, "agent": agent, "to": addr,
        "subject": str(subject or "")[:300], "body": str(body),
        "attachments": [str(x) for x in (attachments or []) if str(x).strip()],
        "account": acct, "state": stato, "gate_key": key})
    qid = str(out.get("id") or "")
    if stato == "pending_gate":
        # One request per recipient and room: the instance is the room, so
        # two rooms asking for the same address are two decisions.
        req = gate.request(agent, scope, key, context=chat, human=principal, chat=chat,
                           mode="async", reason=f"mail a {addr}: {str(subject or '')[:120]}")
        try:
            main._topics().post_message(
                tier, name, author="gate",
                text=_card(agent, addr, subject, acct, qid) + f"\n<!-- gate={req.get('id')} -->",
                kind="ai")
        except Exception as e:  # noqa: BLE001 — the request stands without its card
            LOG.warning("courier send: card not posted in %s (%s)", scope, type(e).__name__)
    LOG.info("courier send: %s queued in %s as %s", qid, scope, stato)
    return {"queue_id": qid, "state": stato, "to": addr, "account": acct}


async def send_now(*, tier: str, name: str, account: str, to: str, subject: str,
                   body: str, attachments: list[str] | None = None) -> dict:
    """The courier's pass: check again, then send. Runs in the room's claims
    (the route sets them). `{ok, detail}`; never raises for a refusal."""
    import asyncio
    import json
    from . import main
    try:
        addr = recipient(to)
    except ValueError as e:
        return {"ok": False, "detail": str(e)}
    scope = f"{tier}/{name}"
    if not await asyncio.to_thread(allowed, addr, scope):
        return {"ok": False, "detail": f"{addr} non è più tra i destinatari autorizzati"}
    try:
        acct = await asyncio.to_thread(sender_account, tier, name, account)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "detail": str(e)[:300]}
    args = {"to": addr, "subject": subject or name, "body": body, "account": acct}
    if attachments:
        args.update({"topic_files": list(attachments), "tier": tier, "name": name})
    tok = main._DELIVER_VIA.set(frozenset({"email.send"}))
    try:
        res = await main.call_tool("email.send", args)
    finally:
        main._DELIVER_VIA.reset(tok)
    testo = res[0].text if res else ""
    head = testo.split(":", 1)[0].strip()
    try:
        parsed = json.loads(testo)
    except ValueError:
        parsed = None
    failed = (head.isupper() and head.isalpha() and len(head) <= 16) \
        or (isinstance(parsed, dict) and parsed.get("error"))
    if failed:
        detail = str(parsed.get("error")) if isinstance(parsed, dict) else testo
        return {"ok": False, "detail": detail[:300]}
    return {"ok": True, "detail": "inviata", "account": acct}

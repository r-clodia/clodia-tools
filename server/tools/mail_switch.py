"""Mail, as the gateway's own code asks for it (clodia-platform#683).

The mail code is the gateway's (`server/mail/`): it came back from comms-pack's
gateway component (#558) without the agent verbs. This module is still the one
place where the rest of the gateway — the mailbox routes and the Tools card
(`tools_api`), the topic's mailbox option set (`topics_api`,
`connectors.actions`), the courier routes (`mail_courier_api`), the
configuration warnings (`main`) — reaches it, by service name, so those
callers did not change with the move.

`ComponentUnavailable` is kept for those callers: it is now raised only for an
unknown service name.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

LOG = logging.getLogger("clodia-tools.mail-switch")

#: The connector id (the builtin `mail` manifest).
CONNECTOR = "mail"


class ComponentUnavailable(PermissionError):
    """No mail service of that name."""


def _services() -> dict[str, Callable]:
    from ..mail import mail, mailboxes
    return {
        "diagnostics": mail.credential_diagnostics,
        "system_mailboxes": mail.system_mailboxes,
        "mailbox_address": mail.mailbox_address,
        "mailboxes_list": mailboxes.mailboxes_list,
        "mailbox_add": mailboxes.mailbox_add,
        "mailbox_remove": mailboxes.mailbox_remove,
        "test_mailboxes": mailboxes.test_mailboxes,
        # The courier (#531): envelopes and attachment bytes, never the body.
        "courier_envelopes": lambda a: mail.courier_envelopes(
            str(a.get("account") or ""), str(a.get("folder") or "INBOX"),
            int(a.get("limit") or 20), list(a.get("skip") or []),
            bool(a.get("keys_only")),
            None if a.get("only") is None else list(a.get("only") or [])),
        # #585: one search for every message box.
        "courier_box_index": lambda a: mail.courier_box_index(
            str(a.get("account") or "")),
        "courier_attachment": lambda a: mail.courier_attachment(
            str(a.get("account") or ""), str(a.get("email_id") or ""),
            str(a.get("filename") or ""), str(a.get("folder") or "INBOX")),
        # #576: the whole message, for the topic's `.eml` copy.
        "courier_eml": lambda a: mail.courier_eml(
            str(a.get("account") or ""), str(a.get("email_id") or ""),
            str(a.get("folder") or "INBOX"), str(a.get("key") or "")),
    }


def why_unavailable() -> str:
    return ""


def service(name: str) -> Callable:
    """The mail service `name`, or `ComponentUnavailable` for an unknown one."""
    fn = _services().get(str(name or ""))
    if fn is None:
        raise ComponentUnavailable(f"no mail service '{name}'")
    return fn


def call(name: str, *args: Any, **kwargs: Any) -> Any:
    return service(name)(*args, **kwargs)


# --------------------------------------------------------------------------
# what the gateway's own code asks
# --------------------------------------------------------------------------

def credential_diagnostics() -> list[dict]:
    """The rows of the mail credential diagnostics (no secret values)."""
    return [dict(r) for r in call("diagnostics")]


def system_mailboxes() -> list[dict]:
    """`[{account, email, send_only}]` of the operational mailboxes: what the
    topic's "Autorizza una casella" button offers."""
    return [dict(r) for r in call("system_mailboxes")]


def component_test_mailboxes() -> dict:
    """`{ok, detail}` of the mailboxes Tools card."""
    return dict(call("test_mailboxes"))

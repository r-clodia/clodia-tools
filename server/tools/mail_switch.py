"""Mail, as the gateway's own code asks for it (clodia-platform#558).

Mail is served by comms-pack's GATEWAY COMPONENT (`catalogs/packs/comms-pack/
gateway` in r-clodia/clodia-logic, fetched, pinned and loaded by
`server.components`): it registers the eight verbs, which the dispatcher runs
through the normal `call_tool` path, and answers the services below. The
gateway's own mail client was removed (#523) and the `native|pack` switch is
retired (#526).

This module is the one place where gateway code that STAYS — the mailbox
routes and the Tools card (`tools_api`), the topic's mailbox button and its
option set (`topics_api`, `connectors.actions`), the configuration warnings
(`main`) — reaches the component. A missing component is a refusal
(`ComponentUnavailable`); listings degrade to empty, with the reason where
there is a place to say it.
"""
from __future__ import annotations

import logging
from typing import Any

LOG = logging.getLogger("clodia-tools.mail-switch")

#: The connector id, and the pack whose component serves it.
CONNECTOR = "mail"
PACK = "comms-pack"


class ComponentUnavailable(PermissionError):
    """comms-pack's gateway component is not serving."""


def why_unavailable() -> str:
    try:
        from .. import components
        st = components.state_of(PACK)
    except Exception:  # noqa: BLE001
        st = None
    if st is None:
        return ("no installed comms-pack declares a gateway component (comms-pack "
                "2.0.0 or later is needed)")
    return f"comms-pack's gateway component is {st['status']}: {st.get('reason') or '-'}"


def service(name: str):
    """The callable of the component's service `name`, or `ComponentUnavailable`."""
    from .. import components
    spec = components.service(PACK, name)
    if spec is None:
        raise ComponentUnavailable(
            f"mail is served by comms-pack, but {why_unavailable()}. "
            "See GET /internal/components.")
    return spec.handler


def call(name: str, *args: Any, **kwargs: Any) -> Any:
    return service(name)(*args, **kwargs)


# --------------------------------------------------------------------------
# what the gateway's own code asks, answered by the component
# --------------------------------------------------------------------------

def credential_diagnostics() -> list[dict]:
    """The rows of `email.credential_diagnostics()` (no secret values), from
    the component. `[]` when the component is not serving."""
    try:
        return [dict(r) for r in call("diagnostics")]
    except ComponentUnavailable:
        return []


def system_mailboxes() -> list[dict]:
    """`[{account, email, send_only}]` of the operational mailboxes: what the
    topic's "Autorizza una casella" button offers. `[]` when the component is
    not serving — nothing offered is nothing authorised."""
    try:
        return [dict(r) for r in call("system_mailboxes")]
    except ComponentUnavailable:
        return []


def component_test_mailboxes() -> dict:
    """`{ok, detail}` of the mailboxes Tools card."""
    try:
        return dict(call("test_mailboxes"))
    except ComponentUnavailable as e:
        return {"ok": False, "detail": str(e)}

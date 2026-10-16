"""Which mail implementation answers on this instance (clodia-platform#558).

The instance switch `connectors: {mail: native|pack}` (`profile.yaml`):

* `native` (default) — the gateway's own `tools/email.py` (with the vendored
  `vendor/email_client.py`) serves the eight `email.*` verbs, and the mailbox
  routes of `tools_api` manage `mailbox_<acct>` directly, as before. A Gmail
  account follows the `google` switch there (google-pack's `mail_run` on
  `google: pack`);
* `pack` — comms-pack's GATEWAY COMPONENT does (`catalogs/packs/comms-pack/
  gateway` in r-clodia/clodia-logic, fetched, pinned and loaded by
  `server.components`): it registers the eight verbs, which the dispatcher runs
  through the normal `call_tool` path, and answers the services below. The
  native module does not run at all: `email._run_cli` refuses in that position
  (`NativeDisabled`), so a native path reached by mistake fails instead of
  using the vault's credential behind the owner's back.

This module is the one place where gateway code that STAYS — the mailbox
routes and the Tools card (`tools_api`), the topic's mailbox button and its
option set (`topics_api`, `connectors.actions`), the configuration warnings
(`main`) — asks which side answers. In `pack` position a missing component is
a refusal (`ComponentUnavailable`), never a fallback to the native code: an
owner who turned the switch must not be verifying the wrong implementation on
real traffic. Listings degrade to empty, with the reason where there is a place
to say it.
"""
from __future__ import annotations

import logging
from typing import Any

LOG = logging.getLogger("clodia-tools.mail-switch")

#: The connector id of the switch, and the pack it hands mail to.
CONNECTOR = "mail"
PACK = "comms-pack"


class ComponentUnavailable(PermissionError):
    """`pack` position, but comms-pack's gateway component is not serving."""


def in_pack() -> bool:
    """`connectors: {mail: pack}`. Asked per call; in doubt `native`."""
    from .. import instance_profile
    return instance_profile.connector_mode(CONNECTOR) == "pack"


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
            f"mail is in `pack` position on this instance, but {why_unavailable()}. "
            "See GET /internal/components; or set `connectors: {mail: native}` "
            "in profile.yaml.")
    return spec.handler


def call(name: str, *args: Any, **kwargs: Any) -> Any:
    return service(name)(*args, **kwargs)


# --------------------------------------------------------------------------
# what the gateway's own code asks, answered by the side in charge
# --------------------------------------------------------------------------

def credential_diagnostics() -> list[dict]:
    """The rows of `email.credential_diagnostics()` (no secret values), from
    the side in charge. `[]` when the component is not serving."""
    if in_pack():
        try:
            return [dict(r) for r in call("diagnostics")]
        except ComponentUnavailable:
            return []
    from . import email
    return email.credential_diagnostics()


def system_mailboxes() -> list[dict]:
    """`[{account, email, send_only}]` of the operational mailboxes: what the
    topic's "Autorizza una casella" button offers. `[]` when the component is
    not serving — nothing offered is nothing authorised."""
    if in_pack():
        try:
            return [dict(r) for r in call("system_mailboxes")]
        except ComponentUnavailable:
            return []
    from . import email
    return email.system_mailboxes()


def component_test_mailboxes() -> dict:
    """`{ok, detail}` of the mailboxes Tools card in `pack` position (the
    native test stays in `tools_api._test_mailboxes`)."""
    try:
        return dict(call("test_mailboxes"))
    except ComponentUnavailable as e:
        return {"ok": False, "detail": str(e)}

"""Which Google implementation answers on this instance (clodia-platform#558).

The instance switch `connectors: {google: native|pack}` (`profile.yaml`):

* `native` (default) — NOTHING serves Google any more: the gateway's own
  modules (`gdrive`, `gsheets`, `gdocs`, `gcalendar`, `google_io`,
  `gdrive_labels`, the Drive-API half of `gdrive_root`) were removed
  (clodia-platform#524). Verbs refused, OAuth routes 409, listings empty;
* `pack` — google-pack's GATEWAY COMPONENT does (`catalogs/packs/google-pack/
  gateway` in r-clodia/clodia-logic, fetched, pinned and loaded by
  `server.components`): it registers the 24 verbs, which the dispatcher runs
  through the normal `call_tool` path, its OAuth routes, and the services
  below.

This module is the one place where gateway code that STAYS — the confinement
API, the labels of a whitelist, the vault's token cache, the Tools card test,
the Gmail provider of `email.*` — asks which side answers. In `pack` position a
missing component is a refusal (`ComponentUnavailable`), never a fallback to
the native code: an owner who turned the switch must not be verifying the
wrong implementation on real traffic.
"""
from __future__ import annotations

import logging
from typing import Any

LOG = logging.getLogger("clodia-tools.google-switch")

#: The connector id of the switch, and the pack it hands Google to.
CONNECTOR = "google"
PACK = "google-pack"


NATIVE_REMOVED = ("Google has no native implementation any more "
                  "(clodia-platform#524): set `connectors: {google: pack}` in the "
                  "instance profile and install google-pack ≥ 2.0.0")


class ComponentUnavailable(PermissionError):
    """`pack` position, but google-pack's gateway component is not serving."""


def in_pack() -> bool:
    """`connectors: {google: pack}`. Asked per call; in doubt `native`."""
    from .. import instance_profile
    return instance_profile.connector_mode(CONNECTOR) == "pack"


def _why_unavailable() -> str:
    try:
        from .. import components
        st = components.state_of(PACK)
    except Exception:  # noqa: BLE001
        st = None
    if st is None:
        return ("no installed google-pack declares a gateway component (google-pack "
                "2.0.0 or later is needed)")
    return f"google-pack's gateway component is {st['status']}: {st.get('reason') or '-'}"


def service(name: str):
    """The callable of the component's service `name`, or `ComponentUnavailable`."""
    from .. import components
    spec = components.service(PACK, name)
    if spec is None:
        raise ComponentUnavailable(
            f"Google is in `pack` position on this instance, but {_why_unavailable()}. "
            "See GET /internal/components.")
    return spec.handler


def call(name: str, *args: Any, **kwargs: Any) -> Any:
    return service(name)(*args, **kwargs)


# --------------------------------------------------------------------------
# what the gateway's own code asks, answered by the side in charge
# --------------------------------------------------------------------------

def accounts() -> list[str]:
    """The Google accounts with a Drive-capable credential."""
    if in_pack():
        return list(call("accounts"))
    return []          # `native`: no Google implementation any more (#524)


def describe_folder(account: str, folder_id: str) -> dict:
    """`{id, name?, is_folder, error?}` of a Drive folder, for the confinement API."""
    if in_pack():
        return dict(call("describe_folder", account, folder_id))
    raise ComponentUnavailable(NATIVE_REMOVED)


def perimeter_changed() -> None:
    """The Drive perimeter moved: drop the component's caches."""
    try:
        from .. import components
        spec = components.service(PACK, "perimeter_changed")
        if spec is not None:
            spec.handler()
    except Exception as e:  # noqa: BLE001 — a cache, never a reason to fail the write
        LOG.warning("google: component cache not reset (%s)", type(e).__name__)


def credential_changed(name: str) -> None:
    """A Google credential was deposited or removed: drop cached access tokens
    on both sides (the vault calls this; never raises)."""
    try:
        from .. import components
        spec = components.service(PACK, "credential_changed")
        if spec is not None:
            spec.handler(name)
    except Exception as e:  # noqa: BLE001
        LOG.warning("google: component token cache not reset (%s)", type(e).__name__)


def folder_labels(uris: list) -> dict:
    """`{uri: {url, name}}` for the `gdrive:folder/` entries of a whitelist.
    Best effort by contract: `{}` when the component is not serving."""
    if in_pack():
        try:
            return dict(call("folder_labels", list(uris)))
        except ComponentUnavailable:
            return {}
    return {}          # `native`: no Google implementation any more (#524)


def component_test_connection() -> dict:
    """`{ok, detail}` of the unified `google` Tools card."""
    try:
        return dict(call("test_connection"))
    except ComponentUnavailable as e:
        return {"ok": False, "detail": str(e)}


def gmail_runner():
    """The Gmail provider of `email.*` in `pack` position: the component's
    `mail_run` service (`{argv, files, timeout}` → `{returncode, stdout,
    stderr}`), or `ComponentUnavailable`."""
    return service("mail_run")

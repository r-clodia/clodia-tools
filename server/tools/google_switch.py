"""Which Google implementation answers on this instance (clodia-platform#558).

The instance switch `connectors: {google: native|pack}` (`profile.yaml`):

* `native` (default) — the gateway's own modules (`gdrive`, `gdrive_root`,
  `gsheets`, `gdocs`, `gcalendar`, `google_io`, `gdrive_labels`, the OAuth
  routes of `tools_api`) serve everything, as before;
* `pack` — google-pack's GATEWAY COMPONENT does (`catalogs/packs/google-pack/
  gateway` in r-clodia/clodia-logic, fetched, pinned and loaded by
  `server.components`): it registers the 24 verbs, which the dispatcher runs
  through the normal `call_tool` path, its OAuth routes, and the services
  below. The native modules do not run at all: `google_io.call` refuses in
  that position, so a native path reached by mistake fails instead of using
  the vault's credential behind the owner's back.

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
            "See GET /internal/components; or set `connectors: {google: native}` "
            "in profile.yaml.")
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
    from . import gdrive
    return gdrive.gworkspace_accounts()


def describe_folder(account: str, folder_id: str) -> dict:
    """`{id, name?, is_folder, error?}` of a Drive folder, for the confinement API."""
    if in_pack():
        return dict(call("describe_folder", account, folder_id))
    from . import gdrive
    from . import google_io
    out = {"id": folder_id}
    try:
        meta = google_io.call(gdrive._resolve_account(account), "drive", "v3",
                              "GET files/{fileId}", params={
                                  "fileId": folder_id, "fields": "id, name, mimeType",
                                  "supportsAllDrives": True})
        out["name"] = meta.get("name")
        out["is_folder"] = meta.get("mimeType") == \
            "application/vnd.google-apps.folder"
    except Exception as e:                       # noqa: BLE001
        out["error"] = f"{type(e).__name__}: {str(e)[:100]}"
        out["is_folder"] = False
    return out


def perimeter_changed() -> None:
    """The Drive perimeter moved: drop the caches of whichever side runs. Both,
    in fact: a cache of the side that is not running is stale the day the
    switch is turned back."""
    from . import gdrive_root
    gdrive_root.reset_cache()
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
        from . import google_io
        google_io.forget()
    except Exception:  # noqa: BLE001
        pass
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
    from . import gdrive_labels
    return gdrive_labels.labels(uris)


def component_test_connection() -> dict:
    """`{ok, detail}` of the unified `google` Tools card in `pack` position
    (the native test stays in `tools_api._test_google`)."""
    try:
        return dict(call("test_connection"))
    except ComponentUnavailable as e:
        return {"ok": False, "detail": str(e)}


def gmail_runner():
    """The Gmail provider of `email.*` in `pack` position: the component's
    `mail_run` service (`{argv, files, timeout}` → `{returncode, stdout,
    stderr}`), or `ComponentUnavailable`."""
    return service("mail_run")

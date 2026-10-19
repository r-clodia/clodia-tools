"""Google, as the gateway's own code asks for it (clodia-platform#558).

Google is served by google-pack's GATEWAY COMPONENT (`catalogs/packs/
google-pack/gateway` in r-clodia/clodia-logic, fetched, pinned and loaded by
`server.components`): it registers the 24 verbs, which the dispatcher runs
through the normal `call_tool` path, its OAuth routes, and the services below.
The gateway's own Google modules were removed (#524) and the `native|pack`
switch is retired (#526).

This module is the one place where gateway code that STAYS — the confinement
API, the labels of a whitelist, the vault's token cache, the Tools card test,
the Gmail provider of `email.*` — reaches the component. A missing component
is a refusal (`ComponentUnavailable`), never a fallback.
"""
from __future__ import annotations

import logging
from typing import Any

LOG = logging.getLogger("clodia-tools.google-switch")

#: The connector id, and the pack whose component serves it.
CONNECTOR = "google"
PACK = "google-pack"


class ComponentUnavailable(PermissionError):
    """google-pack's gateway component is not serving."""


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
            f"Google is served by google-pack, but {_why_unavailable()}. "
            "See GET /internal/components.")
    return spec.handler


def call(name: str, *args: Any, **kwargs: Any) -> Any:
    return service(name)(*args, **kwargs)


# --------------------------------------------------------------------------
# what the gateway's own code asks, answered by the component
# --------------------------------------------------------------------------

def accounts() -> list[str]:
    """The Google accounts with a Drive-capable credential."""
    return list(call("accounts"))


def describe_folder(account: str, folder_id: str) -> dict:
    """`{id, name?, is_folder, error?}` of a Drive folder, for the confinement API."""
    return dict(call("describe_folder", account, folder_id))


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
    try:
        return dict(call("folder_labels", list(uris)))
    except ComponentUnavailable:
        return {}


def component_test_connection() -> dict:
    """`{ok, detail}` of the unified `google` Tools card."""
    try:
        return dict(call("test_connection"))
    except ComponentUnavailable as e:
        return {"ok": False, "detail": str(e)}


def gmail_runner():
    """The Gmail provider of `email.*`: the component's
    `mail_run` service (`{argv, files, timeout}` → `{returncode, stdout,
    stderr}`), or `ComponentUnavailable`."""
    return service("mail_run")

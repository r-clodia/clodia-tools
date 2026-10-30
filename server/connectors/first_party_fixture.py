"""Test support: the three first-party packs, installed as on a real instance.

Since clodia-platform#526 the gateway declares only `core` and `datastore`:
mail, Telegram, Google, GitHub and image generation are connectors of
comms-pack, google-pack and it-pack, and every instance has those packs
installed. A test of the PDP tables (`email.send` → `mailto:`, `github.push` →
`https:`, …) therefore needs them in the registry, as production has them.

The connectors are built from `testdata/former_builtin/*.yaml` — the gateway's
own declarations until #526, i.e. the parity reference the packs were
migrated against — with only what a PACK must write differently (the safe
regex subset, `unmapped:`, `forms:` on the schemes a topic action writes).

Not a test module: imported by the tests. `install()` adds the packs to what
`resolved` reads as installed (oldest first, so a test that installs its own
copy of one of them replaces it); `uninstall()` undoes it.
"""
from __future__ import annotations

import copy
from pathlib import Path
from unittest.mock import patch

import yaml

FORMER_BUILTIN = Path(__file__).resolve().parent / "testdata" / "former_builtin"


def former(stem: str) -> dict:
    """A former builtin declaration (`mail`, `telegram`, `google`, `github`,
    `openai`), parsed."""
    return yaml.safe_load((FORMER_BUILTIN / f"{stem}.yaml").read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# comms-pack
# --------------------------------------------------------------------------

#: Mail verbs with no egress/source mapping and no taint row (`unmapped:`).
MAIL_UNMAPPED = ["email.folders", "email.save_attachment"]

_ADDRESS_FORM = [{"label": "address", "pattern": r"^[^@\s]+@[A-Za-z0-9.-]+$",
                  "example": "studio@example.org"}]


def mail_connector() -> dict:
    """comms-pack's `mail`: the former builtin vocabulary plus `forms:` on the
    mailbox schemes, the `imap` provider and `unmapped:`."""
    entry = copy.deepcopy(former("mail")["connectors"][0])
    for s in entry["schemes"]:
        if s["scheme"] in ("inbox", "outbox"):
            s["forms"] = copy.deepcopy(_ADDRESS_FORM)
    entry["providers"] = [{"id": "imap", "label": "IMAP/SMTP"}]
    entry["unmapped"] = list(MAIL_UNMAPPED)
    return entry


def telegram_connector() -> dict:
    """comms-pack's `telegram`: the former builtin, with anchored forms."""
    entry = copy.deepcopy(former("telegram")["connectors"][0])
    for s in entry.get("schemes") or []:
        for f in s.get("forms") or []:
            f["pattern"] = "^" + f["pattern"].lstrip("^").rstrip("$") + "$"
    return entry


def comms_pack() -> dict:
    return {"name": "comms-pack",
            "connectors": [telegram_connector(), mail_connector()]}


# --------------------------------------------------------------------------
# google-pack
# --------------------------------------------------------------------------

#: Google verbs with no egress/source mapping and no taint row, per connector.
GOOGLE_UNMAPPED = {
    "google": ["gdrive.list", "gdrive.search", "gdrive.rename"],
    "google-docs": ["gdocs.create", "gdocs.append_text", "gdocs.replace_text"],
    "google-calendar": ["gcalendar.list_calendars", "gcalendar.create_event",
                        "gcalendar.update_event", "gcalendar.delete_event",
                        "gcalendar.freebusy"],
}

# Browser URLs into `gdrive:`/`gsheets:`, in the PACK's safe regex subset (no
# quantified group, at most two repeats and two `?`): the builtin's
# `(?:u/\d+/)?` and `(?:[/?#].*)?` become one rule per shape. Same answers on
# every URL of the pinned tables; the `u/<n>/` form covers n < 100.
GDRIVE_CANON = [
    {"from": r"^gdrive://([\w-]+)/?$", "to": "gdrive:folder/{1}"},
    {"from": r"^gdrive://folder/([\w-]+)/?$", "to": "gdrive:folder/{1}"},
    {"from": r"^https?://drive\.google\.com/drive/folders/([\w-]+)$",
     "to": "gdrive:folder/{1}"},
    {"from": r"^https?://drive\.google\.com/drive/folders/([\w-]+)[/?#].*$",
     "to": "gdrive:folder/{1}"},
    {"from": r"^https?://drive\.google\.com/drive/u/\d\d?/folders/([\w-]+)$",
     "to": "gdrive:folder/{1}"},
    {"from": r"^https?://drive\.google\.com/drive/u/\d\d?/folders/([\w-]+)[/?#].*$",
     "to": "gdrive:folder/{1}"},
    {"from": r"^https?://docs\.google\.com/document/d/([\w-]+)$",
     "to": "gdrive:doc/{1}"},
    {"from": r"^https?://docs\.google\.com/document/d/([\w-]+)[/?#].*$",
     "to": "gdrive:doc/{1}"},
    {"from": r"^https?://drive\.google\.com/file/d/([\w-]+)$", "to": "gdrive:file/{1}"},
    {"from": r"^https?://drive\.google\.com/file/d/([\w-]+)[/?#].*$",
     "to": "gdrive:file/{1}"},
]
GSHEETS_CANON = [
    {"from": r"^gsheets://([\w-]+)/?$", "to": "gsheets:{1}"},
    {"from": r"^https?://docs\.google\.com/spreadsheets/d/([\w-]+)$",
     "to": "gsheets:{1}"},
    {"from": r"^https?://docs\.google\.com/spreadsheets/d/([\w-]+)[/?#].*$",
     "to": "gsheets:{1}"},
]


def google_connectors() -> list[dict]:
    """google-pack's four Google connectors: the former builtin declarations
    with the canonicalisation in the safe regex subset and `unmapped:`."""
    entries = copy.deepcopy(former("google")["connectors"])
    owner = entries[0]
    assert owner["id"] == "google"
    for s in owner["schemes"]:
        if s["scheme"] == "gdrive":
            s["canonicalise"] = copy.deepcopy(GDRIVE_CANON)
        if s["scheme"] == "gsheets":
            s["canonicalise"] = copy.deepcopy(GSHEETS_CANON)
    for e in entries:
        if e["id"] in GOOGLE_UNMAPPED:
            e["unmapped"] = list(GOOGLE_UNMAPPED[e["id"]])
    return entries


def gmail_connector() -> dict:
    """Gmail as a provider of the mail vocabulary, in google-pack's `gdrive`
    namespace (`google` stays reserved with the `google_` vault prefix)."""
    return {"id": "mail-gmail", "manifest_version": 1, "namespace": "gdrive",
            "label": "Gmail", "extends": "mail",
            "providers": [{"id": "gmail", "label": "Gmail"}]}


def google_pack() -> dict:
    return {"name": "google-pack",
            "connectors": google_connectors() + [gmail_connector()]}


# --------------------------------------------------------------------------
# it-pack
# --------------------------------------------------------------------------

def github_connector() -> dict:
    """it-pack's `github`: the former builtin, with the github.com warning as
    four bounded rules (a pack regex may not quantify a group)."""
    entry = copy.deepcopy(former("github")["connectors"][0])
    text = entry["danger_uris"][0]["text"]
    entry["danger_uris"] = [{"match": m, "text": text} for m in (
        r"https?://github\.com", r"https?://github\.com[:/].*",
        r"https?://[a-z0-9.-]+\.github\.com",
        r"https?://[a-z0-9.-]+\.github\.com[:/].*")]
    return entry


def images_connector() -> dict:
    return copy.deepcopy(former("openai")["connectors"][0])


def it_pack() -> dict:
    return {"name": "it-pack", "connectors": [github_connector(), images_connector()]}


def manifests() -> dict[str, dict]:
    """`{pack: manifest}` of the three first-party packs."""
    return {"comms-pack": comms_pack(), "google-pack": google_pack(),
            "it-pack": it_pack()}


# --------------------------------------------------------------------------
# installing them
# --------------------------------------------------------------------------

_PATCHES: list = []


def install(without: tuple[str, ...] = ()) -> None:
    """Add the first-party packs (minus `without`) to the installed manifests
    `resolved` reads.

    They come FIRST (the oldest installs); a pack of the same name that the
    test writes or injects replaces them. Usable as `setUpModule`."""
    from . import resolved
    own = resolved._installed_manifests

    def installed() -> dict[str, dict]:
        out = {k: v for k, v in manifests().items() if k not in without}
        for name, doc in own().items():
            out.pop(name, None)
            out[name] = doc
        return out

    p = patch.object(resolved, "_installed_manifests", installed)
    p.start()
    _PATCHES.append(p)
    resolved.invalidate()


def uninstall() -> None:
    """Undo the last `install()`. Usable as `tearDownModule`."""
    from . import resolved
    if _PATCHES:
        _PATCHES.pop().stop()
    resolved.invalidate()


# --------------------------------------------------------------------------
# the mount's ownership stamp, for tests about something else
# --------------------------------------------------------------------------

class _AnyName(frozenset):
    """A `declared_backends` answer that contains every name."""

    def __contains__(self, _item) -> bool:  # noqa: D401
        return True


_STAMP_PATCHES: list = []


def any_pack_declares_any_backend() -> None:
    """Make every pack «declare» every server name (`resolved.declared_backends`).

    Since #641's review `register_mcp_core(pack=…)` stamps a mount only for a
    server the INSTALLED pack names. The tests of ownership conflicts, legacy
    adoption, credentials and name normalisation mount with pack names that
    exist only in the test: they measure those rules, not the declaration
    check, which has its own tests (`test_641_relay_backend`). Usable as
    `setUpModule`; undo with `restore_backend_declarations`.
    """
    from . import resolved
    p = patch.object(resolved, "declared_backends", lambda pack: _AnyName())
    p.start()
    _STAMP_PATCHES.append(p)


def restore_backend_declarations() -> None:
    if _STAMP_PATCHES:
        _STAMP_PATCHES.pop().stop()

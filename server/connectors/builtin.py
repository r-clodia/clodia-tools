"""The connectors this gateway still implements itself, read from `builtin/`.

clodia-platform#518 moves the PDP's tables into a connector registry. The
registry of #516/#517 is fed by the manifests of *installed packs* — and the
connectors of this instance are not packs yet: they are gateway code. So the
tables could not simply be deleted; the knowledge in them had to be declared
somewhere first, in the same grammar, or the registry would answer «no mapping»
for `email.send` and the PDP would stop constraining the one verb it exists for.

`builtin_manifests/*.yaml` is that somewhere. Each file is a `pack.yaml`-shaped document
the gateway ships with itself:

    core.yaml       http: https: topic: mcp: — the platform-intrinsic schemes,
                    the only ones the issue leaves in a core manifest. This file
                    stays here forever.
    mail.yaml       → comms-pack with migration #522
    telegram.yaml   → comms-pack with migration #522
    google.yaml     → google-pack with migration #523
    github.yaml     → it-pack with migration #525

A migration deletes its file in the same change that adds the pack, and the
registry notices nothing: the entries simply arrive from the other side. While
a migration is in flight the two implementations coexist in the image and the
per-instance switch (`instance_profile.connector_backend`, clodia-platform#522)
says which one is in service: a connector in the `pack` position is dropped from
the documents below, which is exactly the «file deleted» state, one instance at
a time and reversible without a rollback of the code. Until
then a pack declaring the same connector id or the same scheme is **refused**
(`build_registry`, `builtin=`): while the gateway is the thing actually sending
the mail, an installed manifest must not be able to redefine where it goes.

These files are code, not input. They live in the image, next to the modules
that implement them, and they are the only manifests allowed to declare the
intrinsic schemes or to span namespaces.
"""
from __future__ import annotations

import logging
from pathlib import Path

LOG = logging.getLogger("clodia-tools.connectors")

DIR = Path(__file__).resolve().parent / "builtin_manifests"


def documents() -> dict[str, dict]:
    """`{pack name: parsed document}` for every file shipped in `builtin_manifests/`,
    *before* the per-instance migration switch.

    A file that does not parse raises: unlike a pack manifest — which comes from
    a volume the gateway does not own, and whose breakage must not take the
    other connectors down — this one is ours, and a gateway whose own mail
    connector is missing would keep working while silently checking nothing.
    """
    import yaml

    out: dict[str, dict] = {}
    for path in sorted(DIR.glob("*.yaml")):
        loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        name = str(loaded.get("name") or path.stem)
        if name in out:
            raise ValueError(f"builtin manifest '{name}' declared twice")
        out[name] = dict(loaded)
    return out


def _entries(doc: dict) -> list:
    raw = doc.get("connectors")
    return list(raw) if isinstance(raw, list) else []


def migrated_namespaces() -> frozenset[str]:
    """The namespaces of the builtin connectors a PACK implements here now.

    Read from the files rather than from the switch, because the switch names
    connector *ids* while the reservations (`CORE_VAULT_PREFIXES`, the native
    namespaces) are about *namespaces*: deriving one from the other by hand
    would be a second mapping, right where a mistake frees a prefix that is
    still in use.
    """
    from .. import instance_profile

    try:
        packed = instance_profile.packed_connectors()
    except Exception:  # noqa: BLE001 — a profile we cannot read migrates nothing
        return frozenset()
    if not packed:
        return frozenset()
    out = set()
    for doc in documents().values():
        for entry in _entries(doc):
            if not isinstance(entry, dict):
                continue
            if str(entry.get("id") or "") in packed:
                out.add(str(entry.get("namespace") or ""))
    return frozenset(n for n in out if n)


def manifests() -> dict[str, dict]:
    """The builtin documents **as this instance serves them**: the connectors
    the migration switch moved to a pack are not in here (clodia-platform#522).

    Dropping the entry is the whole mechanism. `build_registry` already refuses
    a pack connector whose namespace is a builtin one — «it becomes effective
    when that implementation moves into a pack» — so removing the gateway's own
    declaration is what lets the pack's identical declaration take its place,
    with no second code path and nothing to keep in step.

    A document left without connectors is dropped whole: a `name:` with nothing
    under it would reserve a pack name for an empty manifest.
    """
    packed = {c for c in _packed_ids()}
    out: dict[str, dict] = {}
    for name, doc in documents().items():
        entries = _entries(doc)
        kept = [e for e in entries
                if not (isinstance(e, dict) and str(e.get("id") or "") in packed)]
        if entries and not kept:
            LOG.info("connectors: '%s' è implementato da un pack su questa "
                     "istanza, il manifest del gateway non è in servizio", name)
            continue
        doc = dict(doc)
        if entries:
            doc["connectors"] = kept
        out[name] = doc
    return out


def _packed_ids() -> frozenset[str]:
    from .. import instance_profile

    try:
        return instance_profile.packed_connectors()
    except Exception:  # noqa: BLE001 — unreadable profile: nothing is migrated
        return frozenset()


def names() -> tuple[str, ...]:
    """The pack names of the builtin manifests, for `build_registry(builtin=…)`."""
    return tuple(manifests())

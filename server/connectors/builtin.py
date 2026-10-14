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
registry notices nothing: the entries simply arrive from the other side. Until
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


def manifests() -> dict[str, dict]:
    """`{pack name: parsed document}` for every file shipped in `builtin_manifests/`.

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


def names() -> tuple[str, ...]:
    """The pack names of the builtin manifests, for `build_registry(builtin=…)`."""
    return tuple(manifests())

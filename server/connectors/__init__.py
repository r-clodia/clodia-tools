"""Connector manifests: the grammar packs use to declare a connector.

Grammar and parser only — see `manifest.py` for why validation lives in the
gateway, and `SCHEMA.md` for the format with one example per connector that
exists today. Nothing here reads or writes a whitelist: a manifest declares,
the owner who installs grants (clodia-platform#516).

Since clodia-platform#518 this is not a grammar waiting for users: the PDP reads
the registry it builds, and the connectors this gateway still implements itself
are declared in `builtin_manifests/` in the very same grammar. `resolved.py` is
where the two meet.
"""
from .manifest import (  # noqa: F401
    CORE_SCHEMES,
    MANIFEST_VERSION,
    NORMALISERS,
    Connector,
    DangerRule,
    ManifestError,
    Provider,
    Registry,
    Scheme,
    Service,
    Transport,
    VerbMapping,
    build_registry,
    check_namespace,
    core_namespaces,
    load_manifest,
    parse_connector,
    parse_services,
)

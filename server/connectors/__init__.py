"""Connector manifests: the grammar packs use to declare a connector.

Grammar and parser only — see `manifest.py` for why validation lives in the
gateway, and `SCHEMA.md` for the format with one example per connector that
exists today. Nothing here reads or writes a whitelist: a manifest declares,
the owner who installs grants (clodia-platform#516).
"""
from .manifest import (  # noqa: F401
    CORE_SCHEMES,
    MANIFEST_VERSION,
    Connector,
    ManifestError,
    Provider,
    Registry,
    Scheme,
    Service,
    VerbMapping,
    build_registry,
    check_namespace,
    core_namespaces,
    load_manifest,
    parse_connector,
    parse_services,
)

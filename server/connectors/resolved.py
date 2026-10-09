"""The connector registry of the installed packs, as the PDP reads it.

`manifest.py` (clodia-platform#516) says what a connector manifest *is*; this
module says where the installed ones are and answers the two questions the
policy decision point asks on every call:

    where does this verb send?      → `egress_mapping`
    what does this verb read from?  → `source_mapping`

The point of clodia-platform#517 is that those two questions already have a
single asking place — `egress.spec_for` and `main._source_vetted` — and the
answer for a pack verb was simply missing. Nothing new is *checked* here: the
same egress whitelist, the same taint, the same gate and the same audit events
apply, because they all hang off those two answers.

Where the manifests come from
-----------------------------
`$CLODIA_DATA/packs/<pack>/pack.yaml`, the metadata the agent-server writes when
a pack is installed. The precedent is `tools/pack_runtime._declared_pip`, which
already reads `$CLODIA_DATA/plugins/*/plugin.yaml` from the same shared volume:
pack metadata is on disk, and asking the agent-server for it over HTTP would put
a network round trip inside the PDP.

That volume is writable by the agent-server, so a manifest is *not* trusted
input — and it does not need to be. A manifest only ever maps verbs **inside its
own namespace** (`check_namespace`, re-applied below at call time), so the worst
a rewritten one can do is point its own verbs at destinations that the egress
whitelist still has to contain and the gate still has to show. It declares; it
never grants.

Known gap, deliberate: `pack_import.install_pack_from_root` in `clodia-logic`
rewrites a *curated* `pack.yaml` with the keys it knows, so a `connectors:`
block does not survive installation today. Until clodia-platform#519 preserves
it (and refuses a malformed manifest at install time), this registry is empty on
a real instance and every path below is a no-op. That is why the tests build the
registry straight from manifests.
"""
from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .manifest import (
    Connector,
    ManifestError,
    Registry,
    VerbMapping,
    build_registry,
    check_namespace,
)

LOG = logging.getLogger("clodia-tools.connectors")

_DATA = Path(os.environ.get("CLODIA_DATA", "/datadir"))

#: Directory where the agent-server writes the metadata of an installed pack.
PACKS_DIR = "packs"

#: (signature, registry, problems) of the last build. The signature is the
#: `stat` of every manifest file: a registry that lags behind the files is a
#: security defect, not a slow path, so there is no TTL — a handful of `stat()`
#: per call is the price of never answering with a mapping that was removed.
_CACHE: tuple[tuple, Registry, tuple[str, ...]] | None = None


def _manifest_files() -> list[Path]:
    try:
        return sorted((_DATA / PACKS_DIR).glob("*/pack.yaml"))
    except OSError:  # unreadable data dir: no connectors, never an exception
        return []


def _signature(paths: list[Path]) -> tuple:
    out = []
    for p in paths:
        try:
            st = p.stat()
        except OSError:
            continue
        out.append((str(p), st.st_mtime_ns, st.st_size))
    return tuple(out)


def manifests() -> dict[str, dict]:
    """`{pack name: parsed pack.yaml}` for every installed pack.

    A file that does not parse is skipped with a warning: it is already the
    agent-server's job to refuse it, and one broken pack must not make the other
    connectors of the instance disappear — their verbs would silently go back to
    being unmapped, which is the failure direction this issue closes.
    """
    import yaml

    out: dict[str, dict] = {}
    for path in _manifest_files():
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception as e:  # noqa: BLE001
            LOG.warning("connectors: %s non leggibile (%s)", path, e)
            continue
        if not isinstance(loaded, Mapping):
            continue
        name = str(loaded.get("name") or path.parent.name)
        out[name] = dict(loaded)
    return out


def registry() -> Registry:
    """The connectors of the installed packs, rebuilt when the files change."""
    return _build()[0]


def problems() -> tuple[str, ...]:
    """Why the registry is empty, when it is. For diagnostics, not for policy."""
    return _build()[1]


def _build() -> tuple[Registry, tuple[str, ...]]:
    global _CACHE
    sig = _signature(_manifest_files())
    if _CACHE is not None and _CACHE[0] == sig:
        return _CACHE[1], _CACHE[2]
    reg, probs = Registry(), ()
    try:
        reg = build_registry(manifests())
    except ManifestError as e:
        # All-or-nothing is `build_registry`'s own rule (#516): a manifest that
        # collides with another is not half-valid. The consequence here is that
        # the instance falls back to the behaviour it had before this issue —
        # pack verbs unmapped — so the refusal has to be loud, and the real
        # place to stop a malformed manifest is the installation (#519).
        probs = (str(e),)
        LOG.error("connectors: registry non costruibile, i verbi dei pack "
                  "restano senza mappatura (%s)", e)
    except Exception as e:  # noqa: BLE001 — never break a call over this
        probs = (f"{type(e).__name__}: {e}",)
        LOG.error("connectors: registry non costruibile (%s)", e)
    _CACHE = (sig, reg, probs)
    return reg, probs


def invalidate() -> None:
    """Drop the cache. For tests and for whoever installs a pack in-process."""
    global _CACHE
    _CACHE = None


# --------------------------------------------------------------------------
# the two questions the PDP asks
# --------------------------------------------------------------------------

def _owned(verb: str, direction: str) -> tuple[Connector, VerbMapping] | None:
    for c in registry().connectors:
        for v in c.verbs:
            if v.verb == verb and v.direction == direction:
                return c, v
    return None


def namespace_violation(verb: str) -> str:
    """The reason this verb's mapping is illegitimate, or `""`.

    The rule is #516's and the check is #516's function: a second implementation
    would be the place where the two drift apart. It is applied **again** here,
    at call time, because a manifest validated at install time says nothing
    about today: the file is on a volume the gateway does not own, and the set
    of namespaces the gateway itself owns grows with every deploy. A pack that
    legitimately claimed `mail.` before the gateway had such verbs must stop
    being authoritative over them the moment it does — on the next call, not on
    the next reinstall.
    """
    for direction in ("egress", "source"):
        owned = _owned(verb, direction)
        if owned is None:
            continue
        connector, mapping = owned
        try:
            check_namespace(connector.namespace, [mapping.verb],
                            where=f"pack '{connector.pack}', connector "
                                  f"'{connector.id}'")
        except ManifestError as e:
            return str(e)
    return ""


def enforce_namespace(verb: str) -> None:
    """Refuse a call whose mapping breaks the namespace rule. Call-time half of
    clodia-platform#516's rule, and the reason it is a rule and not a lint.

    Raises `PermissionError`, so it stops the call whatever the egress mode is:
    in `report` mode the destination check only logs, and a verb captured by the
    wrong pack would sail through. This is not a question about a destination —
    it is a manifest claiming authority it does not have.
    """
    reason = namespace_violation(verb)
    if reason:
        raise PermissionError(
            f"verbo '{verb}': un pack installato lo mappa fuori dal proprio "
            f"namespace, quindi la chiamata non si fa. {reason}")


def _mapping(verb: str, direction: str) -> VerbMapping | None:
    """The declared mapping, or None — never a mapping that breaks the rule.

    A violating mapping is not merely ignored: `enforce_namespace` refuses the
    call outright. Both are needed, and they are not the same statement. Ignoring
    it here says «this mapping does not describe the call»; refusing there says
    «this call does not happen» — without the second, a pack could disable the
    PDP for someone else's verb simply by naming it.
    """
    owned = _owned(verb, direction)
    if owned is None:
        return None
    return None if namespace_violation(verb) else owned[1]


def egress_mapping(verb: str) -> VerbMapping | None:
    return _mapping(verb, "egress")


def source_mapping(verb: str) -> VerbMapping | None:
    return _mapping(verb, "source")


def destinations(mapping: VerbMapping, arguments: dict | None) -> list[str]:
    """The URIs this call reaches, the way `egress.py`'s extractors build them.

    Case is left as the manifest produced it: `egress._matches` lowercases both
    sides, so normalising here would only mangle what the gate card shows and
    what `remember()` writes down for identifiers that are case-sensitive
    (a Drive id, a Telegram handle).
    """
    raw = (arguments or {}).get(mapping.arg)
    if mapping.multi:
        items: list[Any]
        if isinstance(raw, (list, tuple)):
            items = list(raw)
        else:
            # One field carrying several recipients, as `email.send` does.
            items = str(raw or "").replace(";", ",").split(",")
    else:
        items = [raw]
    out = []
    for item in items:
        value = str(item or "").strip()
        if value:
            out.append(mapping.uri_for(value))
    return out


def spec_for(verb: str):
    """`(destination type, extractor)` for a pack verb, the shape `egress` wants."""
    mapping = egress_mapping(verb)
    if mapping is None:
        return None
    return (mapping.dtype or mapping.scheme,
            lambda a, _m=mapping: destinations(_m, a))


def source_uri(verb: str, arguments: dict | None) -> str | None:
    """The ONE source of a declared read, or None when there is not exactly one.

    Not exactly one is not an accident to paper over: `email.list` and
    `telegram.inbox` mix several senders in one answer, and the gateway already
    refuses to name a source for them rather than name the wrong one. A `multi:`
    read falls in the same bucket.
    """
    mapping = source_mapping(verb)
    if mapping is None:
        return None
    uris = destinations(mapping, arguments)
    return uris[0] if len(uris) == 1 else None


def is_declared_read(verb: str) -> bool:
    """True when a pack declares this verb as a read of an outside source.

    What makes a verb taint is that it brings in content nobody vouched for —
    `taint._TAINTING_EXACT` is that statement made verb by verb. A pack that
    declares `direction: source` has said the same thing about its own verb.
    """
    return source_mapping(verb) is not None

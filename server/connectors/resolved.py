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

from . import builtin as _builtin
from . import normalise as _normalise
from .manifest import (
    Connector,
    ManifestError,
    Registry,
    Scheme,
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
_CACHE: tuple[tuple, Registry, tuple[str, ...], dict] | None = None


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


#: Backend MCP che il CORE monta da sé (il connettore GitHub nativo): non sono
#: di nessun pack, nemmeno di uno che li dichiari fra i propri `mcp_servers`.
_CORE_BACKENDS = frozenset({"github"})


def _slug(name: str) -> str:
    """Lo slug con cui `tools_api.register_mcp_core` monta un server MCP."""
    import re as _re
    return _re.sub(r"[^a-z0-9]+", "-", (name or "").lower()).strip("-")[:40]


def mounted_backends() -> frozenset[str]:
    """I namespace dei backend MCP montati adesso (`mcp_backends` di config)."""
    from .. import proxy
    return frozenset(proxy._backends())


def _plugin_files() -> list[Path]:
    try:
        return sorted((_DATA / "plugins").glob("*/plugin.yaml"))
    except OSError:
        return []


def backend_owners(packs: Mapping[str, Mapping] | None = None) -> dict[str, frozenset[str]]:
    """`{pack: backend che quel pack monta come propri}`.

    Un pack possiede il backend di un server MCP che dichiara lui stesso: nel
    `mcp_servers` del proprio `pack.yaml` o in quello dei suoi plugin
    (`$CLODIA_DATA/plugins/<plugin>/plugin.yaml`, elencati in `plugins:`).
    Un backend dichiarato da due pack non è di nessuno, e i backend del core
    (`_CORE_BACKENDS`) non sono mai di un pack.
    """
    import yaml

    packs = manifests() if packs is None else packs
    plugin_servers: dict[str, set[str]] = {}
    for path in _plugin_files():
        try:
            meta = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:  # noqa: BLE001
            continue
        servers = meta.get("mcp_servers") if isinstance(meta, Mapping) else None
        if isinstance(servers, Mapping):
            plugin_servers[path.parent.name] = {_slug(str(k)) for k in servers}
    claimed: dict[str, set[str]] = {}
    for pack, meta in packs.items():
        own: set[str] = set()
        servers = meta.get("mcp_servers")
        if isinstance(servers, Mapping):
            own |= {_slug(str(k)) for k in servers}
        plugins = meta.get("plugins")
        for plugin in plugins if isinstance(plugins, list) else []:
            name = plugin.get("name") if isinstance(plugin, Mapping) else plugin
            own |= plugin_servers.get(str(name or ""), set())
        claimed[pack] = own - _CORE_BACKENDS
    count: dict[str, int] = {}
    for own in claimed.values():
        for b in own:
            count[b] = count.get(b, 0) + 1
    return {pack: frozenset(b for b in own if count[b] == 1)
            for pack, own in claimed.items()}


def foreign_backends(pack: str) -> frozenset[str]:
    """I namespace di backend MCP che `pack` NON può prendersi come namespace.

    Tutti quelli montati, più quelli del core, meno i soli server MCP che il
    pack monta come propri. Senza questa riserva un pack poteva dichiarare
    `namespace: github` (o quello di un `normattiva` montato con `mcp.add`) e
    mappare `github.get_*` come lettura `direction: source` di una fonte scelta
    da lui — cioè etichettare come fidate le letture di un altro backend e
    spegnere il taint.
    """
    owned = _build_owners().get(pack, frozenset())
    return (mounted_backends() | _CORE_BACKENDS) - owned


def reserved_for(pack: str) -> frozenset[str]:
    """Namespace riservati per `pack`: quelli nativi e i backend non suoi.
    (Quelli degli ALTRI pack li riserva `build_registry`.)"""
    from .manifest import core_namespaces
    return core_namespaces() | foreign_backends(pack)


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


def _build_owners() -> dict[str, frozenset[str]]:
    _build()
    return _CACHE[3] if _CACHE is not None else {}


def _build() -> tuple[Registry, tuple[str, ...]]:
    global _CACHE
    # Nella firma anche i plugin (chi possiede quale server MCP) e i backend
    # montati: un `mcp.add` fatto dopo la costruzione deve riservare quel
    # namespace alla chiamata successiva, non al prossimo cambio di pack.yaml.
    sig = (_signature(_manifest_files()), _signature(_plugin_files()),
           tuple(sorted(mounted_backends())))
    if _CACHE is not None and _CACHE[0] == sig:
        return _CACHE[1], _CACHE[2]
    reg, probs, owners = Registry(), (), {}
    try:
        own = _builtin.manifests()
        installed = {k: v for k, v in manifests().items() if k not in own}
        owners = backend_owners(installed)
        reg = build_registry({**own, **installed}, builtin=tuple(own))
        refused = list(reg.refused)
        # Namespace di backend MCP montati: riservati come quelli nativi, salvo
        # il server MCP che il pack monta come proprio. Il connettore che ne
        # prende uno altrui è rifiutato da solo — gli altri restano.
        mounted = mounted_backends() | _CORE_BACKENDS
        keep = []
        for c in reg.connectors:
            if not c.builtin and \
                    c.namespace in mounted - owners.get(c.pack, frozenset()):
                refused.append(
                    f"pack '{c.pack}', connector '{c.id}': namespace "
                    f"'{c.namespace}' is a mounted MCP backend that is not this "
                    f"pack's own; a pack cannot claim another backend's verbs")
            else:
                keep.append(c)
        if len(keep) != len(reg.connectors):
            reg = Registry(connectors=tuple(keep), refused=tuple(refused))
        if reg.refused:
            # Not a failure of the registry: a pack that collides with a
            # connector this gateway still implements, or with a backend that
            # is not its own, is ignored, by itself.
            for line in reg.refused:
                LOG.warning("connectors: %s", line)
            probs = tuple(reg.refused)
    except ManifestError as e:
        # All-or-nothing is `build_registry`'s own rule (#516): a manifest that
        # collides with another is not half-valid. The consequence is that the
        # instance falls back to the behaviour it had before #517 — PACK verbs
        # unmapped — so the refusal has to be loud, and the real place to stop a
        # malformed manifest is the installation (#519).
        #
        # What does NOT fall back is the gateway's own connectors: they are code
        # in the image, and a pack with a typo must not be able to unmap
        # `email.send`. Before #518 that was true because the tables were in
        # Python; it has to stay true now that they are manifests.
        probs = (str(e),)
        reg = _builtin_only()
        LOG.error("connectors: registry non costruibile, i verbi dei pack "
                  "restano senza mappatura (%s)", e)
    except Exception as e:  # noqa: BLE001 — never break a call over this
        probs = (f"{type(e).__name__}: {e}",)
        reg = _builtin_only()
        LOG.error("connectors: registry non costruibile (%s)", e)
    _CACHE = (sig, reg, probs, owners)
    return reg, probs


def _builtin_only() -> Registry:
    """The gateway's own connectors alone. The floor under every failure above."""
    try:
        own = _builtin.manifests()
        return build_registry(own, builtin=tuple(own))
    except Exception as e:  # noqa: BLE001 — a broken image, not a broken pack
        LOG.error("connectors: nemmeno i manifest del gateway sono leggibili "
                  "(%s): nessun connettore, tutto negato", e)
        return Registry()


def invalidate() -> None:
    """Drop the cache. For tests and for whoever installs a pack in-process."""
    global _CACHE
    _CACHE = None


# --------------------------------------------------------------------------
# the two questions the PDP asks
# --------------------------------------------------------------------------

def _owned(verb: str, direction: str) -> tuple[tuple[Connector, VerbMapping], ...]:
    """Every mapping that describes this call — a verb may have more than one
    (`email.send` reads `to`, `cc` and `bcc`)."""
    return registry().mappings_for(verb, direction)


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
        for connector, mapping in _owned(verb, direction):
            if connector.builtin:
                # A gateway file is the gateway's own authority: it is where the
                # native namespaces are declared, not a claim over someone's.
                continue
            try:
                # Riservati: i namespace nativi E quelli dei backend MCP
                # montati che non sono di questo pack (#517, review).
                check_namespace(connector.namespace, [mapping.verb],
                                reserved=reserved_for(connector.pack),
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


def _mappings(verb: str, direction: str) -> tuple[VerbMapping, ...]:
    """The declared mappings, or `()` — never a mapping that breaks the rule.

    A violating mapping is not merely ignored: `enforce_namespace` refuses the
    call outright. Both are needed, and they are not the same statement. Ignoring
    it here says «this mapping does not describe the call»; refusing there says
    «this call does not happen» — without the second, a pack could disable the
    PDP for someone else's verb simply by naming it.
    """
    owned = _owned(verb, direction)
    if not owned or namespace_violation(verb):
        return ()
    return tuple(m for _c, m in owned)


def egress_mappings(verb: str) -> tuple[VerbMapping, ...]:
    return _mappings(verb, "egress")


def source_mappings(verb: str) -> tuple[VerbMapping, ...]:
    return _mappings(verb, "source")


def egress_mapping(verb: str) -> VerbMapping | None:
    """The first declared destination mapping. For the callers that ask «is this
    verb mapped at all» — the full answer is `egress_mappings`."""
    mappings = egress_mappings(verb)
    return mappings[0] if mappings else None


def source_mapping(verb: str) -> VerbMapping | None:
    mappings = source_mappings(verb)
    return mappings[0] if mappings else None


def destinations(mapping: VerbMapping, arguments: dict | None,
                 result: object = None) -> list[str]:
    """The URIs this call reaches, the way `egress.py`'s extractors build them.

    Case is left as the manifest produced it unless the SCHEME says the whole
    URI is case-insensitive (`lowercase: true`, the mail family): `egress._matches`
    lowercases both sides, so normalising everything here would only mangle what
    the gate card shows and what `remember()` writes down for identifiers that
    are case-sensitive (a Drive id, a Telegram handle) — while for an address it
    is the difference between a whitelist entry that matches and one that was
    granted and can never fire.
    """
    source = result if mapping.reads == "result" else arguments
    data = source if isinstance(source, dict) else {}
    raw = data.get(mapping.arg) if mapping.arg else None
    if mapping.normalise:
        items: list[Any] = _normalise.apply(mapping.normalise, str(raw or ""), data)
    elif mapping.multi:
        if isinstance(raw, (list, tuple)):
            items = list(raw)
        else:
            # One field carrying several recipients, as `email.send` does.
            items = str(raw or "").replace(";", ",").split(",")
    else:
        items = [raw]
    lower = _lowercases(mapping.scheme)
    out = []
    for item in items:
        value = str(item or "").strip()
        if not value:
            continue
        uri = mapping.uri_for(value)
        out.append(uri.lower() if lower else uri)
    return out


def _lowercases(scheme: str) -> bool:
    s: Scheme | None = registry().scheme(scheme)
    return bool(s and s.lowercase)


def spec_for(verb: str):
    """`(destination type, extractor)` for a mapped verb, the shape `egress` wants.

    The destinations of one call are the union of its mappings, in declaration
    order: `gdrive.upload` can name a folder *and* a person to share with, and
    both have to be inside the perimeter for the call to happen.
    """
    mappings = egress_mappings(verb)
    if not mappings:
        return None
    first = mappings[0]

    def extract(arguments: dict, _ms=mappings) -> list[str]:
        out: list[str] = []
        for m in _ms:
            for uri in destinations(m, arguments):
                if uri not in out:
                    out.append(uri)
        return out

    return (first.dtype or first.scheme, extract)


def source_uri(verb: str, arguments: dict | None,
               result: object = None) -> str | None:
    """The ONE source of a declared read, or None when there is not exactly one.

    Not exactly one is not an accident to paper over: `email.list` and
    `telegram.inbox` mix several senders in one answer, and the gateway already
    refuses to name a source for them rather than name the wrong one. A `multi:`
    read falls in the same bucket, and so does a verb whose mappings disagree.
    """
    uris: list[str] = []
    for m in source_mappings(verb):
        for uri in destinations(m, arguments, result):
            if uri not in uris:
                uris.append(uri)
    return uris[0] if len(uris) == 1 else None


def is_declared_read(verb: str) -> bool:
    """True when a pack declares this verb as a read of an outside source.

    What makes a verb taint is that it brings in content nobody vouched for —
    `taint._TAINTING_EXACT` is that statement made verb by verb. A pack that
    declares `direction: source` has said the same thing about its own verb.
    """
    return bool(source_mappings(verb))

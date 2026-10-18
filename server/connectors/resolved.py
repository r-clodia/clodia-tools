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

import dataclasses
import logging
import math
import os
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from . import builtin as _builtin
from . import normalise as _normalise
from .manifest import (
    Connector,
    DefaultArg,
    FileArgument,
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
    """The installed manifests, OLDEST FIRST — i.e. in install order.

    The order is the tie-breaker of a clash (clodia-platform#545 §1: the
    incumbent keeps its namespace, the newcomer is the one dropped), so it has
    to mean something. `sorted()` by path meant «whoever sorts first», which is
    not a fact about the instance.

    Install time is NOT the mtime of `pack.yaml` (review of clodia-tools#369):
    the agent-server rewrites that file on setup, flow approval and update,
    so one click on the incumbent made it the «newcomer» and handed its
    namespace to the intruder. It is the moment the GATEWAY first saw the pack
    (`_first_seen`), stamped once in the gateway's own state and never moved.
    """
    try:
        files = list((_DATA / PACKS_DIR).glob("*/pack.yaml"))
    except OSError:  # unreadable data dir: no connectors, never an exception
        return []
    try:
        seen = _first_seen([p.parent.name for p in files], prune=True)
    except Exception:  # noqa: BLE001 — no stamps: path order, never an exception
        LOG.warning("connectors: anzianità dei pack non disponibile")
        seen = {}
    return sorted(files, key=lambda p: (seen.get(p.parent.name, math.inf), str(p)))


#: Packs first seen in this process when the state file cannot be written.
_SEEN_MEMORY: dict[str, dict[str, float]] = {}
#: When each stamped pack was first found missing (pruning grace period).
_MISSING_SINCE: dict[str, dict[str, float]] = {}
#: How long a pack must be missing before its stamp is forgotten.
PRUNE_AFTER_S = 300.0


def _first_seen_path() -> Path:
    """In the gateway-only state dir when there is one (#80), else next to
    the packs' data dir — never in a directory the tests did not choose."""
    if os.environ.get("CLODIA_TOOLS_STATE_DIR"):
        from .. import state_paths
        return state_paths.state_path("connectors-first-seen.json")
    return _DATA / "clodia-tools-connectors-first-seen.json"


def _first_seen(dirs: list[str], *, prune: bool = False) -> dict[str, float]:
    """`{pack dir: when the gateway first saw it}`, stamping the new ones now.

    Never updated afterwards, whatever happens to `pack.yaml`. Packs seen for
    the first time in the same call share the same stamp — the first boot of
    an instance, or two packs dropped in together — and a clash between equal
    stamps drops both sides (`_build_isolated`): no order is invented.
    """
    import json
    import time
    path = _first_seen_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            data = {}
    except (OSError, ValueError):
        data = {}
    # In-process memories are per STATE FILE: two data dirs in one process
    # (tests, a second instance) must not share seniority or grace periods.
    chiave = str(path)
    mem = _SEEN_MEMORY.setdefault(chiave, {})
    mancanti = _MISSING_SINCE.setdefault(chiave, {})
    data = {**mem, **data}
    now = time.time()
    # A stamp that is not a finite positive number (a hand edit, a corrupted
    # file, NaN which json accepts) is no evidence of seniority: that pack
    # counts as arriving NOW, i.e. the newcomer — never the incumbent, and
    # never a value that breaks the ordering (review of #369: NaN looped
    # `_build_isolated` forever, 0 made an intruder the incumbent).
    def _valid(v) -> bool:
        return (isinstance(v, (int, float)) and not isinstance(v, bool)
                and math.isfinite(v) and v > 0)
    bad = [d for d in dirs if d in data and not _valid(data[d])]
    # `prune` only when `dirs` is the COMPLETE list of installed packs, and
    # only after the pack has been missing for a while: an update that
    # replaces the directory non-atomically must not cost the incumbent its
    # seniority in the instant the glob runs (re-review of #369).
    gone = []
    if prune:
        for d in [d for d in list(data) if d not in dirs]:
            since = mancanti.setdefault(d, now)
            if now - since >= PRUNE_AFTER_S:
                gone.append(d)
        for d in dirs:
            mancanti.pop(d, None)
    for d in gone:
        # Stamps of removed packs go: a new pack in the same directory name
        # must not inherit the old one's seniority.
        data.pop(d, None)
        mem.pop(d, None)
        mancanti.pop(d, None)
    new = [d for d in dirs if d not in data] + bad
    if new or gone:
        for d in new:
            data[d] = now
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=1, sort_keys=True),
                           encoding="utf-8")
            os.replace(tmp, path)
        except OSError:
            LOG.warning("connectors: %s non scrivibile, anzianità in memoria", path)
        mem.update({d: data[d] for d in new})
    return {d: float(data[d]) if _valid(data.get(d)) else now for d in dirs}


def seniority() -> dict[str, float]:
    """`{pack name: first seen}` for the installed packs (see `_first_seen`)."""
    import yaml
    out: dict[str, float] = {}
    files = _manifest_files()
    try:
        seen = _first_seen([p.parent.name for p in files])
    except Exception:  # noqa: BLE001
        return {}
    for path in files:
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except Exception:  # noqa: BLE001
            continue
        name = str((loaded or {}).get("name") or path.parent.name) \
            if isinstance(loaded, Mapping) else path.parent.name
        out[name] = seen.get(path.parent.name, math.inf)
    return out


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
#: `{backend: connector id}` — the connector whose native implementation mounts
#: that backend (`tools_api.github_connect`).
_CORE_BACKEND_CONNECTORS = {"github": "github"}
#: The full set, whatever the switch says. Kept for readers that want the
#: shipped list; the checks below use `core_backends()`.
_CORE_BACKENDS = frozenset(_CORE_BACKEND_CONNECTORS)


def core_backends() -> frozenset[str]:
    """The core backends reserved on THIS instance (clodia-platform#525).

    `github` is the core's own mount only while the gateway implements the
    GitHub connector. With `connectors: {github: pack}` it-pack declares the
    connector (namespace `github`) and mounts the GitHub MCP backend itself:
    reserving the name then would refuse exactly the connector that has to
    take over — the same reason `manifest.reserved_namespaces()` follows
    `builtin.released()`. The reservation goes with the switch, and only with
    it: in `native` position, or when the profile cannot be read, `github`
    stays reserved for everyone, which is yesterday's gateway.
    """
    try:
        from .. import instance_profile
        return frozenset(b for b, cid in _CORE_BACKEND_CONNECTORS.items()
                         if instance_profile.connector_mode(cid) != "pack")
    except Exception:  # noqa: BLE001 — in doubt everything stays reserved
        return _CORE_BACKENDS


def norm_name(name: str) -> str:
    """Un nome di backend o di namespace nella forma in cui si confrontano.

    Gli slug dei backend usano `-` (`tools_api._slugify`), i namespace `_`:
    `norm-attiva` e `norm_attiva` sono lo stesso nome, e un confronto a stringa
    lo mancherebbe.

    Pubblica perché la PROPRIETÀ di un backend e il controllo di conflitto che
    decide se montarlo (`tools_api.register_mcp_core`) devono rispondere alla
    stessa domanda: finché il secondo confrontava gli slug grezzi, un nome
    scritto a mano in `config.yaml` passava il 409 e poi risultava lo stesso
    backend qui (clodia-platform#545 §2).
    """
    import re as _re
    return _re.sub(r"[^a-z0-9]", "_", (name or "").strip().lower())


#: Nome storico, usato in tutto questo modulo.
_norm = norm_name


def _backend_entries() -> list[dict]:
    from .. import proxy
    return list(proxy._backends().values())


def _switch_signature() -> frozenset[str]:
    """The connectors the profile hands to packs: part of every cache key here,
    because the switch decides which builtins exist and which core backends
    are reserved (#525) — a registry built in the other position would answer
    for a connector that is not the one in charge."""
    try:
        return _builtin._packaged()
    except Exception:  # noqa: BLE001
        return frozenset()


def mounted_backends() -> frozenset[str]:
    """I nomi (normalizzati) dei backend MCP montati adesso (`mcp_backends`)."""
    return frozenset(_norm(str(b.get("name") or "")) for b in _backend_entries())


def _mount_signature() -> tuple:
    return tuple(sorted((_norm(str(b.get("name") or "")), str(b.get("pack") or ""))
                        for b in _backend_entries()))


def backend_owners(packs: Mapping[str, Mapping] | None = None) -> dict[str, frozenset[str]]:
    """`{pack: backend che quel pack ha DAVVERO montato}`.

    Review di #354 (seconda verifica): la proprietà non si dichiara, si prova.
    Prima bastava elencare un server in `mcp_servers` (del `pack.yaml` o di un
    `plugin.yaml`) per «possedere» il backend omonimo montato dall'admin — e
    quei file stanno su un volume che il gateway non possiede. Ora conta solo
    chi l'ha montato: `register_mcp_core(..., pack=<nome>)`, il percorso del
    mount di un pack, scrive `pack:` nella voce del backend; un backend montato
    da `mcp.add`/Tools senza pack non è di nessuno, quindi è riservato per
    tutti. I backend del core (`_CORE_BACKENDS`) non sono mai di un pack.
    `packs` è ignorato (resta nella firma per i chiamanti).
    """
    out: dict[str, set[str]] = {}
    for b in _backend_entries():
        pack = b.get("pack")
        name = _norm(str(b.get("name") or ""))
        if isinstance(pack, str) and pack and name and name not in core_backends():
            out.setdefault(pack, set()).add(name)
    return {k: frozenset(v) for k, v in out.items()}


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
    return (mounted_backends() | core_backends()) - owned


def reserved_for(pack: str) -> frozenset[str]:
    """Namespace riservati per `pack`: quelli nativi e i backend non suoi.
    (Quelli degli ALTRI pack li riserva `build_registry`.)"""
    from .manifest import core_namespaces
    return core_namespaces() | foreign_backends(pack)


def manifests() -> dict[str, dict]:
    """`{pack name: manifest}` for every installed pack, OLDEST FIRST.

    The datadir copies (`_installed_manifests`), except for a first-party pack
    with a pinned gateway component: its manifest is the PINNED upstream copy
    (clodia-platform#558, `components.store.pinned_manifest`). The datadir is
    written by the agent-server; once code of a pack runs in the gateway, the
    mappings that make the PDP check that code cannot come from there.
    """
    return _with_pinned(_installed_manifests())


def _with_pinned(installed: dict[str, dict]) -> dict[str, dict]:
    try:
        from ..components import store as _store
        first_party = _builtin.FIRST_PARTY_SOURCES
    except Exception:  # noqa: BLE001
        return installed
    out: dict[str, dict] = {}
    for name, doc in installed.items():
        pinned = None
        if name in first_party:
            try:
                pinned = _store.pinned_manifest(name)
            except Exception as e:  # noqa: BLE001
                LOG.error("connectors: pinned manifest of %s unreadable (%s)", name, e)
        out[name] = pinned if pinned is not None else doc
    return out


def _pins_signature() -> tuple:
    try:
        from ..components import store as _store
        return _store.pins_signature()
    except Exception:  # noqa: BLE001
        return ()


def _installed_manifests() -> dict[str, dict]:
    """`{pack name: parsed pack.yaml}` for every installed pack, OLDEST FIRST.

    The iteration order is install order (`_manifest_files`) and it is load
    bearing: `_build_isolated` reads it to know which side of a clash was there
    first. Tests that patch this function declare that order by building the
    dict in it.

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
        if loaded.get("disabled") is True:
            # A disabled pack (clodia-platform#563) counts as absent for
            # everything that reads manifests: its connectors are gone (their
            # verbs fail closed, its topic buttons vanish) and its gateway
            # component is unloaded and its pin forgotten (the floor stays):
            # enabled again, it is pinned anew at the upstream head, as at a
            # first install. Its FILE still counts for
            # seniority (`_manifest_files`), so enabling it again does not make
            # it the newcomer of a clash it was first in.
            LOG.info("connectors: pack '%s' disabled, ignored", name)
            continue
        out[name] = dict(loaded)
    return out


def _strip_foreign_claims(installed: dict) -> tuple[dict, list[str]]:
    """Drop, from packs other than the expected one, any connector entry that
    claims a builtin connector switched to a pack (by id or by namespace).

    `connectors: {github: pack}` means "to it-pack", not "to whoever comes
    first": before this, a pack imported ahead of it-pack held `github` (the
    push lost its egress mapping) and `openai-images` (its transport received
    the API key). Stripped BEFORE the build, so the expected pack is never
    dropped as the "newcomer" of a clash with an intruder (review of #379).
    """
    try:
        claims = _builtin.expected_claims()
    except Exception:  # noqa: BLE001
        claims = {}
    if not claims:
        return installed, []
    out: dict = {}
    refused: list[str] = []
    for pack, meta in installed.items():
        entries = meta.get("connectors") if isinstance(meta, Mapping) else None
        if not isinstance(entries, list):
            out[pack] = meta
            continue
        kept = []
        for e in entries:
            if isinstance(e, Mapping):
                atteso = claims.get(str(e.get("id") or "")) or \
                    claims.get("ns:" + str(e.get("namespace") or ""))
                if atteso and atteso != pack:
                    refused.append(
                        f"pack '{pack}', connector '{e.get('id')}': on this "
                        f"instance that connector is switched to '{atteso}', "
                        f"not to '{pack}'; refused")
                    continue
            kept.append(e)
        out[pack] = {**meta, "connectors": kept} if len(kept) != len(entries) else meta
    return out, refused


def registry() -> Registry:
    """The connectors of the installed packs, rebuilt when the files change."""
    return _build()[0]


def problems() -> tuple[str, ...]:
    """Why the registry is empty, when it is. For diagnostics, not for policy."""
    return _build()[1]


def _build_owners() -> dict[str, frozenset[str]]:
    _build()
    if _CACHE is not None:
        return _CACHE[3]
    try:
        return backend_owners()
    except Exception:  # noqa: BLE001 — no owner: every backend stays reserved
        return {}


#: Fail-safe when the gateway's OWN connectors cannot be built (review of
#: #358, blocker 2). Without them the registry knows no destination and no
#: source, and an empty registry is permissive: `egress.decide` answers
#: «not checked, allowed» and `taint.taints` answers False. These two sets are
#: the namespaces of the builtin manifests' outbound verbs and of their reads
#: (`test_518_fail_closed` keeps them in step with the manifests): in degraded
#: mode the first are DENIED and the second TAINT.
FAILSAFE_EGRESS_NAMESPACES = frozenset({
    "email", "gdrive", "github", "gsheets", "telegram", "web"})
FAILSAFE_SOURCE_NAMESPACES = frozenset({
    "datastore", "email", "gcalendar", "gdocs", "gdrive", "github", "gsheets",
    "telegram", "topic", "web"})


def degraded() -> str:
    """Why the gateway's own connectors are unavailable, or `""`."""
    try:
        return registry().degraded
    except Exception as e:  # noqa: BLE001
        return f"{type(e).__name__}: {e}"


def _builtin_registry() -> Registry:
    """The gateway's own connectors alone. Raises when they cannot be built.

    `reserved=frozenset()`: the namespace rule is about PACKS, and deriving the
    native namespaces imports `server.main` — a dependency the gateway's own
    manifests do not need and whose transient failure used to leave the PDP
    without any table at all.
    """
    own = _builtin.manifests()
    try:
        return build_registry(own, builtin=tuple(own), reserved=frozenset())
    except ManifestError:
        full = _builtin._all()
        if set(full) == set(own) and all(full[k] == own[k] for k in own):
            raise
        # A connector released to a pack can leave the OTHER builtins unable
        # to stand alone (#523): `gdrive.upload` shares with a person on
        # `mailto:`, which `mail.yaml` declares. Healthy, the pack supplies the
        # scheme and the real registry builds (`_build_isolated`); this floor
        # is what remains when it cannot — and a floor that refused to build
        # would deny every native outbound verb of the instance over a pack
        # problem. So the floor is the gateway's manifests as shipped. The
        # released connector's verbs stay refused all the same: they need
        # the PACK's connector held (`main._check_pack_connector_held`), and
        # a builtin is never that.
        LOG.info("connectors: i builtin rimasti non stanno in piedi da soli "
             "(connettori passati ai pack); pavimento = builtin completi")
        return build_registry(full, builtin=tuple(full), reserved=frozenset())


def _build_isolated(own: dict, installed: dict,
                    seniority: Mapping[str, float] | None = None
                    ) -> tuple[Registry, list[str], list[str]]:
    """The registry with every pack that can be held, and why the others not.

    `build_registry` is all-or-nothing on purpose — a manifest that collides is
    not half-valid — but the INSTANCE must not be: one malformed or clashing
    pack used to drop every pack's connectors (and with #517 their egress
    checks). The packs a refusal is about (`ManifestError.packs`) are removed
    and the build is retried. Raises when a refusal names no installed pack
    (then the floor is the builtins alone).

    When a refusal blames MORE than one pack it is a clash, and only the pack
    installed LAST is dropped (clodia-platform#545 §1). Dropping both sides was
    meant to keep the winner from being «whoever sorts first», but it made
    installing an unrelated pack a way to switch off a healthy one: its
    connectors left the registry and its outbound verbs fell into the failsafe,
    i.e. denied. The incumbent is not an arbitrary winner — it is the one whose
    connectors the instance has been using, and the newcomer is the change an
    owner can undo. `installed` is in install order (see `manifests`).
    """
    remaining = dict(installed)
    # When the packs arrived: the gateway's own first-seen stamps if known,
    # else the iteration order (tests build the dict in install order).
    # A pack with no (or no usable) stamp counts as the NEWEST arrival: the
    # unsafe default would be to make it the incumbent (review of #369).
    def _when(p: str, i: int) -> float:
        if not seniority:
            return float(i)
        v = seniority.get(p)
        try:
            v = float(v)
        except (TypeError, ValueError):
            return math.inf
        return v if math.isfinite(v) else math.inf
    order = {p: _when(p, i) for i, p in enumerate(installed)}
    dropped: list[str] = []
    while True:
        try:
            return (build_registry({**own, **remaining}, builtin=tuple(own)),
                    dropped, sorted(set(installed) - set(remaining)))
        except ManifestError as e:
            culprits = [p for p in e.packs if p in remaining]
            if not culprits:
                raise
            if len(culprits) > 1:
                # A clash: the latest arrival loses, the others stay. One per
                # round — a second clash among those left raises again here.
                # Arrivals with the SAME stamp are all dropped: between them
                # there is no incumbent, and inventing one would be the
                # «whoever sorts first» this replaced (review of #369).
                ultimo = max(order.get(p, math.inf) for p in culprits)
                culprits = [p for p in culprits
                            if order.get(p, math.inf) == ultimo] or culprits
            for p in culprits:
                remaining.pop(p)
                dropped.append(f"pack '{p}' refused, its connectors are "
                               f"inactive: {e}")
            LOG.error("connectors: pack rifiutati %s (%s)", culprits, e)


def _failsafe_from(packs: Mapping[str, Mapping],
                   reserved: Iterable[str] = ()) -> tuple[str, ...]:
    """The OUTBOUND verbs the raw manifests of `packs` declare, for packs whose
    connectors could not be built (second verification of #358).

    Without the registry those verbs are simply unmapped, and an unmapped verb
    is «not checked, allowed»: a pack whose manifest is broken would send
    anywhere. Read from the raw YAML, best effort, and only verbs inside the
    connector's own namespace that is neither native nor builtin — a broken
    manifest must not be able to switch off somebody else's verb. A `prefix:
    true` mapping is kept with a trailing `*`.

    «Somebody else» is not only the gateway (clodia-platform#539 §3):

    - `reserved` are the namespaces of the connectors the registry is actually
      HOLDING, i.e. the healthy packs. Whoever is held owns its namespace; a
      manifest that could not be built does not get to speak for it.
    - Mounted MCP backends are off limits too, EXCEPT the ones the broken pack
      itself mounted (`backend_owners()[pack]`). Excluding those as well would
      fail OPEN: once clodia-logic stamps `pack:` on its mounts, a broken
      manifest would leave its own backend's verbs unmapped — «not checked» —
      exactly the case this failsafe exists for. So the exclusion is computed
      per pack.

    Comparisons are normalised on both sides: backend slugs use `-`, namespaces
    `_`.
    """
    try:
        from .manifest import core_namespaces
        taken = {_norm(x) for x in core_namespaces()}
    except Exception:  # noqa: BLE001
        taken = set()
    try:
        taken |= {_norm(c.namespace) for c in _builtin_registry().connectors}
    except Exception:  # noqa: BLE001
        pass
    taken |= {_norm(x) for x in (reserved or ())}
    try:
        mounted = {_norm(b) for b in (mounted_backends() | core_backends())}
    except Exception:  # noqa: BLE001
        mounted = {_norm(b) for b in _CORE_BACKENDS}
    try:
        owners = backend_owners()
    except Exception:  # noqa: BLE001
        # Without proof of ownership no mounted backend is the pack's own.
        owners = {}
    out: set[str] = set()
    for pack, meta in (packs or {}).items():
        # A broken pack's OWN mounted backend is not «somebody else's».
        foreign = mounted - {_norm(b) for b in owners.get(pack, frozenset())}
        off_limits = taken | foreign
        entries = meta.get("connectors") if isinstance(meta, Mapping) else None
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, Mapping):
                continue
            ns = str(entry.get("namespace") or "")
            if not ns or _norm(ns) in off_limits:
                continue
            verbs = entry.get("verbs")
            for v in verbs if isinstance(verbs, list) else []:
                if not isinstance(v, Mapping) or v.get("direction") != "egress":
                    continue
                verb = str(v.get("verb") or "")
                if verb.startswith(f"{ns}."):
                    out.add(verb + ("*" if v.get("prefix") else ""))
    return tuple(sorted(out))


def failsafe_denied(verb: str) -> bool:
    """True when `verb` is an outbound verb of a pack the registry could not
    hold (see `_failsafe_from`): it fails closed instead of passing unchecked."""
    for v in registry().failsafe_verbs:
        if v.endswith("*") and verb.startswith(v[:-1]):
            return True
        if verb == v:
            return True
    return False


def _build() -> tuple[Registry, tuple[str, ...]]:
    global _CACHE
    # Nella firma anche i plugin (chi possiede quale server MCP) e i backend
    # montati: un `mcp.add` fatto dopo la costruzione deve riservare quel
    # namespace alla chiamata successiva, non al prossimo cambio di pack.yaml.
    sig = (_signature(_manifest_files()), _mount_signature(), _switch_signature(),
           _pins_signature())
    if _CACHE is not None and _CACHE[0] == sig:
        return _CACHE[1], _CACHE[2]
    # 1. The floor: the gateway's own connectors. If THEY fail the result is
    #    a DEGRADED registry — native outbound verbs denied, reads tainted (see
    #    `FAILSAFE_*`) — and it is never cached: the next call tries again,
    #    instead of serving «no tables» until somebody touches a pack.yaml.
    try:
        base = _builtin_registry()
    except Exception as e:  # noqa: BLE001 — a broken image, not a broken pack
        reason = f"{type(e).__name__}: {e}"
        LOG.error("connectors: i manifest del gateway non sono costruibili "
                  "(%s): verbi nativi in uscita NEGATI, letture contaminanti",
                  reason)
        try:
            fs = _failsafe_from(manifests())
        except Exception:  # noqa: BLE001
            fs = ()
        return Registry(degraded=reason, failsafe_verbs=fs), (reason,)
    reg, probs, owners = base, (), {}
    cache = True
    try:
        own = _builtin.manifests()
        installed = {k: v for k, v in manifests().items() if k not in own}
        installed, foreign = _strip_foreign_claims(installed)
        owners = backend_owners(installed)
        try:
            anz = seniority()
        except Exception:  # noqa: BLE001 — no stamps: iteration order
            anz = None
        reg, dropped, dropped_packs = _build_isolated(own, installed, anz)
        refused = list(foreign) + list(dropped) + list(reg.refused)
        # Namespace di backend MCP montati: riservati come quelli nativi, salvo
        # il server MCP che il pack monta come proprio. Il connettore che ne
        # prende uno altrui è rifiutato da solo — gli altri restano.
        mounted = mounted_backends() | core_backends()
        keep = []
        for c in reg.connectors:
            if not c.builtin and \
                    _norm(c.namespace) in mounted - owners.get(c.pack, frozenset()):
                refused.append(
                    f"pack '{c.pack}', connector '{c.id}': namespace "
                    f"'{c.namespace}' is a mounted MCP backend that is not this "
                    f"pack's own; a pack cannot claim another backend's verbs")
            else:
                keep.append(c)
        if len(keep) != len(reg.connectors) or dropped or foreign:
            # The outbound verbs of a DROPPED pack fail closed (second
            # verification): unmapped would mean unchecked.
            reg = Registry(connectors=tuple(keep), refused=tuple(refused),
                           failsafe_verbs=_failsafe_from(
                               {p: installed[p] for p in dropped_packs},
                               # The namespaces the registry is HOLDING belong
                               # to whoever holds them: a broken manifest does
                               # not switch off a healthy neighbour (#539 §3).
                               reserved={c.namespace for c in keep}))
        if reg.refused:
            # Not a failure of the registry: a pack that collides with a
            # connector this gateway still implements, or with a backend that
            # is not its own, is ignored, by itself.
            for line in reg.refused:
                LOG.warning("connectors: %s", line)
            probs = tuple(reg.refused)
    except ManifestError as e:
        # A pack manifest the registry cannot hold. The PACK verbs stay
        # unmapped, loudly; the gateway's own connectors do not fall with it —
        # a pack with a typo must not be able to unmap `email.send`.
        probs = (str(e),)
        reg = dataclasses.replace(base, failsafe_verbs=_failsafe_from(installed))
        LOG.error("connectors: registry non costruibile, i verbi dei pack "
                  "restano senza mappatura (%s)", e)
    except Exception as e:  # noqa: BLE001 — never break a call over this
        # Not a statement about the manifests (they did not change): not
        # cached, so a transient failure does not outlive its call.
        probs = (f"{type(e).__name__}: {e}",)
        try:
            fs = _failsafe_from(manifests())
        except Exception:  # noqa: BLE001
            fs = ()
        reg = dataclasses.replace(base, failsafe_verbs=fs)
        cache = False
        LOG.error("connectors: registry non costruibile (%s)", e)
    if cache:
        _CACHE = (sig, reg, probs, owners)
    return reg, probs


def invalidate() -> None:
    """Drop the cache. For tests and for whoever installs a pack in-process."""
    global _CACHE, _TRANSPORTS
    _CACHE = None
    _TRANSPORTS = None


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


def default_arguments(verb: str) -> tuple[str, tuple[DefaultArg, ...]] | None:
    """`(namespace, default dichiarati)` per questo verbo, o None.

    Senza `try`, come per il contesto e per i file: con un registry illeggibile
    la chiamata non parte, invece di partire con un argomento in meno e una
    destinazione vuota.
    """
    hit = registry().defaults_for(verb)
    if hit is None:
        return None
    connector, decls = hit
    return connector.namespace, decls


def file_argument(verb: str) -> tuple[str, FileArgument] | None:
    """`(namespace, dichiarazione)` del file che questo verbo si fa consegnare.

    Senza `try`, per la stessa ragione di `context_arguments`: se il registry
    non è interrogabile la chiamata non parte. L'alternativa sarebbe spedire al
    backend gli argomenti così come sono arrivati — cioè, per un verbo che
    aspetta dei byte, niente; oppure dei byte scelti dal chiamante.
    """
    hit = registry().file_for(verb)
    if hit is None:
        return None
    connector, decl = hit
    return connector.namespace, decl


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


# --------------------------------------------------------------------------
# gli argomenti che il gateway riempie da sé (clodia-platform#522)
# --------------------------------------------------------------------------

def held_by_pack(namespace: str) -> bool:
    """True when the registry HOLDS a pack connector owning `namespace`.

    In `pack` position the gateway dispatches the namespace's verbs to the
    pack backend; if the pack's connector was refused (malformed manifest,
    clash) its context/egress declarations are gone while the backend may
    still be mounted. Calls must then be refused, not passed through with
    the caller's own `agent`/`channel` (review of clodia-tools#374).
    """
    return any(c.namespace == namespace and not c.builtin
               for c in registry().connectors)


def context_arguments(verb: str) -> dict[str, str]:
    """`{nome dell'argomento: fatto da metterci}` per una chiamata a `verb`.

    Solo da connettori che il namespace lo possiedono DAVVERO: la stessa
    verifica di `namespace_violation`, rifatta qui perché la domanda è diversa
    e la risposta no. Là si chiede «questa mappatura descrive la chiamata»; qui
    «questo manifest può scrivere dentro la chiamata», che è più invasivo di
    descriverla — un pack che riuscisse a dichiarare contesto su un verbo
    altrui potrebbe sovrascriverne un argomento a ogni invocazione.
    """
    out: dict[str, str] = {}
    for connector, arg in registry().context_for(verb):
        # Un builtin non può dichiarare contesto (il parser lo rifiuta): il
        # ramo resta perché è la regola, non perché c'è un caso da servire.
        if not connector.builtin:
            try:
                check_namespace(connector.namespace, [verb],
                                reserved=reserved_for(connector.pack),
                                where=f"pack '{connector.pack}', connector "
                                      f"'{connector.id}'")
            except ManifestError as e:
                LOG.warning("connectors: contesto di '%s' ignorato (%s)", verb, e)
                continue
        out[arg.arg] = arg.value
    return out


def fill_context(verb: str, arguments: Mapping | None,
                 values: Mapping[str, object]) -> dict:
    """Una COPIA di `arguments` con gli argomenti di contesto riscritti.

    Sovrascrive sempre: il valore del chiamante non viene né preferito né usato
    come ripiego. Un ripiego sarebbe la falsificazione di prima con un passaggio
    in più — basterebbe chiamare da dove il gateway non sa rispondere per
    tornare a dire da sé chi si è.

    Un fatto che il gateway non ha (fuori da una stanza non c'è un canale) non
    diventa una stringa vuota: l'argomento viene TOLTO. «Non lo so» e «è vuoto»
    sono due risposte diverse, e il connettore deve poterle distinguere —
    `telegram.send` senza canale deve pretendere un `chat_id`, non credere di
    stare in una stanza che si chiama "".
    """
    out = dict(arguments or {})
    for arg, value in context_arguments(verb).items():
        got = values.get(value)
        text = "" if got is None else str(got)
        if text:
            out[arg] = text
        else:
            out.pop(arg, None)
    return out


def is_declared_read(verb: str) -> bool:
    """True when a pack declares this verb as a read of an outside source.

    What makes a verb taint is that it brings in content nobody vouched for —
    `taint._TAINTING_EXACT` is that statement made verb by verb. A pack that
    declares `direction: source` has said the same thing about its own verb.
    """
    return bool(source_mappings(verb))


# --------------------------------------------------------------------------
# provider transports (clodia-platform#523)
# --------------------------------------------------------------------------

def transport_for(connector_id: str,
                  provider_id: str | None = None) -> tuple[str, str] | None:
    """`(backend, tool)` the gateway hands a connector's I/O to, or None.

    Two ways to ask:

    - `transport_for("mail")` — the connector `connector_id` itself: the first
      of its providers that declares a transport (#523, #525);
    - `transport_for("mail", "gmail")` — provider `provider_id` of the
      VOCABULARY `connector_id`, whichever connector contributes it: the owner
      itself or an `extends:` contributor (#524: google-pack's `mail-gmail`
      adds Gmail to the mail vocabulary comms-pack owns). One vocabulary,
      several implementations, each with its own transport.

    Only in `pack` position of the switch that governs the connector holding
    the provider (`builtin.switch_of`: `mail-gmail` follows `google`, not
    `mail`): in `native` the transport is the gateway's own code, and a pack
    declaration must not be able to redirect it — the position is checked
    first so that the answer never depends on a collision happening to refuse
    the pack's connector.

    Only from a pack connector the registry HOLDS: a refused manifest has no
    say. Only from the pack that connector is switched TO (`RELEASED_TO`), so
    a neighbour contributing a provider of the same name to the same
    vocabulary is never elected. And only when the named backend is really
    that pack's own mount (`backend_owners`, the `pack:` stamp of
    `register_mcp_core`): the gateway hands the transport a credential, and a
    manifest naming somebody else's backend would be a way to have it
    delivered there.

    None means «no usable transport»; the caller fails closed on it.
    """
    from .. import instance_profile
    if provider_id is None and \
            instance_profile.connector_mode(_builtin.switch_of(connector_id)) != "pack":
        return None              # native: not even a registry read
    reg = registry()
    if provider_id is None:
        connector = reg.by_id(connector_id)
        provider = next((p for p in connector.providers if p.transport), None) \
            if connector is not None else None
    else:
        connector, provider = next(
            ((c, p) for c in reg.connectors
             if not c.builtin and c.vocabulary == connector_id
             for p in c.providers if p.id == provider_id and p.transport),
            (None, None))
    if connector is None or connector.builtin or provider is None:
        return None
    if instance_profile.connector_mode(_builtin.switch_of(connector.id)) != "pack":
        return None
    expected = _builtin.RELEASED_TO.get(connector.id)
    if provider_id is not None and expected is None:
        # A provider asked for by name is one the gateway routes credentials
        # of a known kind to (Gmail): only a connector it knows may carry it.
        return None
    if expected is not None and expected != connector.pack:
        LOG.warning("connectors: transport of '%s' declared by pack '%s', but "
                    "the connector is switched to '%s': not used",
                    connector.id, connector.pack, expected)
        return None
    backend = provider.transport.backend
    owned = backend_owners().get(connector.pack, frozenset())
    if _norm(backend) not in owned or _norm(backend) in core_backends():
        LOG.warning("connectors: transport of '%s' names backend '%s', which "
                    "pack '%s' has not mounted: not used", connector.id,
                    backend, connector.pack)
        return None
    return backend, provider.transport.tool


#: (signature, declared transport backends) — see `transport_backends`.
_TRANSPORTS: tuple[tuple, frozenset[str]] | None = None


def transport_backends() -> frozenset[str]:
    """The (normalised) MCP backends packs declare as provider transports.

    Gateway-internal sockets: their tools are never listed to an agent and an
    agent's call to one is refused (`main._check_not_transport`). A transport
    takes a raw argv and the files of a credential; exposed as a verb it would
    be a way around every check the gateway's own verbs make.

    Read from the RAW installed manifests, not from the held connectors, and
    whatever the switch says: in `native` position the pack's connector is
    refused for collision with the builtin, but its backend may well be
    mounted — and is no less raw for that. A backend is withheld unless it is
    a mount the declaring pack itself stamped: a pack may hide its own
    mounts, never a neighbour's, a core one or an unclaimed admin mount.
    """
    global _TRANSPORTS
    try:
        from ..components import loader as _components
        serving = _components.serving_connectors()
    except Exception:  # noqa: BLE001
        serving = ()
    sig = (_signature(_manifest_files()), _mount_signature(), _switch_signature(),
           _pins_signature(), serving)
    if _TRANSPORTS is not None and _TRANSPORTS[0] == sig:
        return _TRANSPORTS[1]
    owners = backend_owners()
    out: set[str] = set()
    for pack, meta in manifests().items():
        entries = meta.get("connectors") if isinstance(meta, Mapping) else None
        for entry in entries if isinstance(entries, list) else []:
            providers = entry.get("providers") if isinstance(entry, Mapping) else None
            for p in providers if isinstance(providers, list) else []:
                t = p.get("transport") if isinstance(p, Mapping) else None
                name = _norm(str(t.get("backend") or "")) \
                    if isinstance(t, Mapping) else ""
                if not name or name in core_backends():
                    continue
                # Only the pack's OWN stamped mounts: an unclaimed backend
                # (mounted by an admin, e.g. normattiva) must not be hideable
                # by any pack that names it (review of clodia-tools#378).
                if name not in (owners.get(pack) or ()):
                    continue
                out.add(name)
    # Transports a pack USED to declare (#558): an Update that drops the
    # declaration does not unmount the backend — the agent-server copies the
    # new plugin over the old one and mounts what is declared, it does not
    # unregister what is not — so `mail-transport` (comms-pack 1.4.0) would
    # stay mounted and, no longer declared, become an agent-callable raw mail
    # client. Still the pack's own stamped mount only.
    # A connector now SERVED by its pack's gateway component (#522/#558): the
    # pack's own stamped backend of the same name (`telegram` up to comms-pack
    # 2.0.x) survives the Update until an admin unmounts it — withheld like a
    # transport, so its tools are neither listed twice nor callable (its raw
    # `getUpdates` would race the relay).
    _docs = manifests()
    for pack, cid in serving:
        nomi = {cid}
        for entry in (_docs.get(pack) or {}).get("connectors") or []:
            if isinstance(entry, Mapping) and str(entry.get("id") or "") == cid \
                    and entry.get("namespace"):
                nomi.add(str(entry["namespace"]))
        for n in nomi:
            if _norm(n) in (owners.get(pack) or ()) and _norm(n) not in core_backends():
                out.add(_norm(n))
    from . import builtin as _builtin
    for pack, names in _builtin.RETIRED_TRANSPORTS.items():
        for n in names:
            if _norm(n) in (owners.get(pack) or ()) and _norm(n) not in core_backends():
                out.add(_norm(n))
    result = frozenset(out)
    _TRANSPORTS = (sig, result)
    return result


def is_transport_backend(name: str) -> bool:
    """True when `name` (a backend, or a `backend.tool` verb) is a transport."""
    backend = (name or "").split(".", 1)[0]
    try:
        return _norm(backend) in transport_backends()
    except Exception:  # noqa: BLE001 — in doubt the socket stays closed
        LOG.warning("connectors: transport backends not readable; '%s' "
                    "withheld", name)
        return bool(backend)

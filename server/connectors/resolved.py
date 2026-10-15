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
import os
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from . import builtin as _builtin
from . import normalise as _normalise
from .manifest import (
    Connector,
    ContextArg,
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


def _norm(name: str) -> str:
    """Un nome di backend o di namespace nella forma in cui si confrontano.

    Gli slug dei backend usano `-` (`tools_api._slugify`), i namespace `_`:
    `norm-attiva` e `norm_attiva` sono lo stesso nome, e un confronto a stringa
    lo mancherebbe.
    """
    import re as _re
    return _re.sub(r"[^a-z0-9]", "_", (name or "").strip().lower())


def _backend_entries() -> list[dict]:
    from .. import proxy
    return list(proxy._backends().values())


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
        if isinstance(pack, str) and pack and name and name not in _CORE_BACKENDS:
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
    return build_registry(own, builtin=tuple(own), reserved=frozenset())


def _build_isolated(own: dict, installed: dict
                    ) -> tuple[Registry, list[str], list[str]]:
    """The registry with every pack that can be held, and why the others not.

    `build_registry` is all-or-nothing on purpose — a manifest that collides is
    not half-valid — but the INSTANCE must not be: one malformed or clashing
    pack used to drop every pack's connectors (and with #517 their egress
    checks). The packs a refusal is about (`ManifestError.packs`) are removed
    and the build is retried; a clash removes BOTH sides, so the winner of a
    contested scheme is never «whoever sorts first». Raises when a refusal
    names no installed pack (then the floor is the builtins alone).
    """
    remaining = dict(installed)
    dropped: list[str] = []
    while True:
        try:
            return (build_registry({**own, **remaining}, builtin=tuple(own)),
                    dropped, sorted(set(installed) - set(remaining)))
        except ManifestError as e:
            culprits = [p for p in e.packs if p in remaining]
            if not culprits:
                raise
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
        mounted = {_norm(b) for b in (mounted_backends() | _CORE_BACKENDS)}
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
    # Nella firma anche l'interruttore di migrazione (#522): spostato un
    # connettore, i manifest del gateway non sono più gli stessi e un registry
    # costruito prima descriverebbe l'implementazione che non è in servizio.
    sig = (_signature(_manifest_files()), _mount_signature(),
           tuple(sorted(_builtin.migrated_namespaces())))
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
        owners = backend_owners(installed)
        reg, dropped, dropped_packs = _build_isolated(own, installed)
        refused = list(dropped) + list(reg.refused)
        # Namespace di backend MCP montati: riservati come quelli nativi, salvo
        # il server MCP che il pack monta come proprio. Il connettore che ne
        # prende uno altrui è rifiutato da solo — gli altri restano.
        mounted = mounted_backends() | _CORE_BACKENDS
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
        if len(keep) != len(reg.connectors) or dropped:
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


def context_arguments(verb: str) -> tuple[ContextArg, ...]:
    """Gli argomenti di contesto dichiarati per `verb`, o `()`.

    Senza `try`: se il registry non è leggibile questa funzione solleva e la
    chiamata non parte. È voluto. Ogni altra risposta sarebbe «non so quali
    argomenti riempire, procedo lo stesso», cioè consegnare al pack il canale e
    l'agente *dichiarati dal chiamante* — esattamente il valore falsificabile
    per cui esiste il meccanismo.

    La regola di namespace vale qui come per le mappature (#516/#517): è
    `build_registry` a garantire che un connettore parli solo del proprio
    namespace, quindi `context_for` risponde solo a chi possiede il verbo.
    """
    return registry().context_for(verb)


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


def is_declared_read(verb: str) -> bool:
    """True when a pack declares this verb as a read of an outside source.

    What makes a verb taint is that it brings in content nobody vouched for —
    `taint._TAINTING_EXACT` is that statement made verb by verb. A pack that
    declares `direction: source` has said the same thing about its own verb.
    """
    return bool(source_mappings(verb))

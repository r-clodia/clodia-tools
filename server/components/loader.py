"""Load gateway components and keep them in step with the installed packs.

`reconcile()` is the one operation: it reads the installed manifests, and for
every `target: gateway` component decides trust, ensures a pin (fetching only
when the declared source changed, or on an explicit refresh), verifies the
pinned tree, scans its imports, imports the entry module in its own namespace
(`clodia_components.<pack>.<id>`) and calls `register(host)`. Components no
longer declared are unloaded and their pins dropped.

A component that is refused or fails is disabled ALONE: logged CRITICAL, its
state says why, and every verb of its connectors' namespaces is DENIED with
that reason (`refusal`). The gateway and the other components carry on.

A component whose connectors the GATEWAY still implements on this instance —
the switch of a migration on `native` (`connectors: {google: native}`), so
their namespaces are reserved by native verbs — is pinned but not imported:
status `standby`, no verb, no route, no service, and nothing denied (the
native verbs serve). It is loaded at the first reconcile after the owner
turns the switch to `pack`, and put back on standby when it is turned back.
"""
from __future__ import annotations

import importlib
import importlib.machinery
import importlib.util
import logging
import re
import sys
import threading
import types
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from . import guard, store, trust
from .grammar import GatewayComponent, parse_components
from .host import Host, RouteSpec, ServiceSpec, VerbSpec

LOG = logging.getLogger("clodia-tools.components")

MODULE_ROOT = "clodia_components"

_LOCK = threading.RLock()


@dataclass
class State:
    component: GatewayComponent
    status: str                      # loaded | standby | failed | refused
    reason: str = ""
    commit: str = ""
    tree_sha256: str = ""
    verbs: dict[str, VerbSpec] = field(default_factory=dict)
    routes: dict[str, RouteSpec] = field(default_factory=dict)
    services: dict[str, ServiceSpec] = field(default_factory=dict)

    def describe(self) -> dict:
        c = self.component
        return {"pack": c.pack, "id": c.id, "status": self.status,
                "reason": self.reason, "repo": c.repo, "path": c.path,
                "ref": c.ref, "commit": self.commit,
                "tree_sha256": self.tree_sha256,
                "connectors": list(c.connectors),
                "verbs": sorted(self.verbs), "routes": sorted(self.routes),
                "services": sorted(self.services)}


#: `{"<pack>/<id>": State}` of every declared gateway component.
_STATES: dict[str, State] = {}
#: Problems of the last reconcile that are not about one loaded component.
_PROBLEMS: list[str] = []
_SIGNATURE: tuple | None = None
#: `() -> Fetcher`, replaceable in tests.
fetcher_factory: Callable[[], store.Fetcher] = store.GitHubFetcher


# --------------------------------------------------------------------------
# lookups used by the dispatcher and the routes
# --------------------------------------------------------------------------

def serving_connectors() -> tuple[tuple[str, str], ...]:
    """`(pack, connector id)` of every SERVING component's connectors, sorted.
    Never raises."""
    out: set[tuple[str, str]] = set()
    try:
        reserved = _reserved_namespaces()
        for st in list(_STATES.values()):
            if _serving(st):
                for cid in st.component.connectors:
                    if st.component.namespaces.get(cid) not in reserved:
                        out.add((st.component.pack, str(cid)))
    except Exception:  # noqa: BLE001
        return ()
    return tuple(sorted(out))


def _serving(st: State) -> bool:
    """Loaded AND its namespaces are not the gateway's right now. Between a
    switch moved back to `native` and the next reconcile, the native verbs
    serve and the component's are neither listed nor dispatched."""
    if st.status != "loaded":
        return False
    try:
        return not _standby_reason(st.component)
    except Exception:  # noqa: BLE001 — unknown: the native side keeps them
        return False


def verb(name: str) -> VerbSpec | None:
    for st in list(_STATES.values()):
        spec = st.verbs.get(name)
        if spec is not None and _serving(st):
            return spec
    return None


def has_verb(name: str) -> bool:
    return verb(name) is not None


def tools() -> list:
    out = []
    for st in list(_STATES.values()):
        if _serving(st):
            out += [v.tool for v in st.verbs.values()]
    return out


def route(pack: str, path: str) -> RouteSpec | None:
    path = path.strip("/")
    for st in list(_STATES.values()):
        if _serving(st) and st.component.pack == pack:
            spec = st.routes.get(path)
            if spec is not None:
                return spec
    return None


def service(pack: str, name: str) -> ServiceSpec | None:
    """The service `name` of `pack`'s serving gateway component, or None.

    The caller is gateway code; None means «the component is not here» and the
    caller fails closed (refuses, or answers without what the service adds)."""
    for st in list(_STATES.values()):
        if _serving(st) and st.component.pack == pack:
            spec = st.services.get(name)
            if spec is not None:
                return spec
    return None


def state_of(pack: str) -> dict | None:
    """`describe()` of `pack`'s gateway component, or None if it declares none."""
    for st in list(_STATES.values()):
        if st.component.pack == pack:
            return st.describe()
    return None


def _holds(pack: str, namespace: str) -> bool:
    from ..connectors import resolved
    return any(c.namespace == namespace and c.pack == pack and not c.builtin
               for c in resolved.registry().connectors)


def refusal(name: str) -> str:
    """Why a call to `name` must be DENIED because of a component, or "".

    * a verb in a namespace of a component that failed or was refused (its
      verbs are unknown, but they are that component's, and an `unknown tool`
      would hide why);
    * a registered verb whose connector the pack does not hold in the registry
      right now: without it the PDP would see an unmapped verb, i.e. a call
      nobody checks.
    """
    if "." not in name:
        return ""
    ns = name.split(".", 1)[0]
    spec = verb(name)
    if spec is not None:
        try:
            held = _holds(spec.pack, ns)
            classified = _classified(name)
        except Exception:  # noqa: BLE001 — unknown registry state: fail closed
            held = classified = False
        if not held:
            return (f"the connector of pack '{spec.pack}' for '{ns}' is not active "
                    f"on this instance (manifest refused or absent): '{name}' is "
                    "not served")
        if not classified:
            return (f"'{name}' has no egress, source or taint classification in the "
                    f"pinned manifest of '{spec.pack}': an unclassified component "
                    "verb is not served")
        return ""
    for st in list(_STATES.values()):
        if st.status != "loaded" and ns in st.component.namespaces.values():
            # The namespaces come from a manifest the agent-server writes: a
            # disabled component must never switch off what the gateway or a
            # mounted backend serves (`topic.*`, another pack's MCP tools).
            if _served_elsewhere(name, ns):
                return ""
            if st.status == "standby":
                return (f"gateway component '{st.component.key}' is on standby: the "
                        "connector switch moved to `pack` and the component loads at "
                        "the next reconcile (CLODIA_COMPONENT_INTERVAL seconds) or on "
                        f"POST /internal/components/{st.component.pack}/refresh")
            return (f"gateway component '{st.component.key}' is disabled "
                    f"({st.status}): {st.reason}")
    return ""


def _classified(name: str) -> bool:
    """Defence in depth: the pack's (pinned) manifest says what this verb does —
    an egress or source mapping, a taint prefix that covers it, or an explicit
    `unmapped:` entry (the verb has no destination or source the PDP reads;
    the component enforces its own perimeter)."""
    from ..connectors import resolved
    if resolved.egress_mappings(name) or resolved.source_mappings(name):
        return True
    reg = resolved.registry()
    if name in reg.unmapped_verbs():
        return True
    return any(name.startswith(p) for p in reg.taint_prefixes())


def _served_elsewhere(name: str, ns: str) -> bool:
    try:
        if ns in _reserved_namespaces() or name in set(_native_names()):
            return True
        from .. import proxy
        return bool(proxy.is_proxied(name))
    except Exception:  # noqa: BLE001 — in doubt, do not deny someone else's verb
        return True


def status() -> list[dict]:
    return [st.describe() for st in list(_STATES.values())]


def problems() -> list[str]:
    return list(_PROBLEMS)


# --------------------------------------------------------------------------
# module namespace
# --------------------------------------------------------------------------

def _ident(s: str) -> str:
    return re.sub(r"[^0-9a-zA-Z_]", "_", s)


def module_name(component: GatewayComponent) -> str:
    return f"{MODULE_ROOT}.{_ident(component.pack)}.{_ident(component.id)}"


def _ensure_parent(name: str) -> None:
    if name in sys.modules:
        return
    mod = types.ModuleType(name)
    mod.__path__ = []          # namespace without a filesystem location
    mod.__spec__ = importlib.machinery.ModuleSpec(name, None, is_package=True)
    sys.modules[name] = mod


def _purge(prefix: str) -> None:
    for k in [k for k in sys.modules if k == prefix or k.startswith(prefix + ".")]:
        sys.modules.pop(k, None)
    importlib.invalidate_caches()


class _NoBytecodeLoader(importlib.machinery.SourceFileLoader):
    """Source loader that never writes `__pycache__` next to pinned code.

    `sys.dont_write_bytecode` is only set while the entry module is imported;
    a component that imports its own modules later — inside `register`, or
    lazily from a handler — would otherwise drop `.pyc` files into the pinned
    tree, change its hash and fail `store.verify` at the next reconcile
    (found by google-pack, #558)."""

    def set_data(self, path, data, *, _mode=0o666):  # noqa: D401
        return None

    def get_code(self, fullname):
        """Always compile from the (hash-verified) source: never read a
        `.pyc`, e.g. one found under a PYTHONPYCACHEPREFIX (review of #383)."""
        path = self.get_filename(fullname)
        return compile(self.get_data(path), path, "exec", dont_inherit=True)


class _ComponentFinder:
    """Meta-path finder for `clodia_components.*`: same files the default
    path finder would find under the package's `__path__`, loaded with
    `_NoBytecodeLoader`, and never a `.pyc` (a pinned tree has none)."""

    def find_spec(self, fullname, path, target=None):
        if not fullname.startswith(MODULE_ROOT + ".") or not path:
            return None
        import os
        leaf = fullname.rsplit(".", 1)[1]
        for entry in path:
            pkg_init = os.path.join(entry, leaf, "__init__.py")
            if os.path.isfile(pkg_init):
                return importlib.util.spec_from_file_location(
                    fullname, pkg_init, loader=_NoBytecodeLoader(fullname, pkg_init),
                    submodule_search_locations=[os.path.join(entry, leaf)])
            src = os.path.join(entry, leaf + ".py")
            if os.path.isfile(src):
                return importlib.util.spec_from_file_location(
                    fullname, src, loader=_NoBytecodeLoader(fullname, src))
        return None

    def invalidate_caches(self) -> None:
        return None


_FINDER = _ComponentFinder()


def _install_finder() -> None:
    if not any(isinstance(f, _ComponentFinder) for f in sys.meta_path):
        sys.meta_path.insert(0, _FINDER)


def _import(component: GatewayComponent, directory) -> Any:
    pkg = module_name(component)
    _install_finder()
    _purge(pkg)
    _ensure_parent(MODULE_ROOT)
    _ensure_parent(pkg.rsplit(".", 1)[0])
    mod = types.ModuleType(pkg)
    mod.__path__ = [str(directory)]
    spec = importlib.machinery.ModuleSpec(pkg, None, is_package=True)
    spec.submodule_search_locations = [str(directory)]
    mod.__spec__ = spec
    mod.__package__ = pkg
    sys.modules[pkg] = mod
    # No `__pycache__` in the pinned tree: it would change the tree hash and
    # put code next to the source that the guard did not read.
    before = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        return importlib.import_module(f"{pkg}.{component.entry}")
    finally:
        sys.dont_write_bytecode = before


# --------------------------------------------------------------------------
# load / unload
# --------------------------------------------------------------------------

def _native_names() -> list[str]:
    from .. import main
    return main.all_native_verb_names()


def _reserved_namespaces() -> frozenset[str]:
    from ..connectors.manifest import core_namespaces
    return core_namespaces()


def _standby_reason(component: GatewayComponent) -> str:
    """Why `component` must not run now although it is trusted and pinned, or "".

    Its connectors' namespaces are reserved by the gateway: the instance switch
    of that migration is on `native`, so the native verbs are listed and
    served, and registering the component's would be refused anyway."""
    reserved = _reserved_namespaces()
    mine = set(component.namespaces.values())
    taken = sorted(ns for ns in mine if ns in reserved)
    # Standby only when it would serve NOTHING: a component of several
    # connectors (comms-pack: mail + Telegram) runs for the ones on `pack` and
    # registers only those (`host.serves`) — one pack, one gateway component.
    if taken and set(taken) == mine:
        return (f"the gateway implements {taken} natively on this instance (the "
                "connector switch is on `native`); the component loads when the "
                "owner turns it to `pack`")
    return ""


def _taken_by(name: str) -> str | None:
    for key, st in _STATES.items():
        if name in st.verbs and st.status == "loaded":
            return key
    return None


def _fail(component: GatewayComponent, status: str, reason: str, pin=None) -> State:
    LOG.critical("components: gateway component %s %s: %s — its verbs are DENIED, "
                 "the gateway carries on", component.key, status, reason)
    _purge(module_name(component))
    return State(component=component, status=status, reason=reason,
                 commit=getattr(pin, "commit", "") or "",
                 tree_sha256=getattr(pin, "tree_sha256", "") or "")


def load(component: GatewayComponent, pin: store.Pin) -> State:
    """Import and register one pinned component. Never raises."""
    try:
        problem = store.verify(pin)
        if problem:
            return _fail(component, "failed", problem, pin)
        directory = pin.dir.resolve()
        violations = guard.scan_tree(directory)
        if violations:
            return _fail(component, "refused",
                         "import guard: " + "; ".join(violations[:5]), pin)
        module = _import(component, directory)
        register = getattr(module, "register", None)
        if not callable(register):
            return _fail(component, "failed",
                         f"entry '{component.entry}' has no register(host)", pin)
        host = Host(component, native_names=_native_names,
                    reserved_namespaces=_reserved_namespaces, taken=_taken_by)
        try:
            register(host)
        finally:
            host.close()
    except (Exception, SystemExit) as e:  # noqa: BLE001 — a component never takes the gateway down
        return _fail(component, "failed", f"{type(e).__name__}: {e}", pin)
    LOG.warning("components: %s loaded at %s (%d verb(s), %d route(s))",
                component.key, pin.commit[:12], len(host.verbs), len(host.routes))
    return State(component=component, status="loaded", commit=pin.commit,
                 tree_sha256=pin.tree_sha256, verbs=dict(host.verbs),
                 routes=dict(host.routes), services=dict(host.services))


def unload(key: str) -> None:
    with _LOCK:
        st = _STATES.pop(key, None)
        if st is not None:
            _purge(module_name(st.component))


def reset() -> None:
    """Forget every component (tests)."""
    global _SIGNATURE
    with _LOCK:
        for key in list(_STATES):
            unload(key)
        _PROBLEMS.clear()
        _SIGNATURE = None


# --------------------------------------------------------------------------
# reconcile
# --------------------------------------------------------------------------

def _declared() -> tuple[dict[str, tuple[GatewayComponent, Mapping]], list[str]]:
    from ..connectors import resolved
    out: dict[str, tuple[GatewayComponent, Mapping]] = {}
    probs: list[str] = []
    for pack, manifest in resolved.manifests().items():
        comps, p = parse_components(manifest, pack=pack)
        probs += p
        for c in comps:
            out[c.key] = (c, manifest)
    return out, probs


def _signature() -> tuple:
    from ..connectors import resolved
    try:
        return (resolved._signature(resolved._manifest_files()),
                resolved._switch_signature())
    except Exception:  # noqa: BLE001
        return ()


def reconcile(*, force: bool = False, refresh_pack: str | None = None,
              allow_downgrade: bool = False) -> list[dict]:
    """Bring the loaded components in line with the installed manifests.

    `refresh_pack` re-resolves that pack's refs upstream (pack Update);
    `allow_downgrade` is honoured only together with it, and only the owner
    path passes it. Never raises."""
    global _SIGNATURE
    with _LOCK:
        sig = _signature()
        if not force and refresh_pack is None and sig and sig == _SIGNATURE:
            return status()
        try:
            declared, probs = _declared()
        except Exception as e:  # noqa: BLE001 — keep what runs, try again later
            LOG.error("components: installed manifests unreadable (%s)", e)
            return status()
        _PROBLEMS[:] = probs
        for p in probs:
            LOG.error("components: %s", p)
        for key in [k for k in _STATES if k not in declared]:
            LOG.warning("components: %s no longer declared, unloaded", key)
            unload(key)
            pack, cid = key.split("/", 1)
            store.forget(pack, cid)
        fetcher = None
        for key, (comp, manifest) in declared.items():
            current = _STATES.get(key)
            why = trust.refusal(comp, manifest)
            if why:
                if current is None or current.status != "refused" or current.reason != why:
                    _STATES[key] = _fail(comp, "refused", why)
                continue
            refresh = refresh_pack == comp.pack
            try:
                if fetcher is None:
                    fetcher = fetcher_factory()
                pin = store.ensure(comp, fetcher, refresh=refresh,
                                   allow_downgrade=allow_downgrade and refresh)
                # What runs is what the PINNED manifest declares — entry,
                # path, connectors, credentials — not the trigger.
                comp = store.pinned_component(pin)
            except Exception as e:  # noqa: BLE001
                reason = f"fetch: {type(e).__name__}: {e}"
                if current is not None and current.status == "loaded" and \
                        current.component.source() == comp.source():
                    # Same declaration, upstream unreachable or refusing a move:
                    # what runs keeps running, pinned.
                    LOG.error("components: %s keeps %s (%s)", key,
                              current.commit[:12], reason)
                    current.reason = reason
                    continue
                unload(key)
                _STATES[key] = _fail(comp, "failed", reason)
                continue
            idle = _standby_reason(comp)
            if idle:
                if current is None or current.status != "standby" or \
                        current.commit != pin.commit or current.reason != idle:
                    unload(key)
                    LOG.warning("components: %s pinned at %s, on standby: %s",
                                key, pin.commit[:12], idle)
                    _STATES[key] = State(component=comp, status="standby",
                                         reason=idle, commit=pin.commit,
                                         tree_sha256=pin.tree_sha256)
                continue
            if current is not None and current.status == "loaded" and \
                    current.commit == pin.commit and current.component == comp:
                current.reason = ""
                continue
            unload(key)
            _STATES[key] = load(comp, pin)
        _SIGNATURE = sig
        return status()


async def reconcile_loop(interval: int | None = None) -> None:
    """Kept alive by the gateway's lifespan: the first round loads at boot."""
    import asyncio
    import os
    every = interval or int(os.environ.get("CLODIA_COMPONENT_INTERVAL") or 60)
    while True:
        try:
            await asyncio.to_thread(reconcile)
        except Exception as e:  # noqa: BLE001 — the loop must survive
            LOG.error("components: reconcile failed (%s)", e)
        await asyncio.sleep(every)

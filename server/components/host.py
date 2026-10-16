"""The host API: the ONLY thing a gateway component gets (clodia-platform#558).

`register(host)` is called once, at load. Everything a component may do with
the gateway goes through the object it receives:

    host.register_verb(tool, handler, *, offload=True)
    host.register_route(path, methods, handler, *, auth="owner")
    host.credentials(prefix)  -> ScopedCredentials
    host.topics               -> read_file / put_file with membership checks
    host.note_crossing(data=None, *, path=None, kind="file")
    host.scratch_path(path)   -> str inside the caller's spawn scratch
    host.config(key, default=None) / host.set_config(key, value)
    host.agent() / host.channel() / host.principal()
    host.log                  -> logging.Logger

Registration is closed when `register` returns: a component cannot add a verb
later, from a handler or a thread.

Verbs join the native catalogue and go through the SAME `call_tool` path as a
native verb — whitelist, deny, unattended block, gates, the egress PDP from the
pack's connector mappings, taint, audit. The dispatcher calls the handler at
the point where it calls a native handler; nothing in this module decides
whether a call is allowed.
"""
from __future__ import annotations

import asyncio
import contextvars
import inspect
import json
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from mcp.types import Tool

from . import trust
from .grammar import GatewayComponent

ROUTE_AUTH = ("owner", "admin")
ROUTE_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
#: Sub-paths an existing core route already answers under `/tools/<x>/…`.
RESERVED_ROUTE_PATHS = frozenset({"test"})
_ROUTE_PATH = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}(/[a-z0-9][a-z0-9_-]{0,39}){0,4}$")
_VERB = re.compile(r"^[a-z][a-z0-9_]{0,31}\.[A-Za-z0-9_.]{1,63}$")
_CONFIG_KEY = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")

#: Set by the route dispatcher while an OWNER-authenticated route runs: the
#: only context in which a component may write its config (perimeter).
OWNER_REQUEST: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "component_owner_request", default=False)


class HostError(PermissionError):
    """A component asked the host for something it may not have."""


@dataclass(frozen=True)
class VerbSpec:
    component: str          # "<pack>/<id>"
    pack: str
    namespace: str
    tool: Tool
    handler: Callable
    offload: bool


@dataclass(frozen=True)
class RouteSpec:
    component: str
    pack: str
    path: str               # relative, under /tools/<pack>/
    methods: frozenset[str]
    handler: Callable
    auth: str


# --------------------------------------------------------------------------
# credentials
# --------------------------------------------------------------------------

class ScopedCredentials:
    """Vault access limited to ONE declared prefix (or exact entry).

    Every name is checked against the prefix before the vault is touched, and
    the prefix is checked again against the instance (switch, releases) at
    every call: an owner who flips a switch back takes the access back at once.
    """

    def __init__(self, component: GatewayComponent, prefix: str) -> None:
        self._component = component
        self._prefix = prefix

    @property
    def prefix(self) -> str:
        return self._prefix

    def _check(self, name: str) -> None:
        problem = trust.credential_problem(self._component, self._prefix)
        if problem:
            raise HostError(problem)
        if not trust.credential_matches(self._prefix, str(name or "")):
            raise HostError(f"credential '{name}' is outside the scope "
                            f"'{self._prefix}' of component '{self._component.key}'")

    def list(self) -> list[str]:
        """Names (never values) of the vault entries under this scope."""
        from .. import vault
        problem = trust.credential_problem(self._component, self._prefix)
        if problem:
            raise HostError(problem)
        return [n for n in vault.store_names()
                if trust.credential_matches(self._prefix, n)]

    def has(self, name: str) -> bool:
        from .. import vault
        self._check(name)
        return vault.has_credential(name)

    def read(self, name: str) -> dict:
        """The bundle, for the CALLING AGENT: its vault grant is enforced and
        the access audited (`vault.get_secret`)."""
        from .. import vault
        from ..whitelist import agent_name
        self._check(name)
        return vault.get_secret(agent_name(), name)

    def read_internal(self, name: str) -> dict:
        """The bundle, as gateway infrastructure (no agent grant): for the
        credentials the component itself uses — an OAuth app client, a token
        refresh. Audited as `system`."""
        from .. import vault
        self._check(name)
        return vault.read_internal(name)

    def deposit(self, name: str, bundle: dict, *, cred_type: str = "opaque",
                grant_agents: Iterable[str] = ()) -> None:
        from .. import vault
        self._check(name)
        if not isinstance(bundle, dict):
            raise HostError("a credential bundle is a dict")
        vault.deposit(name, bundle, cred_type=cred_type,
                      grant_agents=list(grant_agents))

    def remove(self, name: str) -> bool:
        from .. import vault
        self._check(name)
        return vault.remove(name)


# --------------------------------------------------------------------------
# topics
# --------------------------------------------------------------------------

class Topics:
    """Topic file I/O with the gateway's compartment checks and crossing notes."""

    #: A component writes what came from outside (`untrusted`) or what it made
    #: (`agent`); `trusted` is the owner's word and not a component's to give.
    PROVENANCES = ("untrusted", "agent")

    def read_file(self, tier: str, name: str, path: str) -> bytes:
        from .. import main
        svc = main._topics()
        main._require_topic_member(svc, tier, name)
        data = svc.read_file(tier, name, path)
        main._note_crossing(data=data, kind="file")
        return data

    def put_file(self, tier: str, name: str, path: str, data: bytes, *,
                 provenance: str = "untrusted") -> dict:
        from .. import main
        from .. import taint as _taint
        from ..whitelist import agent_name
        if provenance not in self.PROVENANCES:
            raise HostError(f"provenance '{provenance}' not allowed for a "
                            f"component (one of {list(self.PROVENANCES)})")
        svc = main._topics()
        main._require_topic_member(svc, tier, name, mutating=True)
        who = agent_name()
        r = svc.put_file(tier, name, path, bytes(data), provenance, by=who)
        if provenance == "untrusted":
            _taint.mark(f"{tier}/{name}", "file", path, who)
        return r


# --------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------

def _config_path():
    from . import store
    return store.root() / "config.json"


def _load_config() -> dict:
    try:
        data = json.loads(_config_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


# --------------------------------------------------------------------------
# the host
# --------------------------------------------------------------------------

class Host:
    def __init__(self, component: GatewayComponent, *,
                 native_names: Callable[[], Iterable[str]],
                 reserved_namespaces: Callable[[], Iterable[str]],
                 taken: Callable[[str], str | None]) -> None:
        self._c = component
        self._native_names = native_names
        self._reserved = reserved_namespaces
        self._taken = taken
        self._open = True
        self.verbs: dict[str, VerbSpec] = {}
        self.routes: dict[str, RouteSpec] = {}
        self.topics = Topics()
        self.log = logging.getLogger(
            f"clodia-tools.component.{component.pack}.{component.id}")

    # -- registration -----------------------------------------------------

    def close(self) -> None:
        self._open = False

    def _require_open(self) -> None:
        if not self._open:
            raise HostError("registration is closed: verbs and routes are "
                            "registered from register(host) only")

    def register_verb(self, tool: Tool, handler: Callable, *,
                      offload: bool = True) -> None:
        self._require_open()
        if not isinstance(tool, Tool):
            raise HostError("register_verb takes an mcp.types.Tool")
        if not callable(handler):
            raise HostError(f"handler of '{tool.name}' is not callable")
        name = tool.name
        if not _VERB.match(name or ""):
            raise HostError(f"'{name}' is not a valid verb name")
        ns = name.split(".", 1)[0]
        own = set(self._c.namespaces.values())
        if ns not in own:
            raise HostError(
                f"'{name}' is outside the namespaces of the connectors this "
                f"component implements ({sorted(own)})")
        if ns in set(self._reserved()) or name in set(self._native_names()):
            raise HostError(f"'{name}' belongs to the gateway, not to a pack")
        other = self._taken(name)
        if other and other != self._c.key:
            raise HostError(f"'{name}' is already registered by component '{other}'")
        if name in self.verbs:
            raise HostError(f"'{name}' registered twice")
        if inspect.iscoroutinefunction(handler) and offload:
            offload = False       # a coroutine runs on the loop, not in a thread
        self.verbs[name] = VerbSpec(component=self._c.key, pack=self._c.pack,
                                    namespace=ns, tool=tool, handler=handler,
                                    offload=offload)

    def register_route(self, path: str, methods: Iterable[str], handler: Callable,
                       *, auth: str = "owner") -> None:
        """Mount `handler(request)` at `/tools/<pack>/<path>`.

        `auth` is `owner` (a human admin or the trusted core: for anything that
        widens a perimeter or stores a credential) or `admin` (also the
        agent-server's signed role). There is no public route."""
        self._require_open()
        if auth not in ROUTE_AUTH:
            raise HostError(f"route auth must be one of {list(ROUTE_AUTH)}, "
                            f"not '{auth}': a component route is never public")
        path = str(path or "").strip("/")
        if not _ROUTE_PATH.match(path) or path in RESERVED_ROUTE_PATHS:
            raise HostError(f"route path '{path}' is invalid or reserved")
        ms = frozenset(str(m).upper() for m in methods)
        if not ms or not ms <= ROUTE_METHODS:
            raise HostError(f"route methods must be a subset of {sorted(ROUTE_METHODS)}")
        if not callable(handler):
            raise HostError(f"handler of route '{path}' is not callable")
        if path in self.routes:
            raise HostError(f"route '{path}' registered twice")
        self.routes[path] = RouteSpec(component=self._c.key, pack=self._c.pack,
                                      path=path, methods=ms, handler=handler,
                                      auth=auth)

    # -- capabilities -----------------------------------------------------

    def credentials(self, prefix: str) -> ScopedCredentials:
        problem = trust.credential_problem(self._c, str(prefix or ""))
        if problem:
            raise HostError(problem)
        return ScopedCredentials(self._c, prefix)

    def note_crossing(self, data: bytes | None = None, *, path: str | None = None,
                      kind: str = "file") -> None:
        """Record the hash of bytes about to leave (audit of the call)."""
        from .. import main
        if data is not None:
            main._note_crossing(data=bytes(data), kind=kind)
        else:
            # An agent path: hashed only inside the caller's scratch.
            main._note_crossing(path, kind=kind)

    def scratch_path(self, path: str) -> str:
        from .. import main
        return main._safe_scratch_path(path)

    def config(self, key: str, default: Any = None) -> Any:
        conf = (_load_config().get(self._c.pack) or {}).get(self._c.id) or {}
        return conf.get(key, default)

    def set_config(self, key: str, value: Any) -> None:
        """Owner-only: callable from inside an `auth="owner"` route."""
        if not OWNER_REQUEST.get():
            raise HostError("component config is written by the owner only, "
                            "from an owner route")
        if not _CONFIG_KEY.match(str(key or "")):
            raise HostError(f"invalid config key '{key}'")
        json.dumps(value)        # must be JSON
        from . import store
        with store._LOCK:
            data = _load_config()
            data.setdefault(self._c.pack, {}).setdefault(self._c.id, {})[key] = value
            p = _config_path()
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
            os.chmod(tmp, 0o600)
            os.replace(tmp, p)

    def agent(self) -> str:
        from ..whitelist import agent_name
        return agent_name()

    def channel(self) -> str | None:
        from ..whitelist import current_channel
        return current_channel()

    def principal(self) -> str | None:
        from ..whitelist import current_principal
        return current_principal()


async def invoke(spec: VerbSpec, arguments: dict) -> Any:
    """Run a verb handler the way the dispatcher runs a native one."""
    if inspect.iscoroutinefunction(spec.handler):
        return await spec.handler(arguments)
    if spec.offload:
        return await asyncio.to_thread(spec.handler, arguments)
    return spec.handler(arguments)

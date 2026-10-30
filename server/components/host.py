"""The host API: the ONLY thing a gateway component gets (clodia-platform#558).

`register(host)` is called once, at load. Everything a component may do with
the gateway goes through the object it receives:

    host.register_verb(tool, handler, *, offload=True)
    host.register_route(path, methods, handler, *, auth="owner")
    host.register_service(name, fn)
    host.service(pack, name)  -> another pack's component service (granted pairs)
    host.credentials(prefix)  -> ScopedCredentials
    host.perimeter            -> read-only perimeter facts (config, lists, topics,
                                 mailbox whitelist, strict ingress, vetted sources,
                                 the room's approved repositories)
    host.topics               -> read_file / put_file with membership checks
    host.note_crossing(data=None, *, path=None, kind="file")
    host.scratch_path(path)   -> str inside the caller's spawn scratch
    host.config(key, default=None) / host.set_config(key, value)
    host.agent() / host.channel() / host.principal() / host.current_topic()
    host.git_credential()     -> the room's git token, only serving `github`
    host.tool_allowed(verb)   -> the whitelist's answer (raises PermissionError)
    host.audit_decision(verb, kind, result, *, reason_class=None)
                              -> a decision record; AuditUnavailable if unwritable
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
_STATE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_SERVICE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
#: One plain path segment of a room cache entry (#637): no separator, no `..`.
_ROOM_ENTRY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")

#: Set by the route dispatcher while an OWNER-authenticated route runs: the
#: only context in which a component may write its config (perimeter).
OWNER_REQUEST: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "component_owner_request", default=False)


class HostError(PermissionError):
    """A component asked the host for something it may not have."""


class AuditUnavailable(RuntimeError):
    """The audit trail cannot be written (`host.audit_decision`). A component
    whose decision must be on record before it acts — strict ingress, #503 —
    refuses the call on this, as the native code refused on the trail's
    `AuditWriteError`."""


@dataclass(frozen=True)
class VerbSpec:
    component: str          # "<pack>/<id>"
    pack: str
    namespace: str
    tool: Tool
    handler: Callable
    offload: bool


@dataclass(frozen=True)
class ServiceSpec:
    """A callable the GATEWAY calls itself (never an agent): the hooks through
    which core code that stays in the gateway — the confinement API, the
    labels of a whitelist, the PDP's argument lookup, a mail provider — asks
    the component for what only the component knows how to do."""
    component: str
    pack: str
    name: str
    handler: Callable


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
    the prefix is checked again (`trust.credential_problem`) at every call.
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

    def read_file(self, tier: str, name: str, path: str, *,
                  crossing: str | None = "file") -> bytes:
        """The bytes of a topic file, for a caller that is a member.

        `crossing` is the kind under which the bytes are recorded as leaving
        (`file`); `None` when the component records them itself under its own
        kind once they actually leave — `email.send(topic_files=…)` notes them
        as `attachment` after the agent's own attachments, the native order."""
        from .. import main
        svc = main._topics()
        main._require_topic_member(svc, tier, name)
        data = svc.read_file(tier, name, path)
        if crossing:
            main._note_crossing(data=data, kind=crossing)
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
# perimeter
# --------------------------------------------------------------------------

class Perimeter:
    """Read-only facts about the perimeter, as the GATEWAY holds them.

    The perimeter is declared in places the agent-server cannot write — the
    gateway's config (`gdrive_roots`, the egress/source lists), the signed
    channel claim, the topic's `meta` — and the component reads it here, per
    call, never from a copy of its own. Nothing here writes: moving the
    perimeter stays an admin action on the gateway's own endpoints.
    """

    def gdrive_roots(self) -> dict:
        """The `gdrive_roots` mapping of the gateway config, as written there
        (`{account | "*": [folder id, …] | folder id}`), or `{}`."""
        import copy
        from .. import whitelist
        raw = (getattr(whitelist, "CONFIG", None) or {}).get("gdrive_roots") or {}
        return copy.deepcopy(raw) if isinstance(raw, dict) else {}

    def egress_uris(self, scope: str | None = None) -> list[str]:
        """The egress entries in force for the current call: global PLUS the
        calling room's (or `scope`'s), as `egress.effective_uris` gives them."""
        from .. import egress
        return list(egress.effective_uris("egress", scope))

    def approved_calendars(self, scope: str | None = None) -> list[str]:
        """Calendar ids approved by `gcal:` entries for the current call."""
        from .. import egress
        return list(egress.approved_calendars(scope))

    def calendar_allowed(self, calendar_id: str, scope: str | None = None) -> bool:
        """Is `calendar_id` approved for the current call (`gcal:` matching,
        domain wildcards and case included)?"""
        from .. import egress
        return bool(egress.calendar_allowed(calendar_id, scope))

    def topic_drive_folders(self, tier: str, name: str) -> list[dict]:
        """The Drive folders a topic declares (`meta.drive_folders`), read by
        the gateway. A perimeter fact of the room the CALL comes from — the
        caller passes the tier/name of the signed channel, not an argument."""
        from .. import main
        from ..topics.service import drive_folders
        meta = (main._topics().open(tier, name) or {}).get("meta") or {}
        return [dict(d) for d in drive_folders(meta)]

    def in_channel(self) -> bool:
        """True when the call comes from a topic channel (signed claim)."""
        from ..whitelist import in_channel
        return bool(in_channel())

    # -- mail (#558, comms-pack) --------------------------------------------

    def mailbox_allowed(self, direction: str, address: str,
                        scope: str | None = None) -> bool:
        """Is the mailbox `address` usable in `direction` (`inbox` | `outbox`)
        for the current call (or `scope`)? `egress.mailbox_allowed`: the
        `inbox:`/`outbox:` entries, global plus the room's, strict ingress
        included."""
        from .. import egress
        if direction == "inbox" and self.courier_tag():
            # The courier's message-box call (#583): the colony mailbox, and
            # only it, for a row `rooms()` offered with this room's code — or
            # for the one index search of every code (#585).
            from ..mail_courier_api import colony_mailbox
            _acct, colony = colony_mailbox()
            return bool(colony) and (address or "").strip().lower() == colony
        return bool(egress.mailbox_allowed(direction, address, scope))

    def colony_address(self) -> str:
        """The colony mailbox's address (#583), "" while unset. Mail on it
        addressed to `local+X@` belongs to the topics' message boxes ONLY: a
        component hides it from every other read (review of #416)."""
        from ..mail_courier_api import colony_mailbox
        return colony_mailbox()[1]

    def courier_tag(self) -> str:
        """The message-box code of the courier call in progress (#583), "" for
        any other call. Set by the gateway's courier route, never by a caller:
        a component filters the colony mailbox's mail to `box+TAG@…` with it."""
        from ..mail_courier_api import COURIER_TAG
        return COURIER_TAG.get()

    def strict_scope(self) -> str | None:
        """The room of the current call IF it is a strict-ingress channel
        (#503), else None. Read from the signed claim and the gateway config,
        never from an argument."""
        from .. import egress
        scope = egress._scope_of_call()
        return scope if scope and egress.ingress_strict(scope) else None

    def room_declares_sender(self, header: str) -> bool:
        """Is the sender `header` (`Nome <a@b.it>` or `a@b.it`) declared by the
        CURRENT room's `mailfrom:` entries (#576)? The room comes from the
        signed claim, never an argument; outside a room → False. What the mail
        courier delivers into a topic: participants never count; global entries
        count only on a message-box call (`courier_tag()` set, #585), where the
        subaddress already names the one room."""
        from .. import egress
        from ..mail_courier_api import BOX_INDEX_TAG
        tag = self.courier_tag()
        if tag and tag != BOX_INDEX_TAG and egress._scope_of_call():
            # The room's own address (`box+CODE@`) always delivers into its
            # room, whoever sends (owner, 27 Oct 2026): writing to that address
            # IS the declaration. What arrives stays untrusted (provenance and
            # taint as any courier mail).
            return True
        return bool(egress.room_declares_sender(
            header or "", egress._scope_of_call(),
            with_global=bool(tag) and tag != BOX_INDEX_TAG))

    def address_of(self, header: str) -> str:
        """The address of a `From:`-like header (`Nome <a@b.it>` → `a@b.it`),
        "" when it does not parse: the PDP's own parser."""
        from .. import egress
        return egress.address_of(header or "")

    def source_vetted(self, uri: str, scope: str | None = None) -> bool:
        """Is `uri` (e.g. `mailfrom:a@b.it`) a vetted source for the current
        call (or `scope`)? The room's people, or a declared ingress entry —
        `egress.is_vetted_source`, strict ingress included."""
        from .. import egress
        return bool(egress.is_vetted_source(uri, scope))

    def require_approved_repo(self, repo: str) -> str:
        """The canonical form of `repo` if it is approved for the room the
        call comes from (signed claim), else `HostError` (clodia-platform#525).

        The perimeter of the native git verbs: a repository is a whitelist
        entry of the room, matched by repository prefix
        (`TopicService._require_approved_repo`). The room is never an
        argument: a component cannot ask about another one."""
        from .. import main
        from ..tools.github_repo import GitHubError, normalize_repo
        from ..topics.service import TopicError, TopicService
        tier, name = main._current_topic()
        if not tier:
            raise HostError("git verbs act inside a topic: this call has no channel")
        try:
            canonical = normalize_repo(str(repo or ""))
        except GitHubError as e:
            raise HostError(str(e)) from None
        try:
            TopicService._require_approved_repo(canonical, tier, name)
        except TopicError as e:
            raise HostError(str(e)) from None
        return canonical

    def google_mail_account_exists(self, account: str) -> bool:
        """Whether a Google mail credential (`google_<acct>`/`gmail_<acct>`)
        EXISTS for `account` — a yes/no on the NAME, never its content. Lets
        a mail component refuse such an account while google-pack is down,
        instead of silently serving a same-named IMAP mailbox with another
        sender address (review of clodia-tools#384)."""
        from .. import vault
        a = str(account or "")
        return any(vault.has_credential(f"{p}{a}") for p in ("google_", "gmail_"))

    def legacy_mail_accounts(self) -> dict[str, str | None]:
        """`{account: address | None}` of the LEGACY mail accounts of the
        gateway's `secrets/email_config.json`: names and addresses, never the
        file or a secret. A mail component lists them and refuses them: they
        ran natively only, and the native mail code is gone (#523)."""
        return {a: addr for a, addr in sorted(_legacy_mail_config().items())}


def _legacy_mail_config() -> dict[str, str | None]:
    """`{account: address | None}` of the gateway's legacy
    `secrets/email_config.json` (the native mail code's file, kept readable so
    that a component can name and refuse those accounts). Names and addresses
    only. `{}` when absent or unreadable."""
    from pathlib import Path
    secrets_dir = os.environ.get("CLODIA_SECRETS_DIR")
    if not secrets_dir:
        workspace = os.environ.get("CLODIA_WORKSPACE_ROOT")
        secrets_dir = (f"{workspace}/secrets" if workspace
                       else str(Path(__file__).resolve().parents[4] / "secrets"))
    try:
        data = json.loads((Path(secrets_dir) / "email_config.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict) or not data:
        return {}
    if "accounts" in data:
        accounts = data.get("accounts") or {}
        bundles = accounts if isinstance(accounts, dict) else {}
    else:
        bundles = {"demo": data}

    def _addr(b) -> str | None:
        a = str((b or {}).get("email") or "").strip().lower() if isinstance(b, dict) else ""
        return a or None
    return {str(name): _addr(b) for name, b in bundles.items()}


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
        self.services: dict[str, ServiceSpec] = {}
        self.topics = Topics()
        self.perimeter = Perimeter()
        self.AuditUnavailable = AuditUnavailable
        self.log = logging.getLogger(
            f"clodia-tools.component.{component.pack}.{component.id}")

    # -- registration -----------------------------------------------------

    def close(self) -> None:
        self._open = False

    def _require_open(self) -> None:
        if not self._open:
            raise HostError("registration is closed: verbs and routes are "
                            "registered from register(host) only")

    def serves(self, namespace: str) -> bool:
        """Does this component serve `namespace` on this instance now? False
        for a namespace that is not its own, or that the gateway reserves
        (`core_namespaces`): a component of several connectors registers only
        the others (#522)."""
        ns = str(namespace or "")
        return ns in set(self._c.namespaces.values()) and ns not in set(self._reserved())

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

        Both levels require a HUMAN admin (or the trusted core's UI token) and
        every call is audited. `owner` routes may also write the component's
        config (`set_config`); `admin` routes may not. There is no public
        route."""
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

    def register_service(self, name: str, handler: Callable) -> None:
        """A callable the GATEWAY calls itself (`components.service(pack, name)`).

        Not a verb: an agent never reaches it, and it runs inside whatever
        gateway code calls it — after that code's own checks. The names the
        gateway calls are fixed by the gateway (e.g. `pdp_arguments`,
        `describe_folder`, `mail_run`); registering another name is harmless
        and unused."""
        self._require_open()
        name = str(name or "")
        if not _SERVICE.match(name):
            raise HostError(f"service name '{name}' is invalid")
        if not callable(handler):
            raise HostError(f"handler of service '{name}' is not callable")
        if name in self.services:
            raise HostError(f"service '{name}' registered twice")
        self.services[name] = ServiceSpec(component=self._c.key, pack=self._c.pack,
                                          name=name, handler=handler)

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

    def state_path(self, name: str) -> str:
        """A file of THIS component's private state (offsets, queues, leases):
        `<gateway state>/components/state/<pack>/<id>/<name>`, created 0700.

        On the gateway's own volume — not readable by the agent-server — and
        separate per component. `name` is one plain file name, no directories
        (clodia-platform#522: Telegram's state moved in with its code)."""
        n = str(name or "")
        if not _STATE_NAME.fullmatch(n):
            raise HostError(f"invalid state file name '{name}'")
        from . import store
        d = store.root() / "state" / self._c.pack / self._c.id
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
        return str(d / n)

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

    def service(self, pack: str, name: str) -> Callable | None:
        """The service `name` of `pack`'s SERVING gateway component, or None.

        Only the pairs `connectors.builtin.COMPONENT_SERVICES` grants to this
        component's pack (comms-pack → google-pack's `mail_accounts`,
        `mail_exec`); anything else is a `HostError`. Looked up per call: a
        component that stops serving (disabled, failure) is gone
        from the next call on — the caller fails closed on None."""
        from ..connectors import builtin
        pair = (str(pack or ""), str(name or ""))
        if pair not in builtin.COMPONENT_SERVICES.get(self._c.pack, frozenset()):
            raise HostError(f"component '{self._c.key}' may not call service "
                            f"'{pair[1]}' of '{pair[0]}'")
        from . import loader
        spec = loader.service(*pair)
        return spec.handler if spec is not None else None

    def git_credential(self) -> str | None:
        """The git token for the room the call comes from: the room's own
        credential, else the platform PAT, as natively
        (`TopicService.git_credential`), or None (clodia-platform#525).

        Only while this component serves `github`: the token is resolved per
        call from the vault, never handed over at load, and a component that
        does not hold the connector never gets it."""
        if not self.serves("github"):
            raise HostError(f"component '{self._c.key}' does not serve 'github' "
                            "on this instance")
        from .. import main
        tier, name = main._current_topic()
        if not tier:
            raise HostError("git verbs act inside a topic: this call has no channel")
        return main._topics().git_credential(tier, name)[0]

    def judged_targets(self) -> tuple[str, ...]:
        """The targets A·V·R·Q judged for the call in flight, as the
        component's own `authz_targets` named them (#635), or `()`.

        For the component to compare with what it is about to act on: the
        origin of a working tree can change between the check and the act,
        and an approval was given for the repository judged, not another."""
        from .. import authz_runtime
        return tuple(authz_runtime.JUDGED.get() or ())

    def room_cache_path(self, name: str) -> str:
        """The absolute path of the entry `name` in THIS component's private
        cache for the room the call comes from (clodia-platform#637):
        `<gateway state>/components/room-cache/<pack>/<id>/<tier>/<topic>/<name>`.

        For data a component keeps per room and nobody else may write — the
        repository copy `github.clone` starts from. It is on the gateway's own
        volume: not mounted where agents run, not reachable through the topic
        verbs, not on the Mac side (the room's shared folder is writable by
        agents through `topic.put`, review of #637). The room is the signed
        claim's, never an argument; `name` is ONE plain segment; a symlink
        there is refused."""
        n = str(name or "")
        if not _ROOM_ENTRY.fullmatch(n) or ".." in n:
            raise HostError(f"invalid cache entry name '{name}'")
        from .. import main
        tier, topic = main._current_topic()
        if not tier or not topic:
            raise HostError("this call has no channel: no room cache")
        if not (_ROOM_ENTRY.fullmatch(str(tier)) and _ROOM_ENTRY.fullmatch(str(topic))):
            raise HostError("room name not usable as a path segment")
        from .. import state_paths
        if not state_paths.is_isolated():
            # On the datadir the agent-server mounts, the cache would be
            # writable by agents' shells — the very hole of #637's review.
            raise HostError("the gateway state is not isolated from the agents "
                            "(CLODIA_TOOLS_STATE_DIR): no room cache")
        from . import store
        d = store.root() / "room-cache" / self._c.pack / self._c.id / str(tier) / str(topic)
        d.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
        p = d / n
        if p.is_symlink():
            raise HostError(f"'{n}' in the room cache is a link: refused")
        return str(p)

    def current_topic(self) -> tuple[str | None, str | None]:
        """`(tier, name)` of the room the call comes from (signed `chat`
        claim, tier canonical), or `(None, None)` outside a room."""
        from .. import main
        return main._current_topic()

    def tool_allowed(self, verb: str) -> None:
        """The whitelist's answer for the calling agent and `verb`: raises
        PermissionError when it is not granted. For a component that, like
        the native code, looks something up on the agent's behalf with ANOTHER
        verb's authority (`email.reply` reads the message it answers as
        `email.read`)."""
        from ..whitelist import tool_allowed
        tool_allowed(str(verb or ""))

    def audit_decision(self, verb: str, kind: str, result: str, *,
                       reason_class: str | None = None) -> None:
        """Record a decision of the reference monitor taken by the component
        (`audit.policy.decision`), e.g. an ingress filter or refusal (#503).
        `AuditUnavailable` when the trail cannot be written; other failures
        propagate as they are."""
        from .. import audit as _audit
        from ..audit import policy as _apol
        try:
            _apol.decision(verb, kind, result, reason_class=reason_class)
        except _audit.AuditWriteError as e:
            raise AuditUnavailable(str(e)) from None

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

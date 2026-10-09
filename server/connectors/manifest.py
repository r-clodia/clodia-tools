"""Connector manifest — the grammar a pack uses to declare a connector.

Today every connector is hardcoded twice over: the schemes and their validation
live in `egress.py` (`EGRESS_SCHEMES`, `SOURCE_SCHEMES`, `_SPECS`, `_CANON`,
`_HIERARCHICAL`, `_DANGER`), the MCP prefixes that must not taint a channel live
in `taint.py`, the topic buttons live in `topics_api.py` and the setup card lives
in `tools_api.py`. A pack can declare `ingress:`/`egress:` URIs and nothing else,
so shipping a connector means changing the core.

This module is the grammar that replaces those tables, and *only* the grammar:
it parses and validates, it does not decide anything. Building the registry on
top of it and deleting the tables is clodia-platform#518; applying the same
mappings at call time is #517; the generic endpoints are #519.

**Why it lives in the gateway and not in the agent-server.** The same reason
`pack_import.validate_flows` already gives for the flow declarations: the lists
and the rules live here, next to the PDP, and "a second copy would diverge, and
would diverge silently". The agent-server asks; it does not re-implement.

**Declaration, never a grant.** A manifest says what a connector *is* — not what
it may do. The author of a pack declares, the owner who installs grants. That is
the same line `declared_flows` draws, and it is the reason nothing in here reads
or writes the egress/ingress lists.

**The namespace rule (clodia-platform#516, non-negotiable).** A pack may map
verbs to destinations only inside its own namespace. Without that rule a pack
could declare someone else's outbound verb — `email.send`, `telegram.send` — as
a read, or map it to a harmless destination, and walk straight through the egress
check. `check_namespace` is exported on purpose: #517 applies it again at call
time, and two copies of this rule would be one copy too many.

The format itself is documented, with one example per connector that exists
today, in `SCHEMA.md` next to this file. `test_manifest.py` loads the examples
out of that document, so an example that rots fails the suite instead of
quietly lying.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

#: Version of *this grammar*. A manifest declares the version it was written
#: for; a manifest from the future is refused by name instead of being parsed
#: with the wrong rules and half understood.
MANIFEST_VERSION = 1

DIRECTIONS = ("source", "egress", "both")
VERB_DIRECTIONS = ("egress", "source")

#: Platform-intrinsic schemes. They are not a connector's to declare — #518
#: leaves exactly these in a core manifest — but a pack may *point at* the
#: generic ones: GitHub's write verbs resolve to `https://github.com/<owner>/<repo>`
#: and are checked by the ordinary http rules, which is the strictest generic
#: path there is. Pointing at them bypasses nothing; declaring them would mean
#: owning the meaning of every URL on the instance.
CORE_SCHEME_DIRECTION = {
    "http": "both",
    "https": "both",
    "topic": "source",
    "mcp": "source",
}
CORE_SCHEMES = tuple(CORE_SCHEME_DIRECTION)
CREDENTIAL_KINDS = ("form", "oauth")
HEALTH_KINDS = ("http", "tcp", "command")
RESTART_POLICIES = ("always", "on-failure", "never")

_ID = re.compile(r"^[a-z][a-z0-9-]{0,39}$")
_NAMESPACE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]{0,31}$")
_VERB = re.compile(r"^[a-z][a-z0-9_]{0,31}\.[A-Za-z0-9_.]{1,63}$")
_ARG = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_FIELD_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_VAULT_ENTRY = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
#: `{1}` … `{9}` in a canonicalisation template, `{field}` in a topic action.
_PLACEHOLDER = re.compile(r"\{([A-Za-z0-9_]+)\}")


class ManifestError(ValueError):
    """A manifest is refused as a whole, with a message an owner can act on.

    Never a per-entry warning: a connector accepted minus the mapping that did
    not pass would be a connector whose verbs go unchecked, which is the exact
    failure the namespace rule exists to prevent.
    """


# --------------------------------------------------------------------------
# primitives
# --------------------------------------------------------------------------

def _at(pack: str, connector: str = "", detail: str = "") -> str:
    parts = [f"pack '{pack}'"]
    if connector:
        parts.append(f"connector '{connector}'")
    if detail:
        parts.append(detail)
    return ", ".join(parts)


def _mapping(raw: Any, where: str) -> dict:
    if not isinstance(raw, Mapping):
        raise ManifestError(f"{where}: expected a mapping, got {type(raw).__name__}")
    return dict(raw)


def _seq(raw: Any, where: str) -> list:
    if raw is None:
        return []
    if isinstance(raw, (str, bytes)) or isinstance(raw, Mapping):
        raise ManifestError(f"{where}: expected a list, got {type(raw).__name__}")
    if not isinstance(raw, Sequence):
        raise ManifestError(f"{where}: expected a list, got {type(raw).__name__}")
    return list(raw)


def _text(raw: Any, where: str, *, required: bool = True, default: str = "") -> str:
    if raw is None:
        if required:
            raise ManifestError(f"{where}: required")
        return default
    if not isinstance(raw, str):
        raise ManifestError(f"{where}: expected a string, got {type(raw).__name__}")
    value = raw.strip()
    if not value and required:
        raise ManifestError(f"{where}: required")
    return value or default


def _flag(raw: Any, where: str, *, default: bool = False) -> bool:
    if raw is None:
        return default
    if not isinstance(raw, bool):
        raise ManifestError(f"{where}: expected true or false, got {raw!r}")
    return raw


def _one_of(value: str, allowed: Sequence[str], where: str) -> str:
    if value not in allowed:
        raise ManifestError(
            f"{where}: '{value}' is not one of {', '.join(allowed)}")
    return value


def _matching(value: str, pattern: re.Pattern[str], where: str) -> str:
    if not pattern.match(value):
        raise ManifestError(f"{where}: '{value}' does not match {pattern.pattern}")
    return value


def _compiled(raw: Any, where: str) -> re.Pattern[str]:
    """A regex from the manifest, compiled here so a typo fails at load.

    Compiled eagerly and on purpose: a pattern that only blows up the first time
    a real destination is checked would turn an authoring mistake into a runtime
    denial in the middle of someone's turn.
    """
    pattern = _text(raw, where)
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise ManifestError(f"{where}: invalid regular expression ({exc})") from exc


def _placeholders(template: str) -> list[str]:
    return _PLACEHOLDER.findall(template)


# --------------------------------------------------------------------------
# pieces of a connector
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Form:
    """One accepted shape of a URI under a scheme (`tg:-100123`, `tg:@handle`)."""

    label: str
    pattern: re.Pattern[str]
    example: str = ""

    def matches(self, rest: str) -> bool:
        return bool(self.pattern.match(rest))


@dataclass(frozen=True)
class Canonicalisation:
    """Browser URL → canonical id, the declarative form of `egress._CANON`."""

    pattern: re.Pattern[str]
    template: str

    def apply(self, uri: str) -> str | None:
        m = self.pattern.match(uri)
        if not m:
            return None
        return _PLACEHOLDER.sub(lambda g: m.group(int(g.group(1))), self.template)


@dataclass(frozen=True)
class Scheme:
    """A URI scheme with its direction, its shapes and its gate warning."""

    name: str
    direction: str
    label: str = ""
    icon: str = ""
    danger: str = ""
    hierarchical: bool = False
    forms: tuple[Form, ...] = ()
    canonicalise: tuple[Canonicalisation, ...] = ()

    @property
    def is_source(self) -> bool:
        return self.direction in ("source", "both")

    @property
    def is_egress(self) -> bool:
        return self.direction in ("egress", "both")


@dataclass(frozen=True)
class CredentialField:
    name: str
    label: str = ""
    secret: bool = False
    required: bool = True
    placeholder: str = ""


@dataclass(frozen=True)
class Credential:
    """How the owner connects a provider: a form stored in the vault, or OAuth."""

    kind: str
    vault_entry: str = ""
    fields: tuple[CredentialField, ...] = ()
    scopes: tuple[str, ...] = ()
    authorize_url: str = ""
    token_url: str = ""


@dataclass(frozen=True)
class Provider:
    """One implementation of a scheme vocabulary (Gmail and IMAP for mail)."""

    id: str
    label: str
    pack: str
    credential: Credential | None = None
    status_verb: str = ""
    test_verb: str = ""


@dataclass(frozen=True)
class VerbMapping:
    """`verb → destination` and `read → source`: `egress._SPECS` made declarative.

    `arg` names the argument the destination is read from, exactly like the
    extractors in `egress.py` do today. `template` builds the URI from it and
    defaults to `<scheme>:{value}`; `multi` says the argument may carry a list,
    the way `email.send` carries several recipients.
    """

    verb: str
    direction: str
    scheme: str
    arg: str
    template: str = ""
    multi: bool = False
    dtype: str = ""

    def uri_for(self, value: str) -> str:
        template = self.template or f"{self.scheme}:{{value}}"
        return template.replace("{value}", value)


@dataclass(frozen=True)
class ActionField:
    name: str
    label: str = ""
    required: bool = True
    placeholder: str = ""


@dataclass(frozen=True)
class TopicAction:
    """The button a connector adds to a topic, and what it writes.

    `adds` holds the ingress/egress URIs the action proposes, as templates over
    the action's own fields. It proposes: whether they are granted is still the
    owner's decision at the gate — see the module docstring.
    """

    id: str
    label: str
    fields: tuple[ActionField, ...] = ()
    adds_ingress: tuple[str, ...] = ()
    adds_egress: tuple[str, ...] = ()
    binding: str = ""


@dataclass(frozen=True)
class ToolsCard:
    """What the Tools page shows for this connector: setup, status, test."""

    setup_label: str = ""
    status_verb: str = ""
    test_verb: str = ""
    docs_url: str = ""


@dataclass(frozen=True)
class Service:
    """A long-running process the gateway supervises (clodia-platform#515).

    The shape is fixed here so the supervisor consumes it instead of inventing a
    second format; the semantics — start, health, backoff, stop, OS user, env
    scrubbing — belong to #515. `command` is a list and never a string: a string
    would mean a shell, and a shell is a way to smuggle an extra process into a
    manifest that declares one.
    """

    name: str
    pack: str
    command: tuple[str, ...]
    workdir: str = ""
    credentials: tuple[str, ...] = ()
    health_kind: str = ""
    health_target: str = ""
    health_interval: int = 30
    restart: str = "on-failure"
    backoff_seconds: int = 5

    @property
    def state_dir(self) -> str:
        """Path relative to the datadir, as #515 fixes it: state survives rebuilds."""
        return f"services/{self.pack}/{self.name}"


@dataclass(frozen=True)
class StorageRemote:
    """A topic storage backend a pack provides (Drive, clodia-platform#524)."""

    id: str
    label: str
    versioning: bool = False


@dataclass(frozen=True)
class Connector:
    """One connector as a pack declares it.

    Two kinds, and the difference is the whole of the multi-provider decision of
    2026-10-08: a connector either **owns a vocabulary** (it declares `schemes`)
    or **extends** one declared elsewhere, contributing a provider and nothing
    else. Gmail lives in google-pack and IMAP in comms-pack, but `mailto:` means
    one thing: whoever owns the vocabulary owns its schemes, its canonical forms
    and its verb mappings, and a contributor cannot touch them.
    """

    id: str
    label: str
    pack: str
    namespace: str
    extends: str = ""
    schemes: tuple[Scheme, ...] = ()
    providers: tuple[Provider, ...] = ()
    verbs: tuple[VerbMapping, ...] = ()
    taint_prefixes: tuple[str, ...] = ()
    topic_actions: tuple[TopicAction, ...] = ()
    tools_card: ToolsCard | None = None
    services: tuple[Service, ...] = ()
    storage_remote: StorageRemote | None = None

    @property
    def owns_vocabulary(self) -> bool:
        return not self.extends

    @property
    def vocabulary(self) -> str:
        return self.extends or self.id


# --------------------------------------------------------------------------
# the namespace rule
# --------------------------------------------------------------------------

def core_namespaces() -> frozenset[str]:
    """Namespaces the gateway itself owns, derived — never a second list.

    Imported inside the function so that `server.main` can import this module
    (#518) without a cycle, and so that a namespace added to the gateway is
    reserved here the same day it exists, without anybody remembering to.
    """
    from ..main import all_native_verb_names

    return frozenset(
        name.split(".", 1)[0] for name in all_native_verb_names() if "." in name)


def check_namespace(namespace: str, verbs: Iterable[str], *,
                    reserved: Iterable[str] | None = None,
                    where: str = "") -> None:
    """The rule of clodia-platform#516: a pack maps only its own verbs.

    Exported because #517 has to apply it again when the call actually happens:
    a manifest validated at install time says nothing about a verb that appears
    later, and a second implementation of this check would be the place where the
    two drift apart.

    `reserved` defaults to the gateway's own namespaces. Pass it explicitly to
    check a manifest against a registry that also holds other packs.
    """
    taken = frozenset(reserved) if reserved is not None else core_namespaces()
    prefix = f"{namespace}."
    if namespace in taken:
        raise ManifestError(
            f"{where}: namespace '{namespace}' is already taken; a pack cannot "
            f"claim a namespace that is not its own")
    for verb in verbs:
        if not verb.startswith(prefix):
            raise ManifestError(
                f"{where}: verb '{verb}' is outside namespace '{namespace}'. A "
                f"pack may map only verbs it owns: mapping someone else's verb "
                f"would let it declare an outbound call as harmless and bypass "
                f"the egress check")


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------

def _parse_form(raw: Any, where: str) -> Form:
    data = _mapping(raw, where)
    label = _text(data.get("label"), f"{where}.label", required=False)
    pattern = _compiled(data.get("pattern"), f"{where}.pattern")
    example = _text(data.get("example"), f"{where}.example", required=False)
    if example and not pattern.match(example):
        # The cheapest possible proof that the regex says what the author meant.
        raise ManifestError(
            f"{where}: example '{example}' does not match the declared pattern "
            f"'{pattern.pattern}'")
    return Form(label=label, pattern=pattern, example=example)


def _parse_canonicalisation(raw: Any, where: str) -> Canonicalisation:
    data = _mapping(raw, where)
    pattern = _compiled(data.get("from"), f"{where}.from")
    template = _text(data.get("to"), f"{where}.to")
    for ref in _placeholders(template):
        if not ref.isdigit():
            raise ManifestError(
                f"{where}.to: '{{{ref}}}' is not a capture group; a "
                f"canonicalisation refers to groups by number")
        if not (1 <= int(ref) <= pattern.groups):
            raise ManifestError(
                f"{where}.to: group {{{ref}}} does not exist in '{pattern.pattern}' "
                f"(it captures {pattern.groups})")
    return Canonicalisation(pattern=pattern, template=template)


def _parse_scheme(raw: Any, where: str) -> Scheme:
    data = _mapping(raw, where)
    name = _matching(_text(data.get("scheme"), f"{where}.scheme"), _SCHEME,
                     f"{where}.scheme")
    direction = _one_of(_text(data.get("direction"), f"{where}.direction"),
                        DIRECTIONS, f"{where}.direction")
    forms = tuple(
        _parse_form(f, f"{where}.forms[{i}]")
        for i, f in enumerate(_seq(data.get("forms"), f"{where}.forms")))
    canon = tuple(
        _parse_canonicalisation(c, f"{where}.canonicalise[{i}]")
        for i, c in enumerate(
            _seq(data.get("canonicalise"), f"{where}.canonicalise")))
    return Scheme(
        name=name,
        direction=direction,
        label=_text(data.get("label"), f"{where}.label", required=False),
        icon=_text(data.get("icon"), f"{where}.icon", required=False),
        danger=_text(data.get("danger"), f"{where}.danger", required=False),
        hierarchical=_flag(data.get("hierarchical"), f"{where}.hierarchical"),
        forms=forms,
        canonicalise=canon,
    )


def _parse_credential(raw: Any, where: str) -> Credential:
    data = _mapping(raw, where)
    kind = _one_of(_text(data.get("kind"), f"{where}.kind"), CREDENTIAL_KINDS,
                   f"{where}.kind")
    vault_entry = _text(data.get("vault_entry"), f"{where}.vault_entry",
                        required=kind == "form")
    if vault_entry:
        _matching(vault_entry, _VAULT_ENTRY, f"{where}.vault_entry")
    fields = []
    for i, f in enumerate(_seq(data.get("fields"), f"{where}.fields")):
        fdata = _mapping(f, f"{where}.fields[{i}]")
        fields.append(CredentialField(
            name=_matching(_text(fdata.get("name"), f"{where}.fields[{i}].name"),
                           _FIELD_NAME, f"{where}.fields[{i}].name"),
            label=_text(fdata.get("label"), f"{where}.fields[{i}].label",
                        required=False),
            secret=_flag(fdata.get("secret"), f"{where}.fields[{i}].secret"),
            required=_flag(fdata.get("required"), f"{where}.fields[{i}].required",
                           default=True),
            placeholder=_text(fdata.get("placeholder"),
                              f"{where}.fields[{i}].placeholder", required=False),
        ))
    if kind == "form" and not fields:
        raise ManifestError(
            f"{where}: a 'form' credential with no fields cannot be filled in")
    scopes = tuple(
        _text(s, f"{where}.scopes[{i}]")
        for i, s in enumerate(_seq(data.get("scopes"), f"{where}.scopes")))
    return Credential(
        kind=kind,
        vault_entry=vault_entry,
        fields=tuple(fields),
        scopes=scopes,
        authorize_url=_text(data.get("authorize_url"), f"{where}.authorize_url",
                            required=kind == "oauth"),
        token_url=_text(data.get("token_url"), f"{where}.token_url",
                        required=kind == "oauth"),
    )


def _parse_provider(raw: Any, where: str, *, pack: str) -> Provider:
    data = _mapping(raw, where)
    cred = data.get("credential")
    return Provider(
        id=_matching(_text(data.get("id"), f"{where}.id"), _ID, f"{where}.id"),
        label=_text(data.get("label"), f"{where}.label", required=False)
        or _text(data.get("id"), f"{where}.id"),
        pack=pack,
        credential=_parse_credential(cred, f"{where}.credential") if cred else None,
        status_verb=_text(data.get("status_verb"), f"{where}.status_verb",
                          required=False),
        test_verb=_text(data.get("test_verb"), f"{where}.test_verb", required=False),
    )


def _parse_verb(raw: Any, where: str) -> VerbMapping:
    data = _mapping(raw, where)
    verb = _matching(_text(data.get("verb"), f"{where}.verb"), _VERB, f"{where}.verb")
    direction = _one_of(_text(data.get("direction"), f"{where}.direction"),
                        VERB_DIRECTIONS, f"{where}.direction")
    scheme = _matching(_text(data.get("scheme"), f"{where}.scheme"), _SCHEME,
                       f"{where}.scheme")
    arg = _matching(_text(data.get("arg"), f"{where}.arg"), _ARG, f"{where}.arg")
    template = _text(data.get("template"), f"{where}.template", required=False)
    if template and "{value}" not in template:
        raise ManifestError(
            f"{where}.template: '{template}' never uses {{value}}, so every call "
            f"would map to the same destination")
    return VerbMapping(
        verb=verb,
        direction=direction,
        scheme=scheme,
        arg=arg,
        template=template,
        multi=_flag(data.get("multi"), f"{where}.multi"),
        dtype=_text(data.get("dtype"), f"{where}.dtype", required=False),
    )


def _parse_topic_action(raw: Any, where: str) -> TopicAction:
    data = _mapping(raw, where)
    fields = []
    for i, f in enumerate(_seq(data.get("fields"), f"{where}.fields")):
        fdata = _mapping(f, f"{where}.fields[{i}]")
        fields.append(ActionField(
            name=_matching(_text(fdata.get("name"), f"{where}.fields[{i}].name"),
                           _FIELD_NAME, f"{where}.fields[{i}].name"),
            label=_text(fdata.get("label"), f"{where}.fields[{i}].label",
                        required=False),
            required=_flag(fdata.get("required"), f"{where}.fields[{i}].required",
                           default=True),
            placeholder=_text(fdata.get("placeholder"),
                              f"{where}.fields[{i}].placeholder", required=False),
        ))
    known = {f.name for f in fields}
    adds = _mapping(data.get("adds") or {}, f"{where}.adds")
    out: dict[str, tuple[str, ...]] = {}
    for key in ("ingress", "egress"):
        templates = []
        for i, t in enumerate(_seq(adds.get(key), f"{where}.adds.{key}")):
            tpl = _text(t, f"{where}.adds.{key}[{i}]")
            for ref in _placeholders(tpl):
                if ref not in known:
                    raise ManifestError(
                        f"{where}.adds.{key}[{i}]: '{{{ref}}}' is not one of the "
                        f"action's fields ({', '.join(sorted(known)) or 'none'})")
            templates.append(tpl)
        out[key] = tuple(templates)
    return TopicAction(
        id=_matching(_text(data.get("id"), f"{where}.id"), _ID, f"{where}.id"),
        label=_text(data.get("label"), f"{where}.label"),
        fields=tuple(fields),
        adds_ingress=out["ingress"],
        adds_egress=out["egress"],
        binding=_text(data.get("binding"), f"{where}.binding", required=False),
    )


def _parse_tools_card(raw: Any, where: str) -> ToolsCard:
    data = _mapping(raw, where)
    return ToolsCard(
        setup_label=_text(data.get("setup_label"), f"{where}.setup_label",
                          required=False),
        status_verb=_text(data.get("status_verb"), f"{where}.status_verb",
                          required=False),
        test_verb=_text(data.get("test_verb"), f"{where}.test_verb", required=False),
        docs_url=_text(data.get("docs_url"), f"{where}.docs_url", required=False),
    )


def _parse_int(raw: Any, where: str, *, default: int, minimum: int = 1) -> int:
    if raw is None:
        return default
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise ManifestError(f"{where}: expected a whole number, got {raw!r}")
    if raw < minimum:
        raise ManifestError(f"{where}: must be at least {minimum}, got {raw}")
    return raw


def _parse_service(raw: Any, where: str, *, pack: str) -> Service:
    data = _mapping(raw, where)
    name = _matching(_text(data.get("name"), f"{where}.name"), _ID, f"{where}.name")
    raw_command = data.get("command")
    if isinstance(raw_command, str):
        raise ManifestError(
            f"{where}.command: expected a list of arguments, got a string. A "
            f"string would be run through a shell, and a shell is a way to hide "
            f"a second process inside a manifest that declares one")
    command = tuple(
        _text(c, f"{where}.command[{i}]")
        for i, c in enumerate(_seq(raw_command, f"{where}.command")))
    if not command:
        raise ManifestError(f"{where}.command: required")
    credentials = tuple(
        _matching(_text(c, f"{where}.credentials[{i}]"), _VAULT_ENTRY,
                  f"{where}.credentials[{i}]")
        for i, c in enumerate(_seq(data.get("credentials"), f"{where}.credentials")))
    health = _mapping(data.get("health") or {}, f"{where}.health")
    health_kind = ""
    health_target = ""
    health_interval = 30
    if health:
        health_kind = _one_of(_text(health.get("kind"), f"{where}.health.kind"),
                              HEALTH_KINDS, f"{where}.health.kind")
        health_target = _text(health.get("target"), f"{where}.health.target")
        health_interval = _parse_int(health.get("interval_seconds"),
                                     f"{where}.health.interval_seconds", default=30)
    restart = _mapping(data.get("restart") or {}, f"{where}.restart")
    policy = "on-failure"
    backoff = 5
    if restart:
        policy = _one_of(_text(restart.get("policy"), f"{where}.restart.policy"),
                         RESTART_POLICIES, f"{where}.restart.policy")
        backoff = _parse_int(restart.get("backoff_seconds"),
                             f"{where}.restart.backoff_seconds", default=5)
    return Service(
        name=name,
        pack=pack,
        command=command,
        workdir=_text(data.get("workdir"), f"{where}.workdir", required=False),
        credentials=credentials,
        health_kind=health_kind,
        health_target=health_target,
        health_interval=health_interval,
        restart=policy,
        backoff_seconds=backoff,
    )


#: Sections that belong to whoever owns the vocabulary. A contributor adds an
#: implementation, never a meaning: letting it re-declare a scheme, a canonical
#: form or a verb mapping would hand the vocabulary of another pack to the one
#: that installed second.
_OWNER_ONLY = ("schemes", "verbs", "taint", "topic_actions")


def parse_connector(raw: Any, *, pack: str,
                    reserved: Iterable[str] | None = None) -> Connector:
    """One entry of the `connectors:` block, validated on its own.

    `reserved` is passed through to `check_namespace`; cross-connector checks
    (duplicate ids, unknown `extends`, scheme owned twice) belong to
    `build_registry`, which is the only place that can see them.
    """
    where = _at(pack)
    data = _mapping(raw, where)
    cid = _matching(_text(data.get("id"), f"{where}: connector id"), _ID,
                    f"{where}: connector id")
    where = _at(pack, cid)

    version = data.get("manifest_version")
    if version is None:
        raise ManifestError(f"{where}: manifest_version is required")
    if not isinstance(version, int) or isinstance(version, bool):
        raise ManifestError(
            f"{where}: manifest_version must be a whole number, got {version!r}")
    if version > MANIFEST_VERSION:
        raise ManifestError(
            f"{where}: manifest_version {version} is newer than this gateway "
            f"understands ({MANIFEST_VERSION}); refusing to read it with the "
            f"wrong rules")

    namespace = _matching(_text(data.get("namespace"), f"{where}.namespace"),
                          _NAMESPACE, f"{where}.namespace")
    extends = _text(data.get("extends"), f"{where}.extends", required=False)
    if extends:
        _matching(extends, _ID, f"{where}.extends")
        present = [s for s in _OWNER_ONLY if data.get(s)]
        if present:
            raise ManifestError(
                f"{where}: extends '{extends}', so it may not declare "
                f"{', '.join(present)} — those belong to the pack that owns the "
                f"vocabulary. A contributor adds a provider, not a meaning")
        if not data.get("providers"):
            raise ManifestError(
                f"{where}: extends '{extends}' but declares no provider, so it "
                f"contributes nothing")

    schemes = tuple(
        _parse_scheme(s, f"{where}.schemes[{i}]")
        for i, s in enumerate(_seq(data.get("schemes"), f"{where}.schemes")))
    seen_schemes: set[str] = set()
    for s in schemes:
        if s.name in CORE_SCHEMES:
            raise ManifestError(
                f"{where}: scheme '{s.name}' is platform-intrinsic and stays in "
                f"the core manifest; a pack may map verbs onto it but not "
                f"redefine what it means")
        if s.name in seen_schemes:
            raise ManifestError(f"{where}: scheme '{s.name}' declared twice")
        seen_schemes.add(s.name)
    if not (schemes or extends or data.get("providers")):
        raise ManifestError(
            f"{where}: declares no scheme, no provider and extends nothing, so "
            f"it is an empty connector")

    providers = tuple(
        _parse_provider(p, f"{where}.providers[{i}]", pack=pack)
        for i, p in enumerate(_seq(data.get("providers"), f"{where}.providers")))
    seen_providers: set[str] = set()
    for p in providers:
        if p.id in seen_providers:
            raise ManifestError(f"{where}: provider '{p.id}' declared twice")
        seen_providers.add(p.id)

    verbs = tuple(
        _parse_verb(v, f"{where}.verbs[{i}]")
        for i, v in enumerate(_seq(data.get("verbs"), f"{where}.verbs")))
    check_namespace(namespace, [v.verb for v in verbs], reserved=reserved,
                    where=where)
    for v in verbs:
        if v.scheme in seen_schemes:
            direction = next(s.direction for s in schemes if s.name == v.scheme)
        elif v.scheme in CORE_SCHEME_DIRECTION:
            direction = CORE_SCHEME_DIRECTION[v.scheme]
        else:
            raise ManifestError(
                f"{where}: verb '{v.verb}' maps to scheme '{v.scheme}', which "
                f"this connector does not declare and which is not one of the "
                f"platform schemes ({', '.join(CORE_SCHEMES)})")
        if v.direction == "egress" and direction not in ("egress", "both"):
            raise ManifestError(
                f"{where}: verb '{v.verb}' writes to scheme '{v.scheme}', "
                f"declared as '{direction}'")
        if v.direction == "source" and direction not in ("source", "both"):
            raise ManifestError(
                f"{where}: verb '{v.verb}' reads from scheme '{v.scheme}', "
                f"declared as '{direction}'")

    taint = tuple(
        _text(t, f"{where}.taint[{i}]")
        for i, t in enumerate(_seq(data.get("taint"), f"{where}.taint")))
    for prefix in taint:
        if not prefix.startswith(f"{namespace}."):
            raise ManifestError(
                f"{where}: taint prefix '{prefix}' is outside namespace "
                f"'{namespace}'. Declaring what does not taint a channel is a "
                f"statement about one's own tools, never about someone else's")

    actions = tuple(
        _parse_topic_action(a, f"{where}.topic_actions[{i}]")
        for i, a in enumerate(
            _seq(data.get("topic_actions"), f"{where}.topic_actions")))
    services = tuple(
        _parse_service(s, f"{where}.services[{i}]", pack=pack)
        for i, s in enumerate(_seq(data.get("services"), f"{where}.services")))
    seen_services: set[str] = set()
    for s in services:
        if s.name in seen_services:
            raise ManifestError(f"{where}: service '{s.name}' declared twice")
        seen_services.add(s.name)

    card = data.get("tools_card")
    remote = data.get("storage_remote")
    storage = None
    if remote:
        rdata = _mapping(remote, f"{where}.storage_remote")
        storage = StorageRemote(
            id=_matching(_text(rdata.get("id"), f"{where}.storage_remote.id"), _ID,
                         f"{where}.storage_remote.id"),
            label=_text(rdata.get("label"), f"{where}.storage_remote.label",
                        required=False),
            versioning=_flag(rdata.get("versioning"),
                             f"{where}.storage_remote.versioning"),
        )

    # No `seal_cap`: the owner decides a binding at the gate, which shows the
    # topic's tier (epic clodia-platform#527). Today's `_CHANNEL_SEAL_CAP` /
    # `_DRIVE_SEAL_CAP` die with #518 and must not come back as a field.
    if "seal_cap" in data:
        raise ManifestError(
            f"{where}: 'seal_cap' is not part of the manifest. There is no SEAL "
            f"ceiling on a binding: the owner decides, at the gate, per binding")

    return Connector(
        id=cid,
        label=_text(data.get("label"), f"{where}.label", required=False) or cid,
        pack=pack,
        namespace=namespace,
        extends=extends,
        schemes=schemes,
        providers=providers,
        verbs=verbs,
        taint_prefixes=taint,
        topic_actions=actions,
        tools_card=_parse_tools_card(card, f"{where}.tools_card") if card else None,
        services=services,
        storage_remote=storage,
    )


def load_manifest(pack_manifest: Mapping[str, Any], *, pack: str,
                  reserved: Iterable[str] | None = None) -> list[Connector]:
    """The `connectors:` block of one `pack.yaml`. No block → no connector."""
    raw = pack_manifest.get("connectors")
    if raw is None:
        return []
    entries = _seq(raw, f"{_at(pack)}: connectors")
    return [parse_connector(e, pack=pack, reserved=reserved) for e in entries]


def parse_services(pack_manifest: Mapping[str, Any], *, pack: str,
                   reserved: Iterable[str] | None = None) -> list[Service]:
    """Every service a pack declares, flattened — the entry point for #515.

    The supervisor reads the shape from here rather than parsing `pack.yaml`
    again: one format, one parser, one place where a field changes name.
    """
    return [s for c in load_manifest(pack_manifest, pack=pack, reserved=reserved)
            for s in c.services]


# --------------------------------------------------------------------------
# registry
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Registry:
    """Every connector of the installed packs, with `extends` resolved.

    A read-only view: #518 builds the PDP tables out of it. Nothing in here
    grants anything — see the module docstring.
    """

    connectors: tuple[Connector, ...] = ()

    def by_id(self, cid: str) -> Connector | None:
        return next((c for c in self.connectors if c.id == cid), None)

    def vocabularies(self) -> tuple[Connector, ...]:
        return tuple(c for c in self.connectors if c.owns_vocabulary)

    def schemes(self, direction: str = "") -> tuple[Scheme, ...]:
        out = tuple(s for c in self.connectors for s in c.schemes)
        if direction == "egress":
            return tuple(s for s in out if s.is_egress)
        if direction == "source":
            return tuple(s for s in out if s.is_source)
        return out

    def scheme_names(self, direction: str = "") -> tuple[str, ...]:
        return tuple(sorted({s.name for s in self.schemes(direction)}))

    def providers_of(self, vocabulary: str) -> tuple[Provider, ...]:
        return tuple(p for c in self.connectors if c.vocabulary == vocabulary
                     for p in c.providers)

    def verb_map(self, direction: str = "egress") -> dict[str, VerbMapping]:
        return {v.verb: v for c in self.connectors for v in c.verbs
                if v.direction == direction}

    def taint_prefixes(self) -> tuple[str, ...]:
        return tuple(sorted({p for c in self.connectors for p in c.taint_prefixes}))

    def services(self) -> tuple[Service, ...]:
        return tuple(s for c in self.connectors for s in c.services)

    def topic_actions(self) -> tuple[TopicAction, ...]:
        return tuple(a for c in self.connectors for a in c.topic_actions)


def build_registry(manifests: Mapping[str, Mapping[str, Any]], *,
                   reserved: Iterable[str] | None = None) -> Registry:
    """Resolve the connectors of every installed pack, in two passes.

    `manifests` maps pack name → the parsed `pack.yaml`. Two passes because
    `extends:` crosses packs and the install order is not an ordering: google-pack
    may well be installed before the pack that owns the mail vocabulary, and a
    first-pass failure there would mean a connector that works or not depending
    on the day it was installed.
    """
    reserved_set = set(core_namespaces() if reserved is None else reserved)
    parsed: list[Connector] = []
    for pack in sorted(manifests):
        # Each pack is checked against the gateway's namespaces *and* against the
        # namespaces already claimed by the packs parsed before it.
        for connector in load_manifest(manifests[pack], pack=pack,
                                       reserved=reserved_set):
            parsed.append(connector)
        reserved_set.update(
            c.namespace for c in parsed if c.pack == pack)

    by_id: dict[str, Connector] = {}
    for c in parsed:
        if c.id in by_id:
            raise ManifestError(
                f"connector '{c.id}' is declared by both '{by_id[c.id].pack}' and "
                f"'{c.pack}'")
        by_id[c.id] = c

    scheme_owner: dict[str, Connector] = {}
    for c in parsed:
        for s in c.schemes:
            other = scheme_owner.get(s.name)
            if other is not None:
                raise ManifestError(
                    f"scheme '{s.name}' is declared by both '{other.pack}' "
                    f"(connector '{other.id}') and '{c.pack}' (connector "
                    f"'{c.id}'); a scheme vocabulary has exactly one owner")
            scheme_owner[s.name] = c

    provider_owner: dict[tuple[str, str], Connector] = {}
    for c in parsed:
        if c.extends:
            target = by_id.get(c.extends)
            if target is None:
                raise ManifestError(
                    f"{_at(c.pack, c.id)}: extends '{c.extends}', which no "
                    f"installed pack declares. Install the pack that owns that "
                    f"vocabulary, or fix the name")
            if not target.owns_vocabulary:
                raise ManifestError(
                    f"{_at(c.pack, c.id)}: extends '{c.extends}', which is "
                    f"itself an extension; a provider attaches to the vocabulary "
                    f"owner, not to another provider")
        for p in c.providers:
            key = (c.vocabulary, p.id)
            other = provider_owner.get(key)
            if other is not None:
                raise ManifestError(
                    f"provider '{p.id}' of vocabulary '{c.vocabulary}' is "
                    f"declared by both '{other.pack}' and '{c.pack}'")
            provider_owner[key] = c

    return Registry(connectors=tuple(parsed))

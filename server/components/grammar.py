"""The `components:` block of a `pack.yaml` (clodia-platform#558).

A pack is a distribution of components, each mounted in the container it
belongs to. This module says what a component entry *is*; it does not fetch,
trust or load anything (`trust.py`, `store.py`, `loader.py`).

    components:
      - id: google
        target: gateway
        source: {repo: r-clodia/clodia-logic,
                 path: catalogs/packs/google-pack/gateway, ref: main}
        entry: google_component
        connectors: [google, google-sheets]
        credentials: [google_, app_google_oauth]
      - id: ui
        target: webui          # parsed, ignored by the gateway

Only `target: gateway` entries are parsed strictly: they become code running
inside the reference monitor, so an unknown key or a malformed field refuses
that entry (never the pack, never the other components). Entries for the
other targets are checked for `id`/`target` only and otherwise left to the
container that mounts them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Mapping

TARGETS = ("gateway", "agent-server", "webui")

_ID = re.compile(r"^[a-z][a-z0-9-]{0,39}$")
#: `owner/name` on GitHub. Nothing else: no URL, no host, no `..`.
_REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$")
_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,99}$")
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$")
_ENTRY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*){0,4}$")
_CREDENTIAL = re.compile(r"^[a-z][a-z0-9_]{1,63}$")

GATEWAY_KEYS = frozenset({"id", "target", "source", "entry", "connectors",
                          "credentials"})
SOURCE_KEYS = frozenset({"repo", "path", "ref"})


class ComponentError(ValueError):
    """One component entry is refused, with a message an owner can act on."""


@dataclass(frozen=True)
class GatewayComponent:
    """A `target: gateway` component as the pack declares it."""

    pack: str
    id: str
    repo: str
    path: str
    ref: str
    entry: str
    #: Connector ids (of the SAME pack) whose verbs this component implements.
    connectors: tuple[str, ...]
    #: Vault prefixes or entry names the component may read/deposit/remove.
    credentials: tuple[str, ...] = ()
    #: `{connector id: namespace}` read from the same manifest, so the loader
    #: knows which verb names the component may register.
    namespaces: Mapping[str, str] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.pack}/{self.id}"

    @property
    def org(self) -> str:
        return self.repo.split("/", 1)[0].lower()

    def source(self) -> tuple[str, str, str, str]:
        """What a pin is a pin OF: changing any of these is a new fetch."""
        return (self.repo, self.path, self.ref, self.entry)


def _where(pack: str, cid: str = "") -> str:
    return f"pack '{pack}'" + (f", component '{cid}'" if cid else "")


def _text(raw: Any, what: str, where: str) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise ComponentError(f"{where}: '{what}' must be a non-empty string")
    return raw.strip()


def _source_path(raw: str, where: str) -> str:
    if raw.startswith(("/", "~")) or "\\" in raw:
        raise ComponentError(
            f"{where}: source.path '{raw}' must be relative to the repository "
            "root (no leading '/', '~' or backslash)")
    segments = [s for s in raw.strip("/").split("/")]
    for seg in segments:
        if seg in ("", ".", "..") or not _PATH_SEGMENT.match(seg):
            raise ComponentError(
                f"{where}: source.path '{raw}' has an invalid segment '{seg}'")
    return "/".join(segments)


def _connector_namespaces(manifest: Mapping[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for entry in manifest.get("connectors") or []:
        if isinstance(entry, Mapping) and entry.get("id"):
            out[str(entry["id"])] = str(entry.get("namespace") or "")
    return out


def parse_gateway(raw: Mapping[str, Any], *, pack: str,
                  manifest: Mapping[str, Any] | None = None) -> GatewayComponent:
    """One `target: gateway` entry, or `ComponentError`."""
    cid = str(raw.get("id") or "")
    where = _where(pack, cid)
    if not _ID.match(cid):
        raise ComponentError(f"{_where(pack)}: component id '{cid}' must match "
                             f"{_ID.pattern}")
    unknown = sorted(set(map(str, raw)) - GATEWAY_KEYS)
    if unknown:
        raise ComponentError(
            f"{where}: unknown key(s) {unknown}. A gateway component is fetched "
            "by the gateway from its upstream; it cannot name a local path")
    src = raw.get("source")
    if not isinstance(src, Mapping):
        raise ComponentError(f"{where}: 'source' must be a mapping "
                             "{repo, path, ref}")
    unknown = sorted(set(map(str, src)) - SOURCE_KEYS)
    if unknown:
        raise ComponentError(f"{where}: unknown source key(s) {unknown}")
    repo = _text(src.get("repo"), "source.repo", where)
    if not _REPO.match(repo):
        raise ComponentError(f"{where}: source.repo '{repo}' must be "
                             "'<owner>/<repository>' on GitHub")
    path = _source_path(_text(src.get("path"), "source.path", where), where)
    ref = _text(src.get("ref"), "source.ref", where)
    if not _REF.match(ref) or ".." in ref:
        raise ComponentError(f"{where}: source.ref '{ref}' is not a valid ref")
    entry = _text(raw.get("entry"), "entry", where)
    if not _ENTRY.match(entry):
        raise ComponentError(f"{where}: entry '{entry}' must be a dotted Python "
                             "module path inside the component")

    declared = _connector_namespaces(manifest or {})
    conns = raw.get("connectors")
    if not isinstance(conns, list) or not conns:
        raise ComponentError(f"{where}: 'connectors' must be a non-empty list "
                             "of connector ids declared by this pack")
    connectors: list[str] = []
    for c in conns:
        c = str(c or "")
        if c not in declared or not declared[c]:
            raise ComponentError(
                f"{where}: connector '{c}' is not declared (with a namespace) in "
                "this pack's 'connectors:'. A component implements its own "
                "pack's connectors only")
        if c not in connectors:
            connectors.append(c)

    creds = raw.get("credentials") or []
    if not isinstance(creds, list):
        raise ComponentError(f"{where}: 'credentials' must be a list")
    credentials: list[str] = []
    for c in creds:
        c = str(c or "")
        if not _CREDENTIAL.match(c):
            raise ComponentError(
                f"{where}: credential prefix '{c}' must match {_CREDENTIAL.pattern}")
        if c not in credentials:
            credentials.append(c)

    return GatewayComponent(
        pack=pack, id=cid, repo=repo, path=path, ref=ref, entry=entry,
        connectors=tuple(connectors), credentials=tuple(credentials),
        namespaces={c: declared[c] for c in connectors})


def parse_components(manifest: Mapping[str, Any], *, pack: str
                     ) -> tuple[list[GatewayComponent], list[str]]:
    """`(gateway components, problems)` of one pack manifest.

    A malformed entry is refused ALONE and reported in `problems`: one broken
    component must not take the pack's other components down. Entries for the
    other targets are accepted when they have a valid `id` and `target`, and
    otherwise ignored here.
    """
    raw = manifest.get("components")
    if raw is None:
        return [], []
    if not isinstance(raw, list):
        return [], [f"{_where(pack)}: 'components' must be a list"]
    out: list[GatewayComponent] = []
    problems: list[str] = []
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, Mapping):
            problems.append(f"{_where(pack)}: a component entry is not a mapping")
            continue
        cid = str(entry.get("id") or "")
        target = str(entry.get("target") or "")
        if target not in TARGETS:
            problems.append(f"{_where(pack, cid)}: target '{target}' is not one "
                            f"of {list(TARGETS)}")
            continue
        if cid in seen:
            problems.append(f"{_where(pack, cid)}: component id declared twice")
            continue
        seen.add(cid)
        if target != "gateway":
            continue
        try:
            out.append(parse_gateway(entry, pack=pack, manifest=manifest))
        except ComponentError as e:
            problems.append(str(e))
    return out, problems

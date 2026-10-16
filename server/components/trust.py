"""Who may put code inside the reference monitor (clodia-platform#558).

A gateway component runs in the gateway's process, with the gateway's
privileges. Nothing in a `pack.yaml` can make that safe — the file is written
by the agent-server — so the decision is taken here, from facts the
agent-server cannot write, and the default is NO:

1. the pack is in `connectors.builtin.FIRST_PARTY_SOURCES` (code, not
   datadir), and its manifest says `first_party: true` too (necessary, not
   sufficient);
2. `source.repo` EQUALS the repository of that table entry and `source.path`
   lies under its pack prefix — a tampered datadir manifest cannot point the
   gateway at another repository, directory or module;
   secondarily, the repository's organisation is in the allowed list (gateway
   config `components.allowed_orgs`, else `CLODIA_COMPONENT_ORGS`, else
   `r-clodia`), which can only narrow the table;
3. the gateway's state directory is ISOLATED from the shared datadir (#80): the
   pinned code lives there, and on a shared volume the agent-server could
   rewrite it between the integrity check and the import.

More rules are applied by the store at fetch time, because they need the
upstream: `source.ref` must BE the repository's default branch (no tag, branch
or sha chosen by the datadir), the commit is its head, it descends from the
highest commit ever pinned (the floor survives uninstall), and the manifest
that governs the pack from then on is the one at that commit.

The boundary is PROVENANCE — this table, merged code on the default branch, a
pinned commit, review upstream. The import guard and the host API are not a
sandbox: a component runs in-process with the gateway's privileges.

Anything else is refused. `owner_approved` is the hook for the future SYSTEM
gate through which an owner could approve a third-party component; it answers
False today and nothing calls a gate.
"""
from __future__ import annotations

import os
from typing import Any, Mapping

from .grammar import GatewayComponent

DEFAULT_ALLOWED_ORGS = ("r-clodia",)
ORGS_ENV = "CLODIA_COMPONENT_ORGS"


def allowed_orgs() -> frozenset[str]:
    """The GitHub organisations a component may be fetched from (lowercase)."""
    try:
        from .. import whitelist
        conf = (whitelist.CONFIG or {}).get("components") or {}
        orgs = conf.get("allowed_orgs") if isinstance(conf, Mapping) else None
    except Exception:  # noqa: BLE001 — unreadable config: env/default
        orgs = None
    if isinstance(orgs, list) and orgs:
        return frozenset(str(o).strip().lower() for o in orgs if str(o).strip())
    raw = os.environ.get(ORGS_ENV, "")
    if raw.strip():
        return frozenset(o.strip().lower() for o in raw.split(",") if o.strip())
    return frozenset(DEFAULT_ALLOWED_ORGS)


def first_party_packs() -> frozenset[str]:
    from ..connectors import builtin
    return frozenset(builtin.FIRST_PARTY_PACKS)


def first_party_source(pack: str) -> tuple[str, str] | None:
    """`(repository, pack directory prefix)` the gateway knows for `pack`."""
    from ..connectors import builtin
    return builtin.FIRST_PARTY_SOURCES.get(pack)


def source_problem(component: GatewayComponent) -> str:
    """Why the declared `source` is not the pack's known upstream, or ""."""
    known = first_party_source(component.pack)
    if known is None:
        return (f"'{component.pack}' is not a pack this gateway knows as "
                "first-party (no entry in FIRST_PARTY_SOURCES)")
    repo, prefix = known
    if component.repo.lower() != repo.lower():
        return (f"source repository '{component.repo}' is not the upstream of "
                f"'{component.pack}' ('{repo}')")
    if not (component.path.rstrip("/") + "/").startswith(prefix):
        return (f"source.path '{component.path}' is outside the directory of "
                f"'{component.pack}' in '{repo}' ('{prefix}')")
    return ""


def owner_approved(component: GatewayComponent) -> bool:
    """Hook: has the owner approved this (third-party) component through the
    SYSTEM gate? Not implemented — default deny (#558)."""
    return False


def state_isolated() -> bool:
    from .. import state_paths
    try:
        return state_paths.is_isolated()
    except Exception:  # noqa: BLE001
        return False


def refusal(component: GatewayComponent, manifest: Mapping[str, Any]) -> str:
    """Why this component may NOT be fetched and run here, or "" if it may."""
    if not state_isolated():
        return ("the gateway state directory is not isolated from the shared "
                "datadir (CLODIA_TOOLS_STATE_DIR unset or equal to CLODIA_DATA): "
                "component code would sit on a volume the agent-server can write")
    problems = []
    if manifest.get("first_party") is not True:
        problems.append("the pack manifest does not declare 'first_party: true'")
    src = source_problem(component)
    if src:
        problems.append(src)
    # Secondary: the table above is the rule; the org list can only narrow it.
    orgs = allowed_orgs()
    if component.org not in orgs:
        problems.append(f"source repository '{component.repo}' is outside the "
                        f"allowed organisations {sorted(orgs)}")
    if not problems:
        return ""
    if owner_approved(component):
        return ""
    return "; ".join(problems) + " (third-party gateway components are refused)"


def credential_problem(component: GatewayComponent, prefix: str) -> str:
    """Why `component` may not use the vault prefix/entry `prefix` NOW, or "".

    `prefix` ending in `_` is a prefix; otherwise it is one exact entry name.
    Three cases:

    * a `CORE_CREDENTIALS_FOLLOW` key (a prefix or entry of the gateway's
      custody, e.g. `google_`, `app_google_oauth`): only while its switch is on
      `pack` position and hands the connector to this component's pack;
    * anything overlapping a core vault prefix (`google_`, `gmail_`, …): only
      the prefixes the connectors switched to THIS pack release
      (`builtin.released_to`);
    * anything else: inside the namespace of one of the component's connectors
      (`<ns>` or `<ns>_…`), the rule `vault_entry_problem` applies to a pack
      credential.
    """
    from ..connectors import builtin
    from ..connectors.manifest import CORE_VAULT_PREFIXES

    if prefix not in component.credentials:
        return (f"'{prefix}' is not among the credentials component "
                f"'{component.key}' declares ({list(component.credentials)})")
    if prefix in builtin.CORE_CREDENTIALS_FOLLOW:
        if builtin.follows_switch_to(prefix, component.pack):
            return ""
        return (f"'{prefix}' is a gateway credential scope that follows the "
                f"'{builtin.CORE_CREDENTIALS_FOLLOW[prefix]}' switch, which is "
                f"not handed to '{component.pack}' on this instance")
    stem = prefix.rstrip("_")
    cores = [c for c in CORE_VAULT_PREFIXES
             if prefix.startswith(c) or c.startswith(prefix) or stem == c.rstrip("_")]
    if cores:
        freed = builtin.released_to(component.pack)
        missing = [c for c in cores if c not in freed]
        if missing:
            return (f"'{prefix}' overlaps the core vault prefix(es) {missing}, "
                    f"which no connector switched to '{component.pack}' releases "
                    "on this instance")
        return ""
    for ns in component.namespaces.values():
        if stem == ns or stem.startswith(f"{ns}_"):
            return ""
    return (f"'{prefix}' is outside the namespaces of the component's connectors "
            f"({sorted(set(component.namespaces.values()))})")


def credential_matches(prefix: str, name: str) -> bool:
    """Does the vault entry `name` fall under the declared `prefix`?"""
    if prefix.endswith("_"):
        return name.startswith(prefix) and len(name) > len(prefix)
    return name == prefix

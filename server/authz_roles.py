"""Role tools as global A·V·R·Q tuples: a plan the owner applies
(clodia-platform#703, epic #701).

A role tool belongs to a seed and works EVERYWHERE — in the person's DM with
the agent, in a room that does not expose it — without entering the room's
toolbox, so the other participants do not get it. Under A·V·R·Q that is one
global tuple per verb, naming the agent, `where: everywhere`.

These tuples are NOT written by code. `role_plan` proposes them (a dry run,
like `authz_migration.plan`), the owner reads the plan, and `merge` writes the
approved one. `merge` is ADDITIVE, unlike `authz_migration.apply`, which
replaces every global tuple and every room's rules: with enforcement on since
25 Oct 2026, applying a plan that holds only one role would take every other
verb away from every agent.

What the sysadmin role holds (owner, 18 Nov 2026):

- **GitHub**: the verbs of the `github` MCP backend, listed BY NAME from the
  backend itself — a wildcard would grant whatever the backend adds tomorrow
  (17 Aug 2026: `delete_repository`, `force_push`). Irreversible verbs are left
  out (decision-record 35: what cannot be undone is not granted), and so are
  the git component verbs (`github.clone/pull/push/pull_request/mirror`): they
  need a room-approved repository and the helpdesk does not need them.
- **Diagnostics**: `runtime.*`, `logs.*` (both content-free since #704).
- **Governance**: `packs.*`, `agents.*`, `jobs.*`, and the datastore /
  collection CONTAINER verbs — never the verbs that read or write rows or
  documents.

Reads are `allow`. A write is `ask` — the confirmation card, which outside a
room is `authz-global:` and therefore an admin's to answer (gate class
`system`; owner 19 Nov 2026: the widget is admin-only, so the admin using it
approves) — unless the verb already raises its own consent (a gated verb, a
verb the seed gates, or one that asks inside), where a second card for the
same act would only teach people to click through.
"""
from __future__ import annotations

import re
import time
from typing import Iterable, Optional

from . import authz as A

#: Same prefix `authz_runtime.ROLE_PREFIX` filters on (admin principal only).
ID_PREFIX = "role-"
ORIGIN = "role-plan"

#: The roles a plan can be generated for, and the namespaces of each.
ROLES = {"sysadmin": ("runtime", "logs", "packs", "agents", "jobs")}

#: Datastore / collection CONTAINER verbs: create and list the containers,
#: never read or write what is inside them.
CONTAINER_VERBS = frozenset({"packs.create_datastore", "packs.datastore_structures",
                             "rag.collections", "rag.create_collection"})

#: Verbs that return or move what someone wrote — never a role tool of an
#: agent whose charter is «never the contents» (#701). Checked against every
#: plan, whatever the namespaces say: a namespace added to a role tomorrow
#: does not smuggle one of these in.
CONTENT_BEARING = frozenset({
    "rag.search", "rag.list", "rag.ingest", "rag.remove",
    "datastore.read", "datastore.write",
    "eu_corpus.search", "eu_corpus.ingest", "eu_corpus.remove", "eu_corpus.list",
    "profile.read_file", "profile.fetch", "memory.read", "memory.fetch",
    "jobs.report_status",
})
CONTENT_BEARING_NAMESPACES = frozenset({"topic", "datastore", "eu_corpus", "memory",
                                        "web", "email", "mail", "channel", "artifact"})

#: Read-only verbs whose name the generic classifier would call a write
#: (`runtime.agents`: «agents» is not a reading word).
READS = frozenset({
    "runtime.agents", "runtime.jobs", "runtime.skills", "runtime.chats",
    "runtime.topics", "runtime.mcp_servers", "runtime.providers",
    "runtime.current_user", "runtime.inspect_topic", "runtime.room_tools",
    "runtime.health", "logs.tail",
    "agents.list", "agents.show", "agents.list_rules", "agents.list_scoped",
    "agents.list_skills", "agents.list_tools",
    "jobs.list", "packs.list", "packs.show", "packs.drift", "packs.check_command",
    "packs.datastore_structures", "rag.collections",
})

#: Writes that already ask a person inside the verb (their own consent card or
#: signed one-time approval): an `ask` tuple would put a second card in front.
SELF_CONSENT = frozenset({"runtime.room_authorize_mcp", "runtime.room_resource",
                          "jobs.propose"})

#: The git verbs of the `github` namespace (served by it-pack's component,
#: `main._GITHUB_NATIVE_NAMES`): not role tools of the helpdesk.
GITHUB_GIT_VERBS = frozenset({"github.clone", "github.pull", "github.push",
                              "github.pull_request", "github.mirror"})
#: Words of the backend's verbs that cannot be undone (decision-record 35),
#: or that are not the helpdesk's: secret-scanning alerts carry the secret
#: itself, and notifications are the PAT owner's personal inbox.
GITHUB_EXCLUDED = ("delete", "force_push", "merge", "create_repository",
                   "transfer", "archive", "secret", "notification")
#: Verbs left out of every role although their namespace is in it.
ROLE_EXCLUDED = frozenset({
    # `/clodia/chats` no longer exists on the agent-server: a verb that can
    # only fail is not a tool.
    "runtime.chats",
})
#: The backend's verbs known when it cannot be listed (the former
#: `_GH_CONCESSI` minus the git verbs): the plan says it fell back to them.
GITHUB_KNOWN = (
    "github.add_issue_comment", "github.get_commit", "github.get_file_contents",
    "github.get_pull_request", "github.issue_read", "github.issue_write",
    "github.list_branches", "github.list_commits", "github.list_issues",
    "github.list_pull_requests", "github.list_releases", "github.list_tags",
    "github.search_code", "github.search_commits", "github.search_issues",
)
#: `request`, `run`, `label` are nouns as often as verbs (`get_pull_request`,
#: `get_workflow_run`): they decide nothing; a verb without a reading word is
#: a write anyway.
_WRITE_WORDS = frozenset({"write", "create", "update", "add", "comment", "push",
                          "set", "remove", "fork", "assign", "edit", "close",
                          "reopen", "submit", "rerun", "cancel", "dismiss", "lock",
                          "mark", "star", "unstar", "subscribe", "unsubscribe",
                          "manage", "delete", "approve", "resolve"})
_READ_WORDS = frozenset({"list", "read", "get", "search", "show", "open", "status",
                         "fetch", "download", "info", "query", "find", "lookup",
                         "view", "diff", "logs"})


class RoleError(ValueError):
    pass


def _tokens(verb: str) -> set[str]:
    return set(re.split(r"[_\-.]+", verb.split(".", 1)[-1].lower()))


def is_read(verb: str) -> bool:
    """Read-only? The explicit list first; then the connector manifests
    (`authz_shadow.facts`); then the verb's words — a verb with any writing
    word is a write, so an unclear name errs towards the card."""
    if verb in READS:
        return True
    try:
        from . import authz_shadow as S
        f = S.facts(verb, {})
        if f.get("mapped"):
            return f["kind"] == A.READ
    except Exception:  # noqa: BLE001
        pass
    t = _tokens(verb)
    return bool(t & _READ_WORDS) and not (t & _WRITE_WORDS)


def _own_consent(verb: str, agent: str) -> bool:
    if verb in SELF_CONSENT:
        return True
    try:
        from . import gate
        if gate.is_gated(verb):
            return True
    except Exception:  # noqa: BLE001
        pass
    try:
        from . import whitelist
        return bool(whitelist.agent_gates(verb, agent))
    except Exception:  # noqa: BLE001
        return False


def content_bearing(verb: str) -> bool:
    return verb in CONTENT_BEARING or verb.split(".", 1)[0] in CONTENT_BEARING_NAMESPACES


def github_verbs(listed: Optional[Iterable[str]]) -> tuple[list[str], str]:
    """The backend's verbs a role may hold, and where the names came from
    (`backend` when listed live, `known` for the fallback)."""
    if listed:
        names, source = [n if n.startswith("github.") else f"github.{n}" for n in listed], "backend"
    else:
        names, source = list(GITHUB_KNOWN), "known"
    try:
        from . import whitelist
        off = {f"github.{t}" for t in whitelist.disabled_backend_tools("github")}
    except Exception:  # noqa: BLE001
        off = set()
    keep = sorted({n for n in names
                   if n not in GITHUB_GIT_VERBS and n not in off
                   and not any(w in n.split(".", 1)[1].lower() for w in GITHUB_EXCLUDED)})
    return keep, source


def _native_catalogue() -> set[str]:
    from . import main
    names = {t.name for t in main._all_native_tools()}
    names |= {t.name for t in main._EU_CORPUS_TOOLS + main._RAG_TOOLS}
    return names


def role_plan(agent: str = "sysadmin", *, catalogue: Optional[Iterable[str]] = None,
              github_tools: Optional[Iterable[str]] = None) -> dict:
    """The proposed global tuples for `agent`'s role tools. Writes nothing.

    `catalogue`: the native verbs (default: the gateway's own); `github_tools`:
    the names the `github` backend lists (None: not mounted or not listable —
    the known names are proposed and the plan says so)."""
    if agent not in ROLES:
        raise RoleError(f"nessun ruolo definito per '{agent}': {', '.join(sorted(ROLES))}")
    nss = ROLES[agent]
    cat = set(catalogue) if catalogue is not None else _native_catalogue()
    verbs = sorted(v for v in cat
                   if (v.split(".", 1)[0] in nss or v in CONTAINER_VERBS)
                   and not content_bearing(v) and v not in ROLE_EXCLUDED)
    gh, gh_source = github_verbs(github_tools)
    rows, skipped = [], []
    for v in verbs + gh:
        if content_bearing(v):          # belt and braces: never in a role
            skipped.append({"verb": v, "why": "porta contenuti (#704)"})
            continue
        if is_read(v):
            eff, why = A.ALLOW, "lettura"
        elif _own_consent(v, agent):
            eff, why = A.ALLOW, "scrittura con conferma propria (gate del verbo): nessuna seconda card"
        else:
            eff, why = A.ASK, "scrittura: card di conferma (admin, fuori dalle stanze)"
        group = ("github" if v.startswith("github.") else
                 "diagnostica" if v.split(".", 1)[0] in ("runtime", "logs") else "governo")
        rows.append({"id": f"{ID_PREFIX}{agent}-{v}", "agent": agent, "verb": v,
                     "resource": A.ANY, "where": A.EVERYWHERE,
                     "rule": [{"effect": eff, "match": A.ANY}],
                     "origin": ORIGIN, "group": group, "why": why})
    _ok, bad = A.parse_tuples(rows, level=A.GLOBAL)
    if bad:                             # a plan we generate must parse
        raise RoleError("piano non valido: " + "; ".join(bad[:5]))
    return {"generated_at": time.time(), "role": agent, "global": rows, "topics": {},
            "github_source": gh_source, "skipped": skipped,
            "excluded": {"git_verbs": sorted(GITHUB_GIT_VERBS),
                         "content_bearing": sorted(CONTENT_BEARING)},
            "stats": {"tuples": len(rows),
                      "ask": sum(1 for r in rows if r["rule"][0]["effect"] == A.ASK),
                      "allow": sum(1 for r in rows if r["rule"][0]["effect"] == A.ALLOW)}}


def markdown(p: dict) -> str:
    lines = [f"# Strumenti di ruolo: {p['role']} ({p['stats']['tuples']} tuple globali, "
             f"`where: everywhere`)", "",
             f"GitHub: nomi letti da **{p['github_source']}**.", "",
             "| gruppo | verbo | effetto | perché |", "|---|---|---|---|"]
    for t in p["global"]:
        lines.append(f"| {t['group']} | `{t['verb']}` | {t['rule'][0]['effect']} | {t['why']} |")
    lines += ["", "Esclusi: i verbi git (`" + "`, `".join(p["excluded"]["git_verbs"]) + "`), "
              "i verbi irreversibili del backend e ogni verbo che porta contenuti."]
    return "\n".join(lines) + "\n"


def _expected(p: dict, github_tools: Optional[Iterable[str]],
              catalogue: Optional[Iterable[str]]) -> dict:
    role = str((p or {}).get("role") or "").strip()
    if role not in ROLES:
        raise A.AuthzError(f"piano senza un ruolo noto (`role`): {role!r}")
    try:
        fresh = role_plan(role, catalogue=catalogue, github_tools=github_tools)
    except RoleError as e:
        raise A.AuthzError(str(e)) from None
    return {t["id"]: t for t in fresh["global"]}


def _check_row(r: dict, want: Optional[dict]) -> str:
    """"" when `r` is a row `role_plan` would generate — same id, agent,
    verb, resource and `where`, one clause on `*` with the same or a STRICTER
    effect — otherwise why it is refused."""
    if want is None:
        return f"{r.get('id')!r}: non è una riga che il piano di ruolo genera oggi"
    for k in ("agent", "verb", "resource"):
        if r.get(k) != want[k]:
            return f"{r['id']}: {k} {r.get(k)!r} ≠ {want[k]!r}"
    if str(r.get("where") or A.EVERYWHERE) != want["where"]:
        return f"{r['id']}: where {r.get('where')!r} ≠ {want['where']!r}"
    rule = r.get("rule")
    if not (isinstance(rule, list) and len(rule) == 1 and isinstance(rule[0], dict)
            and rule[0].get("match") == A.ANY
            and set(rule[0]) <= {"effect", "match"}):
        return f"{r['id']}: la regola dev'essere una sola clausola su `*`"
    eff, top = rule[0].get("effect"), want["rule"][0]["effect"]
    if eff not in A.RANK or A.RANK[eff] > A.RANK[top]:
        return f"{r['id']}: effetto {eff!r} più largo di {top!r}"
    return ""


def merge(p: dict, *, by: str, github_tools: Optional[Iterable[str]] = None,
          catalogue: Optional[Iterable[str]] = None) -> dict:
    """Add an approved role plan's global tuples to `authz.json`.

    ONLY rows that `role_plan(p["role"])` regenerates now are accepted: same
    id, agent, verb, resource and `where`, and the same effect or a stricter
    one (`ask` or `deny` for an `allow`, `deny` for an `ask`). The owner may
    trim the plan or tighten a row; anything else — a verb the role does not
    hold, a wider effect, a target-specific clause — refuses the whole merge.
    `github_tools`: the backend's names, listed live by the route, so a
    GitHub row is checked against what the backend serves.

    ADDITIVE: nothing already there is changed or removed; a tuple whose id
    is present, or that names the same agent, verb and resource as one already
    there, is skipped (the owner's earlier decision wins).

    ROLLBACK: the state is snapshotted first (the global file AND every room's
    `meta.authz`), and `authz_migration.rollback(backup)` restores THAT
    snapshot whole — it also undoes any rule changed after the merge (a gate
    remembered, a room rule removed). To take back only the role tuples, remove
    them by id (`DELETE /internal/authz/rules`, ids `role-<agent>-<verb>`)."""
    if (p or {}).get("topics"):
        raise A.AuthzError("un piano di ruolo è solo globale: nessuna regola di stanza")
    rows = [r for r in (p or {}).get("global") or [] if isinstance(r, dict)]
    if not rows:
        raise A.AuthzError("piano vuoto: nulla da aggiungere")
    expected = _expected(p, github_tools, catalogue)
    for r in rows:
        if content_bearing(str(r.get("verb") or "")):
            raise A.AuthzError(f"{r.get('verb')!r} porta contenuti: non è uno strumento di ruolo")
        why = _check_row(r, expected.get(str(r.get("id") or "")))
        if why:
            raise A.AuthzError("piano rifiutato, nulla scritto: " + why)
    _ok, bad = A.parse_tuples(rows, level=A.GLOBAL)
    if bad:
        raise A.AuthzError("piano non valido, nulla scritto: " + "; ".join(bad[:5]))
    from . import authz_migration as MIG
    from . import authz_runtime as R
    from . import gate_remember as GR
    if not MIG._apply_lock.acquire(blocking=False):
        raise A.AuthzError("un'altra migrazione è in corso")
    try:
        backup = MIG._backup(MIG._snapshot())
        stamp = {"by": by, "at": time.time()}
        keep = ("id", "agent", "verb", "resource", "where", "rule", "origin", "why")
        rows = [{**r, "where": r.get("where") or A.EVERYWHERE} for r in rows]
        with GR._GLOBAL_LOCK:
            doc = GR._read_global()
            have_ids = {t.get("id") for t in doc["tuples"] if isinstance(t, dict)}
            have = {(t.get("agent"), t.get("verb"), t.get("resource"))
                    for t in doc["tuples"] if isinstance(t, dict)}
            added, skipped = [], []
            for r in rows:
                key = (r["agent"], r["verb"], r["resource"])
                if r["id"] in have_ids or key in have:
                    skipped.append(r["id"])
                    continue
                added.append({**{k: r[k] for k in keep if k in r}, **stamp})
                have.add(key)
            if added:
                doc["tuples"] = list(doc["tuples"]) + added
                GR._write_global_doc(doc)
        R.invalidate()
        return {"ok": True, "backup": backup, "added": len(added),
                "skipped": skipped, "by": by}
    finally:
        MIG._apply_lock.release()

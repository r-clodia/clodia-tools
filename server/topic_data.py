"""Data imported by a scope, and who may use it there (clodia-platform#590:
D2 #592 import, D3 #593 per-agent grants, D4 #594 enforcement; #669 the only
data access; #670 DM and job scopes).

A **scope** is where an agent works: a topic, a DM (a topic with `kind: dm`)
or an agentic job. Imports into a scope are the ONLY way an agent reaches a
datastore or a RAG collection (#669): no seed list, no `rag_read`/`rag_write`,
no legacy mode. The scope comes from the signed `chat` claim
(`scope_of_call`): `chan:<tier>:<name>:<agent>` → `<tier>/<name>`,
`job:<id>:<suffix>` → `job:<id>`.

A topic declares in its meta the catalog resources it uses:

    meta["data"] = [{"kind": "datastore", "name": "tomato/clienti",
                     "grants": {"tomato.commerciale": "write", "clodia": "read"}}]

- **Import** (owner only): the resource must be in the catalog
  (`data_catalog`), the owner an allowed importer with clearance for it, and
  **the topic's tier ≥ the resource's tier** — data never moves down a level.
- **Access** (owner, 5 Nov 2026, #653): every agent IN THE CHANNEL reads and
  writes everything imported there — no per-agent roles. The one exception is
  the room's own index (`topic-*`): read-only, the indexer writes it. The old
  `grants` map is kept in the meta but no longer decides anything.
- **Enforcement** (`authorize`): on the topic of the SIGNED claim, never an
  argument. The resource is imported there, the agent is granted there, its
  clearance covers the resource, and the topic's tier still covers it. No
  topic → no access.

- **Jobs** (#670): an agentic job's `data: [{kind, name}]` lives in the job
  record (agent-server, `scheduler/db.py`) and is read live from there
  (`_job`). Whoever executes the job (its `agent`) uses it; the job's tier is
  the one it declares, or — undeclared — the executing agent's effective
  clearance (the claim). A `topic_trigger` job runs in its topic's channel and
  keeps that topic's imports.

Modelled on `drive_folders`: a declaration of the topic that narrows an
authority which exists elsewhere (the catalog), never opens one.
"""
from __future__ import annotations

from . import data_catalog as cat

MODES = ("read", "write")
FIELD = "data"


class DataError(ValueError):
    pass


def imports(meta: dict) -> list[dict]:
    raw = (meta or {}).get(FIELD)
    out = []
    for e in raw if isinstance(raw, list) else []:
        if isinstance(e, dict) and e.get("kind") in cat.KINDS and e.get("name"):
            g = e.get("grants") if isinstance(e.get("grants"), dict) else {}
            out.append({"kind": e["kind"], "name": str(e["name"]),
                        "grants": {str(a): m for a, m in g.items() if m in MODES}})
    return out


def _find(meta: dict, kind: str, name: str) -> dict | None:
    for e in imports(meta):
        if e["kind"] == kind and e["name"] == name:
            return e
    return None


def _svc():
    from . import main
    return main._topics()


def _write(svc, tier: str, name: str, mutate) -> dict:
    meta, ver = svc._read_meta(tier, name)
    entries = imports(meta)
    result = mutate(meta, entries)
    meta[FIELD] = entries
    svc._write_meta(tier, name, meta, base_version=ver)
    return result


def check_import(kind: str, resource: str, scope_tier: str | None, *,
                 principal: str, is_admin: bool, clearance: str | None,
                 scope_kind: str = "topic") -> dict:
    """The import rules, for any scope (#670): the resource is in the catalog,
    `principal` may import it, and the scope's tier covers the resource's.
    Returns `{kind, name, tier}`; raises DataError / PermissionError."""
    entry = cat.get(kind, resource)
    if entry is None and cat.sync_due():
        cat.sync()                      # a pack installed since the last boot
        entry = cat.get(kind, resource)
    if entry is None:
        raise DataError(f"{kind} '{resource}' non è nel catalogo dei dati")
    if scope_kind == "job" and kind == "rag" and str(resource).startswith("topic-"):
        raise DataError("l'indice di un topic resta nel suo topic: non si importa in un job")
    why = cat.may_import(entry, principal, is_admin=is_admin, clearance=clearance)
    if why:
        raise PermissionError(why)
    need = cat.effective_tier(entry)
    if cat.rank_have(scope_tier) < cat.rank(need):
        raise PermissionError(
            f"{kind} '{resource}' è {need}: non entra in un {scope_kind} "
            f"{cat.norm_tier(scope_tier)} (il tier dello scope deve essere almeno "
            "quello della risorsa)")
    return {"kind": kind, "name": resource, "tier": need}


def import_resource(tier: str, name: str, kind: str, resource: str, *,
                    principal: str, is_admin: bool, clearance: str | None) -> dict:
    checked = check_import(kind, resource, tier, principal=principal,
                           is_admin=is_admin, clearance=clearance)
    need = checked["tier"]
    svc = _svc()

    def mutate(meta, entries):
        if any(e["kind"] == kind and e["name"] == resource for e in entries):
            return {"ok": True, "already": True}
        entries.append({"kind": kind, "name": resource, "grants": {}})
        return {"ok": True, "imported": {"kind": kind, "name": resource, "tier": need}}
    return _write(svc, tier, name, mutate)


def remove(tier: str, name: str, kind: str, resource: str) -> dict:
    svc = _svc()

    def mutate(meta, entries):
        before = len(entries)
        entries[:] = [e for e in entries if not (e["kind"] == kind and e["name"] == resource)]
        if len(entries) == before:
            raise DataError(f"{kind} '{resource}' non è importato in {tier}/{name}")
        return {"ok": True, "removed": {"kind": kind, "name": resource}}
    return _write(svc, tier, name, mutate)


def grant(tier: str, name: str, kind: str, resource: str, agent: str,
          mode: str | None) -> dict:
    """Set `agent`'s mode on an imported resource; `mode` None/"" revokes."""
    if mode and mode not in MODES:
        raise DataError(f"modo sconosciuto: '{mode}' (read | write)")
    if mode == "write" and kind == "rag" and str(resource).startswith("topic-"):
        raise DataError("l'indice di un topic lo scrive solo l'indicizzatore: si concede in lettura")
    agent = str(agent or "").strip()
    svc = _svc()

    def mutate(meta, entries):
        roles = svc.participants_map(meta)          # owner included, map or list
        if mode and agent not in roles and agent != meta.get("owner"):
            raise DataError(f"'{agent}' non partecipa a {tier}/{name}: aggiungilo prima")
        for e in entries:
            if e["kind"] == kind and e["name"] == resource:
                if mode:
                    e["grants"][agent] = mode
                else:
                    e["grants"].pop(agent, None)
                return {"ok": True, "grants": dict(e["grants"])}
        raise DataError(f"{kind} '{resource}' non è importato in {tier}/{name}")
    return _write(svc, tier, name, mutate)


def drop_agent(meta: dict, agent: str) -> bool:
    """Remove `agent`'s grants from `meta` in place (a participant removed)."""
    changed = False
    entries = imports(meta)
    for e in entries:
        if e["grants"].pop(agent, None) is not None:
            changed = True
    if changed:
        meta[FIELD] = entries
    return changed


def check_retier(meta: dict, new_tier: str) -> None:
    """A topic cannot go below the level of the data it imports — its OWN
    index excepted, which follows it (review of #422, B3)."""
    own = str(((meta or {}).get("index") or {}).get("collection") or "") \
        if isinstance((meta or {}).get("index"), dict) else ""
    for e in imports(meta):
        if e["kind"] == "rag" and own and e["name"] == own:
            continue
        try:
            entry = cat.get(e["kind"], e["name"])
        except RuntimeError as err:     # unreadable catalog: refuse, do not crash
            raise DataError(str(err)) from err
        need = cat.effective_tier(entry) if entry else "SEAL-0"
        if cat.rank_have(new_tier) < cat.rank(need):
            raise DataError(
                f"il topic importa {e['kind']} '{e['name']}' ({need}): non può scendere a "
                f"{cat.norm_tier(new_tier)}. Rimuovi prima l'import.")


#: The prefix of a job's chat id and data scope (#670): the agent-server
#: names an agentic job's chat `job:<id>:<suffix>`, and that id is signed into
#: the session token's `chat` claim.
JOB_PREFIX = "job:"


def scope_of_call() -> str | None:
    """The DATA scope of the current call, from the signed `chat` claim:
    `<tier>/<name>` in a topic or DM channel, `job:<id>` in an agentic job's
    turn, None otherwise (an internal call, a Telegram 1:1). Never from an
    argument: that would be the agent's word on where it is."""
    try:
        from .whitelist import current_channel, current_chat
        ch = current_channel()
        if ch:
            return ch
        c = current_chat() or ""
    except Exception:  # noqa: BLE001
        return None
    if c.startswith(JOB_PREFIX):
        jid = c[len(JOB_PREFIX):].split(":", 1)[0]
        if jid.isdigit():
            return f"{JOB_PREFIX}{int(jid)}"
    return None


def job_id(scope: str | None) -> int | None:
    s = str(scope or "")
    if not s.startswith(JOB_PREFIX):
        return None
    rest = s[len(JOB_PREFIX):]
    return int(rest) if rest.isdigit() else None


#: A few seconds of memory per job: every data call of a turn reads the job,
#: and the job record lives in the agent-server. Short enough that an import
#: removed by the owner is out before the next turn; an error is never cached.
_JOB_TTL = 2.0
_job_cache: dict[int, tuple[float, dict]] = {}


def _job(jid: int) -> dict:
    """The job record (agent-server), read live. Any failure is a refusal."""
    import time as _time
    now = _time.monotonic()
    hit = _job_cache.get(jid)
    if hit and now - hit[0] < _JOB_TTL:
        return hit[1]
    try:
        from .tools import runtime
        job = runtime.job_scope(jid)
    except Exception as e:  # noqa: BLE001 — fail closed
        raise PermissionError(f"job {jid} non leggibile: {type(e).__name__}") from e
    if not isinstance(job, dict):
        raise PermissionError(f"job {jid} non leggibile")
    _job_cache[jid] = (now, job)
    return job


def job_tier(job: dict, clearance: str | None) -> str:
    """The job's tier: the one it declares, else the executing agent's
    effective clearance (#670: jobs have no tier of their own unless declared)."""
    return str(job.get("tier") or "").strip() or cat.norm_tier(clearance)


def job_imports(job: dict) -> list[dict]:
    return imports({FIELD: (job or {}).get(FIELD)})


def _job_runs_as(job: dict, agent: str) -> bool:
    return bool(agent) and (job.get("mode") or "agentic") == "agentic" \
        and str(job.get("agent") or "") == agent


def _authorize_job(jid: int, kind: str, resource: str, *, write: bool, agent: str,
                   clearance: str | None) -> dict:
    job = _job(jid)
    if not _job_runs_as(job, agent):
        raise PermissionError(
            f"agent '{agent}' non esegue il job {jid}: i dati importati lì li usa "
            "solo l'agente del job")
    if not any(e["kind"] == kind and e["name"] == resource for e in job_imports(job)):
        raise PermissionError(f"{kind} '{resource}' non è importato nel job {jid}")
    entry = cat.get(kind, resource)
    if entry is None:
        raise PermissionError(f"{kind} '{resource}' non è più nel catalogo dei dati")
    if write and kind == "rag" and str(resource).startswith("topic-"):
        raise PermissionError(f"'{resource}' è l'indice di un topic: lo scrive solo "
                              "l'indicizzazione automatica")
    need = cat.effective_tier(entry)
    if cat.rank_have(job_tier(job, clearance)) < cat.rank(need):
        raise PermissionError(f"{kind} '{resource}' ({need}) sopra il tier del job {jid}")
    if cat.rank_have(clearance) < cat.rank(need):
        raise PermissionError(
            f"agent '{agent}': clearance insufficiente per {kind} '{resource}' ({need})")
    return entry


#: Kinds every PARTICIPANT reads once imported in the room (26 Oct 2026) —
#: since #653 every kind, and they write it too.
READ_FOR_PARTICIPANTS = frozenset({"rag", "datastore"})


def _participant(meta: dict, agent: str) -> bool:
    from .topics.service import TopicService
    return bool(agent) and agent in TopicService.participants_map(meta)


def own_index(e: dict) -> bool:
    """The room's own RAG index: written by the indexer alone (#422 B2)."""
    return e["kind"] == "rag" and str(e["name"]).startswith("topic-")


def _reads(meta: dict, e: dict, agent: str) -> bool:
    """May `agent` read the import `e` of this room? Being in the room is
    enough (#653)."""
    return _participant(meta, agent)


def _writes(meta: dict, e: dict, agent: str) -> bool:
    """May `agent` write the import `e`? Being in the room is enough (#653),
    except for the room's own index."""
    return _participant(meta, agent) and not own_index(e)


def authorize(kind: str, resource: str, *, write: bool, agent: str,
              clearance: str | None, scope: str | None) -> dict:
    """The decision for an AGENT's call, in its scope (topic, DM or job).
    Returns the catalog entry; raises PermissionError with the reason."""
    if not scope:
        raise PermissionError(
            f"{kind} '{resource}': accesso solo dentro un topic, un DM o un job che "
            "lo importa (nessuno scope in questa chiamata)")
    jid = job_id(scope)
    if jid is not None:
        return _authorize_job(jid, kind, resource, write=write, agent=agent,
                              clearance=clearance)
    tier, _, name = scope.partition("/")
    try:
        meta = _svc()._read_meta(tier, name)[0]     # meta only: this runs on every call
    except Exception as e:  # noqa: BLE001
        raise PermissionError(f"topic {scope} non leggibile: {type(e).__name__}") from e
    imp = _find(meta, kind, resource)
    if imp is None:
        raise PermissionError(f"{kind} '{resource}' non è importato nel topic {scope}")
    entry = cat.get(kind, resource)
    if entry is None:
        raise PermissionError(f"{kind} '{resource}' non è più nel catalogo dei dati")
    if write and own_index(imp):
        raise PermissionError(f"'{resource}' è l'indice del topic {scope}: lo scrive "
                              "solo l'indicizzazione automatica")
    if not (_writes(meta, imp, agent) if write else _reads(meta, imp, agent)):
        raise PermissionError(
            f"agent '{agent}' non partecipa al topic {scope}: i dati importati lì li "
            "usano solo i partecipanti")
    need = cat.effective_tier(entry)
    topic_tier = meta.get("tier") or tier
    if cat.rank_have(topic_tier) < cat.rank(need):
        raise PermissionError(f"{kind} '{resource}' ({need}) sopra il tier del topic {scope}")
    if cat.rank_have(clearance) < cat.rank(need):
        raise PermissionError(
            f"agent '{agent}': clearance insufficiente per {kind} '{resource}' ({need})")
    return entry


def visible(kind: str, *, agent: str, scope: str | None,
            clearance: str | None = None) -> set[str]:
    """Names of `kind` the agent may read in its scope (for listings): the
    same answer `authorize` would give, without raising."""
    if not scope:
        return set()
    out = set()
    jid = job_id(scope)
    if jid is not None:
        try:
            job = _job(jid)
        except PermissionError:
            return set()
        for e in job_imports(job):
            if e["kind"] != kind:
                continue
            try:
                _authorize_job(jid, kind, e["name"], write=False, agent=agent,
                               clearance=clearance)
            except PermissionError:
                continue
            out.add(e["name"])
        return out
    tier, _, name = scope.partition("/")
    try:
        meta = _svc()._read_meta(tier, name)[0]
    except Exception:  # noqa: BLE001
        return set()
    for e in imports(meta):
        if e["kind"] != kind or not _reads(meta, e, agent):
            continue
        try:
            authorize(kind, e["name"], write=False, agent=agent, clearance=clearance, scope=scope)
        except PermissionError:
            continue
        out.add(e["name"])
    return out


def importing_topics() -> dict[str, list[str]]:
    """`{catalog key: ["SEAL-2/name", ...]}` — which topics import what (the
    Databases page, #595). Archived topics included: their imports still exist."""
    svc = _svc()
    out: dict[str, list[str]] = {}
    for row in svc.list(include_archived=True):
        try:
            meta = svc._read_meta(row["tier"], row["name"])[0]
        except Exception:  # noqa: BLE001
            continue
        for e in imports(meta):
            out.setdefault(f"{e['kind']}:{e['name']}", []).append(f"{row['tier']}/{row['name']}")
    return out


#: The verbs a room's data grant brings (#590): the grant, not the seed, says
#: what an agent may do with the data imported THERE.
_READ_VERBS = {"rag": ("rag.search", "rag.list", "rag.collections"),
               "datastore": ("datastore.read",)}
_WRITE_VERBS = {"datastore": ("datastore.write",), "rag": ("rag.ingest", "rag.remove")}


def room_verbs(agent: str | None, scope: str | None) -> set[str]:
    """Verbs `agent` gets in the room `scope` from the owner's data grants there.
    Request-local, like a scoped grant: the seed and the static trifecta score
    do not change, and outside this room nothing is added. The resource
    monitors (`_rag_authorize`, `_datastore_authorize`) still decide every call."""
    if not agent or not scope:
        return set()
    tier, _, name = scope.partition("/")
    try:
        meta = _svc()._read_meta(tier, name)[0]
    except Exception:  # noqa: BLE001 — no room, no verbs
        return set()
    out: set[str] = set()
    for e in imports(meta):
        if _reads(meta, e, agent):
            out.update(_READ_VERBS.get(e["kind"], ()))
        if _writes(meta, e, agent):
            out.update(_WRITE_VERBS.get(e["kind"], ()))
    return out

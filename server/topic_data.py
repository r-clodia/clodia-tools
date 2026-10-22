"""Data imported by a topic, and who may use it there (clodia-platform#590:
D2 #592 import, D3 #593 per-agent grants, D4 #594 enforcement).

A topic declares in its meta the catalog resources it uses:

    meta["data"] = [{"kind": "datastore", "name": "tomato/clienti",
                     "grants": {"tomato.commerciale": "write", "clodia": "read"}}]

- **Import** (owner only): the resource must be in the catalog
  (`data_catalog`), the owner an allowed importer with clearance for it, and
  **the topic's tier ≥ the resource's tier** — data never moves down a level.
- **Grants** (owner only): `read` | `write` per agent of the channel (seed
  name). Default none; `write` implies read. Only participants.
- **Enforcement** (`authorize`): on the topic of the SIGNED claim, never an
  argument. The resource is imported there, the agent is granted there, its
  clearance covers the resource, and the topic's tier still covers it. No
  topic → no access.

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


def import_resource(tier: str, name: str, kind: str, resource: str, *,
                    principal: str, is_admin: bool, clearance: str | None) -> dict:
    entry = cat.get(kind, resource)
    if entry is None and cat.sync_due():
        cat.sync()                      # a pack installed since the last boot
        entry = cat.get(kind, resource)
    if entry is None:
        raise DataError(f"{kind} '{resource}' non è nel catalogo dei dati")
    why = cat.may_import(entry, principal, is_admin=is_admin, clearance=clearance)
    if why:
        raise PermissionError(why)
    need = cat.effective_tier(entry)
    if cat.rank_have(tier) < cat.rank(need):
        raise PermissionError(
            f"{kind} '{resource}' è {need}: non entra in un topic {cat.norm_tier(tier)} "
            "(il tier del topic deve essere almeno quello della risorsa)")
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
    agent = str(agent or "").strip()
    svc = _svc()

    def mutate(meta, entries):
        roles = svc.participants_map(meta)          # owner included, map or list
        if mode and agent not in roles and agent != meta.get("owner"):
            raise DataError(f"'{agent}' non partecipa a {tier}/{name}: aggiungilo prima")
        if mode == "write" and roles.get(agent) == "reader":
            raise DataError(f"'{agent}' è lettore in {tier}/{name}: non può avere la scrittura")
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
    """A topic cannot go below the level of the data it imports."""
    for e in imports(meta):
        try:
            entry = cat.get(e["kind"], e["name"])
        except RuntimeError as err:     # unreadable catalog: refuse, do not crash
            raise DataError(str(err)) from err
        need = cat.effective_tier(entry) if entry else "SEAL-0"
        if cat.rank_have(new_tier) < cat.rank(need):
            raise DataError(
                f"il topic importa {e['kind']} '{e['name']}' ({need}): non può scendere a "
                f"{cat.norm_tier(new_tier)}. Rimuovi prima l'import.")


def mode() -> str:
    """`legacy` (seed grants, as before #590) or `topic` (this module)."""
    from . import whitelist
    m = str(whitelist.CONFIG.get("data_access") or "legacy").strip().lower()
    return m if m in ("legacy", "topic") else "legacy"


def authorize(kind: str, resource: str, *, write: bool, agent: str,
              clearance: str | None, scope: str | None) -> dict:
    """The topic-mode decision for an AGENT's call. Returns the catalog entry;
    raises PermissionError with the reason."""
    if not scope:
        raise PermissionError(
            f"{kind} '{resource}': accesso solo dentro un topic che lo importa "
            "(nessun topic in questa chiamata)")
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
    granted = imp["grants"].get(agent)
    if write and granted == "write":
        # A participant demoted to reader keeps no write (second review of #420).
        from .topics.service import TopicService
        if TopicService.participants_map(meta).get(agent) == "reader":
            granted = "read"
    if granted is None or (write and granted != "write"):
        raise PermissionError(
            f"agent '{agent}' senza permesso di {'SCRITTURA' if write else 'LETTURA'} "
            f"su {kind} '{resource}' nel topic {scope} (lo assegna l'owner del topic)")
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
    """Names of `kind` the agent may read in its topic (for listings): the
    same answer `authorize` would give, without raising."""
    if not scope:
        return set()
    out = set()
    tier, _, name = scope.partition("/")
    try:
        meta = _svc()._read_meta(tier, name)[0]
    except Exception:  # noqa: BLE001
        return set()
    for e in imports(meta):
        if e["kind"] != kind or not e["grants"].get(agent):
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

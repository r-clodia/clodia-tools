"""A room's «In ascolto» list (clodia-platform#675/#676).

The owner puts a room in listening on sources — a mail sender, a Telegram
group, a pack connector's chat — and the connector does the rest. The list is
DERIVED, not stored: a template kind's sources are the room's ingress entries
of that kind's shape (`mailfrom:{sender}`), an action kind's source is the chat
its topic action bound to the room. Existing rooms therefore show their
sources with no migration, and the ingress/egress lists stay the one engine.

Listening = trusted (owner, 12 Nov 2026): a source written here is a trusted
ingress entry, exactly as the lists have always meant.

Template kinds are added and removed here (`add`, `remove`). Action kinds are
added and removed by running their topic action (the existing connect /
disconnect route): this module only names which action, so binding, pairing
and the SEAL acknowledgement keep their one implementation.
"""
from __future__ import annotations

import logging

LOG = logging.getLogger("clodia-tools.room_listen")


class ListenError(ValueError):
    """A listen request that cannot be honoured (unknown kind, bad address)."""


def _connectors():
    from . import instance_profile
    from .connectors import resolved
    for c in resolved.registry().connectors:
        if c.listen and instance_profile.connector_allowed(c.id):
            yield c


def kinds() -> list[dict]:
    """Every kind of source the instance can listen to, for the Add dialog."""
    out = []
    for c in _connectors():
        for k in c.listen:
            out.append({"connector": c.id, "connector_label": c.label or c.id,
                        "kind": k.kind, "label": k.label, "reply": k.reply,
                        "action": k.action,
                        "field": ({"name": k.field.name, "label": k.field.label,
                                   "placeholder": k.field.placeholder}
                                  if k.field else None)})
    return out


def _find(connector: str, kind: str):
    for c in _connectors():
        if c.id == connector:
            for k in c.listen:
                if k.kind == kind:
                    return c, k
    raise ListenError(f"nessuna fonte '{kind}' per il connettore '{connector}'")


def _prefix(template: str, field: str) -> str:
    """`mailfrom:{sender}` → `mailfrom:`: the part before the address."""
    return template[: -len("{" + field + "}")]


def _render(template: str, field: str, address: str) -> str:
    return template.replace("{" + field + "}", address)


def sources(tier: str, name: str) -> list[dict]:
    """The sources the room listens to now, derived from its lists and its
    channel bindings."""
    from . import egress
    from .connectors import actions as _actions
    scope = f"{tier}/{name}"
    ingress = list(egress.scope_uris("ingress", scope))
    out_egress = set(egress.scope_uris("egress", scope))
    out = []
    for c in _connectors():
        for k in c.listen:
            if k.action:
                chat = _actions._bound_chat(c.id, tier, name)
                if chat:
                    out.append({"connector": c.id, "kind": k.kind, "label": k.label,
                                "address": str(chat), "reply": True,
                                "action": k.action})
                continue
            pre = _prefix(k.ingress, k.field.name)
            for uri in ingress:
                if not uri.startswith(pre) or len(uri) == len(pre):
                    continue
                addr = uri[len(pre):]
                reply = bool(k.egress) and _render(k.egress, k.field.name, addr) in out_egress
                out.append({"connector": c.id, "kind": k.kind, "label": k.label,
                            "address": addr, "reply": reply, "action": ""})
    return out


def add(tier: str, name: str, connector: str, kind: str, address: str,
        reply: bool = False) -> dict:
    """Listen to a TEMPLATE kind's address: its trusted ingress entry, and the
    egress one when the kind replies (always, or by the owner's choice)."""
    from . import egress
    c, k = _find(connector, kind)
    if k.action:
        raise ListenError(f"'{kind}' si collega con l'azione '{k.action}' del "
                          f"connettore '{connector}', non da qui")
    addr = str(address or "").strip()
    if not addr:
        raise ListenError("indirizzo richiesto")
    pre = _prefix(k.ingress, k.field.name)
    if addr.lower().startswith(pre.lower()):
        addr = addr[len(pre):]          # a pasted full entry stands for its address
    scope = f"{tier}/{name}"
    out = {"connector": c.id, "kind": k.kind,
           "ingress": egress.scope_allow("ingress", scope,
                                         _render(k.ingress, k.field.name, addr))}
    if k.egress and (k.reply == "implicit" or (k.reply == "choice" and reply)):
        out["egress"] = egress.scope_allow("egress", scope,
                                           _render(k.egress, k.field.name, addr))
    return out


def remove(tier: str, name: str, connector: str, kind: str, address: str) -> dict:
    """Stop listening to a TEMPLATE kind's address: its ingress entry and the
    reply entry it implies go; the tool stays authorised (#662)."""
    from . import egress
    c, k = _find(connector, kind)
    if k.action:
        raise ListenError(f"'{kind}' si scollega con l'azione '{k.action}' del "
                          f"connettore '{connector}', non da qui")
    addr = str(address or "").strip()
    scope = f"{tier}/{name}"
    out = {"ingress": egress.scope_revoke("ingress", scope,
                                          _render(k.ingress, k.field.name, addr))}
    if k.egress:
        uri = _render(k.egress, k.field.name, addr)
        if uri in set(egress.scope_uris("egress", scope)):
            out["egress"] = egress.scope_revoke("egress", scope, uri)
    return out

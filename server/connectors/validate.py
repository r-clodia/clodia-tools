"""What a `connectors:` block would do on THIS instance, without doing it.

clodia-platform#519. The agent-server installs a pack; the grammar, the registry
and the whitelists live in the gateway. So the question «is this declaration
acceptable here» can only be answered here — the same reason `validate_flows`
asks `/flow-allow` instead of keeping a copy of the egress rules on the other
side (a second copy diverges, and diverges in silence).

Two classes of verdict, and the difference decides whether a pack installs:

**errors** — the manifest is wrong, or it collides with another pack: a scheme
someone else already owns, a namespace that is not its own, a regex that would
cost the event loop, a field that does not parse. Nothing here depends on the
day it is asked: the install is refused, and the message says where.

**ignored** — the manifest is well formed, but names something this gateway
still implements itself: `telegram.` while the native verbs exist, `tg:` while
`builtin_manifests/telegram.yaml` is there. The install **proceeds** and the
connector stays inactive, exactly as the registry treats it at runtime (#518).
It starts working by itself the day the migration deletes the builtin file.

That split is what makes the pack of a pending migration installable without a
«validation off until #522» switch — a switch somebody then has to remember to
turn on, which is the kind of thing that is remembered in the wrong direction.

Validating never writes anything. The connectors of the candidate pack are not
installed, not granted, and not cached: the registry on disk is untouched.
"""
from __future__ import annotations

import logging
from typing import Any

from . import builtin as _builtin
from . import resolved as _resolved
from .manifest import ManifestError, build_registry

LOG = logging.getLogger("clodia-tools.connectors")


def validate(pack: str, connectors: Any) -> dict:
    """`{ok, errors, ignored, connectors}` for a candidate `connectors:` block.

    `pack` is the name the block would be installed under. It matters: a pack
    may legitimately re-declare what it already declared — reinstalling is not
    colliding with oneself — so the candidate REPLACES the installed manifest of
    the same name instead of being added next to it.
    """
    name = str(pack or "").strip() or "?"
    block = connectors if isinstance(connectors, list) else []
    if not block:
        return {"ok": True, "pack": name, "errors": [], "ignored": [],
                "connectors": []}

    own = _builtin.manifests()
    installed = {k: v for k, v in _resolved.manifests().items() if k not in own}
    candidate = {"name": name, "connectors": block}
    try:
        # The candidate goes in LAST under its own name, so it replaces the
        # installed manifest of that pack instead of sitting next to it:
        # reinstalling a pack is not two packs colliding with each other.
        reg = build_registry({**own, **installed, name: candidate},
                             builtin=tuple(own))
    except ManifestError as e:
        # One message, the author's: `build_registry` is all-or-nothing and the
        # first refusal is the one to fix. Reporting a half-parsed registry
        # instead would describe an instance that will never exist.
        return {"ok": False, "pack": name, "errors": [str(e)], "ignored": [],
                "connectors": []}
    except Exception as e:  # noqa: BLE001 — never answer «fine» on a surprise
        LOG.error("connectors: validazione di '%s' non riuscita (%s)", name, e)
        return {"ok": False, "pack": name,
                "errors": [f"{type(e).__name__}: {e}"], "ignored": [],
                "connectors": []}

    mine = [c for c in reg.connectors if c.pack == name]
    ignored = [r for r in reg.refused if r.startswith(f"pack '{name}'")]
    return {
        "ok": True,
        "pack": name,
        "errors": [],
        # Well formed but inactive here and now, with the reason. The install
        # goes ahead: this is a statement about the gateway's own migration
        # state, not about the pack.
        "ignored": ignored,
        "connectors": [summary(c) for c in mine],
    }


def summary(connector) -> dict:
    """The shape a connector presents to whoever is not the PDP.

    Never a credential and never a secret — only the vault entry NAME a provider
    would use, which is what an owner needs to recognise what they are about to
    connect. Shared with `GET /internal/connectors`, so the install preview and
    the Tools page cannot drift into describing the same connector differently.
    """
    return {
        "id": connector.id,
        "label": connector.label,
        "pack": connector.pack,
        "namespace": connector.namespace,
        "builtin": connector.builtin,
        "extends": connector.extends,
        "schemes": [{"scheme": s.name, "direction": s.direction,
                     "label": s.label, "icon": s.icon,
                     "hierarchical": s.hierarchical,
                     "danger": s.danger,
                     "forms": [{"label": f.label, "example": f.example}
                               for f in s.forms]}
                    for s in connector.schemes],
        "providers": [{"id": p.id, "label": p.label,
                       "kind": p.credential.kind if p.credential else "",
                       "vault_entry": (p.credential.vault_entry
                                       if p.credential else ""),
                       "fields": [{"name": f.name, "label": f.label,
                                   "secret": f.secret, "required": f.required,
                                   "placeholder": f.placeholder}
                                  for f in (p.credential.fields
                                            if p.credential else ())]}
                      for p in connector.providers],
        "verbs": [{"verb": v.verb, "direction": v.direction,
                   "scheme": v.scheme, "prefix": v.prefix}
                  for v in connector.verbs],
        "topic_actions": [{"id": a.id, "label": a.label, "binding": a.binding,
                           "admin_only": a.admin_only,
                           "fields": [{"name": f.name, "label": f.label,
                                       "required": f.required,
                                       "placeholder": f.placeholder}
                                      for f in a.fields],
                           "adds": {"ingress": list(a.adds_ingress),
                                    "egress": list(a.adds_egress)}}
                          for a in connector.topic_actions],
        "tools_card": ({"setup_label": connector.tools_card.setup_label,
                        "status_verb": connector.tools_card.status_verb,
                        "docs_url": connector.tools_card.docs_url,
                        "blurb": connector.tools_card.blurb,
                        "scope": connector.tools_card.scope}
                       if connector.tools_card else None),
        "taint": list(connector.taint_prefixes),
    }

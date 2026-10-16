"""Pack components mounted in the gateway (clodia-platform#558).

Owner decision, 2026-10-16: a pack is a distribution of components, each
mounted in the container it belongs to. A `target: gateway` component is code
that runs INSIDE the reference monitor — the connector's verbs, its OAuth flow,
its perimeter — so the gateway keeps only the mounting mechanism and the rules:

    grammar.py   the `components:` block of pack.yaml
    trust.py     who may put code here (first-party, allowed org, isolated
                 state) and which vault prefixes a component may touch
    store.py     fetch from the upstream, pin by commit, integrity, no
                 downgrade — in the gateway's own state dir
    guard.py     static import guard (no `server.vault`, `server.main`, …)
    host.py      the host API, the ONLY thing a component gets (verbs,
                 routes, services the gateway calls, scoped credentials,
                 topics, perimeter facts)
    loader.py    load/unload/reconcile; a failure disables one component

The dispatcher (`server.main`) lists the components' verbs next to the native
ones and runs them through the same `call_tool` path; `server.components_api`
mounts their routes under `/tools/<pack>/…` and exposes status and refresh.
"""
from .loader import (has_verb, problems, reconcile, reconcile_loop, refusal,
                     route, service, state_of, status, tools, verb)

__all__ = ["has_verb", "problems", "reconcile", "reconcile_loop", "refusal",
           "route", "service", "state_of", "status", "tools", "verb"]

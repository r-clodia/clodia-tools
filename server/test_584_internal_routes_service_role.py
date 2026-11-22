"""clodia-platform#584 — every `/internal/*` route refuses an agent's runtime token.

A spawn of `clodia` holds a runtime token whose `agent` claim is `clodia`
(`CLODIA_TOOLS_TOKEN`, the MCP header) and has a shell that reaches the gateway.
`agent: clodia` is also the privileged principal the internal routes admitted,
so every route meant for the agent-server was one prompt injection away. The
routes whose caller is the agent-server now require the signed service role
(`role: agent-server`, clodia-platform#539 §1), which only the holder of the
keys or of the bootstrap secret can mint.

This module does not test the routes one by one: it ENUMERATES them from
`http_app.build_app()` — the app the gateway actually serves — and fails on any
`/internal/*` route that answers a forbidden token with something other than
401/403. A route added tomorrow is covered without anyone remembering to list
it; a route that must stay reachable goes in an allowlist below WITH its reason,
and an allowlist entry that no longer matches a route fails too.

Only routes expected to REFUSE are called: the allowlisted ones are skipped, not
exercised — a test that ran `/internal/tool` with a spawn token would execute a
verb, and one that ran `/internal/topics/import` would write topics.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from unittest.mock import patch

from starlette.routing import Route
from starlette.testclient import TestClient

from . import http_app, human_mcp, pki_verify

#: A spawn of `clodia`: what `clodia-logic` `sdk_runtime/session.py` mints for a
#: turn (agent = kind, execution_id = spawn, the human it talks to as principal).
SPAWN = {"agent": "clodia", "execution_id": "clodia-77", "principal": "davide",
         "clearance": "SEAL-2", "chat": "chan:SEAL-1:acme:clodia",
         "origin": ["human:davide", "agent:clodia"]}

#: The runner's token before #584: the carrier name, nothing else.
BARE = {"agent": "clodia"}

#: A person's on-behalf session that is NOT an admin — what a human MCP client
#: holds (`human_mcp`, `execution_id: mcp_*`). It reaches the gateway on the
#: same port as `/mcp`.
PERSON = {"agent": "clodia", "execution_id": "mcp_giovanni", "principal": "giovanni",
          "on_behalf": True, "human_role": "user", "clearance": "SEAL-1"}

#: Routes an agent's runtime token legitimately reaches, and why. Keyed by
#: (method, path) as Starlette declares it.
AGENT_TOKEN_ALLOWED = {
    ("POST", "/internal/tool"):
        "the PDP facade: a spawn calls it (`native.consent`, sdk_runtime) and the "
        "verb is authorised there per agent, ceiling and gate, as on /mcp",
    ("POST", "/internal/authorize"):
        "the PDP facade's question 'may I?': answers a decision, executes nothing",
}

#: Routes that keep a PERSON branch (an on-behalf session), and why. Not called
#: with the person token: each applies its own per-person rule downstream.
_TOPICS_PERSON = ("the topics API keeps its human branch (on-behalf sessions, "
                  "owner/admin checks, the human-read audit of #444) — see "
                  "topics_api._authorize")
_DATABASES_PERSON = ("a person's door by design: on-behalf sessions only, the "
                     "per-person ACL is in `databases` (#671)")


def _person_allowed(method: str, path: str) -> str | None:
    if (method, path) in AGENT_TOKEN_ALLOWED:
        return AGENT_TOKEN_ALLOWED[(method, path)]
    if path.startswith(("/internal/topics", "/internal/topic-index",
                        "/internal/dm-tools", "/internal/authz",
                        "/internal/data-catalog")):
        return _TOPICS_PERSON
    if (path.startswith(("/internal/databases/", "/internal/databases"))
            and path != "/internal/datastores/migrate"):
        return _DATABASES_PERSON
    return None


_PARAMS = {"tier": "SEAL-1", "name": "acme", "agent": "vittima", "pid": "anthropic",
           "connector": "telegram", "pack": "it-pack", "id": "telegram",
           "action": "connect", "todo_id": "t1", "filename": "f.txt",
           "direction": "egress", "uri": "x"}


def _internal_routes():
    """(method, declared path, concrete URL) of every `/internal/*` route."""
    out = []
    for r in http_app.build_app().routes:
        if not isinstance(r, Route) or not r.path.startswith("/internal"):
            continue
        url = r.path
        for k in r.param_convertors:
            url = url.replace("{" + k + "}", _PARAMS.get(k, "x"))
        for m in sorted(r.methods or ()):
            if m != "HEAD":
                out.append((m, r.path, url))
    return out


class _Session:
    """Every module's `verify_session_token` answers `payload`; nothing is
    revoked; no bootstrap secret is configured (so the secret-gated routes are
    measured on the bearer, which is all a spawn has)."""

    def __init__(self, payload: dict):
        self.payload = payload

    def __enter__(self):
        # Import every route module first: the patch below reaches the modules
        # that hold their own reference to the verifier, and a module imported
        # after it would keep the real one.
        http_app.build_app()
        original = pki_verify.verify_session_token
        fake = lambda _t: dict(self.payload)  # noqa: E731
        self._p = [patch.object(human_mcp, "is_revoked", lambda _gid: False)]
        for name, mod in list(sys.modules.items()):
            if name.startswith("server.") and \
                    getattr(mod, "verify_session_token", None) is original:
                self._p.append(patch.object(mod, "verify_session_token", fake))
        self._tmp = tempfile.TemporaryDirectory()
        env = {k: v for k, v in os.environ.items()
               if k not in ("CLODIA_ORCHESTRATOR_SECRET", "CLODIA_EGRESS_PROXY_SECRET")}
        env.update({"CLODIA_DATA": self._tmp.name,
                    "CLODIA_AUDIT_DIR": os.path.join(self._tmp.name, "audit")})
        self._p.append(patch.dict(os.environ, env, clear=True))
        for p in self._p:
            p.start()
        return TestClient(http_app.build_app(), raise_server_exceptions=False)

    def __exit__(self, *a):
        for p in reversed(self._p):
            p.stop()
        self._tmp.cleanup()
        return False


_H = {"Authorization": "Bearer ckt1.finto"}


def _call(c: TestClient, method: str, url: str):
    return c.request(method, url, headers=_H, json={})


class EveryInternalRouteRefusesAnAgentsRuntimeTokenTests(unittest.TestCase):

    def test_the_enumeration_finds_the_routes(self):
        # A guard that enumerated nothing would pass forever.
        routes = _internal_routes()
        self.assertGreater(len(routes), 100)
        paths = {p for _m, p, _u in routes}
        for must in ("/internal/vault/{name}", "/internal/providers/{pid}",
                     "/internal/channels/{connector}/poll", "/internal/gate/allow",
                     "/internal/profile/{agent}", "/internal/topics/export"):
            self.assertIn(must, paths)

    def test_the_allowlist_names_real_routes(self):
        declared = {(m, p) for m, p, _u in _internal_routes()}
        for key in AGENT_TOKEN_ALLOWED:
            self.assertIn(key, declared, f"stale allowlist entry {key}")

    def _assert_refused(self, payload: dict, allowed) -> None:
        open_routes = []
        with _Session(payload) as c:
            for method, path, url in _internal_routes():
                if allowed(method, path):
                    continue
                r = _call(c, method, url)
                if r.status_code not in (401, 403):
                    open_routes.append(f"{method} {path} → {r.status_code}")
        self.maxDiff = None
        self.assertEqual(open_routes, [], "internal routes reachable by this token")

    def test_a_spawn_token_is_refused_everywhere_but_the_pdp_facade(self):
        self._assert_refused(SPAWN, lambda m, p: (m, p) in AGENT_TOKEN_ALLOWED)

    def test_the_bare_carrier_token_is_refused_everywhere_but_the_pdp_facade(self):
        self._assert_refused(BARE, lambda m, p: (m, p) in AGENT_TOKEN_ALLOWED)

    def test_a_non_admin_person_reaches_only_the_routes_with_a_person_branch(self):
        self._assert_refused(PERSON, _person_allowed)


class TheAgentServerStillGetsInTests(unittest.TestCase):
    """The opposite error: the guard must not switch off the real callers. Each
    door is asked for its DECISION with the service token clodia-logic mints."""

    SERVICE = {"agent": "clodia", "role": "agent-server"}

    def _request(self, path: str, headers: list | None = None):
        from starlette.requests import Request
        return Request({"type": "http", "method": "GET", "path": path,
                        "headers": [(b"authorization", b"Bearer ckt1.finto"),
                                    *(headers or [])]})

    def test_internal_auth_admits_the_service_role(self):
        from . import internal_auth
        with _Session(self.SERVICE):
            payload, err = internal_auth.authorize(self._request("/internal/vault/x"))
        self.assertIsNone(err)
        self.assertEqual(payload.get("role"), "agent-server")

    def test_the_profile_router_admits_the_service_role_and_its_declared_principal(self):
        from . import profile_api
        with _Session(self.SERVICE):
            who, err = profile_api._principal(self._request(
                "/internal/profile/davide", [(b"x-clodia-principal", b"davide")]))
        self.assertIsNone(err)
        self.assertEqual(who, "davide")

    def test_the_gate_admits_the_service_role_with_the_deciding_human(self):
        from . import gate_api
        with _Session({**self.SERVICE, "principal": "davide"}):
            who, err = gate_api._authorize(self._request("/internal/gate/pending"))
        self.assertIsNone(err)
        self.assertEqual(who, "davide")

    def test_the_gate_still_wants_the_deciding_human(self):
        from . import gate_api
        with _Session(self.SERVICE):
            who, err = gate_api._authorize(self._request("/internal/gate/pending"))
        self.assertIsNone(who)
        self.assertEqual(err.status_code, 403)

    def test_the_topics_api_admits_the_service_role(self):
        from . import topics_api
        with _Session(self.SERVICE):
            _who, err = topics_api._authorize(self._request("/internal/topics"))
        self.assertIsNone(err)

    def test_the_channels_relay_admits_the_service_role(self):
        from . import channels_api
        with _Session(self.SERVICE):
            _who, err = channels_api._authorize(
                self._request("/internal/channels/telegram/poll"))
        self.assertIsNone(err)

    def test_taint_clear_admits_the_service_role(self):
        # The door that had no check at all (#584): `topics_client.clear_taint`.
        from starlette.applications import Starlette
        from . import taint, topics_api
        with _Session(self.SERVICE), \
                patch.object(taint, "clear", lambda scope, by="": {"scope": scope}):
            c = TestClient(Starlette(routes=topics_api.routes))
            r = c.post("/internal/topics/SEAL-1/acme/taint/clear", headers=_H,
                       json={"by": "davide"})
        self.assertEqual(r.status_code, 200, r.text)

    def test_the_global_egress_edit_admits_the_bootstrap_secret(self):
        # The other door that had no check (#584): `observe._gw_post`.
        from starlette.applications import Starlette
        from . import egress, egress_api
        with patch.dict(os.environ, {"CLODIA_ORCHESTRATOR_SECRET": "s3cret"}), \
                patch.object(egress, "allow", lambda d, u: {"uri": u}):
            c = TestClient(Starlette(routes=egress_api.routes))
            ok = c.post("/internal/egress/whitelist/egress/allow",
                        headers={"X-Orchestrator-Secret": "s3cret"},
                        json={"uri": "https://example.org"})
            no = c.post("/internal/egress/whitelist/egress/allow",
                        headers={"X-Orchestrator-Secret": "wrong"},
                        json={"uri": "https://example.org"})
        self.assertEqual(ok.status_code, 200, ok.text)
        self.assertEqual(no.status_code, 401)


if __name__ == "__main__":
    unittest.main()

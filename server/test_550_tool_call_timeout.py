"""Per-call timeout and tool-call telemetry of the gateway
(clodia-platform#550).

15 Oct 2026: four `topic.*` calls hung on the gateway and consumed the
agent's whole 180 s turn; nothing said which call, how slow, or whether the
gateway was slow or dead. What is checked: a call to a backend that never
answers is cancelled within its budget and answered with
`ERROR: ToolCallTimeout`, the backend call is cancelled, and the timeout is
counted; the budget is configurable per verb and per backend; a consent wait
does not count against it; the telemetry counts calls, errors, timeouts and
latency per verb and backend with no argument or content in it; the route is
refused to agents and the `runtime.health` block is shown to admins only.
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

from mcp.types import TextContent
from starlette.applications import Starlette
from starlette.testclient import TestClient

from . import internal_auth, main, proxy, tool_calls, tool_calls_api, whitelist
from .claims import ClaimsContext
from .pki_mint import ROLE_AGENT_SERVER

TOKEN = {"agent": "clodia", "execution_id": "clodia-550", "principal": "davide",
         "chat": "chan:SEAL-2:earnext:clodia"}

_ENV_KEYS = ("CLODIA_TOOL_CALL_TIMEOUT_S", "CLODIA_TOOL_CALL_TIMEOUTS")


class _Isolated(unittest.TestCase):
    def setUp(self) -> None:
        tool_calls.reset()
        self.addCleanup(tool_calls.reset)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        env = patch.dict(os.environ, {
            "CLODIA_AUDIT_DIR": str(Path(tmp.name) / "audit"),
            "CLODIA_AUDIT_KEY_DIR": str(Path(tmp.name) / "k"),
            # Gate state, verb log and shared data in temporary dirs: nothing
            # of whoever runs the test decides, or is touched (see #437).
            "CLODIA_TOOLS_STATE_DIR": str(Path(tmp.name) / "state"),
            "CLODIA_DATA": str(Path(tmp.name) / "data"),
            "GATE_WAIT_LOOPS": "0",
        })
        env.start()
        self.addCleanup(env.stop)
        for k in _ENV_KEYS:
            os.environ.pop(k, None)
        os.environ.pop("CLODIA_AUDIT_FAIL_CLOSED", None)


# ── The budget ───────────────────────────────────────────────────────────────

class TimeoutConfigTests(_Isolated):
    def test_default_and_env_default(self) -> None:
        self.assertEqual(tool_calls.DEFAULT_TIMEOUT_S, tool_calls.timeout_for("topic.open"))
        os.environ["CLODIA_TOOL_CALL_TIMEOUT_S"] = "45"
        self.assertEqual(45.0, tool_calls.timeout_for("topic.open"))

    def test_builtin_long_families(self) -> None:
        self.assertEqual(900.0, tool_calls.timeout_for("packs.install"))
        self.assertEqual(0.0, tool_calls.timeout_for("copybrain.call"))

    def test_env_overrides_exact_prefix_and_backend_name(self) -> None:
        os.environ["CLODIA_TOOL_CALL_TIMEOUTS"] = (
            "github=60, topic.*=30, topic.open=20, packs.*=0, garbage, x=nan?")
        self.assertEqual(60.0, tool_calls.timeout_for("github.list_issues"))
        self.assertEqual(20.0, tool_calls.timeout_for("topic.open"))       # exact wins
        self.assertEqual(30.0, tool_calls.timeout_for("topic.put"))        # prefix
        self.assertEqual(0.0, tool_calls.timeout_for("packs.install"))     # disabled
        # `github` does not cover a namespace that merely starts the same way.
        self.assertEqual(tool_calls.DEFAULT_TIMEOUT_S,
                         tool_calls.timeout_for("githubx.list"))

    def test_config_section_and_backend_entry(self) -> None:
        cfg = {"tool_call_timeouts": {"default": 90, "overrides": {"topic": 25}},
               "mcp_backends": [{"name": "slowmcp", "url": "http://x",
                                 "call_timeout_s": 7}]}
        with patch.dict(whitelist.CONFIG, cfg):
            self.assertEqual(90.0, tool_calls.timeout_for("email.read"))
            self.assertEqual(25.0, tool_calls.timeout_for("topic.open"))
            self.assertEqual(7.0, tool_calls.timeout_for("slowmcp.do"))
            # The environment wins over the config.
            os.environ["CLODIA_TOOL_CALL_TIMEOUTS"] = "slowmcp=3"
            self.assertEqual(3.0, tool_calls.timeout_for("slowmcp.do"))


class DeadlineTests(unittest.TestCase):
    def test_a_consent_wait_does_not_count_against_the_budget(self) -> None:
        async def go():
            with patch.object(tool_calls, "timeout_for", lambda v: 0.3):
                async with tool_calls.deadline("x.y") as call:
                    with tool_calls.paused():          # a person deciding
                        await asyncio.sleep(0.5)
                    await asyncio.sleep(0.1)           # inside what was left
                return call
        call = asyncio.run(go())
        self.assertGreaterEqual(call.paused_s, 0.45)

    def test_the_budget_still_runs_after_the_pause(self) -> None:
        async def go():
            with patch.object(tool_calls, "timeout_for", lambda v: 0.3):
                async with tool_calls.deadline("x.y"):
                    with tool_calls.paused():
                        await asyncio.sleep(0.05)
                    await asyncio.sleep(5)
        t0 = time.monotonic()
        with self.assertRaises(tool_calls.ToolCallTimeout):
            asyncio.run(go())
        self.assertLess(time.monotonic() - t0, 2)

    def test_a_timeout_error_of_the_body_is_not_ours(self) -> None:
        async def go():
            async with tool_calls.deadline("x.y"):
                raise TimeoutError("the backend's own")
        with self.assertRaises(TimeoutError) as cm:
            asyncio.run(go())
        self.assertNotIsInstance(cm.exception, tool_calls.ToolCallTimeout)


# ── Through the real dispatch ────────────────────────────────────────────────

class SlowBackendTests(_Isolated):
    """A mounted MCP backend that never answers, reached through `call_tool`,
    the real `_call_tool_unaudited` dispatch and the real `call_proxied`:
    only the MCP session is fake. Authorisation is not under test here."""

    def setUp(self) -> None:
        super().setUp()
        os.environ["CLODIA_TOOL_CALL_TIMEOUTS"] = "slowmcp=0.5"
        self.state = {"started": False, "cancelled": False, "closed": False}

    def call(self, name: str, args: dict):
        state = self.state

        @asynccontextmanager
        async def session(_b):
            class _S:
                async def call_tool(self, _tool, _arguments):
                    state["started"] = True
                    try:
                        await asyncio.sleep(60)
                    except asyncio.CancelledError:
                        state["cancelled"] = True
                        raise
            try:
                yield _S()
            finally:
                state["closed"] = True        # the session is torn down

        from . import authz_runtime

        async def consent(*_a, **_k):
            # The verb is out of clodia's profile: a person approves it, in
            # 0.8 s — longer than the whole budget, which must not count it.
            await asyncio.sleep(0.8)
            return {}

        async def go():
            with ClaimsContext(TOKEN, "t"), \
                    patch.object(proxy, "_backends",
                                 return_value={"slowmcp": {"transport": "http"}}), \
                    patch.object(proxy, "_session", session), \
                    patch.object(proxy, "_is_transport", lambda n: False), \
                    patch.object(main, "_agent_tool_reachable", lambda n, a: True), \
                    patch.object(authz_runtime, "enforcing", lambda: False), \
                    patch.object(main, "_require_gate_consent_waiting", consent):
                return await main.call_tool(name, args)
        return asyncio.run(go())

    def test_times_out_within_the_limit_with_a_clean_error_and_is_counted(self) -> None:
        secret = "mario.rossi@example.com"
        t0 = time.monotonic()
        out = self.call("slowmcp.fetch", {"query": secret})
        elapsed = time.monotonic() - t0
        self.assertTrue(self.state["started"])
        self.assertTrue(out[0].text.startswith("ERROR: ToolCallTimeout: "), out[0].text)
        self.assertIn("slowmcp.fetch", out[0].text)
        # 0.8 s of consent (paused) + 0.5 s of budget, not the backend's 60 s.
        self.assertGreater(elapsed, 1.2)
        self.assertLess(elapsed, 3.5)
        self.assertTrue(self.state["cancelled"])
        self.assertTrue(self.state["closed"])
        snap = tool_calls.snapshot()
        verb = snap["verbs"]["slowmcp.fetch"]
        self.assertEqual((verb["count"], verb["errors"], verb["timeouts"]), (1, 1, 1))
        self.assertIn("last_timeout_at", verb)
        self.assertEqual(1, snap["backends"]["slowmcp"]["timeouts"])
        self.assertEqual(1, snap["totals"]["timeouts"])
        # The latency is the backend's time, not the person's.
        self.assertGreaterEqual(verb["max_ms"], 450)
        self.assertLess(verb["max_ms"], 1200)
        self.assertNotIn(secret, json.dumps(snap))

    def test_the_audit_trail_names_the_timeout(self) -> None:
        self.call("slowmcp.fetch", {})
        root = Path(os.environ["CLODIA_AUDIT_DIR"])
        events = [json.loads(x) for p in sorted(root.glob("events-*.jsonl"))
                  for x in p.read_text().splitlines() if x.strip()]
        res = [e for e in events if e["event"]["type"] == "tool.result"][-1]
        self.assertEqual(("error", "ToolCallTimeout"),
                         (res["result"]["status"], res["result"]["error"]))


class TelemetryTests(_Isolated):
    def call(self, name: str, args: dict, text: str, delay: float = 0.0):
        async def inner(_n, _a):
            if delay:
                await asyncio.sleep(delay)
            return [TextContent(type="text", text=text)]

        async def go():
            with ClaimsContext(TOKEN, "t"), \
                    patch.object(main, "_call_tool_unaudited", inner), \
                    patch.object(main, "_verb_known", lambda n: n.startswith("topic.")):
                return await main.call_tool(name, args)
        return asyncio.run(go())

    def test_counts_per_verb_and_backend(self) -> None:
        self.call("topic.open", {}, '{"ok": true}')
        self.call("topic.open", {}, "ERROR: TopicError: missing")
        self.call("topic.open", {}, "DENIED: tool 'topic.open' non in whitelist")
        self.call("topic.put", {}, '{"ok": true}')
        snap = tool_calls.snapshot()
        v = snap["verbs"]["topic.open"]
        self.assertEqual((v["count"], v["ok"], v["errors"], v["denied"], v["timeouts"]),
                         (3, 1, 1, 1, 0))
        b = snap["backends"]["topic"]
        self.assertEqual((b["count"], b["ok"]), (4, 2))
        self.assertEqual(4, snap["totals"]["count"])
        self.assertEqual(["topic.open", "topic.put"], list(snap["verbs"]))  # busiest first
        self.assertEqual(["topic.open"], list(tool_calls.snapshot(top=1)["verbs"]))

    def test_latency_percentiles(self) -> None:
        self.call("topic.open", {}, "{}", delay=0.2)
        v = tool_calls.snapshot()["verbs"]["topic.open"]
        self.assertGreaterEqual(v["p50_ms"], 180)
        for ms in range(1, 101):
            tool_calls.record("x.y", "ok", ms / 1000)
        v = tool_calls.snapshot()["verbs"]["x.y"]
        self.assertEqual((v["p50_ms"], v["p95_ms"], v["max_ms"]), (50, 95, 100))

    def test_no_arguments_results_or_identities_in_the_telemetry(self) -> None:
        secret_arg, secret_out = "mario.rossi@example.com", "IBAN IT60X0542811101000000123456"
        self.call("topic.put", {"text": secret_arg}, json.dumps({"body": secret_out}))
        # A made-up verb carries whatever an agent wrote: not kept by name.
        self.call("leak.mario-rossi-at-example-com", {}, "ERROR: ValueError: unknown tool")
        raw = json.dumps(tool_calls.snapshot())
        for leak in (secret_arg, secret_out, "mario-rossi", "clodia-550", "davide",
                     "earnext"):
            self.assertNotIn(leak, raw)
        self.assertIn(tool_calls.UNKNOWN, tool_calls.snapshot()["verbs"])

    def test_distinct_verbs_are_bounded(self) -> None:
        with patch.object(tool_calls, "MAX_VERBS", 3):
            for i in range(10):
                tool_calls.record(f"v{i}.x", "ok", 0.001)
        verbs = tool_calls.snapshot()["verbs"]
        self.assertEqual(4, len(verbs))
        self.assertEqual(7, verbs[tool_calls.OTHER]["count"])


# ── Who may read it ──────────────────────────────────────────────────────────

_H = {"Authorization": "Bearer ckt1.fake"}
_SERVICE = {"agent": "clodia", "role": ROLE_AGENT_SERVER}
_ADMIN = {"agent": "clodia", "principal": "davide", "principal_kind": "human",
          "on_behalf": True, "human_role": "admin"}
_MEMBER = {"agent": "clodia", "principal": "mario", "principal_kind": "human",
           "on_behalf": True, "human_role": "user"}
_CARRIER = {"agent": "clodia"}
_SPAWN = {"agent": "clodia", "execution_id": "clodia-7"}   # an agent's own token


class RouteTests(unittest.TestCase):
    def setUp(self) -> None:
        tool_calls.reset()
        self.addCleanup(tool_calls.reset)
        tool_calls.record("topic.open", "ok", 0.01)
        self.client = TestClient(Starlette(routes=tool_calls_api.routes))

    def get(self, payload: dict | None, query: str = ""):
        url = "/internal/diagnostics/tool-calls" + query
        if payload is None:
            return self.client.get(url)
        with patch.object(internal_auth, "verify_session_token", lambda _t: payload):
            return self.client.get(url, headers=_H)

    def test_the_service_role_and_admins_read_it(self) -> None:
        for payload in (_SERVICE, _ADMIN):
            r = self.get(payload)
            self.assertEqual(200, r.status_code, r.text)
            self.assertEqual(1, r.json()["verbs"]["topic.open"]["count"])
        self.assertEqual(200, self.get(_SERVICE, "?top=0").status_code)
        self.assertEqual({}, self.get(_SERVICE, "?top=0").json()["verbs"])
        self.assertEqual(400, self.get(_SERVICE, "?top=x").status_code)

    def test_refused_to_agents_the_carrier_and_members(self) -> None:
        for who, payload in (("spawn", _SPAWN), ("carrier", _CARRIER),
                             ("member", _MEMBER),
                             ("scoped", {**_CARRIER, "scoped_tools": ["topic.open"]})):
            with self.subTest(who=who):
                r = self.get(payload)
                self.assertEqual(403, r.status_code, r.text)
                self.assertNotIn("topic.open", r.text)
        self.assertEqual(401, self.get(None).status_code)


class HealthBlockTests(unittest.TestCase):
    def setUp(self) -> None:
        from .tools import health
        self.health = health
        health.reset_cache()
        self.addCleanup(health.reset_cache)
        tool_calls.reset()
        self.addCleanup(tool_calls.reset)
        tool_calls.record("topic.open", "error", 1.0, timed_out=True)

    def run_health(self, admin: bool) -> dict:
        async def cached(*, backends=True):
            return {"ok": True, "gateway": {"version": "x"}}
        from . import authz_runtime
        with patch.object(self.health, "_health_cached", cached), \
                patch.object(authz_runtime, "role_principal_ok", lambda: admin):
            return asyncio.run(self.health.health(backends=False))

    def test_admins_see_the_tool_calls_block(self) -> None:
        out = self.run_health(admin=True)
        self.assertEqual(1, out["tool_calls"]["verbs"]["topic.open"]["timeouts"])
        self.assertTrue(out["ok"])

    def test_others_do_not(self) -> None:
        self.assertNotIn("tool_calls", self.run_health(admin=False))


if __name__ == "__main__":
    unittest.main()

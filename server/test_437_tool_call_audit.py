"""clodia-platform#437 — the gateway records every verb call.

Before: `clodia-tools-verbs.jsonl` held `datastore.*` only, the access log
showed `POST /mcp/ 200` with no verb, and the only record of 126 tool calls on
29 Sep was the agent's own transcript. Now one wrapper around the dispatch
emits `tool.call` and `tool.result` for every verb — ok, denied, errored,
borrowed — with hashes of arguments and output, never their content.
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp.types import TextContent

from . import audit, main
from .claims import ClaimsContext

TOKEN = {"agent": "clodia", "execution_id": "clodia-320", "principal": "davide",
         "chat": "chan:SEAL-2:titulon-tech:clodia"}


def _ok(text: str):
    async def inner(name, arguments):
        return [TextContent(type="text", text=text)]
    return inner


class ToolCallAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "audit"
        env = patch.dict(os.environ, {"CLODIA_AUDIT_DIR": str(self.root),
                                      "CLODIA_AUDIT_KEY_DIR": str(Path(tmp.name) / "k")})
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("CLODIA_AUDIT_FAIL_CLOSED", None)

    def events(self) -> list[dict]:
        out = []
        for seg in sorted(self.root.glob("events-*.jsonl")):
            out += [json.loads(x) for x in seg.read_text().splitlines() if x.strip()]
        return out

    def call(self, name: str, args: dict, inner=None):
        async def go():
            with ClaimsContext(TOKEN, "t"):
                if inner is None:
                    return await main.call_tool(name, args)
                with patch.object(main, "_call_tool_unaudited", inner):
                    return await main.call_tool(name, args)
        return asyncio.run(go())

    def test_a_successful_call_is_a_call_and_a_result_with_hashes_only(self) -> None:
        secret = "mario.rossi@example.com"
        self.call("topic.put", {"tier": "SEAL-2", "name": "t", "text": secret},
                  inner=_ok('{"ok": true}'))
        call, res = self.events()
        self.assertEqual((call["event"]["type"], res["event"]["type"]),
                         ("tool.call", "tool.result"))
        self.assertEqual(call["tool"]["name"], "topic.put")
        self.assertTrue(call["tool"]["parameters_hash"].startswith("sha256:"))
        self.assertEqual(res["result"]["status"], "ok")
        self.assertIn("duration_ms", res["result"])
        self.assertTrue(res["result"]["output_hash"].startswith("sha256:"))
        self.assertEqual(res["parent_span_id"], call["event_id"])
        self.assertEqual(call["actor"]["id"], "clodia-320")
        self.assertEqual(call["scope"], {"tier": "SEAL-2", "topic": "titulon-tech"})
        raw = "".join(p.read_text() for p in self.root.glob("events-*.jsonl"))
        self.assertNotIn(secret, raw)

    def test_a_denied_call_is_recorded_with_its_class_not_its_message(self) -> None:
        out = self.call("topic.put", {}, inner=_ok(
            "DENIED: uscita non consentita per l'agent 'clodia': mario@x.it"))
        self.assertTrue(out[0].text.startswith("DENIED"))
        res = self.events()[-1]
        self.assertEqual((res["result"]["status"], res["result"]["error"]),
                         ("denied", "egress"))
        raw = "".join(p.read_text() for p in self.root.glob("events-*.jsonl"))
        self.assertNotIn("mario@x.it", raw)

    def test_an_error_keeps_the_exception_class_only(self) -> None:
        self.call("x.y", {}, inner=_ok("ERROR: TypeError: something about /secret/path"))
        res = self.events()[-1]
        self.assertEqual((res["result"]["status"], res["result"]["error"]),
                         ("error", "TypeError"))

    def test_the_real_dispatch_is_wrapped_too(self) -> None:
        # No stub: an unknown verb goes through the real dispatch and still leaves
        # a call and a result.
        out = self.call("no.such_verb", {})
        self.assertTrue(out[0].text.startswith(("ERROR", "DENIED")))
        types = [e["event"]["type"] for e in self.events()]
        # A refusal of the reference monitor adds its decision in between
        # (#436); whatever happens, the call and its result frame it.
        self.assertEqual((types[0], types[-1]), ("tool.call", "tool.result"))
        self.assertTrue(set(types[1:-1]) <= {"policy.decision"}, types)

    def test_a_borrowed_call_is_nested_under_the_call_that_made_it(self) -> None:
        async def outer(name, arguments):
            if name == "copybrain.call":
                return await main.call_tool("avvocato.search", {"q": "x"})
            return [TextContent(type="text", text="ok")]
        self.call("copybrain.call", {}, inner=outer)
        evs = self.events()
        types = [(e["event"]["type"], e["event"]["resource"]) for e in evs]
        self.assertEqual(types, [("tool.call", "copybrain.call"),
                                 ("tool.call", "avvocato.search"),
                                 ("tool.result", "avvocato.search"),
                                 ("tool.result", "copybrain.call")])
        self.assertEqual(evs[1]["parent_span_id"], evs[0]["event_id"])

    def test_fail_closed_refuses_an_action_that_cannot_be_recorded(self) -> None:
        os.environ["CLODIA_AUDIT_FAIL_CLOSED"] = "1"
        ran = []

        async def inner(name, arguments):
            ran.append(name)
            return [TextContent(type="text", text="ok")]
        with patch.object(audit.store(), "append", side_effect=OSError("disk full")):
            out = self.call("email.send", {}, inner=inner)
        self.assertTrue(out[0].text.startswith("DENIED: audit trail"))
        self.assertEqual(ran, [])


if __name__ == "__main__":
    unittest.main()

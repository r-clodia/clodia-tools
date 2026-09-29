"""clodia-platform#436 — reference-monitor decisions are on record.

`egress.decide()` and the dispatch computed allow / deny / gate, and the
verdict lived in a log line. Now each is a `policy.decision` event with the
policy, the rule that matched (and whether it is in the global or the scope
list), and the hash of the rule set in force.
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from . import egress, main, whitelist
from .audit import policy
from .claims import ClaimsContext

TOKEN = {"agent": "clodia", "execution_id": "clodia-320", "principal": "davide",
         "chat": "chan:SEAL-2:titulon-tech:clodia"}


def _verdict(action: str, refused: bool) -> dict:
    return {"checked": True, "allowed": not refused, "action": action,
            "verb": "gdrive.mkdir", "type": "gdrive",
            "destinations": ["gdrive:folder/abc"],
            "refused": ["gdrive:folder/abc"] if refused else None,
            "rules": ["gdrive:folder/abc"] if not refused else ["gdrive:folder/zzz"],
            "mode": "on", "applied_mode": "on"}


class _Env(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        self.data = base / "data"
        (self.data / "agents" / "avvocato").mkdir(parents=True)
        self.seed = self.data / "agents" / "avvocato" / "agent.yaml"
        self.seed.write_text("tool_permissions: [topic.open]\n")
        self.root = base / "audit"
        env = patch.dict(os.environ, {"CLODIA_AUDIT_DIR": str(self.root),
                                      "CLODIA_AUDIT_KEY_DIR": str(base / "k"),
                                      "CLODIA_DATA": str(self.data)})
        env.start()
        self.addCleanup(env.stop)

    def events(self, type_: str | None = None) -> list[dict]:
        out = []
        for seg in sorted(self.root.glob("events-*.jsonl")):
            out += [json.loads(x) for x in seg.read_text().splitlines() if x.strip()]
        return [e for e in out if type_ is None or e["event"]["type"] == type_]

    def dispatch(self, verdict: dict, token: dict = TOKEN, verb: str = "gdrive.mkdir"):
        async def go():
            with ClaimsContext(token, "t"), \
                    patch.object(egress, "check", return_value=verdict), \
                    patch.object(main, "_require_gate_consent", AsyncMock(return_value={})):
                return await main.call_tool(verb, {"parent_id": "abc", "name": "n"})
        return asyncio.run(go())


class EgressDecisionTests(_Env):
    def test_an_egress_refusal_names_the_policy_the_destination_and_the_rules(self) -> None:
        out = self.dispatch(_verdict("deny", refused=True))
        self.assertTrue(out[0].text.startswith("DENIED"))
        decisions = self.events("policy.decision")
        self.assertEqual(len(decisions), 1, "one decision, not one per layer")
        d = decisions[0]["decision"]
        self.assertEqual((d["policy"], d["result"], d["reason_class"]),
                         ("egress", "deny", "not_listed"))
        self.assertEqual(d["rule"], [{"destination": "gdrive:folder/abc"}])
        self.assertTrue(d["policy_bundle_hash"].startswith("sha256:"))
        self.assertEqual(d["applied_mode"], "on")

    def test_an_allowed_destination_records_the_rule_and_its_list(self) -> None:
        with patch.object(egress, "scope_uris", return_value=[]):
            self.dispatch(_verdict("allow", refused=False))
        d = self.events("policy.decision")[0]["decision"]
        self.assertEqual(d["result"], "allow")
        self.assertEqual(d["rule"], [{"destination": "gdrive:folder/abc",
                                      "rule": "gdrive:folder/abc", "list": "global"}])

    def test_a_scope_rule_is_told_apart_from_a_global_one(self) -> None:
        with patch.object(egress, "scope_uris", return_value=["gdrive:folder/abc"]):
            self.dispatch(_verdict("allow", refused=False))
        self.assertEqual(self.events("policy.decision")[0]["decision"]["rule"][0]["list"],
                         "scope")


class OtherRefusalTests(_Env):
    def test_a_whitelist_refusal_is_a_decision_too(self) -> None:
        token = {"agent": "avvocato", "execution_id": "avvocato-9",
                 "chat": "chan:SEAL-2:titulon-tech:avvocato"}

        async def go():
            with ClaimsContext(token, "t"):
                return await main.call_tool("agents.grant_tool", {})
        out = asyncio.run(go())
        self.assertTrue(out[0].text.startswith("DENIED"))
        d = self.events("policy.decision")[0]
        self.assertEqual(d["decision"]["result"], "deny")
        self.assertEqual(d["actor"]["id"], "avvocato-9")


class BundleHashTests(_Env):
    def test_the_hash_is_stable_and_moves_when_the_rules_move(self) -> None:
        h1 = policy.bundle_hash()
        self.assertEqual(h1, policy.bundle_hash())
        with patch.object(whitelist, "CONFIG", {**(whitelist.CONFIG or {}),
                                                "egress_allow": ["mailto:new@x.it"]}):
            self.assertNotEqual(h1, policy.bundle_hash())
        self.assertEqual(h1, policy.bundle_hash())
        self.seed.write_text("tool_permissions: [topic.open, topic.put]\n")
        os.utime(self.seed, ns=(1, 1))
        self.assertNotEqual(h1, policy.bundle_hash())
        with patch.dict(os.environ, {"CLODIA_EGRESS_ENFORCE": "off"}):
            self.assertNotEqual(policy.bundle_hash(), h1)


if __name__ == "__main__":
    unittest.main()

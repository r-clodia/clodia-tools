"""clodia-platform#448 — approve with modified arguments.

The approver can correct the editable fields of a verb before approving; the
call runs on the corrected arguments, the destination check judges the
corrected call, and the trail records that the decision was a modification
(which fields, hash of the original and of the corrected arguments).
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from . import egress, gate, main
from .claims import ClaimsContext

TOKEN = {"agent": "clodia", "execution_id": "clodia-320", "principal": "davide",
         "chat": "chan:SEAL-2:titulon-tech:clodia"}


def _cap(tok: str) -> dict:
    return {"agent": "clodia", "cap": f"gate:{tok}", "exp": time.time() + 600,
            "jti": f"j-{tok}", "by": "davide"}


class ValidationTests(unittest.TestCase):
    def test_only_the_editable_fields_of_the_verb(self) -> None:
        self.assertEqual(gate.validate_modified("email.send", {"to": "b@x.it"}), {"to": "b@x.it"})
        with self.assertRaises(PermissionError):
            gate.validate_modified("email.send", {"account": "studio"})
        with self.assertRaises(PermissionError):
            gate.validate_modified("egress:mailto:a@x.it", {"to": "b@x.it"})  # destination gate
        with self.assertRaises(PermissionError):
            gate.validate_modified("web.post", {"body": {"nested": object()}})

    def test_the_request_carries_what_can_be_corrected(self) -> None:
        self.assertEqual(gate.editable_of("web.post", {"url": "https://x", "body": "b"}),
                         {"body": "b"})
        self.assertIsNone(gate.editable_of("topic.put", {"x": 1}))


class EndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        (base / "data").mkdir()
        self.root = base / "audit"
        env = patch.dict(os.environ, {"CLODIA_AUDIT_DIR": str(self.root),
                                      "CLODIA_AUDIT_KEY_DIR": str(base / "k"),
                                      "CLODIA_DATA": str(base / "data")})
        env.start()
        self.addCleanup(env.stop)
        for name, f in (("_store_path", "s.json"), ("_revoked_path", "r.json"),
                        ("_req_path", "q.json")):
            p = patch.object(gate, name, return_value=base / f)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(gate.pki_verify, "verify_capability", side_effect=_cap)
        p.start()
        self.addCleanup(p.stop)

    def events(self, t: str) -> list[dict]:
        out = []
        for seg in sorted(self.root.glob("events-*.jsonl")):
            out += [json.loads(x) for x in seg.read_text().splitlines() if x.strip()]
        return [e for e in out if e["event"]["type"] == t]

    def test_the_call_runs_and_is_judged_on_the_corrected_arguments(self) -> None:
        # Verb gates are keyed on the seed (instance "-"), only crosstopic and
        # copybrain on the spawn.
        gate.grant("clodia", "-", "web.post", "web.post", decided_by="davide",
                   decided_by_role="owner", modified={"body": "corrected text"})
        sent, judged = {}, {}

        def fake_post(arguments, agent=""):
            sent.update(arguments)
            return {"status": 200}

        def fake_check(agent, cfg, verb, args, unattended=False):
            judged.update(args)
            return {"checked": True, "allowed": True, "action": "allow", "type": "http",
                    "destinations": ["https://x.example/api"], "rules": ["https://x.example/"]}

        async def go():
            with ClaimsContext(TOKEN, "t"), \
                    patch.object(main.web_post, "post", fake_post), \
                    patch.object(egress, "check", fake_check):
                return await main.call_tool("web.post", {"url": "https://x.example/api",
                                                         "body": "original text"})
        out = asyncio.run(go())
        self.assertFalse(out[0].text.startswith(("DENIED", "ERROR")), out[0].text)
        self.assertEqual(sent["body"], "corrected text")
        self.assertEqual(judged["body"], "corrected text")
        dec = self.events("gate.decision")[0]["authorization"]
        self.assertEqual((dec["result"], dec["modified_fields"]), ("modified", ["body"]))
        (app,) = self.events("gate.apply")
        self.assertNotEqual(app["authorization"]["original_hash"],
                            app["authorization"]["modified_hash"])


if __name__ == "__main__":
    unittest.main()

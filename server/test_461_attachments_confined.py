"""clodia-platform#461 — an agent's attachments come from its own scratch.

`email.send` / `email.reply` used to accept any regular file the gateway could
read. The egress perimeter vets the destination, not where the bytes come from,
so that was a way to mail out the gateway's own files.
"""
from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from . import egress, main
from .claims import ClaimsContext

TOKEN = {"agent": "clodia", "execution_id": "clodia-320", "principal": "davide",
         "chat": "chan:SEAL-1:t:clodia"}
ALLOW = {"checked": True, "allowed": True, "action": "allow", "verb": "email.send",
         "type": "mailto", "destinations": ["mailto:x@example.com"], "refused": None,
         "rules": ["mailto:x@example.com"], "mode": "on", "applied_mode": "on"}


class AttachmentsConfinedTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.scratch = self.base / "spawns" / "clodia-320"
        self.scratch.mkdir(parents=True)
        for p in (patch.object(main, "_SPAWNS_ROOT", str(self.base / "spawns")),
                  patch.dict(os.environ, {"CLODIA_AUDIT_DIR": str(self.base / "audit"),
                                          "CLODIA_AUDIT_KEY_DIR": str(self.base / "k"),
                                          "CLODIA_DATA": str(self.base / "data")})):
            p.start()
            self.addCleanup(p.stop)
        self.sent: list = []

    def call(self, name: str, attachments: list[str]) -> str:
        args = {"attachments": attachments, "body": "b"}
        if name == "email.send":
            args.update(to="x@example.com", subject="s")
        else:
            args.update(email_id="42", to="x@example.com")

        def capture(*a, **k):
            self.sent.append(k.get("attachments"))
            return {"ok": True}

        async def go():
            with ClaimsContext(TOKEN, "t"), \
                    patch.object(main, "_require_gate_consent", AsyncMock(return_value={})), \
                    patch.object(egress, "check", return_value=ALLOW), \
                    patch.object(main.email, "send", capture), \
                    patch.object(main.email, "reply", capture), \
                    patch.object(main, "_email_account", lambda a: "studio"):
                return await main.call_tool(name, args)
        return asyncio.run(go())[0].text

    def test_a_gateway_file_outside_the_scratch_is_refused(self) -> None:
        secret = self.base / "data" / "clodia-tools-config.yaml"
        secret.parent.mkdir(parents=True, exist_ok=True)
        secret.write_text("vault: x\n")
        for verb in ("email.send", "email.reply"):
            self.assertIn("outside your scratch", self.call(verb, [str(secret)]))
        self.assertEqual(self.sent, [])

    def test_a_symlink_out_of_the_scratch_is_refused(self) -> None:
        target = self.base / "outside.txt"
        target.write_text("x")
        link = self.scratch / "looks-local.txt"
        os.symlink(target, link)
        self.assertIn("outside your scratch", self.call("email.send", [str(link)]))
        self.assertEqual(self.sent, [])

    def test_a_relative_path_is_refused(self) -> None:
        self.assertIn("outside your scratch", self.call("email.send", ["report.pdf"]))
        self.assertEqual(self.sent, [])

    def test_a_file_in_the_scratch_is_sent_by_its_resolved_path(self) -> None:
        att = self.scratch / "offerta.pdf"
        att.write_bytes(b"%PDF")
        for verb in ("email.send", "email.reply"):
            text = self.call(verb, [str(att)])
            self.assertFalse(text.startswith(("DENIED", "ERROR")), text)
        self.assertEqual(self.sent, [[os.path.realpath(att)], [os.path.realpath(att)]])

    def test_another_spawn_s_scratch_is_refused(self) -> None:
        other = self.base / "spawns" / "ophelia-7"
        other.mkdir()
        att = other / "theirs.pdf"
        att.write_bytes(b"x")
        self.assertIn("outside your scratch", self.call("email.send", [str(att)]))
        self.assertEqual(self.sent, [])


if __name__ == "__main__":
    unittest.main()

"""clodia-platform#570 — a native runtime tool that leaves the gateway's
perimeter (WebSearch) is used only after the room's owner approves it, with a
gate that explains the risk.

Measured here: an unknown tool is refused; an unattended session is refused
without a gate; the gate is on (tool, channel), time-boxed, no delegation,
decided by the room owner (WALLS); approved → the channel is tainted;
refused → nothing tainted.
"""
from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from . import gate, main
from .claims import ClaimsContext

TOKEN = {"agent": "clodia", "execution_id": "clodia-606", "principal": "davide",
         "origin": ["human:davide", "agent:clodia"]}


class NativeConsentTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        p = patch.dict(os.environ, {"CLODIA_AUDIT_DIR": str(base / "audit"),
                                    "CLODIA_AUDIT_KEY_DIR": str(base / "k"),
                                    "CLODIA_DATA": str(base / "data")})
        p.start()
        self.addCleanup(p.stop)
        self.gate = AsyncMock(return_value={})
        self.marked = []

    def run_(self, args, *, unattended=False):
        async def go():
            with ClaimsContext(TOKEN, "t"), \
                    patch.object(main, "is_unattended", return_value=unattended), \
                    patch.object(main, "current_chat", return_value="chan:SEAL-1:t:clodia"), \
                    patch.object(main, "_require_gate_consent", self.gate), \
                    patch.object(main._taint, "mark", side_effect=lambda *a, **k: self.marked.append((a, k))):
                return await main._native_consent(args, "clodia")
        return asyncio.run(go())

    def test_approved_taints_the_channel(self) -> None:
        out = self.run_({"tool": "WebSearch", "query": "palestre cagliari"})
        self.assertEqual(out, {"granted": True, "tool": "WebSearch"})
        (agent, key), kw = self.gate.await_args
        self.assertEqual(key, "native:WebSearch|chan:SEAL-1:t:clodia")
        self.assertFalse(kw["consume"])
        self.assertFalse(kw["allow_delegation"])
        self.assertIn("palestre cagliari", kw["reason"])
        self.assertIn("fuori dal gateway", kw["reason"])
        self.assertEqual(len(self.marked), 1)

    def test_refused_taints_nothing(self) -> None:
        self.gate.side_effect = PermissionError("gate: negato")
        with self.assertRaises(PermissionError):
            self.run_({"tool": "WebSearch", "query": "x"})
        self.assertEqual(self.marked, [])

    def test_unknown_tool_and_unattended_are_refused(self) -> None:
        for args, una in (({"tool": "Bash"}, False), ({"tool": "WebSearch"}, True)):
            with self.assertRaises(PermissionError):
                self.run_(args, unattended=una)
        self.gate.assert_not_awaited()

    def test_the_owner_decides(self) -> None:
        self.assertEqual(gate.gate_class("native:WebSearch|chan:SEAL-1:t:c"), gate.GATE_WALLS)


if __name__ == "__main__":
    unittest.main()

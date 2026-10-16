"""clodia-platform#553 — one agent's burst of slow calls cannot stall the gateway.

Terra, 15 Oct 2026: 50 `email.read` + 16 `email.save_attachment` from
messaggero. The IMAP subprocess ran ON the event loop (the completion times
came back serialised, ~0.2 s apart) and the offload pool went to 32/32: minting,
topic reads and other agents' turns timed out.

Fixed here: the network-bound native verbs run off the event loop, and each
agent holds at most `CAP` slow calls at once while other agents are untouched.
"""
from __future__ import annotations

import ast
import asyncio
import pathlib
import unittest
from unittest import mock

from server import slow_calls as sc


class CapTests(unittest.IsolatedAsyncioTestCase):
    async def _burst(self, agent: str, n: int, peak: dict, hold: float = 0.05):
        async def one():
            async with sc.slot("email.read", agent):
                peak["now"] = peak.get("now", 0) + 1
                peak["max"] = max(peak.get("max", 0), peak["now"])
                await asyncio.sleep(hold)
                peak["now"] -= 1
        await asyncio.gather(*(one() for _ in range(n)))

    async def test_one_agent_never_exceeds_its_cap(self):
        peak: dict = {}
        await self._burst("messaggero", 20, peak)
        self.assertEqual(peak["max"], sc.CAP)

    async def test_another_agent_is_not_blocked_by_the_burst(self):
        a, b = {}, {}
        t0 = asyncio.get_running_loop().time()
        burst = asyncio.ensure_future(self._burst("messaggero", 40, a, hold=0.1))
        await asyncio.sleep(0.01)
        await self._burst("segretario", 1, b, hold=0.0)
        self.assertLess(asyncio.get_running_loop().time() - t0, 0.2,
                        "segretario waited behind messaggero's burst")
        await burst

    async def test_fast_verbs_and_anonymous_calls_pass_through(self):
        peak: dict = {}
        async def one(verb, agent):
            async with sc.slot(verb, agent):
                peak["now"] = peak.get("now", 0) + 1
                peak["max"] = max(peak.get("max", 0), peak["now"])
                await asyncio.sleep(0.02)
                peak["now"] -= 1
        await asyncio.gather(*(one("topic.open", "messaggero") for _ in range(10)))
        self.assertEqual(peak["max"], 10)
        peak.clear()
        await asyncio.gather(*(one("email.read", None) for _ in range(10)))
        self.assertEqual(peak["max"], 10)

    async def test_waiting_too_long_fails_with_a_clear_message(self):
        with mock.patch.object(sc, "WAIT_S", 0.05), mock.patch.object(sc, "CAP", 1):
            sc._SEMS.clear()
            async def hold():
                async with sc.slot("email.read", "x"):
                    await asyncio.sleep(0.3)
            t = asyncio.ensure_future(hold())
            await asyncio.sleep(0.01)
            with self.assertRaises(sc.TooManySlowCalls) as ctx:
                async with sc.slot("email.read", "x"):
                    pass
            self.assertIn("'x'", str(ctx.exception))
            await t
        sc._SEMS.clear()

    def test_slow_families(self):
        for v in ("email.read", "telegram.send", "gdrive.list", "web.fetch"):
            self.assertTrue(sc.is_slow(v), v)
        for v in ("topic.open", "memory.read", "github.list_prs"):
            self.assertFalse(sc.is_slow(v), v)


class OffTheEventLoopTests(unittest.TestCase):
    """No network-bound native call runs directly in the async dispatcher."""

    def test_dispatcher_offloads_email_telegram_google(self):
        src = pathlib.Path(__file__).with_name("main.py").read_text(encoding="utf-8")
        fn = next(n for n in ast.walk(ast.parse(src))
                  if isinstance(n, ast.AsyncFunctionDef)
                  and n.name == "_call_tool_unaudited")
        direct = []
        for n in ast.walk(fn):
            if not isinstance(n, ast.Call):
                continue
            f = n.func
            if (isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name)
                    and f.value.id == "email" and f.attr != "safe_attachment_name"):
                direct.append(f"email.{f.attr}@{n.lineno}")
            if isinstance(f, ast.Name) and f.id in (
                    "_dispatch_telegram", "_dispatch_gdrive", "_dispatch_gcalendar",
                    "_dispatch_gdocs", "_dispatch_gsheets"):
                direct.append(f"{f.id}@{n.lineno}")
        self.assertEqual(direct, [], "network calls still on the event loop")


if __name__ == "__main__":
    unittest.main()

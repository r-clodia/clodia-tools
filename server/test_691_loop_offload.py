"""clodia-platform#691 — blocking work stays off the gateway's event loop.

Two stalls seen in production: `POST …/participants` (17 s: `add_participant`
asks the agent-server, which calls the gateway back — a circular wait on the
loop) and `POST /internal/logic-run` (47 s: the nightly backup). While such a
handler works, the loop must keep turning: here a ticker counts how often it
ran during a handler that blocks its thread for 0.4 s.
"""
from __future__ import annotations

import asyncio
import time
import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch

from . import logic_api, topics_api

BLOCK_S = 0.4


class _Req:
    def __init__(self, body: dict, method: str = "POST", params: dict | None = None):
        self._body = body
        self.method = method
        self.path_params = params or {}

    async def json(self):
        return self._body


def _blocking(result):
    def fn(*_a, **_k):
        time.sleep(BLOCK_S)
        return result
    return fn


async def _ticks_during(coro) -> tuple[int, object]:
    ticks = 0
    done = False

    async def ticker():
        nonlocal ticks
        while not done:
            ticks += 1
            await asyncio.sleep(0.02)

    t = asyncio.create_task(ticker())
    try:
        out = await coro
    finally:
        done = True
        await t
    return ticks, out


class LoopStaysFreeTests(unittest.TestCase):
    def _assert_free(self, coro):
        ticks, out = asyncio.run(_ticks_during(coro))
        # On the loop the ticker would get ~1 tick; off it, ~BLOCK_S/0.02.
        self.assertGreater(ticks, 5, f"event loop blocked ({ticks} ticks)")
        return out

    def test_adding_a_participant(self):
        svc = NS(add_participant=_blocking({"added": True}),
                 remove_participant=_blocking({"removed": True}))
        with patch.object(topics_api, "_authorize", lambda r: ("davide", None)), \
                patch.object(topics_api, "_service", lambda: svc):
            for method in ("POST", "DELETE"):
                with self.subTest(method=method):
                    r = self._assert_free(topics_api.participants(
                        _Req({"agent": "officer"}, method,
                             {"tier": "SEAL-1", "name": "eventi"})))
                    self.assertEqual(r.status_code, 200)

    def test_a_logic_run_verb(self):
        with patch.object(logic_api, "_authorized", lambda r: True), \
                patch.dict(logic_api._ALLOWED, {"settings.backup_run": _blocking({"ok": True})}):
            r = self._assert_free(logic_api.logic_run(
                _Req({"verb": "settings.backup_run", "args": {}})))
        self.assertEqual(r.status_code, 200)


if __name__ == "__main__":
    unittest.main()

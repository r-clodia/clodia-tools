"""Il claim di spawn arriva anche su `/mcp` (clodia-platform#398).

L'agent-server conia il token MCP con `execution_id` = lo spawn; il middleware di
`/mcp` non lo copiava nel contesto, mentre gli endpoint interni sì. Via MCP —
la porta di ogni agente — `current_spawn()` era sempre `None`: `copybrain` e
`crosstopic` negati, e il confine dello scratch saltato.
"""
from __future__ import annotations

import asyncio
import inspect
import unittest
from unittest.mock import patch

from . import claims, http_app, tool_api, whitelist

PAYLOAD = {"agent": "clodia", "execution_id": "clodia-293", "scope_tier": "SEAL-2",
           "chat": "chan:SEAL-2:preventivi-tomato:clodia", "principal": "davide"}


def _chiama(payload):
    visto = {}

    async def handler(scope, receive, send):
        visto["agent"] = whitelist._CURRENT_AGENT.get()
        visto["spawn"] = whitelist.current_spawn()
        visto["scope_tier"] = whitelist.current_scope_tier()
        visto["chat"] = whitelist.current_chat()

    mw = http_app._AuthMiddleware(handler)
    scope = {"type": "http", "headers": [(b"authorization", b"Bearer ckt1.x.y")]}
    with patch.object(http_app, "verify_session_token", return_value=payload), \
            patch("server.human_mcp.is_revoked", return_value=False):
        asyncio.run(mw(scope, None, None))
    return visto


class McpCarriesTheSpawnTests(unittest.TestCase):
    def test_the_mcp_door_exposes_the_signed_spawn_and_scope_tier(self):
        visto = _chiama(PAYLOAD)
        self.assertEqual("clodia", visto["agent"])
        self.assertEqual("clodia-293", visto["spawn"])
        self.assertEqual("SEAL-2", visto["scope_tier"])
        self.assertEqual(PAYLOAD["chat"], visto["chat"])

    def test_nothing_leaks_after_the_request(self):
        _chiama(PAYLOAD)
        self.assertIsNone(whitelist.current_spawn())

    def test_a_persons_mcp_client_is_not_a_spawn(self):
        visto = _chiama({**PAYLOAD, "agent": "davide", "execution_id": "mcp_ab12"})
        self.assertIsNone(visto["spawn"])


class OneTableTests(unittest.TestCase):
    def test_both_doors_use_the_same_claims_table(self):
        self.assertIs(tool_api._Ctx, claims.ClaimsContext)
        src = inspect.getsource(http_app._AuthMiddleware)
        self.assertIn("ClaimsContext(payload, token)", src)
        self.assertNotIn("set_current_agent", src,
                         "il middleware non deve tornare a riscrivere i claim a mano")

    def test_the_table_covers_every_claim_either_door_used(self):
        nomi = {n for n, *_ in claims.ClaimsContext._VARS}
        self.assertTrue({"agent", "spawn", "scope_tier", "principal", "token", "clearance",
                         "on_behalf", "principal_kind", "human_role", "chat", "origin",
                         "scoped_tools", "unattended"} <= nomi)


if __name__ == "__main__":
    unittest.main()

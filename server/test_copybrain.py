"""`copybrain` e la fine del grant automatico sui mount MCP (clodia-platform#393).

Decisione di Davide (26 set 2026): clodia non tiene `contabilita.*`, `leads.*`,
`normattiva.*`, `sedia.*`; li può assumere, previo gate, per lo spawn che sta
usando. Le proprietà che contano, una per test:

- montare un backend MCP non concede più il suo namespace a clodia;
- i verbi in prestito valgono per il CHIAMANTE e per il suo SPAWN, non per il
  seed né per chi calcola i verbi di un altro agente;
- il prestito non si concatena;
- il consenso è `walls`, legato allo spawn, non consumato e mai delegato;
- `copybrain.call` rifiuta ciò che non è in prestito;
- la capability di copybrain ha un tetto lungo, le altre no;
- la fine dello spawn revoca il prestito.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from mcp.types import Tool

from . import copybrain, gate, main, pki_mint, tools_api, whitelist


class McpMountGrantsNobodyTests(unittest.TestCase):
    def test_mounting_a_backend_does_not_touch_clodias_verbs(self):
        cfg = {"agents": {"clodia": {"allowed_tools": ["web.fetch"]}}, "mcp_backends": []}
        with patch.dict(whitelist.CONFIG, cfg, clear=True), \
                patch.object(whitelist, "save_config"), patch.object(whitelist, "reload_config"), \
                patch.object(tools_api.proxy, "clear_cache"), \
                patch.object(tools_api.instance_profile, "integrations_check"):
            tools_api.register_mcp_core(
                {"mcpServers": {"sedia": {"command": "python3", "args": ["x.py"]}}}, {})
            self.assertEqual(["web.fetch"], whitelist.CONFIG["agents"]["clodia"]["allowed_tools"])
            self.assertEqual(["sedia"], [b["name"] for b in whitelist.CONFIG["mcp_backends"]])


_MATRICI = {
    "clodia": {"web.fetch", "topic.put"},
    "commercialista": {"contabilita.*", "web.fetch"},
    "avvocato": {"normattiva.*"},
}


class BorrowedToolsTests(unittest.TestCase):
    def _run(self, caller, spawn, attivi, name):
        tok = whitelist.set_current_agent(caller)
        try:
            with patch.object(whitelist, "current_spawn", return_value=spawn), \
                    patch.object(whitelist, "_resolved_tools",
                                 side_effect=lambda n: set(_MATRICI.get(n, set()))), \
                    patch.object(gate, "active_with_prefix", return_value=attivi):
                return whitelist.effective_tools(name)
        finally:
            whitelist.reset_current_agent(tok)

    def test_the_calling_spawn_gets_the_borrowed_verbs(self):
        eff = self._run("clodia", "clodia-3", ["copybrain:commercialista"], "clodia")
        self.assertIn("contabilita.*", eff)
        self.assertIn("topic.put", eff)

    def test_without_a_signed_spawn_nothing_is_borrowed(self):
        eff = self._run("clodia", None, ["copybrain:commercialista"], "clodia")
        self.assertNotIn("contabilita.*", eff)

    def test_computing_another_agents_verbs_shows_no_loan(self):
        """La scheda di clodia letta da un altro chiamante non mostra i prestiti."""
        eff = self._run("sysadmin", "sysadmin-1", ["copybrain:commercialista"], "clodia")
        self.assertNotIn("contabilita.*", eff)

    def test_the_loan_does_not_chain(self):
        """Si prende la matrice DICHIARATA del seed copiato, mai i suoi prestiti."""
        chiamati = []

        def risolvi(n):
            chiamati.append(n)
            return set(_MATRICI.get(n, set()))

        tok = whitelist.set_current_agent("clodia")
        try:
            with patch.object(whitelist, "current_spawn", return_value="clodia-3"), \
                    patch.object(whitelist, "_resolved_tools", side_effect=risolvi), \
                    patch.object(gate, "active_with_prefix", return_value=["copybrain:commercialista"]), \
                    patch.object(whitelist, "borrowed_tools", wraps=whitelist.borrowed_tools) as bt:
                whitelist.effective_tools("clodia")
        finally:
            whitelist.reset_current_agent(tok)
        self.assertEqual(["clodia", "commercialista"], sorted(chiamati))
        self.assertEqual(1, bt.call_count)


class GateShapeTests(unittest.TestCase):
    def test_copybrain_is_decided_by_the_owner_of_the_room(self):
        self.assertEqual(gate.GATE_WALLS, gate.gate_class("copybrain:commercialista"))

    def test_only_the_copybrain_capability_has_the_long_ceiling(self):
        self.assertEqual(24 * 60, pki_mint.capability_ceiling_minutes("gate:copybrain:avvocato"))
        self.assertEqual(120, pki_mint.capability_ceiling_minutes("gate:web.post"))
        self.assertEqual(120, pki_mint.capability_ceiling_minutes("sudo"))


class StoreTests(unittest.TestCase):
    def setUp(self):
        d = Path(tempfile.mkdtemp())
        p1 = patch.object(gate, "_store_path", return_value=d / "store.json")
        p2 = patch.object(gate, "_revoked_path", return_value=d / "revoked.json")
        p3 = patch.object(gate.pki_verify, "verify_capability",
                          side_effect=lambda tok: {"agent": "clodia", "cap": f"gate:{tok}",
                                                   "exp": 9e12, "jti": tok})
        for p in (p1, p2, p3):
            p.start()
            self.addCleanup(p.stop)

    def test_active_with_prefix_is_per_spawn_and_revoke_closes_it(self):
        gate.grant("clodia", "clodia-3", "copybrain:commercialista", "copybrain:commercialista")
        gate.grant("clodia", "clodia-3", "web.post", "web.post")
        self.assertEqual(["copybrain:commercialista"],
                         gate.active_with_prefix("clodia", "clodia-3", gate.COPYBRAIN_PREFIX))
        self.assertEqual([], gate.active_with_prefix("clodia", "clodia-4", gate.COPYBRAIN_PREFIX))
        self.assertEqual(["copybrain:commercialista"],
                         gate.revoke_instance("clodia", "clodia-3", gate.COPYBRAIN_PREFIX))
        self.assertEqual([], gate.active_with_prefix("clodia", "clodia-3", gate.COPYBRAIN_PREFIX))
        self.assertTrue(gate.active("clodia", "clodia-3", "web.post"),
                        "la revoca di fine spawn tocca solo i prestiti")

    def test_no_instance_means_no_loan(self):
        self.assertEqual([], gate.active_with_prefix("clodia", "-", gate.COPYBRAIN_PREFIX))


def _ctx(agent="clodia", spawn="clodia-3", on_behalf=False):
    return (patch.object(whitelist, "agent_name", return_value=agent),
            patch.object(whitelist, "current_spawn", return_value=spawn),
            patch.object(whitelist, "is_on_behalf", return_value=on_behalf))


class VerbTests(unittest.IsolatedAsyncioTestCase):
    async def test_assume_asks_a_spawn_scoped_non_consuming_gate_and_lists_the_verbs(self):
        catalogo = [Tool(name="contabilita.list", description="Elenca.", inputSchema={"type": "object"}),
                    Tool(name="web.fetch", description="Legge.", inputSchema={"type": "object"}),
                    Tool(name="copybrain.call", description="x", inputSchema={"type": "object"})]
        a, b, c = _ctx()
        with a, b, c, patch.object(copybrain, "_seed_exists", return_value=True), \
                patch.object(whitelist, "_resolved_tools",
                             side_effect=lambda n: set(_MATRICI.get(n, set()))), \
                patch.object(main, "_require_gate_consent", new=AsyncMock()) as gc:
            out = await copybrain.assume({"seed": "commercialista", "reason": "bilancio"}, catalogo)
        args, kw = gc.call_args
        self.assertEqual(("clodia", "copybrain:commercialista"), args)
        self.assertFalse(kw["consume"])
        self.assertFalse(kw["allow_delegation"])
        self.assertEqual(["contabilita.list"], [v["name"] for v in out["verbs"]])

    async def test_assume_refuses_its_own_seed_and_unknown_seeds(self):
        a, b, c = _ctx()
        with a, b, c, patch.object(main, "_require_gate_consent", new=AsyncMock()) as gc:
            with self.assertRaises(ValueError):
                await copybrain.assume({"seed": "clodia", "reason": "x"}, [])
            with patch.object(copybrain, "_seed_exists", return_value=False):
                with self.assertRaises(ValueError):
                    await copybrain.assume({"seed": "nessuno", "reason": "x"}, [])
        gc.assert_not_called()

    async def test_no_signed_spawn_no_loan(self):
        a, b, c = _ctx(spawn=None)
        with a, b, c:
            with self.assertRaises(PermissionError):
                await copybrain.assume({"seed": "commercialista", "reason": "x"}, [])

    async def test_a_person_does_not_use_copybrain(self):
        a, b, c = _ctx(on_behalf=True)
        with a, b, c:
            with self.assertRaises(PermissionError):
                await copybrain.assume({"seed": "commercialista", "reason": "x"}, [])


class CallTests(unittest.TestCase):
    def test_call_refuses_a_verb_that_is_not_on_loan(self):
        a, b, c = _ctx()
        with a, b, c, patch.object(whitelist, "borrowed_tools", return_value={"contabilita.*"}):
            self.assertEqual(("contabilita.list", {"anno": 2026}),
                             copybrain.check_call({"verb": "contabilita.list",
                                                   "arguments": {"anno": 2026}}))
            with self.assertRaises(PermissionError):
                copybrain.check_call({"verb": "settings.set"})
            with self.assertRaises(ValueError):
                copybrain.check_call({"verb": "copybrain.assume"})


if __name__ == "__main__":
    unittest.main()

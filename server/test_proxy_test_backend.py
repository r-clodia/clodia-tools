"""test_backend: verifica REALE di un connettore MCP montato (clodia-platform#TBD).

Prima di questo modulo `test_connector` (tools_api.py) non aveva alcun ramo
per i backend montati via `mcp.add`/Add-MCP: qualunque id non fosse uno dei
provider nativi (github/telegram/openai/google/mailboxes) tornava sempre
`{"ok": None, "detail": "test non disponibile per questa integrazione"}`,
a prescindere da un secret mancante o invalido — e la webui nascondeva pure
il bottone Test per quelle card (fix separato lato frontend). Buffer, montato
come backend MCP generico, non aveva quindi alcun modo di essere verificato.
"""
import asyncio
import unittest
from contextlib import asynccontextmanager
from unittest.mock import patch

from server import proxy


class _FakeToolsResult:
    def __init__(self, n):
        self.tools = [object()] * n


class TestBackendTests(unittest.IsolatedAsyncioTestCase):
    def test_backend_non_montato_e_non_testabile(self):
        with patch.object(proxy, "_backends", return_value={}):
            r = asyncio.run(proxy.test_backend("buffer"))
        self.assertIsNone(r["ok"])
        self.assertIn("non montato", r["detail"])

    def test_sessione_riuscita_conta_i_tool(self):
        @asynccontextmanager
        async def _fake_session(_b):
            class _S:
                async def list_tools(self):
                    return _FakeToolsResult(3)
            yield _S()

        with patch.object(proxy, "_backends", return_value={"buffer": {"transport": "http"}}), \
             patch.object(proxy, "_session", _fake_session):
            r = asyncio.run(proxy.test_backend("buffer"))
        self.assertTrue(r["ok"])
        self.assertIn("3 tool", r["detail"])

    def test_401_dal_backend_e_un_esito_non_un_crash(self):
        @asynccontextmanager
        async def _fake_session(_b):
            raise RuntimeError("401 Unauthorized")
            yield  # pragma: no cover — rende la funzione un generatore

        with patch.object(proxy, "_backends", return_value={"buffer": {"transport": "http"}}), \
             patch.object(proxy, "_session", _fake_session):
            r = asyncio.run(proxy.test_backend("buffer"))
        self.assertFalse(r["ok"])
        self.assertIn("401", r["detail"])

    def test_timeout_e_un_esito_negativo_non_un_hang(self):
        @asynccontextmanager
        async def _fake_session(_b):
            await asyncio.sleep(999)
            yield None  # pragma: no cover

        with patch.object(proxy, "_backends", return_value={"buffer": {"transport": "http"}}), \
             patch.object(proxy, "_session", _fake_session), \
             patch.object(proxy, "TEST_TIMEOUT_S", 0.05):
            r = asyncio.run(proxy.test_backend("buffer"))
        self.assertFalse(r["ok"])
        self.assertIn("nessuna risposta", r["detail"])


if __name__ == "__main__":
    unittest.main()

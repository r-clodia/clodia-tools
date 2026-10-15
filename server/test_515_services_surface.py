"""clodia-platform#515 — i servizi sono visibili e il gateway li tiene vivi.

Due metà che senza questi test restano scollegate: il supervisore esiste ma
nessuno lo avvia, oppure gira ma il suo stato non arriva alla pagina Tools e
un servizio morto è indistinguibile da un connettore che non è stato
configurato.
"""
import inspect
import json
import unittest
from unittest.mock import patch

from starlette.requests import Request

from . import connectors_api, http_app, tools_api

_ROW = {"pack": "demo-pack", "service": "listener", "state": "blocked",
        "pid": None, "isolated": True, "uid": 60001, "starts": 0,
        "failures": 1, "last_exit": None,
        "last_error": "IsolationUnavailable: …", "health": "",
        "state_dir": "/datadir/services/demo-pack/listener"}


def _request(path: str) -> Request:
    return Request({"type": "http", "method": "GET", "path": path,
                    "headers": [], "query_string": b""})


class ToolsPageShowsServicesTests(unittest.IsolatedAsyncioTestCase):
    async def test_get_tools_carries_state_and_last_error_per_service(self):
        with patch.object(tools_api, "_authorized", return_value=True), \
             patch.object(tools_api, "connectors_snapshot", return_value=[]), \
             patch("server.services.snapshot", return_value=[_ROW]):
            response = await tools_api.list_tools(_request("/tools"))
        served = json.loads(response.body)["services"]
        self.assertEqual(served[0]["service"], "listener")
        self.assertEqual(served[0]["state"], "blocked")
        self.assertIn("last_error", served[0])

    async def test_the_connector_listing_carries_them_too(self):
        with patch.object(connectors_api, "_authorize", return_value=({}, None)), \
             patch("server.services.snapshot", return_value=[_ROW]):
            response = await connectors_api.list_connectors(
                _request("/internal/connectors"))
        self.assertEqual(json.loads(response.body)["services"], [_ROW])

    async def test_no_secret_travels_in_a_service_row(self):
        """La riga nomina la credenziale solo nell'errore, mai il valore: i
        campi sono una lista chiusa, e questa è la lista."""
        from .services.supervisor import Supervisor
        rows = Supervisor(lambda: []).snapshot()
        self.assertEqual(rows, [])
        self.assertEqual(set(_ROW), {
            "pack", "service", "state", "pid", "isolated", "uid", "starts",
            "failures", "last_exit", "last_error", "health", "state_dir"})


class TheGatewayStartsAndStopsThemTests(unittest.TestCase):
    """Il ciclo vive nel lifespan: senza, il supervisore non gira mai."""

    def _lifespan_code(self) -> str:
        source = inspect.getsource(http_app._lifespan)
        # Senza commenti: un controllo testuale che si accontenta di una frase
        # scritta in un commento verifica la buona volontà, non il codice.
        return "\n".join(line for line in source.splitlines()
                         if not line.strip().startswith("#"))

    def test_the_lifespan_runs_the_reconcile_loop(self):
        self.assertIn("reconcile_loop()", self._lifespan_code())

    def test_the_lifespan_stops_the_services_on_shutdown(self):
        code = self._lifespan_code()
        self.assertIn("stop_all", code)
        # In un thread: l'arresto manda SIGTERM e aspetta, e il loop sta
        # chiudendo le connessioni degli agenti.
        self.assertIn("to_thread(_services.stop_all)", code)


if __name__ == "__main__":
    unittest.main()

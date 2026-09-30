"""clodia-platform#455 · il turno che ha chiesto, letto dal lato del gateway.

L'agent-server marca ogni chiamata interna con `X-Clodia-Trace-Id`, il nome del
turno in corso (clodia-logic #489). Qui si raccoglie: senza, il gateway continua
a scrivere le sue righe — richiesta lenta, stallo del loop, 500 — in un
vocabolario che non si incrocia con quello dell'altro lato, ed è esattamente la
situazione da cui è nata la issue: un 500 di `/internal/topics/*` e un turno che
scadeva nello stesso minuto, senza modo di dire se il primo riguardasse il
secondo.

Il 500 ha due forme e vanno colte entrambe: una risposta 500 costruita
dall'handler, e un'eccezione che sale — che in Starlette diventa 500 SOPRA
questo middleware (`ServerErrorMiddleware` sta più fuori), quindi qui non passa
mai come risposta.
"""
from __future__ import annotations

import unittest

from . import inflight

_ROTTA = "/internal/topics/SEAL-1/software-house/files"
_TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"


def _scope(path: str = _ROTTA, trace: str | None = _TRACE,
           client: str = "10.0.0.7") -> dict:
    headers = [(b"x-clodia-caller", b"agent-server")]
    if trace is not None:
        headers.append((b"x-clodia-trace-id", trace.encode()))
    return {"type": "http", "method": "GET", "path": path, "headers": headers,
            "client": (client, 4242)}


async def _noop_receive():  # pragma: no cover - il middleware non lo consuma
    return {"type": "http.request"}


async def _sink(_message) -> None:
    return None


def _risponde(status: int):
    async def app(_scope, _receive, send):
        await send({"type": "http.response.start", "status": status, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})
    return app


class _Base(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        inflight.reset()

    def tearDown(self) -> None:
        inflight.reset()


class IlGatewayRaccoglieIlTraceTests(_Base):

    async def test_il_trace_della_richiesta_in_volo_e_leggibile(self):
        """Chi guarda uno stallo vede le richieste in volo: se portano il nome
        del turno, la riga del gateway e quella dell'agent-server si leggono
        insieme senza incrociare gli orari a mano."""
        arrivata = []

        async def handler(scope, _receive, _send):
            arrivata.append(inflight.snapshot())

        await inflight.InflightMiddleware(handler)(_scope(), _noop_receive, _sink)
        self.assertEqual(1, len(arrivata[0]))
        self.assertEqual(_TRACE, arrivata[0][0].get("trace"))

    async def test_senza_header_la_richiesta_resta_senza_trace(self):
        """Una chiamata della webui non appartiene a nessun turno: si dice, non
        si inventa."""
        arrivata = []

        async def handler(scope, _receive, _send):
            arrivata.append(inflight.snapshot())

        await inflight.InflightMiddleware(handler)(_scope(trace=None),
                                                   _noop_receive, _sink)
        self.assertEqual("", arrivata[0][0].get("trace"))

    async def test_la_riga_dello_stallo_nomina_il_turno(self):
        async def handler(scope, _receive, _send):
            with self.assertLogs("clodia-tools.inflight", level="WARNING") as log:
                self.assertTrue(inflight.report_if_stalled(99.0))
            self.assertIn(_TRACE, "\n".join(log.output))

        await inflight.InflightMiddleware(handler)(_scope(), _noop_receive, _sink)


class IlCinqueCentoDiceDiChiEraIlTurnoTests(_Base):

    async def test_una_risposta_500_lascia_una_riga_col_trace(self):
        mw = inflight.InflightMiddleware(_risponde(500))
        with self.assertLogs("clodia-tools.inflight", level="WARNING") as log:
            await mw(_scope(), _noop_receive, _sink)
        righe = [r for r in log.output if _TRACE in r]
        self.assertEqual(1, len(righe), log.output)
        self.assertIn("500", righe[0])
        self.assertIn("/internal/topics/*", righe[0])

    async def test_un_handler_che_esplode_lascia_la_stessa_riga(self):
        """La forma più comune del 500: l'eccezione sale e diventa risposta
        SOPRA questo middleware, quindi non la si può aspettare come stato."""
        async def esplode(_scope, _receive, _send):
            raise RuntimeError("boom")

        mw = inflight.InflightMiddleware(esplode)
        with self.assertLogs("clodia-tools.inflight", level="WARNING") as log:
            with self.assertRaises(RuntimeError):
                await mw(_scope(), _noop_receive, _sink)
        righe = [r for r in log.output if _TRACE in r]
        self.assertEqual(1, len(righe), log.output)
        self.assertIn("RuntimeError", righe[0])
        # il registro resta pulito: l'eccezione passa, la riga non resta appesa
        self.assertEqual([], inflight.snapshot())

    async def test_una_risposta_buona_non_logga(self):
        mw = inflight.InflightMiddleware(_risponde(200))
        with self.assertNoLogs("clodia-tools.inflight", level="WARNING"):
            await mw(_scope(), _noop_receive, _sink)

    async def test_un_404_non_e_un_guasto_del_gateway(self):
        """Un topic che non c'è è una risposta, non un incidente: loggarlo
        riempirebbe i log proprio dove si cerca il 500."""
        mw = inflight.InflightMiddleware(_risponde(404))
        with self.assertNoLogs("clodia-tools.inflight", level="WARNING"):
            await mw(_scope(), _noop_receive, _sink)


if __name__ == "__main__":
    unittest.main()

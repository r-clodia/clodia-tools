"""clodia-platform#316 · chi occupa il gateway, e chi lo teneva quando si è fermato.

L'incidente del 7 set 2026 (10:47–10:56 UTC): 33 «gateway topics irraggiungibile»
in dieci minuti, contro 1-2 al giorno, auto-risolti senza intervento e senza
causa identificata. Nei log del gateway, nella stessa finestra, una raffica di
`POST /internal/mint` + `GET /internal/gate/pending` ogni 30-70 ms.

La misura smonta l'ipotesi con cui la issue è stata aperta: coniare un token
costa **0,062 ms** e verificarne uno **0,199 ms** (300 iterazioni, CA e cert
generati da `pki_mint`). Trenta coppie concorrenti fanno ~8 ms di lavoro: non
saturano niente. E soprattutto: `mint` e `gate/pending` sono fra i pochi
endpoint che NON scaricano su thread — rispondono inline. Quelli andati in
timeout (`/internal/topics*`, dispatch topic/github, telegram, web.fetch) usano
tutti `asyncio.to_thread`, cioè l'executor di **default** di asyncio, che nessuno
dimensiona: `min(32, cpu+4)`, che su un'istanza da 2 vCPU sono 6 thread per tutto
il gateway. Se qualche offload resta appeso, ogni offload successivo si accoda —
per minuti — mentre gli endpoint inline continuano a rispondere 200 in pochi ms.
La raffica era l'unica strada che funzionava ancora, non la causa.

Questi controlli tengono in piedi ciò che serve a NOMINARE la causa la prossima
volta, invece di dedurla per la terza volta: quante richieste sono in volo e di
chi sono, quali durano troppo, e — quando il loop si ferma — una riga sola che
dice chi lo stava tenendo. Più il pool di offload dimensionato in modo esplicito,
che è la mitigazione: un tetto implicito derivato dalle CPU dell'host è il
parametro sbagliato per un gateway I/O-bound.
"""
from __future__ import annotations

import asyncio
import os
import threading
import unittest
from unittest.mock import patch

from . import inflight

_ROTTA = "/internal/gate/pending"


def _scope(path: str = _ROTTA, method: str = "GET", client: str = "10.0.0.7") -> dict:
    return {"type": "http", "method": method, "path": path, "headers": [],
            "client": (client, 4242)}


async def _noop_receive():  # pragma: no cover - il middleware non lo consuma
    return {"type": "http.request"}


async def _sink(_message) -> None:
    return None


class _Base(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        inflight.reset()
        self._env = {k: os.environ.get(k) for k in
                     ("CLODIA_INFLIGHT_WARN", "CLODIA_SLOW_REQUEST_S",
                      "CLODIA_LOOP_LAG_WARN_S", "CLODIA_OFFLOAD_WORKERS")}
        for k in self._env:
            os.environ.pop(k, None)

    def tearDown(self) -> None:
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        inflight.reset()

    async def _due_in_volo(self, app_factory=None, path: str = _ROTTA):
        """Due richieste concorrenti tenute aperte insieme: è la misura che oggi
        non esiste, e il montaggio minimo per osservarla."""
        aperte = asyncio.Event()
        arrivate = []

        async def handler(scope, _receive, _send):
            arrivate.append(scope["path"])
            await aperte.wait()

        mw = inflight.InflightMiddleware(app_factory or handler)
        tasks = [asyncio.create_task(mw(_scope(path), _noop_receive, _sink))
                 for _ in range(2)]
        while len(arrivate) < 2:
            await asyncio.sleep(0)
        return aperte, tasks


class TheGatewayKnowsWhoIsInFlightTests(_Base):

    async def test_two_concurrent_requests_are_both_visible_with_their_caller(self):
        aperte, tasks = await self._due_in_volo()
        try:
            snap = inflight.snapshot()
            self.assertEqual(2, len(snap), f"snapshot incompleto: {snap}")
            self.assertEqual({_ROTTA}, {r["route"] for r in snap})
            self.assertEqual({"10.0.0.7"}, {r["caller"] for r in snap})
            self.assertTrue(all(r["age_s"] >= 0 for r in snap))
            self.assertEqual(2, inflight.peak(_ROTTA))
        finally:
            aperte.set()
            await asyncio.gather(*tasks)

    async def test_the_registry_empties_even_when_the_handler_raises(self):
        """Un registro che perde righe diventa una lista di fantasmi, e la riga
        dello stallo accuserebbe richieste finite da un pezzo."""
        async def esplode(_scope, _receive, _send):
            raise RuntimeError("boom")

        mw = inflight.InflightMiddleware(esplode)
        with self.assertRaises(RuntimeError):
            await mw(_scope(), _noop_receive, _sink)

        self.assertEqual([], inflight.snapshot())

    async def test_a_path_with_parameters_does_not_explode_the_cardinality(self):
        """`/internal/topics/SEAL-1/hedge-iot-new` e `/internal/topics/SEAL-1/ops`
        sono lo stesso endpoint: contarli separati nasconde la concorrenza."""
        aperte, tasks = await self._due_in_volo(path="/internal/topics/SEAL-1/ops")
        try:
            self.assertEqual({"/internal/topics/*"},
                             {r["route"] for r in inflight.snapshot()})
        finally:
            aperte.set()
            await asyncio.gather(*tasks)

    async def test_a_route_can_say_who_the_caller_really_is(self):
        """L'IP del client non distingue due tab della webui da un loop di retry.
        Le rotte interne il principal lo hanno GIÀ risolto (mint lo legge dal
        body che parsa, gate lo verifica nel token): qui lo attaccano alla
        richiesta in volo, senza un giro di crittografia in più."""
        async def handler(_scope, _receive, _send):
            inflight.attribute("principal:davide")

        mw = inflight.InflightMiddleware(handler)
        visti = []
        with patch.object(inflight, "_finish", side_effect=inflight._finish) as fine:
            await mw(_scope(), _noop_receive, _sink)
            visti = [c.args[0].caller for c in fine.call_args_list]

        self.assertEqual(["principal:davide"], visti)


class WhenItIsTooMuchItSaysSoTests(_Base):

    async def test_crossing_the_concurrency_threshold_names_route_and_caller(self):
        os.environ["CLODIA_INFLIGHT_WARN"] = "2"
        with self.assertLogs(inflight.LOG, level="WARNING") as log:
            aperte, tasks = await self._due_in_volo()
            aperte.set()
            await asyncio.gather(*tasks)

        righe = [r for r in log.output if "concorren" in r]
        self.assertEqual(1, len(righe), f"attesa UNA riga, viste {log.output}")
        self.assertIn(_ROTTA, righe[0])
        self.assertIn("10.0.0.7", righe[0])

    async def test_a_quiet_gateway_says_nothing(self):
        """Il rumore è il modo in cui una misura muore: se la soglia parla anche
        a regime, la riga che conta non la legge più nessuno."""
        mw = inflight.InflightMiddleware(lambda *_a: asyncio.sleep(0))
        with patch.object(inflight.LOG, "warning") as warn:
            await mw(_scope(), _noop_receive, _sink)
        warn.assert_not_called()

    async def test_a_slow_request_is_reported_with_its_duration(self):
        os.environ["CLODIA_SLOW_REQUEST_S"] = "0.01"

        async def lenta(_scope, _receive, _send):
            await asyncio.sleep(0.03)

        mw = inflight.InflightMiddleware(lenta)
        with self.assertLogs(inflight.LOG, level="WARNING") as log:
            await mw(_scope(), _noop_receive, _sink)

        righe = [r for r in log.output if "lenta" in r]
        self.assertEqual(1, len(righe), f"nessuna riga di lentezza: {log.output}")
        self.assertIn(_ROTTA, righe[0])


class TheStallLeavesANameTests(_Base):
    """L'artefatto che la issue chiede — «un dump dei thread nel momento esatto
    della saturazione» — nella forma che si può tenere accesa sempre: una riga,
    scritta mentre il gateway è fermo, con chi era in volo e da quanto."""

    async def test_the_report_lists_who_was_holding_the_loop(self):
        aperte, tasks = await self._due_in_volo()
        try:
            with self.assertLogs(inflight.LOG, level="WARNING") as log:
                inflight.report_if_stalled(2.5)
            riga = "\n".join(log.output)
            self.assertIn("2.5", riga)
            self.assertIn(_ROTTA, riga)
            self.assertIn("10.0.0.7", riga)
        finally:
            aperte.set()
            await asyncio.gather(*tasks)

    async def test_it_reports_the_offload_queue_too(self):
        """Il pool di offload è il sospetto principale di questo incidente: se la
        riga non dice quanti thread sono occupati e quanto è profonda la coda, lo
        stallo resta senza colpevole anche la prossima volta."""
        inflight.install_offload_pool()
        with self.assertLogs(inflight.LOG, level="WARNING") as log:
            inflight.report_if_stalled(2.0)
        riga = "\n".join(log.output)
        self.assertIn("offload", riga)
        self.assertIn(str(inflight.pool_stats()["max_workers"]), riga)

    async def test_below_the_threshold_it_stays_quiet(self):
        self.assertFalse(inflight.report_if_stalled(0.05))

    async def test_the_watchdog_measures_the_lag_and_does_not_die_on_it(self):
        """Il watchdog gira per tutta la vita del processo: un'eccezione dentro il
        ciclo lo spegnerebbe in silenzio, e la misura sparirebbe proprio quando
        serve."""
        chiamate: list[float] = []

        def esplode(lag):
            chiamate.append(lag)
            raise RuntimeError("il report è rotto")

        with patch.object(inflight, "report_if_stalled", esplode):
            task = asyncio.create_task(inflight.watch(interval=0.01))
            await asyncio.sleep(0.05)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task

        self.assertGreaterEqual(len(chiamate), 2,
                                "il watchdog si è fermato al primo errore")


class TheOffloadPoolIsOursAndItIsSizedTests(_Base):
    """La mitigazione. Oggi il tetto di `asyncio.to_thread` è implicito e
    derivato dalle CPU dell'host — il parametro sbagliato per un gateway
    I/O-bound. Nessun call site cambia: `to_thread` usa il default executor, e il
    default executor diventa il nostro."""

    async def test_offloaded_work_runs_on_our_named_pool(self):
        inflight.install_offload_pool()
        nome = await asyncio.to_thread(lambda: threading.current_thread().name)
        self.assertTrue(nome.startswith("offload"), nome)

    async def test_the_size_is_declared_not_inherited_from_the_cpu_count(self):
        inflight.install_offload_pool()
        self.assertEqual(inflight.DEFAULT_OFFLOAD_WORKERS,
                         inflight.pool_stats()["max_workers"])
        self.assertNotEqual(min(32, (os.cpu_count() or 1) + 4),
                            inflight.DEFAULT_OFFLOAD_WORKERS,
                            "se il default coincide con quello di asyncio questo "
                            "controllo non dimostra niente: alzarlo o abbassarlo "
                            "resta una decisione, ma deve essere una decisione")

    async def test_the_size_is_tunable_without_touching_the_code(self):
        os.environ["CLODIA_OFFLOAD_WORKERS"] = "7"
        inflight.install_offload_pool()
        self.assertEqual(7, inflight.pool_stats()["max_workers"])

    async def test_stats_say_how_busy_the_pool_is(self):
        inflight.install_offload_pool()
        parti = threading.Event()
        occupato = threading.Event()

        def blocca():
            occupato.set()
            parti.wait(2)

        fut = asyncio.create_task(asyncio.to_thread(blocca))
        # L'attesa va fatta cedendo il loop: `occupato.wait()` sincrono qui
        # bloccherebbe il thread che deve ancora far partire il task, e il
        # controllo misurerebbe il proprio stallo invece del pool.
        for _ in range(200):
            if occupato.is_set():
                break
            await asyncio.sleep(0.01)
        try:
            self.assertGreaterEqual(inflight.pool_stats()["threads"], 1)
        finally:
            parti.set()
            await fut


class TheGatewayInstallsAllOfThisTests(unittest.TestCase):
    """Un modulo che nessuno monta è codice morto: questi due controlli sono la
    differenza fra «esiste» e «gira in produzione»."""

    def test_the_app_is_wrapped_by_the_counter(self):
        from .http_app import build_app
        classi = [m.cls for m in build_app().user_middleware]
        self.assertIn(inflight.InflightMiddleware, classi)

    def test_the_lifespan_starts_the_watchdog_and_takes_the_pool(self):
        from . import http_app
        # Il bootstrap PKI e il profilo topic non sono ciò che si misura qui, e
        # con il secret presente nell'ambiente il boot proverebbe a scrivere
        # davvero: senza questo, il controllo dipende da dove gira.
        env = {k: v for k, v in os.environ.items()
               if k != "CLODIA_ORCHESTRATOR_SECRET"}
        with patch.dict(os.environ, env, clear=True), \
                patch.object(inflight, "install_offload_pool") as pool, \
                patch.object(inflight, "watch") as watch:
            asyncio.run(self._lifespan(http_app))
        pool.assert_called_once()
        watch.assert_called_once()

    async def _lifespan(self, http_app) -> None:
        async with http_app._lifespan(None):
            pass


if __name__ == "__main__":
    unittest.main()

"""Il log del GATEWAY è leggibile quanto quello dell'agent-server.

clodia-platform#382, punto 2. Il compartimento per-spawn ha vissuto settimane in
modalità `report`: decideva, scriveva un WARNING su `clodia-tools` e lasciava
passare. Quel WARNING finiva su stdout del container, e `logs.tail` — l'unico
strumento diagnostico che sysadmin ha — leggeva **solo** `agent-server.log`.
Risultato: l'evidenza che serviva per chiudere il rollout esisteva e non era
raggiungibile da nessuno dentro la colonia, e infatti l'issue chiede di
verificare un log che chi l'ha scritta non poteva leggere.

Un rollout la cui osservazione non si può leggere non converge mai. Qui il
gateway scrive anche su file, e `logs.tail(source="gateway")` lo mostra.
"""
from __future__ import annotations

import logging
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from . import logs


class _Datadir:
    """`CLODIA_DATA` su una directory temporanea, per l'arco del test."""

    def __enter__(self) -> Path:
        self._tmp = TemporaryDirectory()
        self._p = patch.dict("os.environ", {"CLODIA_DATA": self._tmp.name})
        self._p.start()
        self._t = patch.object(logs, "tool_allowed", lambda _v: None)
        self._t.start()
        return Path(self._tmp.name)

    def __exit__(self, *a):
        self._t.stop()
        self._p.stop()
        self._tmp.cleanup()
        return False


def _stacca() -> None:
    lg = logging.getLogger("clodia-tools")
    for h in list(lg.handlers):
        lg.removeHandler(h)
        h.close()


class SourceTests(unittest.TestCase):
    def tearDown(self) -> None:
        _stacca()

    def test_default_resta_l_agent_server(self) -> None:
        """Nessun chiamante esistente cambia comportamento."""
        with _Datadir() as d:
            (d / "logs").mkdir()
            (d / "logs" / "agent-server.log").write_text("riga di prova\n")
            out = logs.tail(10)
        self.assertEqual(out["lines"], ["riga di prova"])
        self.assertTrue(out["file"].endswith("agent-server.log"))

    def test_il_gateway_e_una_sorgente_leggibile(self) -> None:
        with _Datadir() as d:
            (d / "logs").mkdir()
            (d / "logs" / "clodia-tools.log").write_text("compartimento spawn · x\n")
            out = logs.tail(10, source="gateway")
        self.assertEqual(out["lines"], ["compartimento spawn · x"])

    def test_una_sorgente_sconosciuta_non_ripiega_in_silenzio(self) -> None:
        """Ripiegare sull'agent-server davanti a un refuso darebbe una risposta
        plausibile alla domanda sbagliata: chi diagnostica crederebbe di aver
        guardato il gateway."""
        with _Datadir():
            with self.assertRaises(ValueError):
                logs.tail(10, source="gatewey")

    def test_i_segreti_sono_redatti_anche_qui(self) -> None:
        with _Datadir() as d:
            (d / "logs").mkdir()
            (d / "logs" / "clodia-tools.log").write_text("bearer: ckt1.abcdef\n")
            out = logs.tail(10, source="gateway")
        self.assertNotIn("ckt1.abcdef", out["lines"][0])


class HandlerTests(unittest.TestCase):
    def tearDown(self) -> None:
        _stacca()

    def test_un_warning_del_gateway_finisce_nel_file_e_si_rilegge(self) -> None:
        """La prova end-to-end: la riga che l'issue #382 chiedeva di cercare —
        e che nessuno poteva vedere — ora si legge con un verbo."""
        with _Datadir():
            logs.attach_gateway_file_log()
            logging.getLogger("clodia-tools").warning(
                "compartimento spawn · clodia leggerebbe SEAL-2/segreto")
            out = logs.tail(50, source="gateway")
        self.assertTrue(any("compartimento spawn" in r for r in out["lines"]),
                        out["lines"])

    def test_il_filtro_di_livello_funziona_sulle_righe_scritte_da_noi(self) -> None:
        """Il formato del nostro handler e il filtro di `tail` devono combaciare:
        se non lo fanno, `level="WARNING"` risponde «nessuna riga» su un file
        che ne è pieno — e sembra che non sia successo niente."""
        with _Datadir():
            logs.attach_gateway_file_log()
            lg = logging.getLogger("clodia-tools")
            lg.info("rumore di fondo")
            lg.warning("compartimento spawn · eccomi")
            out = logs.tail(50, level="WARNING", source="gateway")
        self.assertEqual(len(out["lines"]), 1, out["lines"])
        self.assertIn("eccomi", out["lines"][0])

    def test_chiamarlo_due_volte_non_duplica_le_righe(self) -> None:
        with _Datadir():
            logs.attach_gateway_file_log()
            logs.attach_gateway_file_log()
            logging.getLogger("clodia-tools").warning("una volta sola")
            out = logs.tail(50, source="gateway")
        self.assertEqual(sum("una volta sola" in r for r in out["lines"]), 1,
                         out["lines"])

    def test_l_avvio_del_gateway_lo_aggancia(self) -> None:
        """Senza questo controllo tutto il resto potrebbe essere codice morto:
        gli altri test chiamano `attach_gateway_file_log` a mano, e il processo
        vero no. `run_http` è l'unico entry point (cli.py --http)."""
        import inspect

        from .. import http_app
        self.assertIn("attach_gateway_file_log",
                      inspect.getsource(http_app.run_http))

    def test_il_verbo_espone_la_sorgente(self) -> None:
        """Il parametro deve arrivare fino allo schema del tool, se no il
        gateway sa leggere il proprio log e nessun agente può chiederglielo."""
        from .. import main
        tool = next(t for t in main._LOGS_TOOLS if t.name == "logs.tail")
        self.assertIn("gateway",
                      tool.inputSchema["properties"]["source"]["enum"])

    def test_una_datadir_non_scrivibile_non_ferma_il_gateway(self) -> None:
        """Il logging è diagnostica, non funzione: se il volume è read-only il
        gateway parte lo stesso e continua a scrivere su stdout."""
        with _Datadir():
            with patch.object(logs, "_log_file",
                              side_effect=OSError("read-only file system")):
                self.assertIsNone(logs.attach_gateway_file_log())


if __name__ == "__main__":
    unittest.main()

"""Il gateway non serve niente se l'uid di sandbox legge i suoi 0600 (#544).

Due coppie di controlli, e nessuna delle due si può superare per caso:

1. il **verdetto**: con un sentinella leggibile il self-check dice no, con un
   permesso negato dice sì — e la stessa coppia, un gradino sopra, decide se
   `run_http` arriva a `uvicorn.run` o solleva `SystemExit`;
2. il **soggetto**: il probe deve girare con l'uid che gli spawn usano
   davvero. Un probe lanciato con un uid inventato (o con quello del gateway)
   risponderebbe a una domanda che non è questa, e un verde così vale zero.
"""
from __future__ import annotations

import logging
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import http_app, isolation


class _Done:
    """Esito di un figlio del probe: 0 letto, 3 negato, altro inconcludente."""

    def __init__(self, returncode: int) -> None:
        self.returncode = returncode


class _Runner:
    """`subprocess.run` finto che registra argv e privilegi richiesti."""

    def __init__(self, returncode: int = 3) -> None:
        self.returncode = returncode
        self.calls: list[dict] = []

    def __call__(self, argv, **kw):
        self.calls.append({"argv": argv, **kw})
        return _Done(self.returncode)


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "vault").mkdir()
        self.addCleanup(self.tmp.cleanup)
        env = patch.dict(os.environ, {
            "CLODIA_VAULT_DIR": str(self.root / "vault"),
            "CLODIA_DATA": str(self.root),
            "CLODIA_TOOLS_STATE_DIR": "",
            "CLODIA_AGENT_SANDBOX_UID": "60123",
            "CLODIA_ISOLATION_SELFCHECK": "",
        })
        env.start()
        self.addCleanup(env.stop)
        # Il self-check pretende root per poter scendere di uid: qui si fa
        # finta, perché ciò che si misura è la DECISIONE, non il kernel.
        root_euid = patch.object(isolation.os, "geteuid", return_value=0)
        root_euid.start()
        self.addCleanup(root_euid.stop)


class VerdettoTests(_Base):
    def test_un_sentinella_leggibile_e_assenza_di_isolamento(self):
        runner = _Runner(returncode=0)
        problema = isolation.selfcheck(runner=runner)
        self.assertIn("could read", problema)
        self.assertIn("clodia-platform#544", problema)

    def test_un_permesso_negato_e_isolamento_presente(self):
        self.assertEqual(isolation.selfcheck(runner=_Runner(returncode=3)), "")

    def test_un_esito_inconcludente_vale_come_non_isolato(self):
        problema = isolation.selfcheck(runner=_Runner(returncode=4))
        self.assertIn("inconclusive", problema)

    def test_il_sentinella_e_davvero_0600_e_dentro_la_dir_sorvegliata(self):
        visto = {}

        class _Guarda(_Runner):
            def __call__(self, argv, **kw):
                p = Path(argv[-1])
                visto["mode"] = p.stat().st_mode & 0o777
                return super().__call__(argv, **kw)
        runner = _Guarda(returncode=3)
        isolation.selfcheck(runner=runner)
        percorso = Path(runner.calls[0]["argv"][-1])
        self.assertTrue(percorso.is_relative_to((self.root / "vault").resolve()))
        self.assertEqual(visto["mode"], 0o600)
        # The sentinel is removed after the probe (review of #371): it must
        # not stay in the vault or end up in backups.
        self.assertFalse(percorso.exists())
        self.assertFalse(percorso.parent.exists())

    def test_il_probe_vero_legge_davvero_il_sentinella(self):
        """Niente runner finto: il figlio parte sul serio e, senza privilegi da
        lasciar cadere, gira con l'utente del gateway — che il file 0600 lo
        legge. È la stessa forma del guasto di terra, e dimostra che il probe
        non è una funzione che risponde sempre «negato»."""
        problema = isolation.denied(self.root / "vault", None)
        self.assertIn("could read", problema)

    @unittest.skipUnless(os.geteuid() == 0, "serve root per scendere di uid")
    def test_il_probe_vero_riceve_un_permesso_negato_su_un_filesystem_vero(self):
        problema = isolation.denied(self.root / "vault", (65534, 65534))
        self.assertEqual(problema, "")

    def test_senza_root_non_c_e_niente_da_dimostrare(self):
        with patch.object(isolation.os, "geteuid", return_value=1000):
            problema = isolation.selfcheck(runner=_Runner(returncode=3))
        self.assertIn("non è root", problema)

    def test_una_directory_sorvegliata_che_non_esiste_non_si_prova(self):
        """La vault c'è, lo stato e i segreti legacy no: un probe su una
        directory inesistente la CREEREBBE, e misurerebbe il volume sbagliato."""
        self.assertEqual(isolation.guarded_dirs(), [self.root / "vault"])


class SoggettoTests(_Base):
    def test_il_probe_gira_con_l_uid_degli_spawn(self):
        runner = _Runner(returncode=3)
        isolation.selfcheck(runner=runner)
        self.assertEqual(len(runner.calls), 1)
        self.assertEqual(runner.calls[0]["user"], 60123)
        self.assertEqual(runner.calls[0]["extra_groups"], [])

    def test_senza_la_variabile_degli_spawn_vale_il_pool_dei_servizi(self):
        with patch.dict(os.environ, {"CLODIA_AGENT_SANDBOX_UID": "",
                                     "CLODIA_SERVICE_UID_BASE": "61000"}):
            self.assertEqual(isolation.probe_uid(), 61000)

    def test_senza_niente_vale_la_base_del_pool_non_zero(self):
        with patch.dict(os.environ, {"CLODIA_AGENT_SANDBOX_UID": "",
                                     "CLODIA_SERVICE_UID_BASE": ""}):
            self.assertEqual(isolation.probe_uid(), isolation.DEFAULT_SANDBOX_UID)
        self.assertGreater(isolation.DEFAULT_SANDBOX_UID, 0)

    def test_un_uid_che_coincide_col_gateway_non_e_una_prova(self):
        """Se il probe girasse con l'utente del gateway leggerebbe tutto, o
        (peggio) con root risponderebbe sempre «leggibile»: in entrambi i casi
        la risposta non parla dell'isolamento degli spawn."""
        with patch.dict(os.environ, {"CLODIA_AGENT_SANDBOX_UID": "0",
                                     "CLODIA_SERVICE_UID_BASE": "0"}), \
                patch.object(isolation, "DEFAULT_SANDBOX_UID", 0):
            problema = isolation.selfcheck(runner=_Runner(returncode=3))
        self.assertIn("CLODIA_AGENT_SANDBOX_UID", problema)

    def test_il_probe_dei_servizi_di_pack_e_lo_stesso(self):
        """Una sola implementazione: `services.launch` delega a questo modulo.
        Due copie darebbero due risposte il giorno in cui una viene corretta."""
        from .services import launch
        with patch.object(isolation, "denied", return_value="") as finto:
            launch.isolation_probe((60001, 60201))
        self.assertEqual(finto.call_args.args[1], (60001, 60201))


class ModalitaTests(_Base):
    def test_il_default_e_enforce(self):
        self.assertEqual(isolation.mode(), "enforce")
        self.assertEqual(isolation.DEFAULT_MODE, "enforce")

    def test_un_valore_sconosciuto_non_disattiva_il_controllo(self):
        with patch.dict(os.environ, {"CLODIA_ISOLATION_SELFCHECK": "enfrce"}):
            with self.assertLogs("clodia-tools.refmon", logging.WARNING):
                self.assertEqual(isolation.mode(), "enforce")

    def test_warn_logga_critical_e_lascia_partire(self):
        with patch.dict(os.environ, {"CLODIA_ISOLATION_SELFCHECK": "warn"}):
            with self.assertLogs("clodia-tools.refmon", logging.CRITICAL) as log:
                isolation.check_at_boot(runner=_Runner(returncode=0))
        self.assertTrue(any("ISOLAMENTO ASSENTE" in r.getMessage()
                            for r in log.records))

    def test_off_non_prova_niente_ma_lo_dichiara(self):
        runner = _Runner(returncode=0)
        with patch.dict(os.environ, {"CLODIA_ISOLATION_SELFCHECK": "off"}):
            with self.assertLogs("clodia-tools.refmon", logging.WARNING):
                isolation.check_at_boot(runner=runner)
        self.assertEqual(runner.calls, [])

    def test_un_probe_che_esplode_e_un_no(self):
        def boom(argv, **kw):
            raise OSError("nessun interprete")

        with self.assertRaises(SystemExit):
            isolation.check_at_boot(runner=boom)


class AvvioDelGatewayTests(_Base):
    """La coppia che conta: leggibile → rifiuta, negato → parte."""

    def _run_http(self, problema: str):
        chiamate: list = []
        with patch.object(http_app, "build_app", return_value="app"), \
                patch("uvicorn.run", lambda app, **kw: chiamate.append(app)), \
                patch("server.tools.logs.attach_gateway_file_log",
                      return_value=""), \
                patch("server.main.log_spawn_compartment_mode"), \
                patch.object(isolation, "selfcheck", return_value=problema):
            try:
                http_app.run_http(port=0)
            except SystemExit as exc:
                return chiamate, exc
        return chiamate, None

    def test_un_sentinella_leggibile_rifiuta_l_avvio(self):
        with self.assertLogs("clodia-tools.refmon", logging.CRITICAL):
            chiamate, exc = self._run_http("uid 60123 could read a 0600 file")
        self.assertIsNotNone(exc, "il gateway è partito con la vault leggibile")
        self.assertIn("544", str(exc))
        self.assertEqual(chiamate, [], "uvicorn è stato avviato lo stesso")

    def test_un_permesso_negato_lascia_partire_il_gateway(self):
        chiamate, exc = self._run_http("")
        self.assertIsNone(exc)
        self.assertEqual(chiamate, ["app"])

    def test_il_rifiuto_e_scritto_dopo_l_aggancio_del_log_su_file(self):
        """Un CRITICAL che esce solo su stdout è fuori portata di chi deve
        diagnosticarlo da dentro la colonia (#382): sarebbe un gateway che non
        parte e non dice perché."""
        import ast
        import inspect
        import textwrap

        albero = ast.parse(textwrap.dedent(inspect.getsource(http_app.run_http)))
        righe: dict[str, int] = {}
        for nodo in ast.walk(albero):
            if isinstance(nodo, ast.Call) and isinstance(nodo.func, (ast.Name, ast.Attribute)):
                nome = (nodo.func.attr if isinstance(nodo.func, ast.Attribute)
                        else nodo.func.id)
                righe.setdefault(nome, nodo.lineno)
        self.assertIn("check_at_boot", righe)
        self.assertLess(righe["attach_gateway_file_log"], righe["check_at_boot"])
        self.assertLess(righe["check_at_boot"], righe["run"],
                        "il self-check deve precedere uvicorn.run")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

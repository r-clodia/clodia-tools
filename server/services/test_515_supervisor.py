"""clodia-platform#515 — il gateway supervisiona i servizi dei pack.

I test del ciclo di vita avviano PROCESSI VERI: un servizio che non parte
davvero, non muore davvero e non viene riavviato davvero non è un servizio
supervisionato, e un mock di `Popen` direbbe di sì a qualunque cosa. Il tempo
invece è finto (`clock` iniettato), perché un backoff di 5 secondi misurato
dormendo renderebbe la suite lenta e incerta sul risultato.
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from ..connectors.manifest import Service
from . import launch
from .supervisor import Supervisor

#: Resta vivo e dice di esserlo scrivendo nella PROPRIA state dir: è anche la
#: prova che la variabile che riceve punta a una directory scrivibile.
_SLEEPER = (
    "import os,time;"
    "open(os.path.join(os.environ['CLODIA_SERVICE_STATE_DIR'],'alive'),'a')"
    ".write('x');"
    "time.sleep(300)"
)

#: Scrive e muore male: serve a provare il riavvio e la persistenza dello stato.
_CRASHER = (
    "import os,sys;"
    "open(os.path.join(os.environ['CLODIA_SERVICE_STATE_DIR'],'runs'),'a')"
    ".write('x');"
    "sys.exit(3)"
)


class _FakeProc:
    """Un `Popen` che non è un processo: per i casi in cui si verifica COME si
    chiama Popen, non che cosa fa il figlio."""

    pid = 4242

    def poll(self):
        return None


class _Clock:
    """Tempo finto e monotono: avanza solo quando lo dice il test."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.data = Path(self.tmp.name)
        env = patch.dict(os.environ, {"CLODIA_DATA": str(self.data),
                                      "CLODIA_SERVICE_ISOLATION": "off"})
        env.start()
        self.addCleanup(env.stop)
        self.clock = _Clock()
        self.declared: list[Service] = []

    def service(self, script: str = _SLEEPER, **kwargs) -> Service:
        fields = {"name": "listener", "pack": "demo-pack", "namespace": "demo",
                  "command": (sys.executable, "-c", script)}
        fields.update(kwargs)
        return Service(**fields)

    def supervisor(self) -> Supervisor:
        # The isolation self-check (#544) is covered by its own tests; here the
        # filesystem is taken to enforce permission bits.
        sup = Supervisor(lambda: list(self.declared), clock=self.clock,
                         isolation_probe=lambda privs: "")
        self.addCleanup(sup.stop_all)
        return sup

    def wait_for(self, path: Path, timeout: float = 10.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                return
            time.sleep(0.02)
        self.fail(f"{path} non è comparso entro {timeout}s")

    def wait_exit(self, sup: Supervisor, timeout: float = 10.0) -> None:
        """Aspetta che il figlio sia uscito, senza dormire a caso."""
        entry = next(iter(sup._entries.values()))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if entry.proc is None or entry.proc.poll() is not None:
                return
            time.sleep(0.02)
        self.fail("il servizio non è uscito entro il tempo previsto")


class LifecycleTests(_Base):
    """Avviato al boot, riavviato dopo un crash, fermato alla rimozione."""

    def test_a_declared_service_is_started_and_runs_with_its_own_state_dir(self):
        self.declared = [self.service()]
        sup = self.supervisor()
        sup.reconcile()
        self.wait_for(self.data / "services/demo-pack/listener/alive")
        row = sup.snapshot()[0]
        self.assertEqual(row["state"], "running")
        self.assertIsNotNone(row["pid"])
        self.assertEqual(row["state_dir"],
                         str(self.data / "services/demo-pack/listener"))

    def test_a_service_the_pack_no_longer_declares_is_stopped(self):
        self.declared = [self.service()]
        sup = self.supervisor()
        sup.reconcile()
        self.wait_for(self.data / "services/demo-pack/listener/alive")
        pid = sup.snapshot()[0]["pid"]
        self.declared = []          # il pack è stato rimosso
        sup.reconcile()
        self.assertEqual(sup.snapshot(), [])
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_a_crash_is_restarted_only_after_the_declared_backoff(self):
        self.declared = [self.service(_CRASHER, restart="on-failure",
                                      backoff_seconds=5)]
        sup = self.supervisor()
        sup.reconcile()
        self.wait_exit(sup)
        sup.reconcile()                      # raccoglie l'uscita
        row = sup.snapshot()[0]
        self.assertEqual(row["state"], "backoff")
        self.assertEqual(row["last_exit"], 3)
        self.assertEqual(row["starts"], 1)
        self.clock.advance(4)
        sup.reconcile()
        self.assertEqual(sup.snapshot()[0]["starts"], 1)   # non prima del tempo
        self.clock.advance(2)
        sup.reconcile()
        self.assertEqual(sup.snapshot()[0]["starts"], 2)

    def test_the_backoff_grows_with_the_consecutive_failures(self):
        self.declared = [self.service(_CRASHER, restart="always",
                                      backoff_seconds=5)]
        sup = self.supervisor()
        sup.reconcile()
        self.wait_exit(sup)
        sup.reconcile()
        self.clock.advance(5)
        sup.reconcile()                      # secondo avvio
        self.wait_exit(sup)
        sup.reconcile()
        self.clock.advance(5)                # il primo backoff non basta più
        sup.reconcile()
        self.assertEqual(sup.snapshot()[0]["starts"], 2)
        self.clock.advance(5)
        sup.reconcile()
        self.assertEqual(sup.snapshot()[0]["starts"], 3)

    def test_restart_never_is_not_restarted(self):
        self.declared = [self.service(_CRASHER, restart="never")]
        sup = self.supervisor()
        sup.reconcile()
        self.wait_exit(sup)
        sup.reconcile()
        self.assertEqual(sup.snapshot()[0]["state"], "exited")
        self.clock.advance(3600)
        sup.reconcile()
        self.assertEqual(sup.snapshot()[0]["starts"], 1)

    def test_the_state_dir_survives_a_restart(self):
        """Il criterio «lo stato sopravvive» nella sola forma verificabile da
        un test: la directory è la stessa fra due vite del processo."""
        self.declared = [self.service(_CRASHER, restart="always",
                                      backoff_seconds=1)]
        sup = self.supervisor()
        sup.reconcile()
        self.wait_exit(sup)
        sup.reconcile()
        self.clock.advance(1)
        sup.reconcile()
        self.wait_exit(sup)
        runs = self.data / "services/demo-pack/listener/runs"
        self.assertEqual(runs.read_text(), "xx")


class EnvironmentTests(_Base):
    """L'ambiente è costruito da zero, non filtrato."""

    GATEWAY_ONLY = {"CLODIA_ORCHESTRATOR_SECRET": "bootstrap",
                    "CLODIA_VAULT_DIR": "/vault",
                    "CLODIA_TOOLS_STATE_DIR": "/stato",
                    "AWS_SECRET_ACCESS_KEY": "zzz"}

    def test_the_gateway_environment_does_not_reach_the_service(self):
        with patch.dict(os.environ, self.GATEWAY_ONLY):
            env = launch.build_env(self.service())
        for leaked in self.GATEWAY_ONLY:
            self.assertNotIn(leaked, env)
        self.assertLessEqual(
            set(env),
            {"PATH", "PYTHONPATH", "HOME", "CLODIA_SERVICE_STATE_DIR",
             "CLODIA_SERVICE_PACK", "CLODIA_SERVICE_NAME"})

    def test_the_path_has_no_empty_entry(self):
        """Un elemento vuoto in PATH significa «la directory corrente»: il
        servizio eseguirebbe un binario piantato nella sua state dir."""
        env = launch.build_env(self.service())
        self.assertTrue(env["PATH"])
        self.assertNotIn("", env["PATH"].split(os.pathsep))

    def test_only_the_declared_credential_is_handed_over(self):
        bundles = {"demo_token": {"token": "s3gr3t0"},
                   "other_token": {"token": "non-tua"}}
        svc = self.service(credentials=("demo_token",))
        with patch.object(launch.vault, "read_internal", bundles.__getitem__):
            env = launch.build_env(svc)
        self.assertIn("CLODIA_CREDENTIAL_DEMO_TOKEN", env)
        self.assertNotIn("CLODIA_CREDENTIAL_OTHER_TOKEN", env)
        self.assertIn("s3gr3t0", env["CLODIA_CREDENTIAL_DEMO_TOKEN"])

    def test_a_missing_credential_blocks_the_service_without_echoing_it(self):
        self.declared = [self.service(credentials=("demo_token",))]
        sup = self.supervisor()
        with patch.object(launch.vault, "read_internal",
                          side_effect=KeyError("demo_token")):
            sup.reconcile()
        row = sup.snapshot()[0]
        self.assertEqual(row["state"], "blocked")
        self.assertIn("demo_token", row["last_error"])
        self.assertIsNone(row["pid"])
        self.assertFalse((self.data / "services/demo-pack/listener/alive").exists())


class IsolationTests(_Base):
    """Senza isolamento non si parte: nessun fallback all'utente del gateway."""

    def test_without_root_and_without_an_explicit_off_nothing_starts(self):
        self.declared = [self.service()]
        sup = self.supervisor()
        with patch.dict(os.environ, {"CLODIA_SERVICE_ISOLATION": ""}), \
             patch.object(launch.os, "geteuid", return_value=1000):
            sup.reconcile()
        row = sup.snapshot()[0]
        self.assertEqual(row["state"], "blocked")
        self.assertIn("root", row["last_error"])
        self.assertIsNone(row["pid"])
        self.assertFalse((self.data / "services/demo-pack/listener/alive").exists())

    def test_two_services_never_share_a_uid(self):
        first = self.service(name="listener")
        second = self.service(name="poller")
        with patch.dict(os.environ, {"CLODIA_SERVICE_ISOLATION": "",
                                     "CLODIA_SERVICE_UID_SPAN": "2"}), \
             patch.object(launch.os, "geteuid", return_value=0):
            uid_a, gid_a = launch.privileges(first)
            uid_b, gid_b = launch.privileges(second, {uid_a})
        self.assertNotEqual(uid_a, uid_b)
        self.assertEqual(gid_a, gid_b)          # stesso pack, stesso gruppo
        self.assertNotIn(0, {uid_a, uid_b, gid_a})

    def test_the_uid_of_a_service_is_stable_across_restarts(self):
        svc = self.service()
        with patch.dict(os.environ, {"CLODIA_SERVICE_ISOLATION": ""}), \
             patch.object(launch.os, "geteuid", return_value=0):
            self.assertEqual(launch.privileges(svc), launch.privileges(svc))

    def test_a_leftover_of_a_previous_life_is_killed_before_starting(self):
        """Dopo un SIGKILL del gateway i figli restano orfani e tengono la
        porta: il secondo avvio morirebbe con «address already in use», e il
        guasto sembrerebbe del pack."""
        self.declared = [self.service()]
        sup = self.supervisor()
        visti: list[int] = []
        with patch.dict(os.environ, {"CLODIA_SERVICE_ISOLATION": ""}), \
             patch.object(launch.os, "geteuid", return_value=0), \
             patch.object(launch.os, "chown"), \
             patch.object(launch, "kill_leftovers", visti.append), \
             patch("server.services.supervisor.subprocess.Popen",
                   lambda argv, **kw: _FakeProc()):
            sup.reconcile()
        self.assertEqual(len(visti), 1)
        self.assertGreater(visti[0], 0)
        sup._entries.clear()

    def test_kill_leftovers_of_an_unused_uid_kills_nothing(self):
        self.assertEqual(launch.kill_leftovers(None), 0)
        self.assertEqual(launch.kill_leftovers(2 ** 30), 0)

    def test_the_child_drops_privileges_and_supplementary_groups(self):
        self.declared = [self.service()]
        sup = self.supervisor()
        captured: dict = {}

        def _popen(argv, **kwargs):
            captured.update(kwargs)
            return _FakeProc()

        with patch.dict(os.environ, {"CLODIA_SERVICE_ISOLATION": ""}), \
             patch.object(launch.os, "geteuid", return_value=0), \
             patch.object(launch.os, "chown"), \
             patch.object(launch, "kill_leftovers", return_value=0), \
             patch("server.services.supervisor.subprocess.Popen", _popen):
            sup.reconcile()
        self.assertEqual(sup.snapshot()[0]["state"], "running")
        self.assertGreater(captured["user"], 0)
        self.assertGreater(captured["group"], 0)
        self.assertEqual(captured["extra_groups"], [])
        self.assertTrue(sup.snapshot()[0]["isolated"])
        sup._entries.clear()           # il finto processo non va fermato davvero


class HealthTests(_Base):
    def test_a_health_target_outside_loopback_refuses_the_service(self):
        self.declared = [self.service(health_kind="http",
                                      health_target="http://example.com/health")]
        sup = self.supervisor()
        sup.reconcile()
        row = sup.snapshot()[0]
        self.assertEqual(row["state"], "blocked")
        self.assertIn("loopback", row["last_error"])
        self.assertIsNone(row["pid"])

    def test_a_loopback_target_is_accepted(self):
        self.declared = [self.service(health_kind="http",
                                      health_target="http://127.0.0.1:8099/health",
                                      health_interval=30)]
        sup = self.supervisor()
        sup.reconcile()
        self.assertEqual(sup.snapshot()[0]["state"], "running")

    def test_two_failed_probes_restart_the_service(self):
        self.declared = [self.service(health_kind="tcp",
                                      health_target="127.0.0.1:9",
                                      health_interval=30,
                                      restart="always", backoff_seconds=5)]
        sup = self.supervisor()
        with patch.object(launch, "probe", return_value=(False, "health tcp: rifiutata")):
            sup.reconcile()
            self.assertEqual(sup.snapshot()[0]["state"], "running")
            self.clock.advance(31)
            sup.reconcile()                       # primo fallimento: si annota
            self.assertEqual(sup.snapshot()[0]["health"], "failing")
            self.assertEqual(sup.snapshot()[0]["state"], "running")
            self.clock.advance(31)
            sup.reconcile()                       # secondo: si riavvia
        row = sup.snapshot()[0]
        self.assertEqual(row["state"], "backoff")
        self.assertIn("health", row["last_error"])

    def test_a_probe_never_raises(self):
        svc = self.service(health_kind="tcp", health_target="127.0.0.1:1")
        ok, why = launch.probe(svc)
        self.assertFalse(ok)
        self.assertIn("health tcp", why)


class DeclaredFromTheRegistryTests(_Base):
    """I servizi arrivano dal registry dei connettori, non da una lettura
    nostra dei `pack.yaml`: un pack rifiutato non ha servizi che girano."""

    def test_the_default_source_is_the_connector_registry(self):
        from ..connectors import manifest as M
        from .supervisor import _declared_services
        pack = {"connectors": [{
            "id": "demo", "manifest_version": 1, "namespace": "demo",
            "schemes": [{"scheme": "demo", "direction": "egress"}],
            "services": [{"name": "listener", "command": ["python", "-m", "x"]}],
        }]}
        registry = M.build_registry({"demo-pack": pack}, reserved=())
        with patch("server.connectors.resolved.registry", return_value=registry):
            services = _declared_services()
        self.assertEqual([(s.pack, s.name) for s in services],
                         [("demo-pack", "listener")])

    def test_an_unreadable_registry_is_unknown_instead_of_raising(self):
        """None, not []: an empty set would stop every running service."""
        from .supervisor import _declared_services
        with patch("server.connectors.resolved.registry",
                   side_effect=RuntimeError("volume illeggibile")):
            self.assertIsNone(_declared_services())


if __name__ == "__main__":
    unittest.main()

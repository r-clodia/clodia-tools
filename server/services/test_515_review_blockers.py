"""Review blockers of clodia-tools #362 (clodia-platform#515, #544).

1. a service may only receive credentials of its OWN namespace, never a core
   credential — checked at manifest load and again at launch;
2. before any isolated service starts, the gateway proves that the service uid
   cannot read a 0600 file of the gateway; if it can (OrbStack virtiofs on terra,
   #544) nothing starts;
3. `workdir` is confined to the pack directory or the service state dir.

Plus the review notes: log capped and opened without following symlinks,
environment built once per process start, a transient registry error does not
stop running services, TCP listeners outside loopback are refused.
"""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ..connectors import manifest as M
from ..connectors.manifest import Service
from . import launch
from .supervisor import Supervisor


class _FakeProc:
    pid = 4242

    def poll(self):
        return None


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


_SLEEPER = "import time; time.sleep(300)"

#: Credentials a pack with namespace `evil` must never receive.
FOREIGN = ("github_pat", "app_google_oauth", "google_x", "telegram_bot_token",
           "provider_claude_team", "other_token")


def _pack(credentials=(), workdir=None, namespace="evil") -> dict:
    service = {"name": "listener", "command": ["python", "-m", "x"],
               "credentials": list(credentials)}
    if workdir is not None:
        service["workdir"] = workdir
    return {"connectors": [{
        "id": "evil", "manifest_version": 1, "namespace": namespace,
        "schemes": [{"scheme": namespace, "direction": "egress"}],
        "services": [service],
    }]}


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
        self.declared: list[Service] | None = []

    def service(self, **kwargs) -> Service:
        fields = {"name": "listener", "pack": "demo-pack", "namespace": "demo",
                  "command": (sys.executable, "-c", _SLEEPER)}
        fields.update(kwargs)
        return Service(**fields)

    def supervisor(self, **kwargs) -> Supervisor:
        sup = Supervisor(lambda: self.declared if self.declared is None
                         else list(self.declared), clock=self.clock, **kwargs)
        self.addCleanup(sup.stop_all)
        return sup


# --------------------------------------------------------------------------
# 1. credentials
# --------------------------------------------------------------------------
class CredentialNamespaceAtLoadTests(_Base):
    def test_foreign_and_core_credentials_refuse_the_manifest(self):
        for name in FOREIGN:
            with self.subTest(credential=name):
                with self.assertRaises(M.ManifestError) as caught:
                    M.load_manifest(_pack([name]), pack="evil-pack")
                self.assertIn(name, str(caught.exception))

    def test_a_refused_pack_has_no_service_in_the_registry(self):
        """The instance registry drops the offending pack, keeps the others."""
        from ..connectors import resolved
        good = _pack(["good_token"], namespace="good")
        registry, dropped, _ = resolved._build_isolated(
            {}, {"evil-pack": _pack(FOREIGN), "good-pack": good})
        self.assertEqual([(s.pack, s.credentials) for s in registry.services()],
                         [("good-pack", ("good_token",))])
        self.assertTrue(any("evil-pack" in d for d in dropped))

    def test_own_namespace_credentials_are_accepted_and_carry_the_namespace(self):
        services = M.parse_services(_pack(["evil", "evil_token"]), pack="evil-pack")
        self.assertEqual(services[0].credentials, ("evil", "evil_token"))
        self.assertEqual(services[0].namespace, "evil")


class CredentialNamespaceAtLaunchTests(_Base):
    """Defence in depth: a `Service` built without the manifest (or a parser
    regression) still never reaches a foreign vault entry."""

    def test_nothing_is_read_from_the_vault_for_a_foreign_credential(self):
        reads: list[str] = []
        for name in FOREIGN:
            with self.subTest(credential=name), \
                 patch.object(launch.vault, "read_internal",
                              lambda n: reads.append(n) or {"token": "x"}):
                svc = self.service(namespace="evil", credentials=(name,))
                with self.assertRaises(launch.ServiceRefused):
                    launch.build_env(svc)
        self.assertEqual(reads, [])

    def test_a_service_without_a_namespace_gets_no_credential(self):
        svc = self.service(namespace="", credentials=("demo_token",))
        reads: list[str] = []
        with patch.object(launch.vault, "read_internal",
                          lambda n: reads.append(n) or {"token": "x"}):
            with self.assertRaises(launch.ServiceRefused):
                launch.build_env(svc)
        self.assertEqual(reads, [])

    def test_the_supervisor_blocks_it_and_injects_nothing(self):
        self.declared = [self.service(namespace="evil",
                                      credentials=("github_pat",))]
        sup = self.supervisor()
        popen: list = []
        reads: list[str] = []
        with patch.object(launch.vault, "read_internal",
                          lambda n: reads.append(n) or {"token": "x"}), \
             patch("server.services.supervisor.subprocess.Popen",
                   lambda argv, **kw: popen.append(kw) or _FakeProc()):
            sup.reconcile()
        row = sup.snapshot()[0]
        self.assertEqual(row["state"], "blocked")
        self.assertIn("github_pat", row["last_error"])
        self.assertEqual(popen, [])
        self.assertEqual(reads, [])
        self.assertFalse(any("CLODIA_CREDENTIAL" in k
                             for kw in popen for k in kw.get("env", {})))


# --------------------------------------------------------------------------
# 2. isolation self-check (#544)
# --------------------------------------------------------------------------
class IsolationProbeTests(_Base):
    def _as_root(self):
        return [patch.dict(os.environ, {"CLODIA_SERVICE_ISOLATION": ""}),
                patch.object(launch.os, "geteuid", return_value=0),
                patch.object(launch.os, "chown"),
                patch.object(launch, "kill_leftovers", return_value=0)]

    def test_readable_sentinel_blocks_every_service_and_logs_critical_once(self):
        self.declared = [self.service(name="listener"), self.service(name="poller")]
        probes: list = []
        sup = self.supervisor(
            isolation_probe=lambda privs: probes.append(privs) or "uid could read it")
        popen: list = []
        patches = self._as_root() + [
            patch("server.services.supervisor.subprocess.Popen",
                  lambda argv, **kw: popen.append(kw) or _FakeProc())]
        for p in patches:
            p.start()
        try:
            with self.assertLogs("clodia-tools.services", "CRITICAL") as logs:
                sup.reconcile()
                self.clock.advance(3600)
                sup.reconcile()
        finally:
            for p in reversed(patches):
                p.stop()
        self.assertEqual(popen, [])
        self.assertEqual(len(probes), 1)
        critical = [r for r in logs.records if r.levelname == "CRITICAL"]
        self.assertEqual(len(critical), 1)
        for row in sup.snapshot():
            self.assertEqual(row["state"], "blocked")
            self.assertTrue(row["last_error"].startswith("isolation unavailable"))
            self.assertEqual(row["isolation"], "unavailable")
            self.assertIsNone(row["pid"])
        # nothing was prepared for a service that will not run
        self.assertFalse((self.data / "services/demo-pack/listener").exists())

    def test_an_isolated_filesystem_lets_the_service_start(self):
        self.declared = [self.service()]
        sup = self.supervisor(isolation_probe=lambda privs: "")
        patches = self._as_root() + [
            patch("server.services.supervisor.subprocess.Popen",
                  lambda argv, **kw: _FakeProc())]
        for p in patches:
            p.start()
        try:
            sup.reconcile()
        finally:
            for p in reversed(patches):
                p.stop()
        row = sup.snapshot()[0]
        self.assertEqual(row["state"], "running")
        self.assertEqual(row["isolation"], "ok")
        sup._entries.clear()

    def test_a_probe_that_raises_fails_closed(self):
        self.declared = [self.service()]

        def boom(privs):
            raise OSError("no such interpreter")

        sup = self.supervisor(isolation_probe=boom)
        popen: list = []
        patches = self._as_root() + [
            patch("server.services.supervisor.subprocess.Popen",
                  lambda argv, **kw: popen.append(kw) or _FakeProc())]
        for p in patches:
            p.start()
        try:
            sup.reconcile()
        finally:
            for p in reversed(patches):
                p.stop()
        self.assertEqual(popen, [])
        self.assertEqual(sup.snapshot()[0]["state"], "blocked")

    def test_the_real_probe_reports_a_readable_sentinel(self):
        """Without privileges to drop, the child runs as the gateway user and
        CAN read the sentinel: exactly what virtiofs looks like."""
        problem = launch.isolation_probe(None)
        self.assertIn("could read", problem)
        sentinel = self.data / "services" / ".isolation-probe" / "sentinel"
        self.assertEqual(sentinel.stat().st_mode & 0o777, 0o600)

    def test_the_real_probe_accepts_a_permission_denied(self):
        class _Done:
            returncode = 3
        with patch.object(launch.subprocess, "run", return_value=_Done()):
            self.assertEqual(launch.isolation_probe((60001, 60201)), "")

    def test_an_inconclusive_probe_is_a_problem(self):
        class _Done:
            returncode = 4
        with patch.object(launch.subprocess, "run", return_value=_Done()):
            self.assertNotEqual(launch.isolation_probe((60001, 60201)), "")


# --------------------------------------------------------------------------
# 3. workdir
# --------------------------------------------------------------------------
class WorkdirTests(_Base):
    def test_escaping_workdirs_refuse_the_manifest(self):
        for bad in ("/gateway-state/x", "/datadir/clodia-vault", "../other-pack",
                    "bin/../../x", "~root"):
            with self.subTest(workdir=bad):
                with self.assertRaises(M.ManifestError):
                    M.load_manifest(_pack(workdir=bad), pack="evil-pack")

    def test_a_relative_workdir_inside_the_pack_is_accepted(self):
        services = M.parse_services(_pack(workdir="bin"), pack="evil-pack")
        self.assertEqual(services[0].workdir, "bin")

    def test_a_symlink_out_of_the_pack_is_refused_at_launch(self):
        pack_dir = self.data / "packs" / "demo-pack"
        pack_dir.mkdir(parents=True)
        outside = self.data / "gateway-state"
        outside.mkdir()
        (pack_dir / "out").symlink_to(outside)
        self.declared = [self.service(workdir="out")]
        sup = self.supervisor()
        popen: list = []
        with patch("server.services.supervisor.subprocess.Popen",
                   lambda argv, **kw: popen.append(kw) or _FakeProc()):
            sup.reconcile()
        self.assertEqual(popen, [])
        row = sup.snapshot()[0]
        self.assertEqual(row["state"], "blocked")
        self.assertIn("workdir", row["last_error"])

    def test_an_absolute_workdir_is_refused_at_launch(self):
        svc = self.service(workdir=str(self.data))
        with self.assertRaises(launch.ServiceRefused):
            launch.resolve_workdir(svc)

    def test_workdir_resolves_inside_the_pack_or_defaults_to_the_state_dir(self):
        (self.data / "packs" / "demo-pack" / "bin").mkdir(parents=True)
        self.assertEqual(launch.resolve_workdir(self.service(workdir="bin")),
                         (self.data / "packs/demo-pack/bin").resolve())
        launch.prepare_state_dir(self.service(), None)
        self.assertEqual(launch.resolve_workdir(self.service()),
                         (self.data / "services/demo-pack/listener").resolve())


# --------------------------------------------------------------------------
# notes
# --------------------------------------------------------------------------
class LogTests(_Base):
    def test_a_symlinked_log_is_never_followed(self):
        """The state dir belongs to the service uid; the log is opened by root.
        Following a symlink planted there would let the service append to any
        file of the gateway."""
        state = launch.prepare_state_dir(self.service(), None)
        victim = self.data / "victim"
        victim.write_text("intact")
        (state / "service.log").symlink_to(victim)
        with self.assertRaises(launch.ServiceRefused):
            launch.open_log(state / "service.log")
        self.assertEqual(victim.read_text(), "intact")

    def test_the_log_is_rotated_past_the_cap(self):
        state = launch.prepare_state_dir(self.service(), None)
        log = state / "service.log"
        log.write_bytes(b"a" * 100 + b"TAIL")
        with patch.object(launch, "LOG_MAX_BYTES", 50):
            self.assertTrue(launch.rotate_log(log))
        self.assertEqual(log.stat().st_size, 0)
        kept = (state / "service.log.1").read_bytes()
        self.assertLessEqual(len(kept), 50)
        self.assertTrue(kept.endswith(b"TAIL"))

    def test_a_small_log_is_left_alone(self):
        state = launch.prepare_state_dir(self.service(), None)
        (state / "service.log").write_bytes(b"x")
        self.assertFalse(launch.rotate_log(state / "service.log"))


class EnvCacheTests(_Base):
    def test_command_health_probes_do_not_read_the_vault_again(self):
        self.declared = [self.service(credentials=("demo_token",),
                                      health_kind="command",
                                      health_target="true",
                                      health_interval=1)]
        reads: list[str] = []
        sup = self.supervisor()
        with patch.object(launch.vault, "read_internal",
                          lambda n: reads.append(n) or {"t": "x"}):
            sup.reconcile()
            for _ in range(3):
                self.clock.advance(2)
                sup.reconcile()
        self.assertEqual(sup.snapshot()[0]["health"], "ok")
        self.assertEqual(reads, ["demo_token"])


class RegistryErrorTests(_Base):
    def test_a_transient_registry_error_keeps_the_running_services(self):
        self.declared = [self.service()]
        sup = self.supervisor()
        sup.reconcile()
        pid = sup.snapshot()[0]["pid"]
        self.assertIsNotNone(pid)
        self.declared = None                     # registry unreadable this round
        sup.reconcile()
        row = sup.snapshot()[0]
        self.assertEqual(row["state"], "running")
        self.assertEqual(row["pid"], pid)
        os.kill(pid, 0)                          # still alive

    def test_the_default_source_reports_an_error_as_unknown(self):
        from .supervisor import _declared_services
        with patch("server.connectors.resolved.registry",
                   side_effect=RuntimeError("volume unreadable")):
            self.assertIsNone(_declared_services())


class ListenerTests(_Base):
    TCP = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000 60001        0 1 1\n"
        "   1: 00000000:1F91 00000000:0000 0A 00000000:00000000 00:00000000 00000000 60001        0 2 1\n"
        "   2: 00000000:1F92 00000000:0000 0A 00000000:00000000 00:00000000 00000000 60002        0 3 1\n"
        "   3: 00000000:C350 0100007F:1F90 01 00000000:00000000 00:00000000 00000000 60001        0 4 1\n"
    )
    TCP6 = (
        "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 00000000000000000000000001000000:1F93 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 60001        0 5 1\n"
        "   1: 00000000000000000000000000000000:1F94 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 60001        0 6 1\n"
    )

    def test_only_non_loopback_listeners_of_that_uid_are_reported(self):
        found = launch.exposed_listeners(60001, [self.TCP, self.TCP6])
        self.assertEqual(sorted(found), ["0.0.0.0:8081", "[::]:8084"])

    def test_a_service_listening_outside_loopback_is_stopped(self):
        self.declared = [self.service(restart="always", backoff_seconds=5)]
        sup = self.supervisor()
        sup.reconcile()
        entry = next(iter(sup._entries.values()))
        entry.uid = 60001                        # as if isolated
        pid = entry.proc.pid
        with patch.object(launch, "exposed_listeners",
                          return_value=["0.0.0.0:8081"]):
            sup.reconcile()
        row = sup.snapshot()[0]
        self.assertEqual(row["state"], "blocked")
        self.assertIn("0.0.0.0:8081", row["last_error"])
        self.assertIsNone(row["pid"])
        with self.assertRaises(ProcessLookupError):
            for _ in range(200):
                os.kill(pid, 0)
                import time
                time.sleep(0.01)


if __name__ == "__main__":
    unittest.main()

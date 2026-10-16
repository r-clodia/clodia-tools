"""clodia-platform#545 §5 — le code di #515 sul supervisore dei servizi.

Quattro cose che il supervisore non faceva, e che hanno in comune il non
essere visibili finché non servono:

1. **rlimit per servizio.** Un servizio di pack girava con i limiti di
   risorsa del GATEWAY. Due conseguenze concrete: un core dump di un servizio
   finisce nella sua state dir con le credenziali che gli abbiamo dato in
   chiaro dentro, e una fork bomb (o un bug) di un pack esaurisce i processi
   di tutto il container, cioè ferma il gateway.
2. **Zombie.** Il gateway è PID 1 nel suo container e i nipoti orfani di un
   servizio gli vengono riparentati: senza raccoglierli, la tabella dei
   processi si riempie e nessuno lo nota finché i fork non falliscono.
3. **uid stabile fra i riavvii.** `uid_for` è derivato dal nome, ma la
   risoluzione di una collisione dipendeva da CHI era partito prima: due
   servizi che cadono sullo stesso resto si scambiavano l'uid al riavvio, e
   la state dir — che è chowned 0700 — non era più del servizio che la usa.
4. **UDP.** `exposed_listeners` guarda solo TCP, dichiarandolo. Un servizio
   che ascolta su UDP fuori da loopback è raggiungibile da tutto lo stack
   esattamente come uno TCP, e scavalca il proxy di egress allo stesso modo.
"""
from __future__ import annotations

import json
import os
import resource
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from ..connectors.manifest import Service
from . import launch
from .supervisor import Supervisor


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.data = Path(tmp.name)
        env = patch.dict(os.environ, {"CLODIA_DATA": str(self.data),
                                      "CLODIA_SERVICE_ISOLATION": "off"})
        env.start()
        self.addCleanup(env.stop)
        self.clock = _Clock()
        self.declared: list[Service] = []

    def service(self, **kwargs) -> Service:
        fields = {"name": "svc", "pack": "demo-pack", "namespace": "demo",
                  "command": (sys.executable, "-c", "import time; time.sleep(300)")}
        fields.update(kwargs)
        return Service(**fields)

    def supervisor(self, **kwargs) -> Supervisor:
        sup = Supervisor(lambda: list(self.declared), clock=self.clock, **kwargs)
        self.addCleanup(sup.stop_all)
        return sup


# --------------------------------------------------------------------------
# 1. rlimit
# --------------------------------------------------------------------------
#: Scrive i propri limiti e resta vivo: è il processo VERO a dire con che
#: limiti gira, non il modo in cui lo abbiamo avviato.
_DICHIARA_I_LIMITI = (
    "import json, os, resource, time\n"
    "limiti = {n: resource.getrlimit(getattr(resource, n))\n"
    "          for n in ('RLIMIT_CORE', 'RLIMIT_NPROC', 'RLIMIT_NOFILE',\n"
    "                    'RLIMIT_FSIZE')}\n"
    "open(os.path.join(os.environ['CLODIA_SERVICE_STATE_DIR'], 'limiti.json'),\n"
    "     'w').write(json.dumps(limiti))\n"
    "time.sleep(300)\n"
)


class RlimitTests(_Base):
    def test_a_service_runs_with_its_own_limits_not_the_gateways(self):
        self.declared = [self.service(
            command=(sys.executable, "-c", _DICHIARA_I_LIMITI))]
        sup = self.supervisor()
        sup.reconcile()
        path = self.data / "services" / "demo-pack" / "svc" / "limiti.json"
        for _ in range(300):
            if path.exists():
                break
            time.sleep(0.01)
        self.assertTrue(path.exists(), "il servizio non ha scritto i suoi limiti")
        letti = json.loads(path.read_text(encoding="utf-8"))
        attesi = launch.rlimits()
        # Nessun core dump: un core di un servizio contiene in chiaro le
        # credenziali che il manifest gli fa ricevere.
        self.assertEqual(letti["RLIMIT_CORE"], [0, 0])
        for nome in ("RLIMIT_NPROC", "RLIMIT_NOFILE", "RLIMIT_FSIZE"):
            with self.subTest(limite=nome):
                soft, hard = letti[nome]
                self.assertLessEqual(soft, attesi[nome])
                self.assertEqual(soft, hard)

    def test_the_wrapper_never_raises_a_limit_it_cannot_raise(self):
        """Abbassare si può sempre, alzare il tetto duro no (da non root).

        Chiedere più di quello che il gateway ha fa fallire `setrlimit` e il
        servizio non partirebbe affatto: il limite va CLAMPATO sul tetto
        esistente, non preteso.
        """
        _, duro = resource.getrlimit(resource.RLIMIT_NOFILE)
        illimitato = duro == resource.RLIM_INFINITY
        if illimitato:
            duro = 4096
        enorme = {"RLIMIT_NOFILE": duro * 1000}
        argv = launch.with_rlimits(
            [sys.executable, "-c",
             "import resource;print(resource.getrlimit(resource.RLIMIT_NOFILE)[0])"],
            enorme)
        done = subprocess.run(argv, capture_output=True, text=True,
                              timeout=30, check=False)
        self.assertEqual(done.returncode, 0, done.stderr)
        if not illimitato:   # with no hard ceiling there is nothing to clamp to
            self.assertLessEqual(int(done.stdout.strip()), duro)

    def test_the_command_still_runs_and_keeps_its_arguments(self):
        argv = launch.with_rlimits([sys.executable, "-c",
                                    "import sys;print('|'.join(sys.argv[1:]))",
                                    "uno", "due tre"])
        done = subprocess.run(argv, capture_output=True, text=True,
                              timeout=30, check=False)
        self.assertEqual(done.stdout.strip(), "uno|due tre")

    def test_an_empty_command_is_refused(self):
        with self.assertRaises(launch.ServiceRefused):
            launch.with_rlimits([])

    def test_the_limits_are_configurable(self):
        with patch.dict(os.environ, {"CLODIA_SERVICE_RLIMIT_NPROC": "7"}):
            self.assertEqual(launch.rlimits()["RLIMIT_NPROC"], 7)
        with patch.dict(os.environ, {"CLODIA_SERVICE_RLIMIT_NPROC": "non-un-numero"}):
            self.assertEqual(launch.rlimits()["RLIMIT_NPROC"],
                             launch.DEFAULT_RLIMITS["RLIMIT_NPROC"])


# --------------------------------------------------------------------------
# 2. zombie
# --------------------------------------------------------------------------
@unittest.skipUnless(Path("/proc/self/stat").exists(), "needs /proc (Linux)")
class ReapTests(_Base):
    def _zombie(self, own_session: bool = True) -> int:
        """A dead child. `own_session` = it was a service (session leader);
        otherwise it is one of the gateway's other children."""
        pid = os.fork()
        if pid == 0:  # pragma: no cover - vive il tempo di morire
            if own_session:
                os.setsid()
            os._exit(0)
        for _ in range(300):
            if self._stato(pid) == "Z":
                return pid
            time.sleep(0.01)
        self.fail("il figlio non è diventato zombie")
        raise AssertionError  # pragma: no cover

    @staticmethod
    def _stato(pid: int) -> str:
        try:
            riga = Path(f"/proc/{pid}/stat").read_text()
        except OSError:
            return ""
        coda = riga.rpartition(")")[2].split()
        return coda[0] if coda else ""

    def test_an_orphan_zombie_is_reaped(self):
        pid = self._zombie()
        self.assertEqual(launch.reap_orphans((), {pid}), 1)
        self.assertEqual(self._stato(pid), "", "lo zombie è ancora lì")

    def test_a_session_with_no_process_left_is_forgotten(self):
        """Pid reuse (review of #370): once nothing holds the session id, the
        supervisor drops it, so a recycled pid cannot look like a service."""
        pid = self._zombie()
        sup = self.supervisor()
        sup._sessions[pid] = None
        sup.reconcile()                      # reaps it…
        sup.reconcile()                      # …and the empty session goes
        self.assertNotIn(pid, sup._sessions)
        self.assertEqual(launch.live_sessions({pid}), set())

    def test_another_child_of_the_gateway_is_never_reaped(self):
        """Review of #370: a `subprocess.run` (restic, git, IMAP) that has
        just exited is a zombie until its own wait; stealing it made a failed
        backup read as `returncode = 0`. Not a service session → not ours."""
        pid = self._zombie(own_session=False)
        try:
            self.assertEqual(launch.reap_orphans((), {pid + 999_999}), 0)
            self.assertEqual(launch.reap_orphans(), 0)
            self.assertEqual(self._stato(pid), "Z")
        finally:
            _, status = os.waitpid(pid, 0)
        self.assertTrue(os.WIFEXITED(status), "il codice di uscita è andato perso")

    def test_a_supervised_child_is_never_reaped_from_under_the_supervisor(self):
        """È la ragione per cui non si fa `waitpid(-1)`: rubare l'uscita di un
        servizio lascerebbe il supervisore con un `Popen` che non saprà mai
        com'è finito, cioè un servizio «vivo» che non c'è più."""
        pid = self._zombie()
        try:
            self.assertEqual(launch.reap_orphans({pid}, {pid}), 0)
            self.assertEqual(self._stato(pid), "Z")
        finally:
            os.waitpid(pid, 0)

    def test_the_supervisor_reaps_while_it_reconciles(self):
        pid = self._zombie()
        sup = self.supervisor()
        sup._sessions[pid] = None   # as if it had been one of its services
        sup.reconcile()
        self.assertEqual(self._stato(pid), "", "reconcile non raccoglie gli orfani")

    def test_reconcile_does_not_reap_its_own_services(self):
        self.declared = [self.service()]
        sup = self.supervisor()
        sup.reconcile()
        entry = next(iter(sup._entries.values()))
        self.assertIsNotNone(entry.proc)
        sup.reconcile()
        self.assertEqual(sup.snapshot()[0]["state"], "running")


# --------------------------------------------------------------------------
# 3. uid stabile
# --------------------------------------------------------------------------
class StableUidTests(_Base):
    def _svc(self, name: str) -> Service:
        return self.service(name=name)

    def test_the_same_service_gets_the_same_uid_across_restarts(self):
        uno = launch.uid_for(self._svc("alfa"))
        due = launch.uid_for(self._svc("alfa"))
        self.assertEqual(uno, due)

    def test_a_collision_is_resolved_the_same_way_whoever_starts_first(self):
        """Il caso che si rompeva: due servizi sullo stesso resto.

        Prima la risoluzione dipendeva da `taken`, cioè da chi era già partito:
        invertendo l'ordine di avvio i due si scambiavano l'uid, e ciascuno
        trovava una state dir 0700 che non era più sua.
        """
        with patch.dict(os.environ, {"CLODIA_SERVICE_UID_SPAN": "2"}):
            alfa, beta = self._svc("alfa"), self._svc("beta")
            # I due COLLIDONO davvero: con uno span di 2 cadono sullo stesso
            # resto (`crc32('demo-pack/alfa') % 2 == crc32('demo-pack/beta') % 2`),
            # che è esattamente il caso che questa regola deve risolvere.
            base, span = launch._uid_base(), launch._uid_span()
            import zlib
            self.assertEqual(
                zlib.crc32(b"demo-pack/alfa") % span,
                zlib.crc32(b"demo-pack/beta") % span,
                "le fixture non collidono più: il test non misura nulla")
            primo = launch.uid_for(alfa)
            secondo = launch.uid_for(beta, {primo})
            self.assertNotEqual(primo, secondo)
            self.assertTrue(base <= secondo < base + span)
            # Riavvio, ordine inverso: nessuno dei due cambia uid.
            self.assertEqual(launch.uid_for(beta), secondo)
            self.assertEqual(launch.uid_for(alfa, {secondo}), primo)

    def test_an_uid_remembered_for_another_service_is_not_handed_out(self):
        with patch.dict(os.environ, {"CLODIA_SERVICE_UID_SPAN": "2"}):
            alfa = launch.uid_for(self._svc("alfa"))
            # `taken` vuoto: alfa è fermo. L'uid resta comunque suo, perché la
            # sua state dir è ancora chowned a quell'uid.
            beta = launch.uid_for(self._svc("beta"))
            self.assertNotEqual(alfa, beta)

    def test_the_map_survives_a_fresh_process(self):
        atteso = launch.uid_for(self._svc("alfa"))
        self.assertEqual(launch.uid_map().get("demo-pack/alfa"), atteso)

    def test_a_corrupt_map_does_not_stop_a_service(self):
        """Il file sta sotto la datadir, che l'agent-server monta: se è
        illeggibile o assurdo si deriva, non si fallisce."""
        path = self.data / "services" / launch.UID_MAP_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{non json", encoding="utf-8")
        self.assertIsInstance(launch.uid_for(self._svc("alfa")), int)

    def test_an_out_of_range_record_is_ignored(self):
        path = self.data / "services" / launch.UID_MAP_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"demo-pack/alfa": 0}), encoding="utf-8")
        uid = launch.uid_for(self._svc("alfa"))
        self.assertGreaterEqual(uid, launch._uid_base())


# --------------------------------------------------------------------------
# 4. UDP
# --------------------------------------------------------------------------
class UdpTests(_Base):
    #: `st` 07 = non connesso, 01 = connesso. Porte: 1F90=8080 (fissa),
    #: C350=50000 (effimera).
    UDP = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
        # loopback: va bene
        "   0: 0100007F:1F90 00000000:0000 07 00000000:00000000 00:00000000 00000000 60001 0 1 2 0 0\n"
        # wildcard su porta FISSA: è un servizio, ed è esposto
        "   1: 00000000:1F91 00000000:0000 07 00000000:00000000 00:00000000 00000000 60001 0 2 2 0 0\n"
        # wildcard su porta EFFIMERA e non connesso: socket di client
        "   2: 00000000:C350 00000000:0000 07 00000000:00000000 00:00000000 00000000 60001 0 3 2 0 0\n"
        # indirizzo specifico non-loopback, CONNESSO: client che ha scritto
        "   3: 0F02000A:C351 08080808:0035 01 00000000:00000000 00:00000000 00000000 60001 0 4 2 0 0\n"
        # indirizzo specifico non-loopback, non connesso: esposto
        "   4: 0F02000A:1F92 00000000:0000 07 00000000:00000000 00:00000000 00000000 60001 0 5 2 0 0\n"
        # di un altro uid
        "   5: 00000000:1F93 00000000:0000 07 00000000:00000000 00:00000000 00000000 60002 0 6 2 0 0\n"
    )
    UDP6 = (
        "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
        "   0: 00000000000000000000000001000000:1F94 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000 60001 0 7 2 0 0\n"
        "   1: 00000000000000000000000000000000:1F95 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000 60001 0 8 2 0 0\n"
    )

    def test_only_the_binds_that_mean_a_server_are_reported(self):
        found = launch.exposed_udp(60001, [self.UDP, self.UDP6],
                                   ephemeral=(32768, 60999))
        self.assertEqual(sorted(found),
                         ["udp 0.0.0.0:8081", "udp 10.0.2.15:8082",
                          "udp [::]:8085"])

    def test_a_service_bound_on_udp_outside_loopback_is_stopped(self):
        self.declared = [self.service(restart="always", backoff_seconds=5)]
        sup = self.supervisor()
        sup.reconcile()
        entry = next(iter(sup._entries.values()))
        entry.uid = 60001                        # come se fosse isolato
        with patch.object(launch, "exposed_listeners", return_value=[]), \
                patch.object(launch, "exposed_udp",
                             return_value=["udp 0.0.0.0:8081"]):
            sup.reconcile()
        row = sup.snapshot()[0]
        self.assertEqual(row["state"], "blocked")
        self.assertIn("udp 0.0.0.0:8081", row["last_error"])
        self.assertIsNone(row["pid"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

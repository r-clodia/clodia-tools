"""Il supervisore: avvia, sorveglia, riavvia e ferma i servizi dei pack (#515).

Un solo metodo fa il lavoro — `reconcile()` — ed è deliberato: confronta i
servizi DICHIARATI con i processi VIVI e porta i secondi sui primi. Installare
un pack, rimuoverlo, riavviare il gateway e riprendersi da un crash sono lo
stesso confronto fatto in momenti diversi, quindi non ci sono quattro percorsi
che possono divergere.

Il ciclo gira in un thread (`asyncio.to_thread`) perché `subprocess` e i probe
di health sono bloccanti, e il loop del gateway serve le chiamate degli agenti.
"""
from __future__ import annotations

import logging
import os
import signal
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable

from ..connectors.manifest import Service
from . import launch

LOG = logging.getLogger("clodia-tools.services")

#: Ogni quanto si riconcilia. Il registry si invalida da sé sullo `stat` dei
#: `pack.yaml`, quindi questo intervallo è anche la latenza con cui un pack
#: appena installato vede partire il suo servizio.
DEFAULT_INTERVAL = 10

#: Tetto del backoff esponenziale: un servizio rotto non va ritentato ogni 5
#: secondi per sempre, ma nemmeno abbandonato — il guasto può essere fuori
#: (la rete, il servizio a cui si connette).
MAX_BACKOFF = 300

#: Quanto deve restare su un processo perché il tentativo conti come riuscito.
#: Senza, il backoff crescerebbe all'infinito su un servizio che vive per ore e
#: poi muore una volta al giorno.
STABLE_SECONDS = 60

#: Health check consecutivi falliti dopo i quali il servizio viene riavviato.
#: Uno solo sarebbe un riavvio a ogni singhiozzo della rete.
HEALTH_STRIKES = 2

#: Secondi fra SIGTERM e SIGKILL quando si ferma un servizio.
STOP_GRACE = 10


@dataclass
class _Running:
    """Lo stato di UN servizio, come il supervisore lo vede."""

    service: Service
    proc: subprocess.Popen | None = None
    uid: int | None = None
    state: str = "pending"           # pending|running|backoff|exited|blocked
    since: float = 0.0
    starts: int = 0
    failures: int = 0                # fallimenti consecutivi, per il backoff
    next_attempt: float = 0.0
    last_exit: int | None = None
    last_error: str = ""
    health: str = ""                 # ""|ok|failing
    health_due: float = 0.0
    health_failures: int = 0
    log: str = field(default="", repr=False)
    #: The environment the CURRENT process was started with. Kept so a
    #: `command` health probe does not read the vault at every round. It
    #: holds the credentials and `CLODIA_SERVICE_TOKEN`, so it lives exactly
    #: as long as the process: cleared when the process exits or is stopped.
    env: dict | None = field(default=None, repr=False)
    #: The per-start secret the gateway authenticates itself with to this
    #: service (#638, `launch.SERVICE_TOKEN_HEADER`). In memory only, new at
    #: every start, cleared when the process goes: never logged, never shown.
    token: str = field(default="", repr=False)

    @property
    def key(self) -> tuple[str, str]:
        return self.service.pack, self.service.name


def _declared_services() -> list[Service] | None:
    """I servizi dei pack installati, dal registry dei connettori.

    Dal registry e non da una scansione nostra di `pack.yaml`: un pack rifiutato
    (manifest malformato, namespace di un altro) non è nel registry, e i suoi
    servizi non devono girare. Una seconda lettura dei file sarebbe una seconda
    opinione su che cosa è installato.

    None when the registry cannot be read: "unknown", not "nothing declared".
    Treating a transient error as an empty set would stop every running service
    (review of clodia-tools #362); `reconcile` keeps the last known set instead.
    """
    from ..connectors import resolved
    try:
        return list(resolved.registry().services())
    except Exception as exc:  # noqa: BLE001 - il registry non deve fermare il ciclo
        LOG.error("services: registry unreadable (%s): keeping the last known "
                  "set of services", exc)
        return None


class Supervisor:
    """I servizi di questa istanza. Una sola istanza viva (`supervisor()`)."""

    def __init__(self, declared: Callable[[], Iterable[Service] | None] | None = None,
                 *, clock: Callable[[], float] = time.monotonic,
                 isolation_probe: Callable[[tuple[int, int]], str] | None = None
                 ) -> None:
        self._declared = declared or _declared_services
        self._clock = clock
        self._probe_isolation = isolation_probe or launch.isolation_probe
        #: None = not probed yet; "" = the uid isolates; text = why it does not.
        #: Probed once per gateway process: the storage under the datadir does
        #: not change while the gateway runs, and fixing it means a restart.
        self._isolation: str | None = None
        self._entries: dict[tuple[str, str], _Running] = {}
        self._lock = threading.Lock()
        #: Session ids of every service started by this process (= their pids,
        #: they start with `start_new_session=True`): the only sessions whose
        #: orphans `reap_orphans` may collect. Bounded, oldest dropped.
        self._sessions: dict[int, None] = {}

    # -- ciclo ------------------------------------------------------------
    def reconcile(self) -> None:
        """Porta i processi vivi su ciò che i pack dichiarano ADESSO."""
        with self._lock:
            found = self._declared()
            if found is None:
                # Registry unreadable this round: keep what was declared.
                declared = {k: e.service for k, e in self._entries.items()}
            else:
                declared = {(s.pack, s.name): s for s in found}
            for key, entry in list(self._entries.items()):
                if key not in declared:
                    self._stop(entry, "il pack non lo dichiara più")
                    del self._entries[key]
                elif declared[key] != entry.service:
                    # Il manifest è cambiato: fermare e ripartire è l'unico modo
                    # di applicarlo — un processo vivo ha già il suo ambiente.
                    self._stop(entry, "dichiarazione cambiata")
                    entry.service = declared[key]
                    entry.state = "pending"
                    entry.next_attempt = 0.0
            for key, service in sorted(declared.items()):
                entry = self._entries.get(key)
                if entry is None:
                    entry = self._entries[key] = _Running(service=service)
                self._tick(entry)
            # I nipoti orfani di un servizio vengono riparentati al gateway,
            # che nel suo container è PID 1 (clodia-platform#545 §5). Dopo il
            # `_tick`, così i servizi che sono appena usciti li ha già
            # raccolti `Popen.poll()` e non c'è niente da togliergli.
            launch.reap_orphans(self._live_pids(), self._sessions)
            # Forget sessions with no process left (pid reuse, see
            # `launch.live_sessions`); the live services always keep theirs.
            vive = launch.live_sessions(self._sessions) | self._live_pids()
            for sid in [s for s in self._sessions if s not in vive]:
                del self._sessions[sid]

    def _tick(self, entry: _Running) -> None:
        if entry.proc is not None:
            code = entry.proc.poll()
            if code is None:
                if entry.log:
                    launch.rotate_log(entry.log)
                if self._exposed(entry):
                    return
                self._health(entry)
                return
            self._exited(entry, code)
        if entry.state == "exited":
            return
        if self._clock() < entry.next_attempt:
            return
        self._start(entry)

    # -- avvio e arresto --------------------------------------------------
    def _live_pids(self) -> set[int]:
        """I pid dei servizi supervisionati: ciò che `reap_orphans` non deve
        toccare, perché il loro codice d'uscita lo aspetta un `Popen`."""
        return {e.proc.pid for e in self._entries.values() if e.proc is not None}

    def _taken_uids(self, entry: _Running) -> set[int]:
        return {e.uid for e in self._entries.values()
                if e.uid is not None and e.key != entry.key}

    def _isolation_problem(self, privs: tuple[int, int]) -> str:
        """The isolation self-check (clodia-platform#544), run once."""
        if self._isolation is None:
            try:
                self._isolation = self._probe_isolation(privs) or ""
            except Exception as exc:  # noqa: BLE001 - a probe that fails is a no
                self._isolation = (f"isolation probe failed "
                                   f"({type(exc).__name__}: {str(exc)[:200]})")
            if self._isolation:
                LOG.critical(
                    "services: isolation unavailable, NO pack service will be "
                    "started: %s", self._isolation)
        return self._isolation

    def _start(self, entry: _Running) -> None:
        service = entry.service
        try:
            problem = launch.health_problem(service) \
                or launch.credentials_problem(service)
            if problem:
                raise launch.ServiceRefused(problem)
            privs = launch.privileges(service, self._taken_uids(entry))
            if privs is not None:
                unavailable = self._isolation_problem(privs)
                if unavailable:
                    # Before anything is prepared or read from the vault, and
                    # without a log line per round: the CRITICAL was logged once.
                    entry.state = "blocked"
                    entry.last_error = f"isolation unavailable: {unavailable}"
                    entry.next_attempt = self._clock() + MAX_BACKOFF
                    return
            path = launch.prepare_state_dir(service, privs)
            workdir = str(launch.resolve_workdir(service))
            env = launch.build_env(service)
            token = launch.new_service_token()
            env[launch.SERVICE_TOKEN_ENV] = token
            kw: dict = {}
            if privs is not None:
                # Prima di avviare: niente resti di una vita precedente sotto
                # quell'uid, o il nuovo processo trova la porta occupata e il
                # guasto sembra del pack.
                launch.kill_leftovers(privs[0])
                # `extra_groups=[]`: senza, il figlio terrebbe i gruppi
                # supplementari del gateway (root compreso) e scendere di uid
                # non lo escluderebbe da niente.
                kw.update(user=privs[0], group=privs[1], extra_groups=[],
                          umask=0o077)
            logfile = path / "service.log"
            launch.rotate_log(logfile)
            handle = launch.open_log(logfile)
            try:
                proc = subprocess.Popen(  # noqa: S603 - argv dal manifest, mai una shell
                    launch.with_rlimits(service.command), cwd=workdir, env=env,
                    stdin=subprocess.DEVNULL, stdout=handle, stderr=handle,
                    close_fds=True, start_new_session=True, **kw)
            finally:
                os.close(handle)
        except Exception as exc:  # noqa: BLE001 - un servizio rotto non ferma gli altri
            entry.state = "blocked"
            entry.last_error = f"{type(exc).__name__}: {str(exc)[:300]}"
            entry.failures += 1
            entry.next_attempt = self._clock() + self._backoff(entry)
            LOG.error("services: %s/%s non avviato: %s",
                      service.pack, service.name, entry.last_error)
            return
        entry.proc = proc
        self._sessions[proc.pid] = None
        while len(self._sessions) > 1024:
            self._sessions.pop(next(iter(self._sessions)))
        entry.env = env
        entry.token = token
        entry.uid = privs[0] if privs else None
        entry.state = "running"
        entry.since = self._clock()
        entry.starts += 1
        entry.last_error = ""
        entry.health = ""
        entry.health_failures = 0
        entry.health_due = self._clock() + service.health_interval
        entry.log = str(logfile)
        LOG.info("services: %s/%s avviato (pid %s, uid %s, stato in %s)",
                 service.pack, service.name, proc.pid,
                 entry.uid if entry.uid is not None else "gateway", path)

    def _exited(self, entry: _Running, code: int) -> None:
        service = entry.service
        entry.proc = None
        entry.env = None
        entry.token = ""
        entry.last_exit = code
        stable = (self._clock() - entry.since) >= STABLE_SECONDS
        if stable:
            entry.failures = 0
        if service.restart == "never" or (service.restart == "on-failure" and code == 0):
            entry.state = "exited"
            LOG.info("services: %s/%s uscito con %s, restart='%s': resta fermo",
                     service.pack, service.name, code, service.restart)
            return
        entry.failures += 1
        delay = self._backoff(entry)
        entry.state = "backoff"
        entry.next_attempt = self._clock() + delay
        entry.last_error = f"uscito con codice {code}"
        LOG.warning("services: %s/%s uscito con %s: riavvio fra %ss",
                    service.pack, service.name, code, delay)

    def _backoff(self, entry: _Running) -> int:
        base = max(1, entry.service.backoff_seconds)
        return min(base * (2 ** max(0, entry.failures - 1)), MAX_BACKOFF)

    def _stop(self, entry: _Running, reason: str) -> None:
        proc = entry.proc
        entry.proc = None
        entry.env = None
        entry.token = ""
        entry.state = "stopped"
        if proc is None or proc.poll() is not None:
            return
        LOG.info("services: fermo %s/%s (%s)",
                 entry.service.pack, entry.service.name, reason)
        self._signal(proc, signal.SIGTERM)
        try:
            proc.wait(timeout=STOP_GRACE)
            return
        except subprocess.TimeoutExpired:
            LOG.warning("services: %s/%s non si è fermato in %ss, SIGKILL",
                        entry.service.pack, entry.service.name, STOP_GRACE)
        self._signal(proc, signal.SIGKILL)
        try:
            proc.wait(timeout=STOP_GRACE)
        except subprocess.TimeoutExpired:  # pragma: no cover - zombie del kernel
            LOG.error("services: %s/%s sopravvive a SIGKILL",
                      entry.service.pack, entry.service.name)

    @staticmethod
    def _signal(proc: subprocess.Popen, sig: int) -> None:
        """Al GRUPPO, non al solo pid: il servizio parte con
        `start_new_session=True`, e un processo che ha forkato lascerebbe i
        figli vivi a tenersi la porta."""
        try:
            os.killpg(os.getpgid(proc.pid), sig)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.send_signal(sig)
            except Exception:  # noqa: BLE001
                pass

    # -- salute -----------------------------------------------------------
    def _exposed(self, entry: _Running) -> bool:
        """Stop a service listening outside loopback, on TCP or on UDP.

        A service is reachable by the gateway only (#515): one bound to 0.0.0.0
        is reachable from the whole stack and bypasses the egress proxy. Only
        for an isolated service, whose sockets carry its own uid.

        UDP è entrato qui con clodia-platform#545 §5: un bind UDP fuori da
        loopback è raggiungibile e scavalca il proxy esattamente come uno TCP,
        e restava fuori solo perché distinguere un server da un client richiede
        una regola diversa (vedi `launch.exposed_udp`).
        """
        if entry.uid is None:
            return False
        exposed = launch.exposed_listeners(entry.uid) + launch.exposed_udp(entry.uid)
        if not exposed:
            return False
        service = entry.service
        self._stop(entry, "listening outside loopback")
        entry.state = "blocked"
        entry.failures += 1
        entry.next_attempt = self._clock() + self._backoff(entry)
        entry.last_error = (f"listening outside loopback ({', '.join(exposed[:4])}): "
                            f"a service is reachable by the gateway only")
        LOG.error("services: %s/%s %s", service.pack, service.name, entry.last_error)
        return True

    def _health(self, entry: _Running) -> None:
        service = entry.service
        if not service.health_kind or self._clock() < entry.health_due:
            return
        entry.health_due = self._clock() + max(1, service.health_interval)
        privs = (entry.uid, launch.gid_for(service.pack)) if entry.uid is not None else None
        ok, why = launch.probe(service, privs, entry.env)
        if ok:
            entry.health = "ok"
            entry.health_failures = 0
            return
        entry.health = "failing"
        entry.health_failures += 1
        entry.last_error = why
        LOG.warning("services: %s/%s health fallito (%s/%s): %s",
                    service.pack, service.name, entry.health_failures,
                    HEALTH_STRIKES, why)
        if entry.health_failures >= HEALTH_STRIKES and service.restart != "never":
            self._stop(entry, f"health fallito {entry.health_failures} volte")
            entry.failures += 1
            entry.state = "backoff"
            entry.next_attempt = self._clock() + self._backoff(entry)

    def _isolation_state(self, entry: _Running) -> str:
        if entry.uid is not None:
            return "ok"
        if self._isolation:
            return "unavailable"
        if launch.isolation_disabled():
            return "off"
        return "unknown" if self._isolation is None else "ok"

    # -- spegnimento e lettura --------------------------------------------
    def stop_all(self) -> None:
        with self._lock:
            for entry in self._entries.values():
                self._stop(entry, "gateway in arresto")

    def service_token(self, pack: str, name: str) -> str | None:
        """The secret of the RUNNING process of `pack/name`, or None (#638).

        None whenever the process is not running: a caller that gets None
        answers «service unavailable», and a token outliving its process
        would authenticate the gateway to whatever binds the port next.
        Without the lock, like `snapshot`.
        """
        entry = self._entries.get((pack, name))
        if entry is None or entry.state != "running" or entry.proc is None \
                or entry.proc.poll() is not None or not entry.token:
            return None
        return entry.token

    def snapshot(self) -> list[dict]:
        """Stato per la pagina Tools. Mai un segreto: nomi, stato, errore.

        SENZA il lock, deliberatamente: `reconcile()` lo tiene anche mentre
        aspetta che un servizio muoia (fino a `STOP_GRACE`), e la pagina Tools
        resterebbe appesa proprio nel momento in cui la si guarda per capire
        cosa sta succedendo. `list(dict.values())` è atomico, e una riga letta
        un giro prima è esattamente ciò che una pagina di stato mostra sempre.
        """
        rows = []
        for entry in sorted(list(self._entries.values()), key=lambda e: e.key):
            proc = entry.proc
            rows.append({
                "pack": entry.service.pack,
                "service": entry.service.name,
                "state": entry.state,
                "pid": proc.pid if proc is not None and proc.poll() is None else None,
                "isolated": entry.uid is not None,
                "uid": entry.uid,
                "starts": entry.starts,
                "failures": entry.failures,
                "last_exit": entry.last_exit,
                "last_error": entry.last_error,
                "health": entry.health,
                "isolation": self._isolation_state(entry),
                "state_dir": str(launch.state_dir(entry.service)),
            })
        return rows


_INSTANCE: Supervisor | None = None
_INSTANCE_LOCK = threading.Lock()


def supervisor() -> Supervisor:
    global _INSTANCE
    with _INSTANCE_LOCK:
        if _INSTANCE is None:
            _INSTANCE = Supervisor()
        return _INSTANCE


def snapshot() -> list[dict]:
    return supervisor().snapshot()


def service_token(pack: str, name: str) -> str | None:
    return supervisor().service_token(pack, name)


def stop_all() -> None:
    supervisor().stop_all()


async def reconcile_loop(interval: int | None = None) -> None:
    """Il ciclo che il lifespan del gateway tiene vivo."""
    import asyncio
    every = interval or int(os.environ.get("CLODIA_SERVICE_INTERVAL")
                            or DEFAULT_INTERVAL)
    if launch.isolation_disabled():
        LOG.warning("services: isolamento DISATTIVATO (CLODIA_SERVICE_ISOLATION=off): "
                    "i servizi dei pack girano con l'utente del gateway")
    while True:
        try:
            await asyncio.to_thread(supervisor().reconcile)
        except Exception as exc:  # noqa: BLE001 - il ciclo deve sopravvivere
            LOG.error("services: riconciliazione fallita (%s)", exc)
        await asyncio.sleep(every)

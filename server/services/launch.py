"""Con che ambiente, con che identità e dove gira un servizio di pack (#515).

Separato dal supervisore perché sono le due domande che si verificano da sole:
`supervisor.py` decide *quando* avviare e riavviare, qui si decide *cosa*
riceve il processo. Tutto ciò che è di sicurezza sta in questo file.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import secrets
import shlex
import socket
import stat
import subprocess
import sys
import zlib
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from .. import vault
from ..connectors.manifest import (
    Service, entry_owner, vault_entry_problem, workdir_problem)
from ..tools import pack_runtime

LOG = logging.getLogger("clodia-tools.services")

#: Prima base del pool di uid dedicati, quando `CLODIA_SERVICE_UID_BASE` non è
#: impostata. Un uid numerico non ha bisogno di una riga in `/etc/passwd` per
#: essere usato da `setuid`: non c'è niente da provisionare nell'immagine.
DEFAULT_UID_BASE = 60000

#: `PATH` di partenza del servizio. Esplicito e non ereditato: `runtime_path`
#: antepone venv e npm del volume dei pack a quello che riceve, e ricevere ""
#: lascerebbe un elemento VUOTO in coda — che per la ricerca dei binari
#: significa «la directory corrente».
BASE_PATH = "/usr/local/bin:/usr/bin:/bin"

#: Host che valgono «raggiungibile solo dal gateway». Il criterio della issue
#: («mai esposti fuori dallo stack») non è verificabile sul bind del figlio, ma
#: un health check che punta fuori da qui dichiara un servizio che si aspetta
#: di essere raggiunto da altrove: è il segnale più vicino, ed è controllabile.
LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost", "ip6-localhost"})

#: Size past which `service.log` is rotated into `service.log.1` (one kept).
LOG_MAX_BYTES = 5 * 1024 * 1024

#: Limiti di risorsa con cui parte OGNI servizio di pack
#: (clodia-platform#545 §5). Senza, un servizio eredita quelli del gateway.
#:
#: `RLIMIT_CORE = 0` non è igiene: un core dump finisce nella state dir del
#: servizio e contiene IN CHIARO le credenziali che il manifest gli fa
#: ricevere. `RLIMIT_NPROC` è per uid, e l'uid è dedicato: è esattamente il
#: confine giusto perché un fork bomb di un pack non esaurisca i processi del
#: container — cioè non fermi il gateway.
#:
#: SHORTCUT: un solo insieme di limiti per tutti i servizi, non dichiarabile
#:           per servizio. Regge finché i servizi sono i processi piccoli che
#:           #515 descrive (un poller, un bridge). Il giorno che un pack
#:           dichiara un servizio che ha bisogno di più — un indice, una
#:           build — il manifest deve poter dichiarare i propri limiti, e
#:           questi restano i default sotto cui ricade chi non dichiara nulla.
DEFAULT_RLIMITS = {
    "RLIMIT_CORE": 0,
    "RLIMIT_NPROC": 256,
    "RLIMIT_NOFILE": 4096,
    "RLIMIT_FSIZE": 1024 * 1024 * 1024,
}

#: Lo stub che si abbassa i limiti e poi `exec`a il comando vero.
#:
#: Un processo separato e non `preexec_fn`: quello esegue codice Python fra
#: `fork` e `exec` in un gateway che ha altri thread, ed è la ricetta per un
#: deadlock su un lock preso da un thread che nel figlio non esiste. Qui il
#: figlio è un interprete nuovo (`-I`), che si limita da sé e sparisce
#: nell'`exec`: il pid che il supervisore tiene resta quello del servizio.
#:
#: I limiti si CLAMPANO sul tetto duro esistente: alzarlo non è permesso a chi
#: non è root, e pretenderlo farebbe fallire l'avvio invece di confinarlo.
_LIMITER = (
    "import json, os, resource, sys\n"
    "for nome, valore in json.loads(sys.argv[1]).items():\n"
    "    chiave = getattr(resource, nome, None)\n"
    "    if chiave is None:\n"
    "        continue\n"
    "    try:\n"
    "        _, duro = resource.getrlimit(chiave)\n"
    "        if duro != resource.RLIM_INFINITY:\n"
    "            valore = min(valore, duro)\n"
    "        resource.setrlimit(chiave, (valore, valore))\n"
    "    except (OSError, ValueError) as exc:\n"
    "        sys.stderr.write('rlimit %s: %s\\n' % (nome, exc))\n"
    "        os._exit(71)\n"
    "os.execvp(sys.argv[2], sys.argv[2:])\n"
)

#: Dove si ricorda quale uid appartiene a quale servizio, sotto
#: `<datadir>/services/`.
UID_MAP_FILE = "uids.json"

#: Where the isolation self-check keeps its sentinel, under `<datadir>/services`
#: — the same volume as the state dirs and the vault (clodia-platform#544).
PROBE_DIR = ".isolation-probe"

#: The child of the isolation probe. Exit 0 = it READ the sentinel (no
#: isolation), 3 = permission denied (isolated), anything else = inconclusive.
_PROBE_READER = (
    "import sys\n"
    "try:\n"
    "    open(sys.argv[1], 'rb').read(1)\n"
    "except PermissionError:\n"
    "    sys.exit(3)\n"
    "except BaseException:\n"
    "    sys.exit(4)\n"
    "sys.exit(0)\n"
)


class ServiceRefused(RuntimeError):
    """Il servizio è dichiarato male per questa istanza: non si avvia."""


class IsolationUnavailable(ServiceRefused):
    """L'isolamento è richiesto ma non applicabile: si fallisce chiusi.

    Mai un fallback all'utente del gateway: quel processo potrebbe leggere la
    vault e lo stato decisionale del reference monitor, cioè esattamente ciò
    che l'isolamento esiste per impedire.
    """


class CredentialUnavailable(ServiceRefused):
    """Una credenziale dichiarata dal manifest non è nella vault."""


def data_dir() -> Path:
    """Letta a ogni chiamata, non all'import: i test (e un riavvio con un
    volume diverso) devono poterla cambiare senza ricaricare il modulo."""
    return Path(os.environ.get("CLODIA_DATA") or "/datadir")


def state_dir(service: Service) -> Path:
    """`<datadir>/services/<pack>/<servizio>` — il percorso lo calcola
    `Service.state_dir`, qui si aggiunge solo la radice."""
    return data_dir() / service.state_dir


def isolation_disabled() -> bool:
    return (os.environ.get("CLODIA_SERVICE_ISOLATION") or "").strip().lower() == "off"


def _uid_base() -> int:
    raw = (os.environ.get("CLODIA_SERVICE_UID_BASE") or "").strip()
    return int(raw) if raw.isdigit() and int(raw) > 0 else DEFAULT_UID_BASE


def _uid_span() -> int:
    raw = (os.environ.get("CLODIA_SERVICE_UID_SPAN") or "").strip()
    return int(raw) if raw.isdigit() and int(raw) > 0 else 200


def rlimits() -> dict[str, int]:
    """I limiti con cui parte un servizio. `CLODIA_SERVICE_<NOME>` li cambia
    (`CLODIA_SERVICE_RLIMIT_NPROC=512`); un valore non numerico è il default,
    non un errore — un limite scritto male non deve impedire un avvio."""
    out: dict[str, int] = {}
    for nome, default in DEFAULT_RLIMITS.items():
        raw = (os.environ.get(f"CLODIA_SERVICE_{nome}") or "").strip()
        out[nome] = int(raw) if raw.isdigit() else default
    return out


def with_rlimits(command: Iterable[str],
                 limits: dict[str, int] | None = None) -> list[str]:
    """`command` preceduto dallo stub che applica i limiti (vedi `_LIMITER`).

    Si antepone sempre, anche con l'isolamento disattivato: i limiti valgono
    per il processo, non per l'identità, e in sviluppo locale confinare un
    servizio che fa `fork` resta esattamente ciò che si vuole.
    """
    argv = [str(x) for x in command]
    if not argv:
        raise ServiceRefused("comando vuoto: non c'è niente da avviare")
    scelti = rlimits() if limits is None else limits
    return [sys.executable, "-I", "-c", _LIMITER, json.dumps(scelti), *argv]


def reap_orphans(tracked: Iterable[int] = (), sessions: Iterable[int] = ()) -> int:
    """Raccoglie gli zombie orfani DEI SERVIZI, e nessun altro.

    Solo un processo della **sessione di un servizio** (`sessions`: i pid dei
    servizi avviati, che partono con `start_new_session=True` e ne sono quindi
    i session leader) è un orfano da raccogliere. Il gateway ha molti altri
    figli suoi — `subprocess.run` di restic, git, del client IMAP, i backend
    MCP stdio — e uno di loro appena uscito è uno zombie finché il SUO `wait`
    non arriva: raccoglierlo prima faceva leggere a `subprocess.run` un
    `ECHILD`, cioè `returncode = 0` per un backup fallito (review di
    clodia-tools#370).

    Il gateway è PID 1 nel suo container, quindi i nipoti orfani di un
    servizio gli vengono riparentati: senza raccoglierli la tabella dei
    processi si riempie, e il sintomo arriva molto dopo come un `fork` che
    fallisce (clodia-platform#545 §5).

    Si raccoglie PER PID, mai con `waitpid(-1)`: quello ruberebbe l'uscita di
    un servizio supervisionato e lascerebbe il suo `Popen` senza codice di
    uscita — un servizio «vivo» che non c'è più. Per lo stesso motivo
    `tracked` non è una precauzione: è la condizione di correttezza.
    """
    noti = {int(p) for p in tracked}
    sessioni = {int(p) for p in sessions}
    if not sessioni:
        return 0
    mio = os.getpid()
    raccolti = 0
    try:
        voci = list(Path("/proc").glob("[0-9]*"))
    except OSError:
        return 0
    for entry in voci:
        try:
            pid = int(entry.name)
        except ValueError:
            continue
        if pid in noti or pid == mio:
            continue
        try:
            # `comm` sta fra parentesi e può contenere spazi: si parte da
            # DOPO l'ultima `)`, se no i campi scalano.
            coda = (entry / "stat").read_text().rpartition(")")[2].split()
            # Campi dopo `)`: stato, ppid, pgrp, session.
            if len(coda) < 4 or coda[0] != "Z" or int(coda[1]) != mio:
                continue
            if int(coda[3]) not in sessioni:
                continue
            if os.waitpid(pid, os.WNOHANG)[0] == pid:
                raccolti += 1
        except (OSError, ValueError):
            continue
    if raccolti:
        LOG.info("services: raccolti %s processi zombie orfani", raccolti)
    return raccolti


def _uid_map_path() -> Path:
    return data_dir() / "services" / UID_MAP_FILE


def uid_map() -> dict[str, int]:
    """`{"<pack>/<servizio>": uid}` come è stato registrato finora.

    Tollerante a tutto: il file sta sotto la datadir, che l'agent-server monta,
    quindi un contenuto assurdo è uno scenario da gestire e non da credere.
    Illeggibile o malformato = nessun ricordo, e si deriva come prima.
    """
    base, span = _uid_base(), _uid_span()
    try:
        raw = json.loads(_uid_map_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(raw, dict):
        return {}
    return {str(k): int(v) for k, v in raw.items()
            if isinstance(v, int) and not isinstance(v, bool)
            and base <= v < base + span}


def _remember_uid(key: str, uid: int) -> None:
    mappa = uid_map()
    if mappa.get(key) == uid:
        return
    mappa[key] = uid
    path = _uid_map_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text(json.dumps(mappa, sort_keys=True), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError as exc:  # noqa: BLE001 - il servizio parte lo stesso
        LOG.warning("services: uid di '%s' non memorizzato (%s): al prossimo "
                    "riavvio potrebbe cambiare", key, exc)


def gid_for(pack: str) -> int:
    """gid stabile per PACK: i servizi di uno stesso pack possono condividere
    file fra loro, mai con quelli di un altro pack."""
    return _uid_base() + _uid_span() + (zlib.crc32(pack.encode()) % _uid_span())


def uid_for(service: Service, taken: frozenset[int] | set[int] = frozenset()) -> int:
    """uid dedicato, derivato dal nome e stabile fra i riavvii.

    Derivato e non allocato da un contatore: al riavvio del gateway il servizio
    deve ritrovare uid uguale, se no la sua state dir — che è chowned — non
    sarebbe più sua. `taken` risolve la collisione fra due nomi che cadono sullo
    stesso resto: due servizi con lo stesso uid si leggerebbero lo stato a
    vicenda, che è l'isolamento che si voleva.

    La derivazione da sola però NON basta a essere stabili, ed è il difetto di
    clodia-platform#545 §5: la risoluzione di una collisione dipendeva da
    `taken`, cioè da CHI era partito prima. Due servizi che cadono sullo stesso
    resto si scambiavano l'uid al riavvio — e ciascuno trovava una state dir
    0700 che non era più sua, cioè un servizio che non riparte per un motivo
    che non nomina la causa. Quindi l'assegnazione si RICORDA (`uid_map`): il
    ricordo vince sulla derivazione, e un uid già di un altro servizio non
    viene mai riassegnato, nemmeno se quel servizio adesso è fermo.
    """
    base, span = _uid_base(), _uid_span()
    key = f"{service.pack}/{service.name}"
    mappa = uid_map()
    occupati = set(taken) | {u for k, u in mappa.items() if k != key}
    ricordato = mappa.get(key)
    if ricordato is not None and ricordato not in set(taken):
        return ricordato
    start = zlib.crc32(key.encode()) % span
    for step in range(span):
        candidate = base + (start + step) % span
        if candidate not in occupati:
            _remember_uid(key, candidate)
            return candidate
    raise IsolationUnavailable(
        f"nessun uid libero nel pool ({base}..{base + span - 1}): "
        f"troppi servizi dichiarati per lo spazio configurato")


def privileges(service: Service,
               taken: frozenset[int] | set[int] = frozenset()
               ) -> tuple[int, int] | None:
    """`(uid, gid)` con cui far girare il servizio, o None se l'isolamento è
    stato disattivato esplicitamente. Solleva `IsolationUnavailable` quando è
    richiesto (il default) ma non applicabile."""
    if isolation_disabled():
        return None
    if os.geteuid() != 0:
        raise IsolationUnavailable(
            "l'isolamento richiede che il gateway sia root per poter scendere a "
            "un utente dedicato; per lo sviluppo locale si dichiara "
            "CLODIA_SERVICE_ISOLATION=off, e allora il servizio gira con "
            "l'utente del gateway")
    return uid_for(service, taken), gid_for(service.pack)


def prepare_state_dir(service: Service,
                      privs: tuple[int, int] | None) -> Path:
    """Crea `<datadir>/services/<pack>/<servizio>`, 0700 e di proprietà del
    servizio. È l'unico posto scrivibile che riceve, ed è su volume: è quello
    che fa sopravvivere lo stato a un rebuild dell'immagine."""
    path = state_dir(service)
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    if privs is not None:
        os.chown(path, privs[0], privs[1])
    return path


def kill_leftovers(uid: int | None) -> int:
    """Uccide i processi rimasti dell'uid di QUESTO servizio, e ritorna quanti.

    Serve dopo un arresto non pulito del gateway (SIGKILL del container, crash):
    i figli restano orfani, tengono la porta, e il supervisore ne avvierebbe un
    secondo che muore con «address already in use» — un guasto che sembra del
    pack. L'uid è dedicato e stabile per servizio, quindi tutto ciò che gira
    sotto quell'uid è una vita precedente dello stesso servizio: la stessa
    ragione per cui `clodia-logic` pulisce un uid di sandbox prima di riusarlo.
    """
    if uid is None:
        return 0
    import signal as _signal
    killed = 0
    for entry in Path("/proc").glob("[0-9]*"):
        try:
            if entry.stat().st_uid != uid:
                continue
            os.kill(int(entry.name), _signal.SIGKILL)
            killed += 1
        except (OSError, ValueError):
            continue
    if killed:
        LOG.warning("services: uccisi %s processi rimasti dell'uid %s "
                    "(arresto non pulito del gateway)", killed, uid)
    return killed


def installed_namespaces() -> frozenset[str]:
    """Every namespace a vault entry can belong to on this instance: the
    connectors of the registry and the gateway's own."""
    from ..connectors import manifest, resolved
    return (frozenset(c.namespace for c in resolved.registry().connectors)
            | manifest.core_namespaces())


def credentials_problem(service: Service,
                        namespaces: Iterable[str] | None = None) -> str:
    """Why this service may not receive its declared credentials, or "".

    The manifest already refuses a foreign or core entry; this is the same rule
    applied again where the vault is actually read, so that a `Service` that did
    not come from the parser — or a parser regression — still cannot reach
    `github_pat`, `provider_*` or another pack's token (review of #362).
    """
    if not service.credentials:
        return ""
    if not service.namespace:
        return (f"credential '{service.credentials[0]}': the service declares "
                f"no namespace, so it may not receive any vault entry")
    if namespaces is None:
        try:
            namespaces = installed_namespaces()
        except Exception as exc:  # noqa: BLE001 - unknown owner: fail closed
            return (f"cannot verify the owner of its credentials "
                    f"({type(exc).__name__})")
    known = set(namespaces) | {service.namespace}
    for name in service.credentials:
        problem = vault_entry_problem(name, service.namespace)
        if problem:
            return f"credential '{name}': {problem}"
        owner = entry_owner(name, known)
        if owner != service.namespace:
            return (f"credential '{name}': belongs to namespace '{owner}', not "
                    f"to the service's own '{service.namespace}'")
    return ""


def credentials_env(service: Service) -> dict[str, str]:
    """Le SOLE credenziali che il manifest dichiara, come JSON in una variabile
    ciascuna. Una credenziale assente ferma il servizio: partire senza è il modo
    di avere un processo vivo che fallisce ogni chiamata senza dire perché.

    Il valore non viene mai loggato né restituito da una rotta: esce da qui ed
    entra nell'ambiente del figlio, che gira con un uid diverso da quello di
    chiunque altro.
    """
    problem = credentials_problem(service)
    if problem:
        raise ServiceRefused(problem)
    env: dict[str, str] = {}
    for name in service.credentials:
        try:
            bundle = vault.read_internal(name)
        except Exception as exc:  # noqa: BLE001 - il motivo esatto non è utile qui
            raise CredentialUnavailable(
                f"credenziale '{name}' dichiarata dal servizio "
                f"'{service.pack}/{service.name}' non disponibile nella vault "
                f"({type(exc).__name__})") from exc
        env[f"CLODIA_CREDENTIAL_{name.upper()}"] = json.dumps(bundle)
    return env


def build_env(service: Service) -> dict[str, str]:
    """L'ambiente del servizio, COSTRUITO DA ZERO.

    `pack_runtime.runtime_env` con una base vuota dà solo `PATH` e `PYTHONPATH`
    del volume dei pack — le stesse di un server MCP di pack, perché un servizio
    usa le stesse dipendenze installate da `packs.install_pip`. Quello che NON
    arriva è tutto il resto: `CLODIA_ORCHESTRATOR_SECRET`, `CLODIA_VAULT_DIR`,
    i token. Non c'è una lista di variabili da togliere, e per questo non può
    dimenticarne una.
    """
    env = pack_runtime.runtime_env(base={"PATH": BASE_PATH})
    path = state_dir(service)
    env["HOME"] = str(path)
    env["CLODIA_SERVICE_STATE_DIR"] = str(path)
    env["CLODIA_SERVICE_PACK"] = service.pack
    env["CLODIA_SERVICE_NAME"] = service.name
    env.update(credentials_env(service))
    return env


def _loopback(host: str) -> bool:
    return (host or "").strip("[]").lower() in LOOPBACK


def health_problem(service: Service) -> str:
    """Perché questo health check non è accettabile, "" se lo è."""
    kind, target = service.health_kind, service.health_target
    if not kind:
        return ""
    if not target:
        return f"health {kind}: manca il target"
    if kind == "http":
        parsed = urlparse(target)
        if parsed.scheme not in ("http", "https"):
            return f"health http: '{target}' non è un URL http(s)"
        if not _loopback(parsed.hostname or ""):
            return (f"health http: '{target}' non è su loopback. Un servizio è "
                    f"raggiungibile dal solo gateway (clodia-platform#515): un "
                    f"health check verso l'esterno dichiara il contrario")
    elif kind == "tcp":
        host, _, port = target.rpartition(":")
        if not port.isdigit() or not _loopback(host):
            return (f"health tcp: '{target}' non è host:porta su loopback")
    return ""


def probe(service: Service, privs: tuple[int, int] | None = None,
          env: dict[str, str] | None = None) -> tuple[bool, str]:
    """Esegue l'health check dichiarato. `(ok, motivo)`; mai un'eccezione.

    `env`: l'ambiente costruito all'avvio del processo. Passarlo evita una
    lettura della vault (e una riga di audit) a ogni probe `command`."""
    kind, target = service.health_kind, service.health_target
    if not kind:
        return True, ""
    try:
        if kind == "http":
            import httpx
            resp = httpx.get(target, timeout=5.0)
            if resp.status_code >= 500:
                return False, f"health http: {resp.status_code}"
            return True, ""
        if kind == "tcp":
            host, _, port = target.rpartition(":")
            with socket.create_connection((host.strip("[]"), int(port)), timeout=5.0):
                return True, ""
        # `command`: il target è una riga di comando, divisa come farebbe una
        # shell ma SENZA una shell — niente espansioni, niente `;` che nasconde
        # un secondo processo. Stessa regola del `command` del servizio.
        argv = shlex.split(target)
        if not argv:
            return False, "health command: comando vuoto"
        kw: dict = {}
        if privs is not None:
            kw.update(user=privs[0], group=privs[1], extra_groups=[])
        done = subprocess.run(argv, timeout=10, capture_output=True,
                              env=env if env is not None else build_env(service),
                              check=False, **kw)
        if done.returncode != 0:
            return False, f"health command: uscita {done.returncode}"
        return True, ""
    except Exception as exc:  # noqa: BLE001 - un probe non deve mai propagare
        return False, f"health {kind}: {type(exc).__name__}: {str(exc)[:120]}"


# -- workdir -----------------------------------------------------------------
def pack_dir(service: Service) -> Path:
    return data_dir() / "packs" / service.pack


def resolve_workdir(service: Service) -> Path:
    """The directory the service starts in, confined to its pack directory or
    its own state dir after resolving symlinks and `..`.

    The `chdir` happens as root, before the privilege drop: an unconfined path
    would put the service inside a directory its uid could never enter.
    """
    state = state_dir(service).resolve()
    if not service.workdir:
        return state
    problem = workdir_problem(service.workdir)
    if problem:
        raise ServiceRefused(problem)
    root = pack_dir(service).resolve()
    target = (root / service.workdir).resolve()
    if not (target.is_relative_to(root) or target.is_relative_to(state)):
        raise ServiceRefused(
            f"workdir '{service.workdir}' resolves outside the pack directory "
            f"and the service state dir")
    if not target.is_dir():
        raise ServiceRefused(f"workdir '{service.workdir}' is not a directory")
    return target


# -- log ---------------------------------------------------------------------
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


def _check_plain(fd: int, path: Path) -> os.stat_result:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        os.close(fd)
        raise ServiceRefused(
            f"{path.name} is not a plain file with a single link: refusing to "
            f"write to it")
    return st


def open_log(path: Path) -> int:
    """Open `service.log` for appending, WITHOUT following a symlink.

    The state dir belongs to the service uid and the log is opened by the
    gateway (root): following a symlink or a hard link planted there would let
    the service make root append to any file.
    """
    try:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | _NOFOLLOW
                     | _CLOEXEC, 0o600)
    except OSError as exc:
        raise ServiceRefused(f"{path.name}: cannot open safely ({exc.strerror})") from exc
    _check_plain(fd, path)
    return fd


def rotate_log(path: Path | str, limit: int | None = None) -> bool:
    """Past `LOG_MAX_BYTES`, keep the last `limit` bytes in `service.log.1` and
    truncate `service.log` in place. True if it rotated.

    In place (copy + `ftruncate`), not by rename: the running child holds the
    file open with O_APPEND, so after the truncation it keeps writing at the new
    end of the same file. Every open refuses symlinks, as in `open_log`.
    """
    path = Path(path)
    limit = LOG_MAX_BYTES if limit is None else limit
    try:
        fd = os.open(path, os.O_RDWR | _NOFOLLOW | _CLOEXEC)
    except OSError:
        return False
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size <= limit:
            return False
        kept = path.with_name(path.name + ".1")
        try:
            os.unlink(kept)
        except FileNotFoundError:
            pass
        except OSError:
            return False
        try:
            out = os.open(kept, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW
                          | _CLOEXEC, 0o600)
        except OSError:
            out = -1
        if out >= 0:
            try:
                os.lseek(fd, max(0, st.st_size - limit), os.SEEK_SET)
                remaining = limit
                while remaining > 0:
                    chunk = os.read(fd, min(remaining, 1 << 16))
                    if not chunk:
                        break
                    os.write(out, chunk)
                    remaining -= len(chunk)
            finally:
                os.close(out)
        os.ftruncate(fd, 0)
        return True
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


# -- isolation self-check (clodia-platform#544) ------------------------------
def isolation_probe(privs: tuple[int, int] | None) -> str:
    """Prove that the service uid cannot read a 0600 file of the gateway.

    Returns "" when it is denied, otherwise why isolation is unavailable. On
    terra the datadir is an OrbStack virtiofs bind mount that ignores permission
    bits: a dedicated uid there isolates nothing, and a service would read the
    vault. Inconclusive means unavailable: this check fails closed.
    """
    root = data_dir() / "services" / PROBE_DIR
    root.mkdir(parents=True, exist_ok=True)
    os.chmod(root, 0o711)
    sentinel = root / "sentinel"
    try:
        os.unlink(sentinel)
    except FileNotFoundError:
        pass
    fd = os.open(sentinel, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW
                 | _CLOEXEC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, secrets.token_hex(16).encode())
    finally:
        os.close(fd)
    kw: dict = {}
    if privs is not None:
        kw.update(user=privs[0], group=privs[1], extra_groups=[])
    done = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-I", "-c", _PROBE_READER, str(sentinel)],
        env={"PATH": BASE_PATH}, cwd="/", stdin=subprocess.DEVNULL,
        capture_output=True, timeout=15, check=False, **kw)
    who = f"uid {privs[0]}" if privs is not None else "the gateway user"
    if done.returncode == 3:
        return ""
    if done.returncode == 0:
        return (f"{who} could read a 0600 file owned by the gateway "
                f"({sentinel}): this storage does not enforce permission bits "
                f"(clodia-platform#544), so a service uid isolates nothing")
    return (f"isolation probe inconclusive (exit {done.returncode}) as {who}: "
            f"failing closed")


# -- network exposure --------------------------------------------------------
_PROC_NET = ("/proc/net/tcp", "/proc/net/tcp6")


def _decode_address(hex_addr: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    raw = bytes.fromhex(hex_addr)
    # /proc/net stores each 32-bit word in host (little-endian) order.
    swapped = b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
    return ipaddress.ip_address(swapped)


def exposed_listeners(uid: int, tables: list[str] | None = None) -> list[str]:
    """TCP sockets in LISTEN owned by `uid` and bound outside loopback.

    Read from `/proc/net/tcp{,6}` of the gateway's network namespace, which the
    services share: cheap enough to run on every reconcile. UDP is covered by
    `exposed_udp`, which needs a different rule.
    """
    if tables is None:
        tables = []
        for name in _PROC_NET:
            try:
                tables.append(Path(name).read_text())
            except OSError:
                continue
    found: list[str] = []
    for table in tables:
        for line in table.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 8 or fields[3] != "0A":
                continue
            try:
                if int(fields[7]) != uid:
                    continue
                addr_hex, port_hex = fields[1].split(":")
                addr = _decode_address(addr_hex)
                port = int(port_hex, 16)
            except ValueError:
                continue
            mapped = getattr(addr, "ipv4_mapped", None)
            if addr.is_loopback or (mapped is not None and mapped.is_loopback):
                continue
            found.append(f"[{addr}]:{port}" if addr.version == 6 else f"{addr}:{port}")
    return found


_PROC_NET_UDP = ("/proc/net/udp", "/proc/net/udp6")

#: Intervallo delle porte effimere quando `/proc/sys` non si legge. È il
#: default del kernel Linux dal 2.6.
_EPHEMERAL = (32768, 60999)


def _ephemeral_range() -> tuple[int, int]:
    try:
        lo, hi = Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split()[:2]
        return int(lo), int(hi)
    except (OSError, ValueError):
        return _EPHEMERAL


def exposed_udp(uid: int, tables: list[str] | None = None,
                ephemeral: tuple[int, int] | None = None) -> list[str]:
    """UDP socket di `uid` che significano «sono raggiungibile da fuori».

    Il motivo per cui #515 aveva lasciato fuori UDP è vero: UDP non ha uno
    stato LISTEN, e un socket di CLIENT è anch'esso «bound». Quindi non si
    guarda il bind, si guarda cosa quel bind dichiara:

    * **connesso** (la parte remota ha una porta) = un client che ha già
      scritto a qualcuno. Mai segnalato — ed è il caso che rendeva inutile la
      regola ingenua, perché una volta connesso il kernel mette come indirizzo
      locale quello dell'interfaccia d'uscita, cioè un indirizzo NON loopback;
    * **loopback** = il caso buono, come per TCP;
    * **indirizzo specifico non-loopback, non connesso** = qualcuno ha scelto
      di stare su quell'interfaccia e di aspettare: è un servizio;
    * **wildcard, non connesso** = dipende dalla porta.

    SHORTCUT: sul wildcard la discriminante è l'intervallo delle porte
              effimere — un client riceve una porta da lì, un servizio ne
              sceglie una fissa fuori. Regge finché il pack non chiede una
              porta fissa DENTRO quell'intervallo, che è legale e qui
              passerebbe inosservata. Il modo di salire è farsi dichiarare la
              porta dal manifest (`Service`) e confrontare quella, invece di
              dedurla; allora questa euristica serve solo a chi non dichiara.
    """
    if tables is None:
        tables = []
        for name in _PROC_NET_UDP:
            try:
                tables.append(Path(name).read_text())
            except OSError:
                continue
    lo, hi = ephemeral if ephemeral is not None else _ephemeral_range()
    found: list[str] = []
    for table in tables:
        for line in table.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 8:
                continue
            try:
                if int(fields[7]) != uid:
                    continue
                addr_hex, port_hex = fields[1].split(":")
                addr = _decode_address(addr_hex)
                port = int(port_hex, 16)
                remote = int(fields[2].split(":")[1], 16)
            except ValueError:
                continue
            if remote:                      # connesso: è un client
                continue
            mapped = getattr(addr, "ipv4_mapped", None)
            if addr.is_loopback or (mapped is not None and mapped.is_loopback):
                continue
            if addr.is_unspecified and lo <= port <= hi:
                continue                    # porta effimera sul wildcard
            found.append(f"udp [{addr}]:{port}" if addr.version == 6
                         else f"udp {addr}:{port}")
    return found

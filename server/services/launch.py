"""Con che ambiente, con che identità e dove gira un servizio di pack (#515).

Separato dal supervisore perché sono le due domande che si verificano da sole:
`supervisor.py` decide *quando* avviare e riavviare, qui si decide *cosa*
riceve il processo. Tutto ciò che è di sicurezza sta in questo file.
"""
from __future__ import annotations

import json
import logging
import os
import shlex
import socket
import subprocess
import zlib
from pathlib import Path
from urllib.parse import urlparse

from .. import vault
from ..connectors.manifest import Service
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
    """
    base, span = _uid_base(), _uid_span()
    start = zlib.crc32(f"{service.pack}/{service.name}".encode()) % span
    for step in range(span):
        candidate = base + (start + step) % span
        if candidate not in taken:
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


def credentials_env(service: Service) -> dict[str, str]:
    """Le SOLE credenziali che il manifest dichiara, come JSON in una variabile
    ciascuna. Una credenziale assente ferma il servizio: partire senza è il modo
    di avere un processo vivo che fallisce ogni chiamata senza dire perché.

    Il valore non viene mai loggato né restituito da una rotta: esce da qui ed
    entra nell'ambiente del figlio, che gira con un uid diverso da quello di
    chiunque altro.
    """
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


def probe(service: Service, privs: tuple[int, int] | None = None
          ) -> tuple[bool, str]:
    """Esegue l'health check dichiarato. `(ok, motivo)`; mai un'eccezione."""
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
                              env=build_env(service), check=False, **kw)
        if done.returncode != 0:
            return False, f"health command: uscita {done.returncode}"
        return True, ""
    except Exception as exc:  # noqa: BLE001 - un probe non deve mai propagare
        return False, f"health {kind}: {type(exc).__name__}: {str(exc)[:120]}"

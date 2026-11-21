"""Il gateway non parte se l'uid di sandbox può leggere i suoi segreti (#544).

Su terra la datadir è il bind mount di una directory macOS attraverso virtiofs,
che **non applica i bit di permesso**: misurato, l'uid di sandbox di uno spawn
(60123) legge file mode 600 di root e scrive in `/datadir/clodia-vault`. Tutto
il confinamento per-uid — gli spawn di clodia-logic, i servizi di pack qui —
poggia su una garanzia che quel filesystem non dà, e nessuno se ne accorgeva:
non c'è errore, c'è un `open()` che riesce.

Questo modulo pone la domanda nell'unico modo che non si può sbagliare: crea un
sentinella 0600 e prova a leggerlo **con l'uid vero** del sandbox, in un figlio
con i privilegi lasciati cadere. Esito:

* ``PermissionError`` → il kernel sta applicando i bit: isolamento ok;
* letto → nessun isolamento, e in modalità ``enforce`` (il default) il gateway
  **rifiuta di avviarsi**. Un avviso che resta per sempre è l'infortunio di
  #382: il default non può essere ``warn``;
* qualunque altro esito → inconcludente, che vale come «non isolato». Un probe
  che non sa rispondere non può autorizzare l'avvio.

La condizione si corregge nello storage (clodia-logic#525: segreti e vault su
volume nominato, non su bind virtiofs), non qui: qui si rende impossibile che
passi inosservata.

The probe covers only the gateway's own directories. `check_datadir_mount`
looks at the rest of the datadir from the mount table and logs an ERROR when it
sits on virtiofs / 9p / FUSE (clodia-platform#554): it never blocks the start.
"""
from __future__ import annotations

import logging
import os
import re
import secrets as _secrets
import subprocess
import sys
from pathlib import Path

# The reference-monitor logger, which `tools/logs.py` also writes to the
# gateway's log FILE: a refusal to start that only reached stdout would be the
# blind spot of #382 again (review of clodia-tools#371).
LOG = logging.getLogger("clodia-tools.refmon")

#: Modalità del self-check, da `CLODIA_ISOLATION_SELFCHECK`.
#: ``enforce`` (default) = il gateway non parte; ``warn`` = CRITICAL e si parte
#: lo stesso; ``off`` = nessun probe (sviluppo locale, dove il gateway non è
#: root e non può nemmeno scendere di uid).
MODES = ("enforce", "warn", "off")
DEFAULT_MODE = "enforce"

#: Sottodirectory in cui vive il sentinella, dentro ogni directory sorvegliata.
PROBE_DIR = ".isolation-probe"

#: `PATH` del figlio: esplicito, mai ereditato (un elemento vuoto in coda
#: significherebbe «la directory corrente»).
BASE_PATH = "/usr/local/bin:/usr/bin:/bin"

#: Il figlio del probe. Exit 0 = ha LETTO il sentinella (nessun isolamento),
#: 3 = permesso negato (isolato), altro = inconcludente.
PROBE_READER = (
    "import sys\n"
    "try:\n"
    "    open(sys.argv[1], 'rb').read(1)\n"
    "except PermissionError:\n"
    "    sys.exit(3)\n"
    "except BaseException:\n"
    "    sys.exit(4)\n"
    "sys.exit(0)\n"
)

#: Stessa base del pool di uid dei servizi di pack (`services.launch`): è il
#: numero da cui partono gli uid non privilegiati di questa istanza quando
#: nessuno dichiara niente.
DEFAULT_SANDBOX_UID = 60000

_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)


def mode() -> str:
    """Modalità dichiarata. Un valore che non conosciamo vale ``enforce``:
    un refuso in una variabile d'ambiente non deve disattivare un controllo
    di sicurezza senza che nessuno lo dica."""
    raw = (os.environ.get("CLODIA_ISOLATION_SELFCHECK") or "").strip().lower()
    if not raw:
        return DEFAULT_MODE
    if raw in MODES:
        return raw
    LOG.warning("CLODIA_ISOLATION_SELFCHECK=%r non è fra %s: vale %s",
                raw, "/".join(MODES), DEFAULT_MODE)
    return DEFAULT_MODE


def probe_uid() -> int:
    """L'uid con cui porre la domanda: quello **vero** degli spawn.

    `CLODIA_AGENT_SANDBOX_UID` è la base del pool che clodia-logic alloca agli
    spawn (ed è dichiarata anche per questo container, clodia-logic#525). Senza
    di lei si ripiega sul pool degli uid dei servizi di pack, che in questo
    container girano davvero. Un uid inventato proverebbe qualcosa su un
    soggetto che non esiste: il risultato non direbbe niente sull'istanza.
    """
    for env in ("CLODIA_AGENT_SANDBOX_UID", "CLODIA_SERVICE_UID_BASE"):
        raw = (os.environ.get(env) or "").strip()
        if raw.isdigit() and int(raw) > 0:
            return int(raw)
    return DEFAULT_SANDBOX_UID


def guarded_dirs() -> list[Path]:
    """Le directory che il gateway deve tenere per sé, nell'ordine in cui
    conviene nominarle in un errore: la vault (credenziali vive), lo stato
    decisionale del reference monitor (#80), i segreti legacy."""
    from . import state_paths, vault
    out = [vault.vault_dir()]
    # Lo stato decisionale SOLO quando ha un volume suo (#80). Se non ce l'ha
    # vive nella datadir condivisa, e sorvegliarlo qui significherebbe provare
    # `/datadir` intero: su terra quel volume non isola per costruzione, il
    # gateway non ripartirebbe più nemmeno dopo aver messo in sicurezza vault e
    # segreti, e la prima mossa di chiunque sarebbe spegnere il controllo.
    # Quella metà del problema la chiude #80, non i bit di permesso.
    if state_paths.is_isolated():
        out.append(state_paths.state_dir())
    out.append(state_paths.shared_dir() / "secrets")
    visti: list[Path] = []
    for d in out:
        if d not in visti and d.is_dir():
            visti.append(d)
    return visti


def _sentinel(directory: Path) -> Path:
    root = directory / PROBE_DIR
    root.mkdir(parents=True, exist_ok=True)
    # 0711: il figlio deve poter ATTRAVERSARE la directory per arrivare al
    # file, se no «negato» misurerebbe il permesso della directory invece di
    # quello del file — e direbbe «isolato» su qualunque filesystem.
    os.chmod(root, 0o711)
    path = root / "sentinel"
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW
                 | _CLOEXEC, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, _secrets.token_hex(16).encode())
    finally:
        os.close(fd)
    return path


def denied(directory: Path, privs: tuple[int, int] | None, *,
           runner=None) -> str:
    """"" se `privs` NON riesce a leggere un file 0600 creato in `directory`,
    altrimenti il motivo per cui l'isolamento non è disponibile.

    `privs` a None = nessun privilegio da lasciar cadere: il figlio gira con
    l'utente del gateway, che il sentinella lo legge — ed è il verdetto giusto,
    perché senza poter scendere di uid non c'è isolamento da dimostrare.
    """
    run = runner or subprocess.run
    # Absolute: the child runs with cwd="/", and a relative CLODIA_DATA would
    # make the probe inconclusive for the wrong reason (review of #371).
    path = _sentinel(Path(directory).resolve())
    try:
        return _probe(path, privs, run)
    finally:
        # The sentinel is evidence of the check, not state: never leave it in
        # the vault or the secrets (it would end up in backups).
        try:
            os.unlink(path)
            os.rmdir(path.parent)
        except OSError:
            pass


def _probe(path: Path, privs: tuple[int, int] | None, run) -> str:
    kw: dict = {}
    if privs is not None:
        kw.update(user=privs[0], group=privs[1], extra_groups=[])
    done = run(  # noqa: S603 - argv fisso, nessuna shell
        [sys.executable, "-I", "-c", PROBE_READER, str(path)],
        env={"PATH": BASE_PATH}, cwd="/", stdin=subprocess.DEVNULL,
        capture_output=True, timeout=15, check=False, **kw)
    chi = f"uid {privs[0]}" if privs is not None else "l'utente del gateway"
    if done.returncode == 3:
        return ""
    if done.returncode == 0:
        return (f"{chi} could read a 0600 file owned by the gateway ({path}): "
                f"this storage does not enforce permission bits "
                f"(clodia-platform#544), so a dedicated uid isolates nothing")
    return (f"isolation probe inconclusive (exit {done.returncode}) as {chi}: "
            f"failing closed")


def selfcheck(*, runner=None) -> str:
    """"" quando ogni directory sorvegliata è protetta dai bit di permesso,
    altrimenti il primo motivo trovato. Un probe per FILESYSTEM: la proprietà è
    del volume, non della directory, e ripeterlo per directory sorelle costa
    processi senza aggiungere informazione."""
    if os.geteuid() != 0:
        return ("il gateway non è root e non può scendere all'uid di sandbox: "
                "l'isolamento non è dimostrabile. Per lo sviluppo locale si "
                "dichiara CLODIA_ISOLATION_SELFCHECK=off")
    uid = probe_uid()
    if uid <= 0 or uid == os.geteuid():
        return (f"l'uid del probe ({uid}) è quello del gateway o è privilegiato: "
                f"la domanda non avrebbe senso. Dichiarare "
                f"CLODIA_AGENT_SANDBOX_UID con la base del pool degli spawn")
    visti: set[int] = set()
    for directory in guarded_dirs():
        try:
            st = directory.stat()
        except OSError as exc:  # noqa: PERF203 - una dir illeggibile è un no
            return f"{directory} non è ispezionabile ({exc}): fallisco chiuso"
        if st.st_dev in visti:
            continue
        visti.add(st.st_dev)
        problema = denied(directory, (uid, uid), runner=runner)
        if problema:
            return problema
    return ""


#: Where the kernel lists this process's mounts. A module constant so tests
#: can point it at a fixture; absent outside Linux, where the check is moot.
MOUNTINFO = "/proc/self/mountinfo"

#: Filesystems that do NOT enforce POSIX permission bits for the container: a
#: host folder shared into the VM of a macOS/Windows runtime. virtiofs and 9p
#: (Colima, Lima, Docker Desktop), any FUSE (`fuse.grpcfuse`, `fuse.sshfs`),
#: OrbStack's `fakeowner`. A named Docker volume shows the VM's own filesystem
#: (ext4, btrfs, xfs, overlay) and is not matched.
PERMISSIONLESS_FSTYPES = ("virtiofs", "9p", "fakeowner")


def _unescape_mount_field(field: str) -> str:
    """mountinfo octal-escapes space, tab, newline and backslash (`\\040`)."""
    return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), field)


def mount_fstype(mountpoint: Path, *, mountinfo: str | None = None) -> str:
    """The fstype of the mount AT `mountpoint` (exact match), "" if `mountpoint`
    is not itself a mount point or mountinfo is unreadable. The LAST matching
    line wins: a later mount on the same point covers the earlier ones."""
    target = str(mountpoint)
    try:
        text = Path(mountinfo or MOUNTINFO).read_text(encoding="utf-8",
                                                      errors="replace")
    except OSError:
        return ""
    found = ""
    for line in text.splitlines():
        # `id parent maj:min root mountpoint opts [optional...] - fstype src super`
        left, sep, right = line.partition(" - ")
        if not sep:
            continue
        fields = left.split()
        if len(fields) < 5 or _unescape_mount_field(fields[4]) != target:
            continue
        tail = right.split()
        if tail:
            found = tail[0]
    return found


def permissionless(fstype: str) -> bool:
    return fstype in PERMISSIONLESS_FSTYPES or fstype == "fuse" \
        or fstype.startswith("fuse.")


def datadir_mount_problem(*, mountinfo: str | None = None) -> str:
    """"" unless the shared datadir is mounted from a filesystem that ignores
    permission bits — then the reason, naming clodia-platform#554.

    The probe above covers only the gateway's own directories (vault, state,
    legacy secrets). The REST of the datadir — transcripts, spawns, audit,
    topics, data, pack services' state — is what every spawn uid could read on
    a virtiofs bind (terra, until 19 Nov 2026). Asked of the mount table rather
    than with a sentinel: the answer is a property of the filesystem, and the
    datadir root is shared with the agent-server, where a probe file would be
    one more thing to clean up."""
    from . import state_paths
    datadir = state_paths.shared_dir().resolve()
    fstype = mount_fstype(datadir, mountinfo=mountinfo)
    if not fstype or not permissionless(fstype):
        return ""
    return (f"{datadir} is mounted from a {fstype} filesystem, which does not "
            f"enforce permission bits: every spawn uid can read transcripts, "
            f"audit, topics and pack-service state there "
            f"(clodia-platform#554). Move the datadir to a named Docker volume: "
            f"scripts/migrate-datadir-to-volume.sh in clodia-platform")


def check_datadir_mount(*, mountinfo: str | None = None) -> str:
    """Log an ERROR when the datadir sits on a permissionless filesystem. Never
    blocks the start: on such a host the gateway's own secrets are already
    guarded by the probe (or by named volumes), and refusing to start over the
    rest would push operators to switch the whole check off."""
    try:
        problem = datadir_mount_problem(mountinfo=mountinfo)
    except Exception as exc:  # noqa: BLE001 - a diagnostic must not crash boot
        LOG.warning("datadir mount check skipped (%s: %s)",
                    type(exc).__name__, str(exc)[:200])
        return ""
    if problem:
        LOG.error("DATADIR NOT ISOLATED: %s", problem)
    return problem


def check_at_boot(*, runner=None) -> None:
    """Il self-check all'avvio del gateway. In `enforce` solleva `SystemExit`.

    Va chiamato DOPO l'aggancio del log su file: un CRITICAL che esce solo su
    stdout è fuori portata di chi deve diagnosticarlo da dentro la colonia
    (#382), ed è esattamente la riga che qui spiega perché il gateway non parte.
    """
    # Independent of the mode: it only logs, and `off` is exactly the setup in
    # which nobody would otherwise notice (#554).
    check_datadir_mount()
    scelta = mode()
    if scelta == "off":
        LOG.warning("self-check di isolamento DISATTIVATO "
                    "(CLODIA_ISOLATION_SELFCHECK=off): nessuna garanzia che "
                    "l'uid di sandbox non legga la vault (clodia-platform#544)")
        return
    try:
        problema = selfcheck(runner=runner)
    except Exception as exc:  # noqa: BLE001 - un probe che esplode è un no
        problema = (f"self-check di isolamento fallito "
                    f"({type(exc).__name__}: {str(exc)[:200]})")
    if not problema:
        LOG.info("self-check di isolamento: l'uid %s non legge i file 0600 del "
                 "gateway", probe_uid())
        return
    LOG.critical("ISOLAMENTO ASSENTE: %s", problema)
    if scelta == "warn":
        LOG.critical("CLODIA_ISOLATION_SELFCHECK=warn: il gateway parte lo "
                     "stesso, con la vault leggibile da qualunque spawn")
        return
    raise SystemExit(
        "clodia-tools: avvio rifiutato, isolamento assente "
        f"(clodia-platform#544): {problema}")

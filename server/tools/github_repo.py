"""`github.*` — le azioni git che ATTRAVERSANO il confine dello scope.

§5.2 della specifica: «A topic has **no git remote**. Actions that cross the
boundary — clone, pull, push, pull request — are performed by the **gateway**,
with the credential the owner supplied; git stays in the agent's container only
for scratch-local work: `add`, `diff`, `commit`.»

È il §4.1 applicato a git. `add` e `commit` restano dentro lo scope e non
passano di qui: l'agente li esegue nella propria scratch con il git del suo
container. `clone`, `pull`, `push` e la pull request escono, quindi li esegue il
gateway.

**La credenziale non entra mai nel processo dell'agente.** È la ragione per cui
questo modulo esiste, e la proprietà più facile da perdere senza accorgersene:
un `git clone https://<token>@github.com/...` funziona, e lascia il token in
`.git/config` — dentro la scratch, che l'agente legge. Da qui due regole:

  1. il token viaggia SOLO in `GIT_PAT`, letto al volo da un credential helper
     passato con `-c` a ogni invocazione (mai persistito, mai in argv);
  2. dopo il clone l'origin è riscritto all'URL PULITO, e si verifica che nel
     `.git/config` risultante non compaia il segreto.

La seconda non è ridondante rispetto alla prima: la prima è una scelta di
questo file, la seconda è un controllo su ciò che è finito su disco. Un
meccanismo di sicurezza che non misura il proprio esito è una convenzione.

**Il perimetro.** Il repository è una voce di whitelist dello scope (§5.2),
confrontata per repository e non per host: un cap per host direbbe solo «github
sì», che con una credenziale capace è un perimetro nominale. Niente in lista =
nessun confinamento, che è la direzione giusta della retrocompatibilità — una
lista vuota che chiudesse tutto verrebbe spenta il giorno stesso.
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
from pathlib import Path

LOG = logging.getLogger("clodia-tools.github")

#: Lo stesso helper di `topics/remote.py`, e per la stessa ragione: username
#: convenzionale GitHub per l'auth via token, valore preso da env al volo.
_CRED_HELPER = (
    "!f() { test \"$1\" = get && "
    "printf 'username=x-access-token\\npassword=%s\\n' \"$GIT_PAT\"; }; f"
)
_TIMEOUT = 180


class GitHubError(RuntimeError):
    """Un rifiuto o un fallimento di un verbo `github.*`."""


#: `file://` è rifiutato: il git del gateway vede il filesystem del gateway, e
#: un `file:///datadir/...` sarebbe una lettura del vault o del topic-store con
#: la forma di un clone. La lista dei repository approvati lo fermerebbe già —
#: questa è la seconda linea, quella che vale se la lista è vuota (e vuota
#: significa «nessun confinamento», §5.2).
#: Il seam esiste per i test, che clonano da un repository locale vero invece
#: che da un finto: si sposta ciò che è raggiungibile, non la regola.
ALLOW_LOCAL_REPOS = False


def normalize_repo(url: str) -> str:
    """URL di repository in forma canonica `https://host/owner/repo`.

    Serve perché lo stesso repository si scrive in almeno quattro modi — con
    `.git`, con lo slash finale, in SSH, con le credenziali nell'URL — e un
    confronto testuale con la whitelist direbbe «non approvato» a un repository
    approvato. Un perimetro che rifiuta a caso viene spento.

    La forma breve `owner/repo` è la quinta: è come GitHub stesso nomina un
    repository, ed è quella che si scrive a mano. Qui vale
    `https://github.com/owner/repo` — l'host default è un'assunzione, dichiarata
    perché non è deducibile: un repository di un GitHub Enterprise va scritto
    per intero. Non allarga il perimetro, perché la voce di whitelist si
    confronta DOPO la normalizzazione: una forma breve non approvata resta
    negata.
    """
    u = str(url or "").strip()
    if not u:
        raise GitHubError("repository mancante")
    m = re.match(r"^git@([^:]+):(.+)$", u)          # git@host:owner/repo
    if m:
        u = f"https://{m.group(1)}/{m.group(2)}"
    u = re.sub(r"^ssh://", "https://", u)
    # `owner/repo` (e `owner/repo.git`): due soli segmenti, nessuno schema e
    # nessuno slash iniziale. I caratteri sono quelli che GitHub ammette in un
    # nome: così un path del filesystem — `/datadir/vault`, `../etc/passwd` —
    # non può entrare da questa porta travestito da forma breve.
    if "://" not in u and re.match(r"^[A-Za-z0-9][\w.-]*/[A-Za-z0-9][\w.-]*$",
                                   u.rstrip("/")):
        u = f"https://github.com/{u.rstrip('/')}"
    if u.startswith("file://"):
        if not ALLOW_LOCAL_REPOS:
            raise GitHubError(
                "un repository locale (file://) non è un repository remoto: "
                "il git del gateway vede il filesystem del gateway")
        return u.rstrip("/")
    u = re.sub(r"^(https?://)[^/@]+@", r"\1", u)     # credenziali nell'URL: via
    u = re.sub(r"\.git$", "", u.rstrip("/"))
    if not re.match(r"^https?://[^/]+/[^/]+/[^/]+$", u):
        # Il messaggio dice QUALI forme valgono: un rifiuto che nomina solo la
        # forma canonica manda a indovinare, e chi indovina riprova con la
        # stessa forma sbagliata.
        raise GitHubError(
            f"'{url}' non ha la forma di un repository: serve "
            "'https://host/owner/repo' (o la forma breve 'owner/repo', "
            "che vale su github.com)")
    return u


def _run(args: list, cwd: str | None, token: str | None) -> subprocess.CompletedProcess:
    cmd = ["git"]
    if token:
        host = "https://github.com"
        cmd += ["-c", f"credential.{host}.helper={_CRED_HELPER}"]
    if cwd:
        cmd += ["-C", cwd]
    cmd += list(args)
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    if token:
        env["GIT_PAT"] = token
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=_TIMEOUT)
    if r.returncode != 0:
        # L'errore di git può contenere l'URL con le credenziali se qualcuno le
        # ha messe lì: si riporta ripulito, altrimenti il segreto esce dal
        # gateway attraverso il messaggio d'errore — la via meno sorvegliata.
        err = _redact((r.stderr or r.stdout or "").strip(), token)
        raise GitHubError(f"git {args[0]} fallito: {err[:600]}")
    return r


def _redact(text: str, token: str | None) -> str:
    out = re.sub(r"(https?://)[^/@\s]+@", r"\1", text or "")
    if token:
        out = out.replace(token, "«credenziale»")
    return out


def _assert_no_secret_on_disk(workdir: str, token: str | None) -> None:
    """Il controllo che rende la proprietà misurata invece che dichiarata.

    Se il token comparisse in `.git/config`, l'agente lo leggerebbe con un
    `cat` — e l'intero disegno («la credenziale non entra nel processo
    dell'agente») sarebbe soddisfatto sulla carta e falso sul disco.
    """
    cfg = Path(workdir) / ".git" / "config"
    try:
        testo = cfg.read_text(errors="ignore")
    except OSError:
        return
    if token and token in testo:
        raise GitHubError(
            "la credenziale è finita in .git/config: operazione interrotta e "
            "working tree da considerare compromesso")
    if re.search(r"https?://[^/@\s]+:[^/@\s]+@", testo):
        raise GitHubError("credenziali incorporate nell'origin: operazione interrotta")


# ── I verbi ─────────────────────────────────────────────────────────────────

def remote_url(workdir: str) -> str:
    """URL del remote `origin` di un working tree, o stringa vuota.

    Serve a chi deve giudicare la DESTINAZIONE di un push: il verbo riceve una
    directory, e il repository sta nel remote. Non solleva — chi chiama sta
    decidendo se chiedere un permesso, e un errore qui deve valere «non lo so»,
    che porta a chiedere.
    """
    try:
        out = _run(["remote", "get-url", "origin"], cwd=workdir, token=None)
        return normalize_repo(out.stdout.strip())
    except Exception:  # noqa: BLE001
        return ""


def clone(repo: str, dest: str, token: str | None = None,
          branch: str | None = None) -> dict:
    """Clona un repository APPROVATO nella scratch dello spawn chiamante.

    `dest` è già validato da chi chiama (`_safe_scratch_path`): qui non si
    ricontrolla, perché due controlli sullo stesso path in due file divergono —
    ed è il difetto ricorrente di questa settimana. Qui si controlla ciò che
    solo qui si sa: che l'URL sia un repository e che il segreto non resti.
    """
    url = normalize_repo(repo)
    d = Path(dest)
    if d.exists() and any(d.iterdir()):
        raise GitHubError(f"la destinazione non è vuota: {dest}")
    d.parent.mkdir(parents=True, exist_ok=True)
    args = ["clone", "--quiet"]
    if branch:
        args += ["--branch", branch]
    args += [url, str(d)]
    _run(args, cwd=None, token=token)
    # L'origin torna all'URL pulito: il clone lo scrive già senza credenziali
    # (viaggiano nell'helper), ma riscriverlo rende la proprietà indipendente da
    # come git decide di salvare l'URL — che è una scelta di git, non nostra.
    _run(["remote", "set-url", "origin", url], cwd=str(d), token=None)
    _assert_no_secret_on_disk(str(d), token)
    testa = _run(["rev-parse", "--short", "HEAD"], cwd=str(d), token=None).stdout.strip()
    ramo = _run(["rev-parse", "--abbrev-ref", "HEAD"], cwd=str(d), token=None).stdout.strip()
    return {"ok": True, "repo": url, "dir": str(d), "branch": ramo, "head": testa}


def pull(workdir: str, token: str | None = None) -> dict:
    _assert_repo(workdir)
    out = _run(["pull", "--ff-only", "--quiet"], cwd=workdir, token=token)
    _assert_no_secret_on_disk(workdir, token)
    return {"ok": True, "dir": workdir,
            "head": _run(["rev-parse", "--short", "HEAD"], cwd=workdir, token=None).stdout.strip(),
            "output": _redact((out.stdout or "").strip(), token)}


def push(workdir: str, token: str | None = None, branch: str | None = None) -> dict:
    """Manda FUORI ciò che l'agente ha committato nella sua scratch.

    Non committa: il commit è dentro lo scope e lo fa l'agente. Se questo verbo
    committasse, la separazione «dentro/fuori» sarebbe scritta nella specifica e
    non nel codice.
    """
    _assert_repo(workdir)
    ramo = branch or _run(["rev-parse", "--abbrev-ref", "HEAD"],
                          cwd=workdir, token=None).stdout.strip() or "HEAD"
    sporco = _run(["status", "--porcelain"], cwd=workdir, token=None).stdout.strip()
    out = _run(["push", "--quiet", "origin", ramo], cwd=workdir, token=token)
    return {"ok": True, "branch": ramo,
            # Ciò che NON è partito, perché non era committato. Tacerlo lascia
            # credere di aver pubblicato un lavoro che è ancora solo locale.
            "uncommitted": len([r for r in sporco.splitlines() if r.strip()]),
            "output": _redact((out.stderr or out.stdout or "").strip(), token)}


def _assert_repo(workdir: str) -> None:
    if not (Path(workdir) / ".git").is_dir():
        raise GitHubError(f"non è un working tree git: {workdir}")


def pull_request(repo: str, head: str, base: str, title: str,
                 body: str = "", token: str | None = None) -> dict:
    """Apre una pull request. Attraversa il confine due volte: il codice esce e
    il titolo/corpo diventano pubblici sul repository."""
    import json
    import urllib.error
    import urllib.request

    url = normalize_repo(repo)
    if "github.com" not in url:
        raise GitHubError(f"pull request supportata solo su github.com: {url}")
    if not token:
        raise GitHubError("nessuna credenziale per questo repository: "
                          "l'owner la fornisce al mount (topic.remote_enable)")
    owner_repo = url.split("github.com/", 1)[1]
    req = urllib.request.Request(
        f"https://api.github.com/repos/{owner_repo}/pulls",
        data=json.dumps({"title": title, "head": head, "base": base,
                         "body": body or ""}).encode(),
        headers={"Authorization": f"Bearer {token}",
                 "Accept": "application/vnd.github+json",
                 "Content-Type": "application/json",
                 "User-Agent": "clodia-gateway"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            d = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        det = _redact(e.read().decode(errors="ignore")[:400], token)
        raise GitHubError(f"pull request rifiutata da GitHub ({e.code}): {det}") from e
    except urllib.error.URLError as e:
        # Irraggiungibile non è «negato»: un guasto travestito da rifiuto manda
        # a cercare un permesso che non manca.
        raise GitHubError(f"GitHub irraggiungibile: {e.reason}") from e
    return {"ok": True, "number": d.get("number"), "url": d.get("html_url"),
            "state": d.get("state")}

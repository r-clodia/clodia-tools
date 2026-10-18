"""Repository URL normalisation, for the egress PDP and the host API.

The git client that lived here (`clone`, `pull`, `push`, `pull_request`, the
credential helper, the on-disk secret check) moved into it-pack's gateway
component as `gateway/git_core.py` (clodia-platform#525): the gateway no longer
runs git. What stays is the one definition of «the shape of a repository»,
which the PDP (`connectors/normalise.py`, `repo_url`) and the host
(`perimeter.require_approved_repo`) share — two definitions would drift.
"""
from __future__ import annotations

import re


class GitHubError(RuntimeError):
    """A repository that is not one."""


#: `file://` is refused: a local repository is the gateway's filesystem, not a
#: remote. The seam exists for tests only.
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

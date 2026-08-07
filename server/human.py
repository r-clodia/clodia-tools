"""human — ruolo e matrice dei principal umani, letti dal loro seed.

Perché dalla datadir e non dalla config del gateway. La regola generale è che
l'autorità non deve stare dove il soggetto può riscriverla (#80), e per gli
agenti questo significa `config.yaml` sul volume del gateway, che il container
degli agenti non monta. Il seed di un umano è un caso diverso e va verificato,
non assunto: `/datadir/agents/` è `drwx------ root:root`, e gli spawn girano come
uid 60000. Misurato — uno spawn non riesce **né a leggere né a scrivere**
`/datadir/agents/davide/agent.yaml`.

Quindi qui il confine lo mette il **kernel**, non logica applicativa, ed è più
robusto di un controllo nel nostro codice. È anche il posto da cui il gateway già
legge il ruolo umano (`tools_api._is_human_admin`), quindi leggere la matrice
dalla stessa fonte non introduce una seconda verità — e soprattutto non crea
un'altra «dichiarazione che nessuno trasporta», che è il modo in cui oggi
falliscono i nostri controlli più spesso che per una decisione sbagliata.

Se un domani gli spawn dovessero poter leggere quella cartella, questa scelta va
rifatta: la sua validità dipende da una misura, non da un'intenzione.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

LOG = logging.getLogger("clodia-tools.human")

_ADMIN_ROLES = ("superadmin", "admin")
_CACHE: dict[str, tuple[float, dict]] = {}
_TTL = 30.0


def _seed_path(name: str) -> Path:
    root = Path(os.environ.get("CLODIA_DATA", "/datadir"))
    return root / "agents" / name / "agent.yaml"


def _seed(name: str) -> dict:
    """Il seed di un principal, con cache breve. `{}` se assente o illeggibile."""
    import time
    if not name:
        return {}
    hit = _CACHE.get(name)
    now = time.time()
    if hit and (now - hit[0]) < _TTL:
        return hit[1]
    d: dict = {}
    p = _seed_path(name)
    try:
        if p.is_file():
            import yaml
            d = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except Exception as e:                       # noqa: BLE001
        LOG.warning("seed di '%s' illeggibile (%s)", name, type(e).__name__)
        d = {}
    if not isinstance(d, dict):
        d = {}
    _CACHE[name] = (now, d)
    return d


def is_human(name: str) -> bool:
    return _seed(name).get("type") == "human"


def role(name: str) -> str:
    """`superadmin` | `admin` | `user`. Un seed illeggibile NON è admin."""
    d = _seed(name)
    if d.get("type") != "human":
        return "user"
    r = str(d.get("role") or "user")
    return r if r in _ADMIN_ROLES else "user"


def declared_role(name: str) -> Optional[str]:
    """Il ruolo COSÌ COME È SCRITTO nel seed, per la visualizzazione.

    Diverso da `role()`, che normalizza a `admin|superadmin|user` perché serve
    alla decisione. Confonderli fa mostrare `user` a una persona il cui seed dice
    `member`, e allora la scheda non riconcilia col file — chi la legge conclude
    che il sistema stia guardando un altro dato.
    """
    d = _seed(name)
    if d.get("type") != "human":
        return None
    r = d.get("role")
    return str(r) if r else "user"


def is_admin(name: str) -> bool:
    return role(name) in _ADMIN_ROLES


#: I DUE SEED FONDAMENTALI degli umani (voce 20).
#:
#: «Gli umani sono agenti come gli altri, ma non hanno provider, non forkano
#: spawn — sono essi stessi spawn di due seed fondamentali: admin e member. Il
#: loro seed definisce verbi e tier.»
#:
#: Prima di oggi i seed NON esistevano: `grep 'type: human' catalogs/` non
#: trovava nulla, e ogni umano era un `agent.yaml` individuale che poteva
#: portarsi la propria `tool_permissions`. La matrice era quindi **per persona** e
#: derivava: due member sulla stessa istanza potevano avere verbi diversi senza
#: che nessuno l'avesse deciso. È precisamente ciò che un seed impedisce.
#:
#: Stanno nel CODICE e non nella datadir per due ragioni. Sono fondamentali — se
#: fossero file, un'istanza potrebbe non averli, e «i due seed» smetterebbe di
#: essere un'affermazione vera ovunque. E l'autorità non deve stare dove il
#: soggetto può riscriverla (#80): la datadir la scrive l'agent-server, questo
#: modulo no. `config.yaml` può comunque sovrascriverli (chiave `human_seeds`),
#: perché resta sul volume del solo gateway.
SEED_ADMIN = "admin"
SEED_MEMBER = "member"

#: Cosa un member può invocare DIRETTAMENTE. Derivata dai namespace reali, non
#: inventata: fuori restano i cinque che cambiano le regole della macchina —
#: `agents`, `packs`, `providers`, `mcp`, `settings` — più `workflows`, che è in
#: via di rimozione.
#:
#: Non è una duplicazione dei gate: è difesa in profondità nell'altro verso. Un
#: gate chiede un consenso quando l'azione parte; questa lista dice che per un
#: member certe azioni non partono affatto. Se un verbo amministrativo restasse
#: gated per errore, il member lo troverebbe comunque chiuso.
_MEMBER_NAMESPACES = (
    "artifact", "egress", "email", "eu_corpus", "fs", "gcalendar", "gdocs",
    "gdrive", "gsheets", "image", "ingress", "integrations", "jobs", "logs",
    "memory", "profile", "rag", "runtime", "telegram", "topic", "trello",
    "web",
)

_BUILTIN_SEEDS: dict[str, dict] = {
    SEED_ADMIN: {"tool_permissions": ["*"]},
    SEED_MEMBER: {"tool_permissions": [f"{ns}.*" for ns in _MEMBER_NAMESPACES]},
}


def seeds() -> dict[str, dict]:
    """I due seed, con l'eventuale override da `config.yaml` (`human_seeds`)."""
    try:
        from .whitelist import CONFIG
        over = (CONFIG or {}).get("human_seeds")
    except Exception:  # noqa: BLE001 — senza config valgono i built-in
        over = None
    if not isinstance(over, dict):
        return dict(_BUILTIN_SEEDS)
    out = {k: dict(v) for k, v in _BUILTIN_SEEDS.items()}
    for k, v in over.items():
        if isinstance(v, dict):
            out[k] = dict(v)
    return out


def seed_of(name: str) -> Optional[str]:
    """Di quale dei due seed questa persona è spawn. `None` se non è un umano.

    Il ruolo scritto nel seed individuale dice a quale CLASSE la persona
    appartiene; la classe dice quali verbi ha. Un fatto per posto: il ruolo è
    per persona e sta nel suo file, la matrice è per classe e sta qui.
    """
    d = _seed(name)
    if d.get("type") != "human":
        return None
    return SEED_ADMIN if str(d.get("role") or "") in _ADMIN_ROLES else SEED_MEMBER


def is_instance_owner(name: str) -> bool:
    """`superadmin` non è un admin più forte: è il PROPRIETARIO dell'istanza, un
    singleton, usato come destinatario di ripiego quando un gate va notificato e
    il principal non è umano. Con due soli seed diventa un ATTRIBUTO dello spawn
    admin, non un terzo seed (voce 20, precisazione 1).

    Il campo nel file resta `role: superadmin` per ora: rinominarlo tocca
    l'autenticazione, e non è il pezzo che questa modifica deve muovere.
    """
    return str(_seed(name).get("role") or "") == "superadmin"


def seed_matrix(name: str) -> Optional[list[str]]:
    """I verbi che il SEED della persona concede. `None` se non è un umano."""
    s = seed_of(name)
    if not s:
        return None
    tp = (seeds().get(s) or {}).get("tool_permissions")
    if tp is None:
        return None
    return [str(x) for x in tp] if isinstance(tp, list) else []


def matrix(name: str) -> Optional[list[str]]:
    """Verbi dichiarati per questo umano, o `None` se non dichiara nulla.

    `None` e `[]` sono cose diverse e la distinzione è il cuore della
    migrazione: `None` significa «non si pronuncia» → si ricade sulla regola
    precedente; `[]` significa «nessun verbo» → l'umano non può invocare niente
    direttamente. Trattare l'assenza come lista vuota disconnetterebbe ogni
    utente esistente al primo deploy; trattare la lista vuota come assenza
    renderebbe impossibile dichiarare un utente di sola lettura.
    """
    d = _seed(name)
    if d.get("type") != "human":
        return None
    tp = d.get("tool_permissions")
    if tp is None:
        return None
    return [str(x) for x in tp] if isinstance(tp, list) else []


def clearance(name: str) -> Optional[str]:
    c = _seed(name).get("clearance")
    return str(c) if c else None


def reset_cache() -> None:
    _CACHE.clear()

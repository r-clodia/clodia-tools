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

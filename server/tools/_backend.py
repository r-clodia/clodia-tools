"""L'errore dell'agent-server, tradotto in un'eccezione che PORTA il motivo.

`raise_for_status()` di httpx nomina metodo e URL e non guarda il corpo: proprio
le due cose che il chiamante sapeva già, e non l'unica che non sapeva. Il 403 di
clodia-platform#297 (`403 Forbidden — POST http://agent-server:7842/clodia/packs/
studio-legale/setup-done`) è quella stringa, mentre il backend nel corpo aveva
già scritto quale verbo era negato e a chi.

Due lati, non uno:

- il TESTO — `{"detail": ...}` di `HTTPException`, `{"error": ...}` di
  `JSONResponse`: in `clodia-logic` esistono entrambe le forme, e leggerne una
  sola lascia metà dei motivi nel corpo;
- la CLASSE — `call_tool` smista per eccezione: `PermissionError` diventa
  `DENIED:` e finisce nel run record dei rifiuti (clodia-platform#206),
  qualunque altra diventa `ERROR:`. Un rifiuto travestito da guasto non si vede
  né come l'uno né come l'altro.

Solo il 403 è un rifiuto. Il 503 del PDP che non ha *deciso* resta un guasto e
lo dice: tradurlo in «non hai i permessi» manda a cercare un permesso che c'è,
ed è la diagnosi che la #297 è costata tre volte.
"""
from __future__ import annotations

# Un corpo non JSON (una pagina d'errore di un proxy) va riportato, non
# ricopiato per intero: il messaggio finisce in chat davanti a una persona.
_MAX_TESTO = 400


def _motivo(response) -> str:
    try:
        payload = response.json()
    except Exception:  # noqa: BLE001 — corpo non JSON: si ripiega sul testo
        payload = None
    if isinstance(payload, dict):
        detail = str(payload.get("detail") or payload.get("error") or "").strip()
        if detail:
            return detail
    return (getattr(response, "text", "") or "").strip()[:_MAX_TESTO]


def raise_for_backend_error(response, *, policy_deny: bool = True) -> None:
    """Solleva l'eccezione corrispondente allo status, col motivo del backend.

    403 → `PermissionError` (rifiuto), qualunque altro >= 400 → `ValueError`
    (guasto). Sotto il 400 non fa niente, come `raise_for_status`.

    `policy_deny=False` per le chiamate a rotte che NON autorizzano per verbo —
    le GET di metadati di `runtime.*`, per esempio. Lì un 403 non può venire da
    una policy: verrebbe da un intermediario, e registrarlo come rifiuto
    conterebbe come decisione un guasto — la confusione della #297, al
    contrario. Il motivo passa comunque; cambia solo la classe.
    """
    status = getattr(response, "status_code", 0)
    if status < 400:
        return
    motivo = _motivo(response)
    if status == 403 and policy_deny:
        raise PermissionError(motivo or f"azione non consentita (HTTP {status})")
    raise ValueError(motivo or f"richiesta rifiutata dal backend (HTTP {status})")

"""Autorizzazione UNICA delle rotte HTTP interne (`/internal/*`) del gateway.

`http_app.build_app()` monta sullo stesso processo e sulla stessa porta il
`Mount("/mcp", …)` — avvolto da `_AuthMiddleware` — e tutte le rotte interne. Il
percorso HTTP interno però non è il percorso MCP, e le due autorizzazioni non
erano la stessa cosa: sette moduli ricopiavano la stessa costante e lo stesso
controllo (`agent ∈ CLODIA_PROVIDER_PRINCIPALS`), e nessuno guardava il tetto
`scoped_tools` né la revoca (clodia-platform#261).

Il claim `agent` non è chi chiama: è il **carrier**. `proxy_auth.token_for` conia
sull'identità del carrier — di norma `clodia`, cioè esattamente il principal
privilegiato che queste API ammettono — e sul percorso MCP quel token è stretto a
quattro verbi di chat. Fuori da `/mcp` quel tetto non veniva letto: con lo stesso
bearer si leggeva il vault e si riscriveva la whitelist dei verbi di un agente.

Questo modulo è il posto **unico** da cui prendere la regola. Chi aggiunge la
prossima rotta interna non deve ricostruirla: chiama `authorize(...)` e, se la
rotta corrisponde a un verbo del gateway, lo dichiara.

    payload, err = internal_auth.authorize(request, verb="topic.messages")
    if err:
        return err

Ordine dei controlli, dal più economico al più costoso, e tutti fail-closed:

1. firma/`aud`/`exp` del bearer ckt1 (`verify_session_token`) → 401;
2. **revoca** (`human_mcp.is_revoked`), la stessa lettura che fa
   `_AuthMiddleware` su `/mcp`: senza, un token revocato restava valido su ogni
   rotta interna fino alla scadenza naturale → 401;
3. `agent ∈ principals()`, il controllo che c'era già → 403;
4. `on_behalf`: rifiutato salvo `allow_on_behalf=True`. Le rotte
   infrastrutturali (vault, provider, whitelist, connettori, imagegen, telegram)
   non hanno un ramo umano — chi le chiama è il runner di clodia-logic con un
   token nudo sul principal. Il ramo umano vive su `/internal/tool` e
   `/internal/authorize` (`tool_api`), dove resta ammesso → 403;
5. tetto `scoped_tools` (`whitelist.scoped_ceiling_allows`, la stessa regola di
   `main._scoped_ceiling_ok`): un token che porta il claim può arrivare **solo**
   alle rotte il cui verbo sta sotto il tetto. Una rotta senza verbo dichiarato
   non è raggiungibile da un token scoped: è la direzione giusta dell'ignoranza,
   perché il verbo mancante è una dichiarazione mancante, non un permesso → 403.

Un token senza `scoped_tools` non ha tetto e passa come prima: i chiamanti reali
(`git_client`, `provider_store`, `topics_client`, `telegram_client`,
`connectors_client`, `imagegen_client`, `gateway_admin`, `pack_deprovision` in
clodia-logic) coniano tutti `pki.mint_session_token(_PRINCIPAL, ttl)` — senza
`scoped_tools`, senza `on_behalf`, senza `execution_id`. Un insieme di verbi
indovinato al posto di questo censimento spegnerebbe un servizio in produzione.
"""
from __future__ import annotations

import logging
import os

from starlette.requests import Request
from starlette.responses import JSONResponse

from . import human_mcp, whitelist
from .pki_verify import verify_session_token

LOG = logging.getLogger("clodia-tools.internal_auth")


def principals() -> frozenset[str]:
    """I principal privilegiati ammessi sulle rotte interne (default: `clodia`).

    Letta a ogni richiesta e non fotografata all'import: sette moduli tenevano
    ognuno la propria copia congelata al momento dell'import, e quella copia è la
    ragione per cui i test dovevano ricaricare i moduli per cambiare l'env.
    L'insieme è minuscolo e la lettura di una variabile d'ambiente non è il costo
    di questa richiesta.
    """
    raw = os.environ.get("CLODIA_PROVIDER_PRINCIPALS") or "clodia"
    return frozenset(p.strip() for p in raw.split(",") if p.strip())


def bearer(request: Request) -> str:
    auth = request.headers.get("authorization", "")
    return auth[7:] if auth.lower().startswith("bearer ") else ""


def _no(status: int, error: str) -> JSONResponse:
    return JSONResponse({"error": error}, status_code=status)


def refuse_if_revoked(payload: dict, log: logging.Logger | None = None,
                      ) -> JSONResponse | None:
    """401 se la sessione è revocata, `None` se no.

    Estratta perché ha due chiamanti: `authorize` e la facciata del PDP
    (`tool_api`), che il resto di questa regola non lo vuole — ma la revoca sì.
    """
    log = log or LOG
    gid = payload.get("execution_id")
    try:
        revocato = human_mcp.is_revoked(gid)
    except Exception:  # noqa: BLE001
        # Su `/mcp` un difetto qui viene loggato e la richiesta prosegue, per non
        # chiudere il gateway. Qui no: dietro queste rotte ci sono il vault e la
        # whitelist, e `is_revoked` non tocca il disco per i token che non
        # portano un `execution_id` `mcp_*` — cioè per tutti i chiamanti reali.
        # Chi può inciampare in questa riga è solo una sessione umana.
        log.error("verifica revoca fallita (%s): nego", gid)
        return _no(401, "unauthorized")
    if revocato:
        log.warning("sessione revocata su rotta interna: %s", gid)
        return _no(401, "unauthorized")
    return None


def authorize(request: Request, *, verb: str | None = None,
              allow_on_behalf: bool = False,
              log: logging.Logger | None = None,
              ) -> tuple[dict | None, JSONResponse | None]:
    """`(payload, None)` se la richiesta è ammessa, `(None, risposta)` se no."""
    log = log or LOG
    try:
        payload = verify_session_token(bearer(request))
    except PermissionError as e:
        log.warning("auth interna fallita: %s", e)
        return None, _no(401, "unauthorized")

    err = refuse_if_revoked(payload, log=log)
    if err:
        return None, err

    agent = str(payload.get("agent") or "")
    if agent not in principals():
        log.warning("principal '%s' non autorizzato sulle rotte interne", agent)
        return None, _no(403, "forbidden")

    if payload.get("on_behalf") and not allow_on_behalf:
        log.warning("sessione on-behalf rifiutata su rotta interna "
                    "(principal=%s, kind=%s)", payload.get("principal"),
                    human_mcp.principal_kind_of(payload))
        return None, _no(403, "forbidden")

    tetto = payload.get("scoped_tools") or []
    if tetto and not (verb and whitelist.scoped_ceiling_allows(verb, tetto)):
        log.warning("token scoped (%d verbi) rifiutato su rotta interna: "
                    "verbo richiesto %s", len(tetto), verb or "-")
        return None, _no(403, "forbidden")

    return payload, None

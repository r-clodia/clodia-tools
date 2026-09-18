"""egress_api — read-only view of the egress confinement, for the agent-server.

Why an endpoint at all. The trifecta score is computed in the agent-server, but
the destination whitelist lives in the GATEWAY's config, on a volume the
agent-server deliberately does not mount (clodia-platform#80: whoever can rewrite
the whitelist self-grants destinations). So the score cannot read the data it now
needs, and the only correct way across that boundary is the existing
server-to-server channel.

Authentication: `CLODIA_ORCHESTRATOR_SECRET` (`X-Orchestrator-Secret`), the same
as `/internal/logic-run` and `/internal/mint`. Not reachable from a spawn.

What it returns is metadata only — the mode and, per agent, which destination
types have rules and how many. **Never the destinations themselves**: an
address book is private data, and the score does not need it to tell arbitrary
egress from circumscribed egress. Sending the list would put the owner's
contacts into the context of whatever renders the score.
"""
from __future__ import annotations

import hmac
import logging
import os

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

LOG = logging.getLogger("clodia-tools.egress-api")


def _authorized(request: Request) -> bool:
    expected = (os.environ.get("CLODIA_ORCHESTRATOR_SECRET") or "").strip()
    if not expected:
        return False  # fail-closed
    got = (request.headers.get("x-orchestrator-secret") or "").strip()
    return bool(got) and hmac.compare_digest(got, expected)


def _shape(uris: list) -> dict:
    """Forma di una lista, senza gli indirizzi: quante voci e di quali schemi.

    `wide` copre l'opt-out esplicito `*`: una lista che lo contiene è dichiarata
    ma non vincola niente, e riportarla come circoscritta sarebbe la sola
    direzione d'errore che questa misura non può permettersi.
    """
    if not uris:
        return {"scope": "none", "count": 0, "schemes": []}
    if "*" in uris:
        return {"scope": "wide", "count": len(uris), "schemes": ["*"]}
    return {"scope": "listed", "count": len(uris),
            "schemes": sorted({str(u).partition(":")[0] for u in uris})}


async def profile(request: Request):
    """GET /internal/egress → modo + FORMA delle liste, mai le destinazioni.

    Il consumatore è il punteggio trifecta, che per distinguere uscita
    circoscritta da arbitraria non ha bisogno degli indirizzi e non deve averli:
    una rubrica è dato privato, e finirebbe nel contesto di qualunque cosa
    renderizzi il numero.
    """
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from . import egress
    out = {"mode": egress.mode(),
           "egress": _shape(egress.allowed_uris()),
           "source": _shape(egress.source_uris())}
    # Query di APPARTENENZA, non dump: `?uri=gdrive:folder/1AbC` risponde
    # `allowed: true|false`. Serve al punteggio trifecta, che deve sapere se il
    # remote di un canale punta a una destinazione vagliata — ma NON deve
    # ricevere la lista: una rubrica è dato privato. Il chiamante conosce già
    # l'URI (viene dal meta del topic), quindi chiedendo non impara nulla di
    # nuovo; ricevendo la lista imparerebbe tutto.
    q = (request.query_params.get("uri") or "").strip()
    if q:
        out["query"] = q
        # `direction=ingress` gira la stessa domanda dall'altro lato: non «posso
        # scrivere a X» ma «è fidato ciò che arriva da X», cioè `is_vetted_source`
        # — la funzione che decide davvero, non una sua copia. Serve all'altro
        # lato del confine: il relay Telegram vive nell'agent-server, che non
        # monta il volume del gateway di proposito (clodia-platform#80), quindi
        # senza questa risposta dovrebbe rifare il match (wildcard di schema,
        # prefissi gerarchici, voci degeneri) in una seconda copia che diverge
        # alla prima modifica (clodia-platform#365).
        #
        # `scope` nomina la stanza di cui vale la lista, e va passato quando il
        # bersaglio NON è il chiamante — qui non lo è mai, perché la chiamata
        # arriva da un server, non da dentro un canale. Omesso significa «solo la
        # lista globale»: la direzione restrittiva, l'unica che si può sbagliare
        # senza aprire niente.
        if (request.query_params.get("direction") or "").strip().lower() in (
                "ingress", "source"):
            scope = (request.query_params.get("scope") or "").strip() or None
            out["direction"] = "ingress"
            out["scope"] = scope
            out["vetted"] = egress.is_vetted_source(q, scope)
        else:
            out["allowed"] = any(egress._matches(q, r) for r in egress.allowed_uris())
    return JSONResponse(out)


async def observations(request: Request):
    """GET /internal/observations?since=<epoch> → gate che SAREBBERO scattati.

    Alimenta il feedback effimero nel footer della webui: in modalità di
    osservazione l'owner lavora come prima, e questo è l'unico modo in cui vede
    che un controllo *avrebbe* chiesto qualcosa. Senza, l'osservazione è muta e
    l'unico modo di leggerla sarebbe aprire il registro a mano.

    Solo metadati, come il registro da cui legge.
    """
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        since = int(request.query_params.get("since") or 0)
    except ValueError:
        since = 0
    limit = 50
    from . import observe, telemetry
    rows = []
    try:
        p = telemetry._path()
        if p.is_file():
            import json as _j
            for line in p.read_text(encoding="utf-8").splitlines()[-2000:]:
                try:
                    r = _j.loads(line)
                except ValueError:
                    continue
                if r.get("outcome") in ("would_gate", "would_deny") \
                        and int(r.get("at") or 0) > since:
                    rows.append(r)
    except OSError as e:
        return JSONResponse({"error": str(e)[:120], "observations": []})
    return JSONResponse({"observing": observe.skipping(),
                         "observations": rows[-limit:]})


async def whitelist_view(request: Request):
    """GET /internal/egress/whitelist → le due liste globali, in notazione URI.

    Diverso da `/internal/egress`, che ritorna solo la forma: là il consumatore è
    il punteggio; qui è l'owner nelle impostazioni, che ha tutto il diritto di
    vedere la propria rubrica — è la sua.
    """
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from . import egress
    return JSONResponse(egress.summary())


async def scope_whitelist_view(request: Request):
    """GET /internal/egress/whitelist/scope/{tier}/{name} → le due liste
    LOCALI di un topic, in notazione URI.

    Gemella di `whitelist_view`, ma per lo scope invece che per l'istanza:
    `scope_uris` esisteva già (nato con #150, la lista per-canale) ma non era
    mai stato esposto fuori dal modulo — la webui non aveva modo di mostrare
    all'owner cosa vale SOLO in questo topic, distinto da ciò che vale
    ovunque. Nessuna nuova logica di lettura: la stessa funzione che
    `effective_uris` già usa per fare l'unione.
    """
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    tier = request.path_params["tier"]
    name = request.path_params["name"]
    from . import egress
    scope = f"{tier}/{name}"
    return JSONResponse({
        "egress": egress.scope_uris("egress", scope),
        "ingress": egress.scope_uris("ingress", scope),
    })


async def scope_whitelist_edit(request):
    """Aggiunge o rimuove una voce dalle liste LOCALI di un topic, a mano.

    Richiesta di Davide, 18 set 2026: «devo poter aggiungere manualmente un
    egress/ingress nella sidebar di canale» — gemella scoped di `whitelist_edit`
    sopra, con la stessa divisione di responsabilità: il gateway esegue e non
    conosce i ruoli umani, l'agent-server verifica che il chiamante sia OWNER
    dello scope (non basta un admin qualunque: qui il perimetro che si sposta è
    di una stanza precisa) prima di inoltrare.

    Stesso storage di `scope_allow`/`scope_revoke` (`egress.py`, nato con
    l'epic Telegram #359/#364): niente logica nuova qui, solo la porta HTTP che
    mancava — i verbi MCP `topic.egress_add`/`ingress_add` esistevano già per
    gli AGENTI, ma un umano dalla webui non passa da un turno per compilare un
    form.
    """
    if not _authorized(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    direzione = request.path_params["direction"]
    if direzione not in ("egress", "ingress"):
        return JSONResponse({"error": "direction_invalid"}, status_code=400)
    tier = request.path_params["tier"]
    name = request.path_params["name"]
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = {}
    uri = str((body or {}).get("uri") or "").strip()
    if not uri:
        return JSONResponse({"error": "uri_required"}, status_code=400)
    azione = request.path_params["action"]
    from . import egress as eg
    scope = f"{tier}/{name}"
    try:
        if azione == "allow":
            out = eg.scope_allow(direzione, scope, uri)
        elif azione == "revoke":
            out = eg.scope_revoke(direzione, scope, uri)
        else:
            return JSONResponse({"error": "action_invalid"}, status_code=400)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    return JSONResponse({"ok": True, **out})


async def whitelist_edit(request):
    """Aggiunge o rimuove una voce dalle liste globali, per conto dell'OWNER.

    Richiesta dell'owner, 17 ago 2026: «devo poter inserire un egress o ingress
    anche a mano». Fino a oggi le liste si riempivano solo attraverso il dialog
    del gate — che è il posto giusto quando la destinazione arriva da un agente
    che la chiede, e nessun posto quando l'owner sa già cosa vuole censire (le
    cento fonti di un digest non passano da cento dialog).

    La validazione NON è qui: la fa `egress.allow`, che rifiuta gli schemi della
    direzione sbagliata (`mailfrom:` in uscita) e le voci degeneri
    (`gdrive:folder/`, che aprirebbe l'intero Drive). Duplicarla qui vorrebbe dire
    due regole che divergono al primo cambiamento.

    Rotta INTERNA: chi verifica che il richiedente sia admin è l'agent-server. Il
    gateway non conosce i ruoli umani, e un controllo che non può fare sarebbe un
    controllo per finta.
    """
    direzione = request.path_params["direction"]
    if direzione not in ("egress", "ingress"):
        return JSONResponse({"error": "direction_invalid"}, status_code=400)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        body = {}
    uri = str((body or {}).get("uri") or "").strip()
    if not uri:
        return JSONResponse({"error": "uri_required"}, status_code=400)
    azione = request.path_params["action"]
    from . import egress as eg
    try:
        if azione == "allow":
            out = eg.allow(direzione, uri)
        elif azione == "revoke":
            out = eg.revoke(direzione, uri)
        else:
            return JSONResponse({"error": "action_invalid"}, status_code=400)
    except ValueError as e:
        # Un URI rifiutato è un errore dell'utente, non del server: torna 400 col
        # MOTIVO, perché «non valido» non dice come correggerlo.
        return JSONResponse({"error": str(e)}, status_code=400)
    return JSONResponse({"ok": True, **out})


routes = [Route("/internal/egress", profile, methods=["GET"]),
          Route("/internal/egress/whitelist", whitelist_view, methods=["GET"]),
          Route("/internal/egress/whitelist/scope/{tier}/{name}", scope_whitelist_view,
                methods=["GET"]),
          Route("/internal/egress/whitelist/{direction}/{action}", whitelist_edit,
                methods=["POST"]),
          Route("/internal/egress/whitelist/scope/{tier}/{name}/{direction}/{action}",
                scope_whitelist_edit, methods=["POST"]),
          Route("/internal/observations", observations, methods=["GET"])]

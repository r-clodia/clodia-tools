"""Endpoint interni M-gate.

Il consenso a un verbo *gated* è un artefatto crittografico: una capability
`ccap1` firmata dalla CA (`cap = gate:<verb>`), coniata dal flusso di
approvazione umano di clodia-logic (che verifica la RBAC dell'approvatore sul
verbo). Qui il gateway: elenca le richieste pending, registra il consenso
verificando la firma CA (`gate.grant`), nega/risolve. Auth ckt1 come gli altri
/internal; la RBAC-per-verbo dell'approvatore è applicata a monte (clodia-logic)
e la firma CA è la prova non falsificabile.
"""
import logging

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import gate, internal_auth
from .pki_verify import verify_session_token

LOG = logging.getLogger("clodia-tools.gate_api")


def _authorize(request: Request):
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    try:
        payload = verify_session_token(token)
    except PermissionError as e:
        LOG.warning("gate_api auth fallita: %s", e)
        return None, JSONResponse({"error": "unauthorized"}, status_code=401)
    # Il consenso di un umano è per definizione una sessione on-behalf, quindi
    # qui non si applica il resto di `internal_auth`; la revoca sì, che su `/mcp`
    # c'è e qui mancava — una sessione revocata concedeva gate (#261).
    err = internal_auth.refuse_if_revoked(payload, log=LOG)
    if err:
        return None, err
    principal = str(payload.get("principal") or "")
    if not principal:
        return None, JSONResponse({"error": "forbidden"}, status_code=403)
    return principal, None


async def grant(request: Request):
    """POST /internal/gate/grant {agent, instance, verb, token} — registra il
    consenso (capability ccap1 gate:<verb>). fail-closed se la firma non verifica."""
    principal, err = _authorize(request)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "bad_json"}, status_code=400)
    agent = (body.get("agent") or "").strip()
    instance = (body.get("instance") or "-").strip() or "-"
    verb = (body.get("verb") or "").strip()
    token = body.get("token") or ""
    if not (agent and verb and token):
        return JSONResponse({"error": "agent/verb/token richiesti"}, status_code=400)
    try:
        res = gate.grant(agent, instance, verb, token)
    except PermissionError as e:
        LOG.warning("gate grant rifiutato %s@%s:%s — %s", agent, instance, verb, e)
        return JSONResponse({"error": "bad_capability", "detail": str(e)}, status_code=400)
    gate.resolve_request(agent, instance, verb)
    LOG.info("GATE consenso %s@%s:%s da %s (%ss)", agent, instance, verb,
             principal, res.get("expires_in_s"))
    return JSONResponse({"ok": True, **res})


async def deny(request: Request):
    """POST /internal/gate/deny {agent, instance, verb} — nega la richiesta."""
    principal, err = _authorize(request)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "bad_json"}, status_code=400)
    agent = (body.get("agent") or "").strip()
    instance = (body.get("instance") or "-").strip() or "-"
    verb = (body.get("verb") or "").strip()
    removed = gate.resolve_request(agent, instance, verb)
    LOG.info("GATE richiesta NEGATA %s@%s:%s da %s: %s", agent, instance, verb,
             principal, removed)
    return JSONResponse({"ok": True, "denied": removed})


async def pending(request: Request):
    """GET /internal/gate/pending — richieste di gate in attesa (per il popup)."""
    _principal, err = _authorize(request)
    if err:
        return err
    return JSONResponse({"requests": gate.list_requests(), "gated": gate.gated_verbs_spec()})


async def remember(request: Request):
    """POST /internal/gate/allow {verb, direction, scope?} — rende PERMANENTE una
    destinazione approvata, nella lista dello scope o in quella globale.

    Un gate di uscita è la domanda «questa destinazione va bene?». Rispondere
    solo «per stavolta» significa riproporre la stessa domanda ogni volta, e una
    domanda che torna identica si finisce per approvarla per riflesso — cioè il
    gate smette di essere un controllo e diventa un rumore da spegnere.
    Ricordare la risposta è ciò che tiene il gate significativo: chiede quando
    c'è qualcosa di nuovo da decidere.

    Chi ha titolo lo decide clodia-logic **prima** di chiamare qui: l'owner
    della stanza per la lista di quella stanza, un admin per quella globale. La
    verifica sta là perché là si conosce l'identità umana; qui si scrive.
    """
    principal, err = _authorize(request)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "bad_json"}, status_code=400)
    verb = (body.get("verb") or "").strip()
    direction = (body.get("direction") or "egress").strip()
    scope = (body.get("scope") or "").strip()
    # `egress:<tipo>:<destinazione>` — la destinazione contiene i ':' dell'URL,
    # quindi si divide al massimo due volte e il resto è l'URI.
    parti = verb.split(":", 2)
    if len(parti) != 3 or parti[0] not in ("egress", "ingress"):
        return JSONResponse(
            {"error": f"'{verb}' non è un gate di destinazione: solo egress/ingress "
                      "si possono ricordare, perché solo lì la decisione riguarda "
                      "un indirizzo e non un'azione"}, status_code=400)
    uri = parti[2]
    from . import egress as _eg
    try:
        res = (_eg.scope_allow(direction, scope, uri) if scope
               else _eg.allow(direction, uri))
    except (ValueError, PermissionError) as e:
        return JSONResponse({"error": str(e)[:300]}, status_code=400)
    LOG.info("GATE ricordato %s → %s (%s) da %s", uri,
             scope or "GLOBALE", direction, principal)
    return JSONResponse({"remembered": True, "uri": uri,
                         "scope": scope or None, "direction": direction, **res})


routes = [
    Route("/internal/gate/allow", remember, methods=["POST"]),
    Route("/internal/gate/grant", grant, methods=["POST"]),
    Route("/internal/gate/deny", deny, methods=["POST"]),
    Route("/internal/gate/pending", pending, methods=["GET"]),
]

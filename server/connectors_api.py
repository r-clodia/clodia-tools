"""connectors_api — the connectors of this instance, generically.

clodia-platform#519. Until now every connector had its own routes, one family
per vendor (`tg-link`, `mailbox-link`, `drive-folder`, `/tools/google/*`,
`/tools/telegram/*`). The registry of #518 made that unnecessary for the
READING side: what a connector is, which schemes it speaks, which button it adds
to a topic and which credential it needs is declared in its manifest, so one
route can serve all of them and a connector arriving with a pack appears without
a deploy.

Three routes here:

    GET  /internal/connectors                    what is installed (#520)
    POST /internal/connectors/validate           what a candidate block would do
    POST /internal/tools/connectors/{id}/connect the credential a provider declares

The second is the install-time half: `pack_import` in clodia-logic asks before
registering a pack, the way it already asks `/flow-allow` for the flow
declarations. The verdict is computed in `connectors/validate.py` — see there
for why a refusal and an «ignored because the gateway still implements it» are
two different answers, and only the first stops an installation.

**No secret is ever returned.** A provider is described by the NAME of its vault
entry and by whether something is stored under it, never by its contents.
"""
from __future__ import annotations

import logging

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import instance_profile, vault
from .connectors import resolved as _resolved
from .connectors import validate as _validate
from .connectors.manifest import vault_entry_problem

LOG = logging.getLogger("clodia-tools.connectors-api")


def _authorize(request: Request):
    """The ADMIN check of the Tools routes (`tools_api._authorized`).

    Review of #359: `internal_auth.authorize(allow_on_behalf=True)` let ANY
    human session through. The real callers are an admin at the Tools page
    (on-behalf with `human_role: admin`) and `pack_import` in clodia-logic,
    which mints a plain session token for its principal (`clodia`) — both pass
    here, a non-admin session does not.
    """
    from . import tools_api
    if not tools_api._authorized(request):
        LOG.warning("connectors: richiesta non autorizzata (serve un admin)")
        return {}, JSONResponse({"error": "unauthorized"}, status_code=401)
    return {}, None


def _allowed(cid: str) -> bool:
    """The instance profile decides which connectors exist here at all.

    Asked per connector rather than filtering a list afterwards, so a connector
    that the profile excludes is missing from the listing for the same reason it
    is refused at the Tools page: one rule, one place (`connector_check`).
    """
    try:
        instance_profile.connector_check(cid)
        return True
    except PermissionError:
        return False


async def list_connectors(request: Request):
    """GET /internal/connectors → the installed connectors, from the registry.

    Includes the ones the gateway still implements itself (`builtin: true`):
    from the outside they are connectors like the others, which is the point of
    declaring them in the same grammar. `problems` is not an error field — it
    says why the list may be shorter than the packs installed, and an empty
    registry with no reason shown is the failure that looks like «no packs».
    """
    _payload, err = _authorize(request)
    if err:
        return err
    reg = _resolved.registry()
    rows = [_validate.summary(c) for c in reg.connectors if _allowed(c.id)]
    # `services`: ciò che il supervisore (#515) sta davvero facendo girare, non
    # ciò che il manifest dichiara — sono due cose diverse esattamente quando
    # serve saperlo, cioè quando un servizio non parte.
    from . import services as _services
    return JSONResponse({
        "connectors": rows,
        "schemes": {"egress": list(reg.scheme_names("egress")),
                    "source": list(reg.scheme_names("source"))},
        "services": _services.snapshot(),
        "problems": list(_resolved.problems()),
        "ignored": list(reg.refused),
    })


async def validate_connectors(request: Request):
    """POST /internal/connectors/validate {pack, connectors} → verdict, no write.

    Called by `pack_import` before it registers a pack. Answers `ok: false` only
    for what is wrong wherever and whenever it is asked; a declaration that is
    merely inert on this instance today comes back in `ignored`, with `ok: true`
    — a pack must not become uninstallable because the gateway has not finished
    its own migration.
    """
    _payload, err = _authorize(request)
    if err:
        return err
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "bad_json"}, status_code=400)
    body = body or {}
    out = _validate.validate(str(body.get("pack") or ""), body.get("connectors"))
    if out["errors"]:
        LOG.warning("connectors: blocco rifiutato per il pack '%s': %s",
                    out["pack"], out["errors"][0])
    return JSONResponse(out)


async def connect(request: Request):
    """POST /internal/tools/connectors/{id}/connect {provider?, fields…}.

    La credenziale che il manifest DICHIARA: `kind: form` → i campi dichiarati
    finiscono nella voce di vault dichiarata, e niente altro. Un campo che il
    provider non dichiara viene ignorato, così il corpo della richiesta non può
    scrivere nel vault chiavi che nessuno ha previsto.

    Credenziale di infrastruttura, senza grant per-agente: la legge il gateway
    quando materializza i segreti di una chiamata, e un agente non deve poterla
    ottenere in mano. Per disconnettere si mandano i campi vuoti.

    **La risposta non contiene mai ciò che è stato scritto.** Dice che c'è, non
    cosa c'è.

    `kind: oauth` **non passa di qui**: un consenso OAuth ha credenziali
    d'applicazione, uno stato da custodire fra le due gambe del giro e un
    callback, e oggi quelle cose vivono nelle rotte del provider (Google su
    tutte). Renderle generiche senza il manifest che le descrive sarebbe
    riscriverle, non generalizzarle — resta a #520, che porta la UI.
    """
    _payload, err = _authorize(request)
    if err:
        return err
    cid = request.path_params["id"]
    if not _allowed(cid):
        return JSONResponse({"error": f"connettore '{cid}' non ammesso su "
                                      f"questa istanza"}, status_code=403)
    connector = _resolved.registry().by_id(cid)
    if connector is None:
        return JSONResponse({"error": f"connettore '{cid}' non installato"},
                            status_code=404)
    if connector.builtin:
        # Review of #360: a connector the gateway implements itself has a
        # credential whose SHAPE its native code reads (`github_pat` is
        # `{"value": pat}`, read by `proxy._resolve_secrets`) and side effects
        # around it (the MCP backend, `_connector_guard`, the integrations
        # profile). The generic route delegates to that handler, so the two
        # URLs are one behaviour; with no handler it refuses.
        legacy = _LEGACY_CONNECT.get(cid)
        if legacy is None:
            return JSONResponse(
                {"error": f"il connettore '{cid}' è del gateway: si collega "
                          f"dalla sua pagina, non da qui"}, status_code=400)
        return await _delegate(legacy, request, connector)
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "bad_json"}, status_code=400)
    body = body or {}
    scelto = str(body.get("provider") or "").strip()
    providers = [p for p in connector.providers
                 if not scelto or p.id == scelto]
    if len(providers) != 1:
        nomi = ", ".join(p.id for p in connector.providers) or "nessuno"
        return JSONResponse(
            {"error": f"indica quale provider di '{cid}' connettere: {nomi}"},
            status_code=400)
    provider = providers[0]
    cred = provider.credential
    if cred is None or cred.kind != "form":
        return JSONResponse(
            {"error": f"il provider '{provider.id}' non si connette con un "
                      f"form: la sua credenziale è "
                      f"'{cred.kind if cred else 'assente'}'"},
            status_code=400)
    # The vault entry is the connector's own (review of #359/#360). Checked at
    # load already; again here because what the route writes or REMOVES must
    # never be decided by a file on a volume the gateway does not own.
    problem = vault_entry_problem(cred.vault_entry, connector.namespace)
    owner_type = _cred_type(connector)
    esistente = vault.credential_type(cred.vault_entry)
    if not problem and esistente is not None and esistente != owner_type:
        problem = (f"la voce di vault '{cred.vault_entry}' esiste già e non è "
                   f"di questo connettore")
    if problem:
        LOG.warning("connettore '%s': voce di vault rifiutata (%s)", cid, problem)
        return JSONResponse({"error": problem}, status_code=409)

    bundle = {}
    mancanti = []
    for field in cred.fields:
        value = str(body.get(field.name) or "").strip()
        if value:
            bundle[field.name] = value
        elif field.required:
            mancanti.append(field.name)
    if not bundle:
        # Tutti i campi vuoti = disconnessione esplicita, come fa oggi
        # `openai_connect` con `api_key: ""`.
        vault.remove(cred.vault_entry)
        LOG.info("connettore '%s': credenziale '%s' rimossa", cid,
                 cred.vault_entry)
        return JSONResponse({"connected": False, "connector": cid,
                             "provider": provider.id,
                             "vault_entry": cred.vault_entry})
    if mancanti:
        return JSONResponse({"error": "campi richiesti mancanti: "
                                      + ", ".join(mancanti)}, status_code=400)
    vault.deposit(cred.vault_entry, bundle, cred_type=owner_type,
                  grant_agents=[])
    # Mai il contenuto nei log: solo che è successo, e su quale voce.
    LOG.info("connettore '%s': credenziale '%s' depositata (%d campi)", cid,
             cred.vault_entry, len(bundle))
    return JSONResponse({"connected": True, "connector": cid,
                         "provider": provider.id,
                         "vault_entry": cred.vault_entry})


def _cred_type(connector) -> str:
    """The vault `type` a connector's credential is written with: it is how the
    route later recognises an entry as THIS connector's before touching it."""
    return f"connector:{connector.id}"


#: Built-in connectors whose credential has a dedicated handler in `tools_api`.
_LEGACY_CONNECT = {"github": "github_connect"}


async def _delegate(handler_name: str, request: Request, connector):
    """Run the legacy handler and answer in the generic route's shape."""
    import json as _json

    from . import tools_api
    resp = await getattr(tools_api, handler_name)(request)
    if resp.status_code != 200:
        return resp
    try:
        body = _json.loads(resp.body)
    except Exception:  # noqa: BLE001
        return resp
    provider = connector.providers[0] if connector.providers else None
    cred = provider.credential if provider else None
    return JSONResponse({"connected": bool(body.get("connected")),
                         "connector": connector.id,
                         "provider": provider.id if provider else "",
                         "vault_entry": cred.vault_entry if cred else ""})


routes = [
    Route("/internal/connectors", list_connectors, methods=["GET"]),
    Route("/internal/connectors/validate", validate_connectors, methods=["POST"]),
    Route("/internal/tools/connectors/{id}/connect", connect, methods=["POST"]),
]

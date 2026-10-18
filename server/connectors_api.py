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

Two of them answer at a SECOND address as well (#520):

    GET  /tools/connectors                       = /internal/connectors
    POST /tools/connectors/{id}/connect          = /internal/tools/connectors/…

Same functions, same authorisation, no second logic — only the prefix differs,
because `/internal/` is server-to-server by construction and the webui's proxy
does not forward it (`vite.config.ts` routes `/tools` to the gateway and nothing
else). They are the URLs #519 names in its Goal, so the registry reaches the
page it was built for instead of being readable only from the inside.

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
    rows = [_with_connected(_validate.summary(c))
            for c in reg.connectors if _allowed(c.id)]
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


def _with_connected(row: dict) -> dict:
    """Adds `connected` to each provider of a listing row: a BOOLEAN, nothing else.

    `summary()` says which vault entry a provider would use; it cannot say
    whether anything is stored under it, because the install preview shares it
    and there the question has no meaning. The Tools page asks exactly that,
    though, and without an answer a connector that arrives with a pack can only
    ever be drawn as «not connected» (clodia-platform#520).

    Deliberately not a connector-level field: a connector with no declared
    provider — `mail`, whose mailboxes are configured elsewhere — would come
    back `connected: false` while the page shows its boxes working, and a state
    that contradicts the page next to it is worse than a state that is missing.
    The answer is `vault.has_credential`, which never reads the contents.
    """
    for provider in row.get("providers") or ():
        entry = str(provider.get("vault_entry") or "")
        provider["connected"] = bool(entry) and vault.has_credential(entry)
    return row


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
        if cid == "telegram":
            # No native Telegram any more (#522): its credential is comms-pack's
            # connector's, deposited by this route in `pack` position.
            return JSONResponse(
                {"error": "Telegram non ha più un'implementazione nativa: metti "
                          "`connectors: {telegram: pack}` nel profilo e installa "
                          "comms-pack ≥ 2.2.0, poi collega il bot da qui"},
                status_code=409)
        legacy = _LEGACY_CONNECT.get(cid)
        if legacy is None:
            return JSONResponse(
                {"error": f"il connettore '{cid}' è del gateway: si collega "
                          f"dalla sua pagina, non da qui"}, status_code=400)
        return await _delegate(legacy, request, connector)
    adopted = _LEGACY_ADOPTED.get(cid)
    if adopted is not None:
        # In `pack` position (#525) the connector is the pack's, but the
        # credential is still read by the GATEWAY in the shape its handler
        # writes: `github_pat` = `{"value"}` of type `mcp_secret`,
        # `openai_api_key` = `{"api_key"}` of type `api_key`. The generic
        # deposit would refuse those entries (their type is not
        # `connector:<id>`) or rewrite them in a type the native position
        # does not recognise — so the handler keeps doing it, with the grant
        # to clodia and the profile checks around it. Only when the pack
        # declares that very entry: a different one is not what the gateway
        # reads, and accepting it would deposit a credential nobody uses.
        entries = {p.credential.vault_entry for p in connector.providers
                   if p.credential is not None}
        if entries and entries != {adopted}:
            return JSONResponse(
                {"error": f"il connettore '{cid}' deve dichiarare la voce di "
                          f"vault '{adopted}', quella che il gateway legge"},
                status_code=409)
        return await _delegate(_LEGACY_CONNECT[cid], request, connector)
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
    # The entry the removed native handler wrote (`telegram_bot_token`, type
    # `api_key`, #522) is the same credential: adopted, so the bot can be
    # rotated or disconnected from here; the deposit rewrites its type.
    _adottabile = (cid == "telegram" and esistente == "api_key"
                   and cred.vault_entry == "telegram_bot_token")
    if (not problem and esistente is not None and esistente != owner_type
            and not _adottabile):
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
#: Ognuno fa, attorno al deposito, qualcosa che il deposito generico non fa e
#: che non va perso: GitHub monta/smonta il backend MCP ufficiale, OpenAI passa
#: per il gating `integrations` del profilo. (Telegram non c'è più: il suo
#: handler nativo è stato rimosso con il client, #522.) La rotta generica delega, così le due URL
#: restano UN comportamento e la webui può chiamarne una sola (#520).
_LEGACY_CONNECT = {"github": "github_connect",
                   "openai-images": "openai_connect"}


#: Connectors whose credential the GATEWAY keeps reading after the switch to
#: `pack` (clodia-platform#525): `{connector id: the vault entry it reads}`.
#: The generic route delegates to the legacy handler for them in BOTH
#: positions, so the entry keeps its shape and type (`mcp_secret`, `api_key`)
#: and switching back to `native` finds it where it always was. Telegram is
#: not here: in `pack` position its credential is the pack's own (#522).
_LEGACY_ADOPTED = {"github": "github_pat", "openai-images": "openai_api_key"}


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
    # Lo stesso, dove il browser arriva (#520). Le funzioni sono quelle sopra:
    # un alias che rifacesse l'autorizzazione sarebbe una seconda regola, e la
    # seconda regola è quella che un giorno dice il contrario della prima —
    # qui in particolare #539 §5 sta restringendo `_authorize`, e questo
    # ingresso eredita la stretta perché non ne ha uno suo.
    Route("/tools/connectors", list_connectors, methods=["GET"]),
    Route("/tools/connectors/{id}/connect", connect, methods=["POST"]),
]

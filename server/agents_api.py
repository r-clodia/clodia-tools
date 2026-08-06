"""Endpoint INTERNO per registrare un agent nella whitelist del gateway.

Serve all'auto-provisioning dei responder confinati (clone per-topic dal backend):
quando il backend crea un'identità confinata per un canale, la registra qui così
la sua sessione MCP può aprirsi (l'auth middleware richiede l'agent in config.yaml).
Auth ckt1 ristretta al principal privilegiato (clodia), come gli altri /internal.
"""
from __future__ import annotations

import logging
import os

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import whitelist
from .pki_verify import verify_session_token

LOG = logging.getLogger("clodia-tools.agents_api")

_PRINCIPALS = {
    p.strip() for p in (os.environ.get("CLODIA_PROVIDER_PRINCIPALS") or "clodia").split(",")
    if p.strip()
}


def _authorize(request: Request):
    auth = request.headers.get("authorization", "")
    token = auth[7:] if auth.lower().startswith("bearer ") else ""
    try:
        payload = verify_session_token(token)
    except PermissionError as e:
        LOG.warning("agents_api auth fallita: %s", e)
        return None, JSONResponse({"error": "unauthorized"}, status_code=401)
    agent = str(payload.get("agent") or "")
    if agent not in _PRINCIPALS:
        return None, JSONResponse({"error": "forbidden"}, status_code=403)
    return agent, None


async def register(request: Request):
    """POST /internal/agents/whitelist {agent, allowed_tools?} → upsert config.yaml."""
    _agent, err = _authorize(request)
    if err:
        return err
    body = await request.json()
    name = (body.get("agent") or "").strip()
    if not name:
        return JSONResponse({"error": "agent richiesto"}, status_code=400)
    # `gated_tools` arriva dal SEED (dichiarazione) e viene custodito qui
    # (autorità): il seed vive sulla datadir insieme al codice degli agenti, e un
    # agente capace di riscriverlo cancellerebbe i propri gate. Assente nel corpo
    # → non si tocca ciò che è già registrato: un chiamante vecchio non deve
    # poter azzerare i gate per omissione.
    spec = whitelist.upsert_agent(name, allowed_tools=body.get("allowed_tools"),
                                  gated_tools=body.get("gated_tools"),
                                  gated_in_channel=body.get("gated_in_channel"))
    whitelist.reload_config()
    return JSONResponse({"ok": True, "agent": name,
                         "allowed_tools": spec.get("allowed_tools"),
                         "gated_tools": spec.get("gated_tools") or [],
                         "gated_in_channel": spec.get("gated_in_channel") or []})


async def flow_allow(request: Request):
    """POST /internal/agents/flow-allow → concede le voci di flusso di un pack.

    Un pack può DICHIARARE nel proprio manifest le destinazioni (`egress:`) e le
    fonti (`ingress:`) che considera parte del proprio funzionamento normale. È
    una dichiarazione di **flusso**, non di permessi, e per questo non ha
    equivalenti nei sistemi di plugin: `host_permissions` di un'estensione dice
    «posso toccare questo host»; qui si dice «il contenuto che arriva da qui non
    contamina ciò che potrai fare dopo».

    Per la stessa ragione la dichiarazione **non è fiducia**. I pack arrivano da
    repo di terzi: se `ingress:` diventasse una concessione automatica, l'autore
    del pack deciderebbe cosa non contamina il canale di chi lo installa, e lo
    deciderebbe nella direzione d'errore che non si vede. Quindi due modi:

    - `validate: true` → **non concede nulla**, dice solo cosa sarebbe concesso e
      cosa verrebbe rifiutato. È ciò che l'installazione mostra all'owner.
    - senza → concede, e ogni voce finisce nella lista globale come qualunque
      altra: visibile nelle impostazioni e revocabile una per una.
    """
    _agent, err = _authorize(request)
    if err:
        return err
    body = await request.json()
    validate = bool(body.get("validate"))
    src = str(body.get("source") or "").strip()
    from . import egress
    out: dict = {"validate": validate, "source": src, "granted": [], "refused": []}
    for direction in ("egress", "ingress"):
        for raw in (body.get(direction) or []):
            uri = str(raw).strip()
            try:
                if validate:
                    egress.check_grantable(direction, uri)
                    out["granted"].append({"direction": direction,
                                           "uri": egress.canonical(uri),
                                           "note": egress.admin_note(direction, uri)})
                else:
                    r = egress.allow(direction, uri)
                    r["direction"] = direction
                    out["granted"].append(r)
            except ValueError as e:
                out["refused"].append({"direction": direction, "uri": uri,
                                       "reason": str(e)})
    if not validate and out["granted"]:
        LOG.warning("flusso · %d voci concesse da %s (approvate da un umano)",
                    len(out["granted"]), src or "?")
        whitelist.reload_config()
    return JSONResponse(out)


async def verbs(request: Request):
    """GET /internal/agents/{name}/verbs → verbi EFFETTIVI con il flag gated.

    Serve alla scheda del seed. Espande i wildcard, ma **solo dove serve**: un
    `ns.*` che non contiene nessun verbo gated resta compatto. La regola è di
    Davide e ha una buona ragione — si espande dove c'è qualcosa da vedere,
    altrimenti `clodia` con `*` diventa un muro di duecento righe in cui il
    lucchetto che conta non si nota.

    Sta nel gateway perché è l'unico posto che conosce tutte e quattro le cose
    insieme: l'elenco dei verbi nativi, la lista gated GLOBALE, i `gated_tools`
    per-agente e i `denied_tools`. Il backend ne ha solo la dichiarazione del
    seed, e una risposta costruita là sarebbe una seconda verità.
    """
    _agent, err = _authorize(request)
    if err:
        return err
    name = (request.path_params.get("name") or "").strip()
    if not name:
        return JSONResponse({"error": "agent richiesto"}, status_code=400)
    from . import gate as _gate, main as _main
    # Si legge la config DIRETTAMENTE: `agent_config()` risolve l'agente della
    # richiesta corrente, che qui è il principal privilegiato, non il soggetto.
    spec = (whitelist.CONFIG.get("agents") or {}).get(name) or {}
    # UN SOLO TIPO DI PRINCIPAL (security-model §1). Un umano non sta in
    # `config.yaml`: la sua matrice vive nel seed, dove `/datadir/agents/` è
    # `drwx------ root` e uno spawn (uid 60000) non riesce né a leggerlo né a
    # scriverlo — il confine lo mette il kernel. Senza questo ramo la scheda di
    # un umano mostra zero verbi, che è il contrario di quello che accade: senza
    # matrice dichiarata l'umano ricade sulla regola precedente, cioè può
    # QUASI TUTTO. Dire «nessun verbo» dove il vero stato è «illimitato» è la
    # direzione d'errore peggiore per un pannello.
    from . import human as _human
    is_human = _human.is_human(name)
    human_matrix = _human.matrix(name) if is_human else None
    if is_human:
        allowed = [str(x) for x in (human_matrix or [])]
    else:
        allowed = [str(x) for x in (spec.get("allowed_tools") or [])]
    denied = {str(x) for x in (spec.get("denied_tools") or [])}
    per_agent = {str(x) for x in (spec.get("gated_tools") or [])}
    # Quarto motivo di gate (1.30.0): libero fuori da un canale, gated dentro.
    # Non compariva nel pannello, quindi la scheda di `messaggero` mostrava
    # `email.send` senza lucchetto mentre in un canale richiede un admin. Un
    # pannello che non mostra un controllo esistente insegna a fidarsi meno del
    # pannello, che è il danno peggiore di un'omissione in una vista di sicurezza.
    in_channel = {str(x) for x in (spec.get("gated_in_channel") or [])}
    # I backend MCP montati fanno parte del catalogo: `normattiva.*` copre i verbi
    # di quel server, e senza di essi il gruppo direbbe «0 verbi» per un namespace
    # che l'agente usa dieci volte al giorno. Un pannello che dichiara zero su
    # qualcosa di vivo è peggio di un pannello che non dichiara.
    catalogue = list(_main.all_native_verb_names())
    proxied_ok = True
    try:
        from . import proxy as _proxy
        catalogue += [t.name for t in await _proxy.list_proxied_tools()]
    except Exception as e:  # noqa: BLE001
        proxied_ok = False
        import logging as _lg
        _lg.getLogger("clodia-tools").warning(
            "verbs: elenco dei tool MCP non disponibile (%s): i namespace proxied "
            "risulterebbero vuoti", str(e)[:120])
    catalogue = sorted(set(catalogue))

    profile = [str(x) for x in (spec.get("profile_tools") or [])]
    has_profile = bool(profile)
    # Distinzione che il pannello DEVE poter mostrare: matrice assente
    # (`None` → ricade sulla regola precedente, quindi ampia) contro matrice
    # vuota (`[]` → nessun verbo). Confonderle farebbe leggere «illimitato» come
    # «bloccato», e un owner che crede di aver chiuso un accesso che è aperto è
    # peggio servito di uno che non ha il pannello.
    principal_kind = "human" if is_human else "agent"
    matrix_declared = (human_matrix is not None) if is_human else True
    descriptions = _main.native_verb_descriptions()

    def _row(v: str, via: str) -> dict:
        g_global = _gate.is_gated(v)
        g_agent = v in per_agent
        g_chan = v in in_channel
        off = has_profile and not whitelist._listed(v, set(profile))
        # `gated_by` distingue le tre ragioni perché chiedono all'umano di
        # valutare cose diverse: pericoloso per chiunque, pericoloso per costui,
        # o semplicemente fuori dal suo mestiere.
        by = ("global" if g_global else
              ("agent" if g_agent else
               ("channel" if g_chan else ("profile" if off else None))))
        # Per un umano il lucchetto ha un significato diverso e va detto: non
        # «serve un'approvazione», ma «serve essere admin». È la RBAC umana, ed è
        # l'unica ragione di gate che si applica a una persona.
        if is_human and g_global:
            by = "admin"
        return {"verb": v, "gated": bool(g_global or g_agent or off or g_chan),
                "gated_by": by, "in_profile": (not off) if has_profile else None,
                # Una riga di descrizione: senza, un elenco di verbi è un elenco di
                # nomi, e `topic.fetch` contro `topic.read_file` non si distingue.
                "description": descriptions.get(v, ""),
                "via": via}

    out: list[dict] = []
    groups: list[dict] = []
    for grant in allowed:
        if grant == "*" or grant.endswith(".*"):
            ns = None if grant == "*" else grant[:-2]
            covered = [v for v in catalogue
                       if v not in denied and (ns is None or v.split(".", 1)[0] == ns)]
            gated_inside = [v for v in covered
                            if _gate.is_gated(v) or v in per_agent or v in in_channel]
            # I verbi coperti da un wildcard entrano SEMPRE nella risposta.
            #
            # Prima ci entravano solo se il gruppo conteneva un lucchetto, e la
            # regola sembrava giusta — non trasformare il `*` di clodia in un muro
            # di 145 righe. Ma il criterio era quello sbagliato: ciò che rende un
            # gruppo un muro è la sua DIMENSIONE, non l'assenza di serrature.
            # L'effetto misurato: sulla scheda di `messaggero`, `email.*` e
            # `telegram.*` — 8 verbi ciascuno, il suo mestiere — non comparivano
            # affatto, mentre `topic` e `jobs` sì. Un pannello che nasconde
            # proprio il mestiere dell'agente non si legge meglio: si legge male.
            #
            # La parte buona della regola resta, e si sposta dove appartiene:
            # `open_by_default` (sotto) apre solo ciò che ha un lucchetto o è
            # fuori profilo. Tutto il resto c'è, chiuso, e si apre con un clic.
            groups.append({"grant": grant, "expanded": True,
                           "count": len(covered),
                           "has_gated": bool(gated_inside),
                           "verbs": [_row(v, grant) for v in covered]})
        else:
            if grant in denied:
                continue
            out.append(_row(grant, grant))
    # Vista ad ALBERO: un nodo per namespace. Serve perché un elenco piatto di 159
    # verbi non si legge — e perché il criterio di apertura è chiaro: si apre ciò
    # che ha un lucchetto o è fuori profilo, si tiene chiuso il resto.
    tree: dict[str, dict] = {}
    for r in out + [v for g in groups for v in g["verbs"]]:
        ns = r["verb"].split(".", 1)[0]
        node = tree.setdefault(ns, {"namespace": ns, "verbs": [], "gated": 0, "outside": 0})
        node["verbs"].append(r)
        if r["gated"]:
            node["gated"] += 1
        if r.get("in_profile") is False:
            node["outside"] += 1
    tree_list = sorted(tree.values(), key=lambda n: n["namespace"])
    for node in tree_list:
        node["verbs"].sort(key=lambda r: r["verb"])
        # Aperto di default dove c'è qualcosa da GUARDARE — un lucchetto o un
        # verbo fuori profilo. È l'unico criterio di apertura, e ora è anche
        # l'unico posto in cui si decide: i verbi sono tutti presenti, quindi
        # «chiuso» significa «richiudibile con un clic» e non «assente».
        node["open_by_default"] = bool(node["gated"] or node["outside"])
        node["count"] = len(node["verbs"])
    return JSONResponse({"agent": name, "verbs": out, "groups": groups,
                         "tree": tree_list,
                         "profile": sorted(profile),
                         "has_profile": has_profile,
                         "denied": sorted(denied),
                         "gated_agent": sorted(per_agent),
                         "gated_in_channel": sorted(in_channel),
                         # `False` → i gruppi su namespace MCP sono INCOMPLETI, e il
                         # consumatore deve poterlo dire invece di mostrare un conteggio
                         # che sembra completo.
                         "catalogue_complete": proxied_ok,
                         "gated_global_spec": _gate.gated_verbs_spec(),
                         # Un solo tipo di principal, ma il pannello deve poter
                         # dire QUALE ha davanti: per un umano il lucchetto
                         # significa «serve essere admin», non «serve
                         # un'approvazione una volta».
                         "principal_kind": principal_kind,
                         # il ruolo DICHIARATO (es. `member`), non il suo bucket di
                         # autorizzazione: la scheda deve riconciliare col seed
                         "role": _human.declared_role(name) if is_human else None,
                         "is_admin": _human.is_admin(name) if is_human else None,
                         "clearance": _human.clearance(name) if is_human else None,
                         # `False` = nessuna matrice dichiarata → si ricade sulla
                         # regola precedente, che è AMPIA. Non è «zero verbi».
                         "matrix_declared": matrix_declared})


routes = [
    Route("/internal/agents/whitelist", register, methods=["POST"]),
    Route("/internal/agents/flow-allow", flow_allow, methods=["POST"]),
    Route("/internal/agents/{name}/verbs", verbs, methods=["GET"]),
]

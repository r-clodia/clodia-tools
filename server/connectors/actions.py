"""Topic actions, applied from what the manifest declares.

clodia-platform#519. «Collega questa stanza a quella chat» and «autorizza questa
casella per questa stanza» were two routes with two bodies and two answers, and
a third connector meant a third route plus a deploy. A `topic_actions:` entry
already says everything the route needs — which fields the owner fills in, which
ingress and egress entries result, whether a binding follows — so here the
action is *executed* from the declaration, and `topics_api` keeps only the HTTP
shell.

Three things this module is careful about, in order of how badly they would hurt:

1. **A template is rendered with values the GATEWAY resolved, never with what
   the client sent**, whenever the field declares an option set. The mailbox
   action is the case: the address that ends up in `inbox:`/`outbox:` comes from
   `system_mailboxes()`, because a whitelist written by whoever is subject to it
   is not a whitelist. A free-text field (a chat id) is of course the client's —
   but that value is then checked against the scheme's own forms, so it cannot
   be anything the whitelist would not accept.
2. **Nothing is granted that the manifest did not declare.** The action can only
   write the URIs its own templates produce, and only into the scope of the
   topic it was called on.
3. **The owner is the one calling.** These helpers do not authenticate: the
   route does, owner-only, as today. They do refuse an action that is not
   declared, a field that was not declared, and a value that cannot match.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from . import resolved as _resolved
from .manifest import ActionField, Connector, TopicAction

LOG = logging.getLogger("clodia-tools.connectors")

_PLACEHOLDER = re.compile(r"\{([A-Za-z0-9_]+)\}")


def _shape(template: str) -> "re.Pattern[str]":
    """The template as a pattern: its literal text verbatim, each placeholder
    a non-empty run. `gdrive:folder/{folder}` matches `gdrive:folder/X` and
    not `gdrive:file/X`."""
    parts = _PLACEHOLDER.split(template)
    # split() alternates literal, name, literal, …: the odd items are names.
    return re.compile("".join(
        "(.+)" if i % 2 else re.escape(part) for i, part in enumerate(parts)))


class ActionError(ValueError):
    """Something the owner can fix, with the message they should read."""


# --------------------------------------------------------------------------
# option sets: values the gateway supplies, instead of free text
# --------------------------------------------------------------------------

def _mailbox_options() -> list[dict]:
    """The system mailboxes, as `{value, label, values}`.

    `values` carries the ADDRESS, which is what a template interpolates: the
    account name is what the owner recognises, the address is what the whitelist
    compares. Keeping both is the whole reason a chosen option is richer than
    the string that was chosen.
    """
    # From the side in charge of mail (#558): comms-pack's component on
    # `mail: pack`, and no option at all when it is not serving.
    from ..tools import mail_switch
    return [{"value": row["account"],
             "label": f"{row['account']} · {row['email']}",
             "values": {"account": row["account"], "address": row["email"]}}
            for row in mail_switch.system_mailboxes()]


#: Closed list, like `NORMALISERS`: a pack may point a field at one of these,
#: never supply one. An option set is «values this gateway vouches for», and a
#: pack that could define one would be vouching on the gateway's behalf.
OPTION_SETS = {"mailboxes": _mailbox_options}


def options_for(field: ActionField) -> list[dict] | None:
    source = getattr(field, "options", "")
    if not source:
        return None
    resolver = OPTION_SETS.get(source)
    if resolver is None:  # refused at load; defensive here
        raise ActionError(f"insieme di valori '{source}' sconosciuto")
    return resolver()


# --------------------------------------------------------------------------
# finding and rendering an action
# --------------------------------------------------------------------------

def find(connector_id: str, action_id: str) -> tuple[Connector, TopicAction]:
    from .. import instance_profile
    if not instance_profile.connector_allowed(connector_id):
        # The edition's gating (#526): a connector the profile excludes has
        # no topic button, and no request reaches its action either.
        raise ConnectorNotAllowed(
            f"connettore '{connector_id}' non previsto dall'edizione")
    reg = _resolved.registry()
    connector = reg.by_id(connector_id)
    if connector is None:
        raise ActionError(f"connettore '{connector_id}' non installato")
    action = next((a for a in connector.topic_actions if a.id == action_id), None)
    if action is None:
        dichiarate = ", ".join(a.id for a in connector.topic_actions) or "nessuna"
        raise ActionError(
            f"il connettore '{connector_id}' non dichiara l'azione "
            f"'{action_id}' (dichiarate: {dichiarate})")
    return connector, action


def resolve_values(action: TopicAction, body: dict) -> dict[str, str]:
    """`{nome: valore}` per i campi dichiarati, e solo per quelli.

    Un campo con un insieme di valori accetta la SCELTA e restituisce i valori
    che il gateway le associa; un campo libero accetta la stringa. Un campo non
    dichiarato viene ignorato: il corpo della richiesta non può introdurre
    variabili nei template.
    """
    out: dict[str, str] = {}
    for field in action.fields:
        raw = str((body or {}).get(field.name) or "").strip()
        opts = options_for(field)
        if opts is not None:
            scelta = next((o for o in opts if o["value"] == raw), None)
            if scelta is None:
                ammesse = ", ".join(o["value"] for o in opts) or "nessuna"
                raise ActionError(
                    f"'{raw or '(vuoto)'}' non è fra i valori che questa "
                    f"istanza offre per '{field.name}': {ammesse}. Si sceglie "
                    f"fra quelli esistenti, non se ne creano da qui")
            out.update({k: str(v) for k, v in scelta["values"].items()})
            out.setdefault(field.name, raw)
            continue
        if not raw and field.required:
            raise ActionError(f"richiesto '{field.name}'")
        out[field.name] = raw
    return out


def render(action: TopicAction, values: dict[str, str]) -> dict[str, list[str]]:
    """Gli URI che questa azione scriverebbe. Solo i suoi template.

    Il valore di un campo passa prima per `egress.canonical()`: ciò che una
    persona incolla è l'URL che ha nella barra del browser, e lo schema lo
    riconduce alla forma canonica con le proprie regole `canonicalise:`. Senza,
    il bottone Drive generico sarebbe un passo indietro rispetto a quello
    cablato che sostituisce, dove incollare l'URL della cartella funziona
    (clodia-platform#520).

    Il valore canonicalizzato vale PER SÉ solo se è già un indirizzo dello
    schema che il template scrive: `https://drive.google.com/drive/folders/X`
    diventa `gdrive:folder/X` e sostituisce il template, mentre
    `https://evil.example` resta ciò che è, finisce dentro il template come
    testo e lì non ha la forma di un `gdrive:` — cioè viene rifiutato. Nessuna
    guardia si sposta: `check_uris` (schema posseduto, forma, `check_grantable`)
    gira dopo, su quello che esce di qui.
    """
    from .. import egress as eg

    def _one(template: str) -> str:
        def _sub(m):
            key = m.group(1)
            if key not in values:
                raise ActionError(
                    f"il template '{template}' nomina '{key}', che l'azione non "
                    f"dichiara fra i propri campi")
            return values[key]

        scheme = template.partition(":")[0]
        nomi = _PLACEHOLDER.findall(template)
        if len(nomi) == 1 and nomi[0] in values:
            canonico = eg.canonical(values[nomi[0]])
            if canonico.partition(":")[0] == scheme and ":" in canonico:
                # Review of #365: a URI of the scheme stands for itself only
                # if it has the TEMPLATE's shape. Otherwise a Drive action
                # declared for `gdrive:folder/{folder}` could write
                # `gdrive:file/…` or `gdrive:doc/…` — any grantable form of
                # the scheme, not the one the manifest declared.
                if not _shape(template).fullmatch(canonico):
                    raise ActionError(
                        f"'{values[nomi[0]]}' è un indirizzo '{scheme}:' ma "
                        f"non della forma che questa azione scrive "
                        f"('{template}')")
                return canonico
        return eg.canonical(_PLACEHOLDER.sub(_sub, template))

    return {"ingress": [_one(t) for t in action.adds_ingress],
            "egress": [_one(t) for t in action.adds_egress]}


# --------------------------------------------------------------------------
# applying it
# --------------------------------------------------------------------------

def state(connector: Connector, action: TopicAction, tier: str,
          name: str) -> dict:
    """Cosa c'è ADESSO, per questa azione su questo topic.

    `entries` sono le voci di QUESTA stanza che un'azione già applicata ha
    lasciato: è l'unica cosa che si può togliere da qui, e non distinguerla da
    un'autorizzazione globale farebbe sembrare rotto il bottone «scollega».
    """
    from .. import egress as eg
    scope = f"{tier}/{name}"
    locali = {"ingress": set(eg.scope_uris("ingress", scope)),
              "egress": set(eg.scope_uris("egress", scope))}
    out: dict[str, Any] = {
        "connector": connector.id,
        "action": action.id,
        "label": action.label,
        "binding": action.binding,
        # Chi può OFFRIRE questa azione (#520). Lo stato è ciò che l'agent-server
        # legge prima di inoltrare una POST: senza il campo qui, il controllo
        # «questa la fa un admin» — che oggi protegge `mailbox-link` in
        # clodia-logic — non arriverebbe alla rotta generica, e la rotta
        # generica sarebbe la porta di servizio della rotta specifica.
        "admin_only": action.admin_only,
        "fields": [{"name": f.name, "label": f.label, "required": f.required,
                    "placeholder": f.placeholder,
                    "options": options_for(f)} for f in action.fields],
        "entries": {k: sorted(v) for k, v in locali.items()},
    }
    if action.binding == "channel":
        out["seal"] = _seal_state(connector, tier, name)
        out["bound"] = _bound_chat(connector.id, tier, name)
        out["connected"] = out["bound"] is not None
        out["suggestions"] = _suggestions(connector, action, tier, name,
                                          out["bound"])
    else:
        # The owner decides with the topic's tier in front of them, for EVERY
        # action (#519): what is being authorised and at which SEAL level.
        out["seal"] = {"tier": _topic_tier(tier, name), "cap": None,
                       "requires_ack": False, "ack": None}
    out["tier"] = out["seal"]["tier"]
    return out


def _topic_tier(tier: str, name: str) -> str:
    """The SEAL tier the topic declares (its meta), else the one in the path."""
    from ..topics.service import TopicError
    from ..topics_api import _service
    try:
        return str(_service().open(tier, name).get("meta", {}).get("tier")
                   or tier)
    except TopicError:
        return tier


def _seal_state(connector: Connector, tier: str, name: str) -> dict:
    """Il cap SEAL del channel su questo topic (#405), per la UI.

    Resta la logica di oggi, letta per tipo di channel: #519 non tocca il cap —
    cade con la migrazione del connettore che cappa (#522), decisione
    dell'orchestratore del 14/10.
    """
    from ..topics.service import _tier_rank, channel_ack, channel_cap_acked
    from ..topics_api import _service
    from ..topics.service import TopicError
    try:
        meta = _service().open(tier, name).get("meta", {})
    except TopicError:
        meta = {}
    cap = channel_cap(connector)
    t = meta.get("tier", tier)
    morde = cap is not None and _tier_rank(t) > cap
    return {"tier": t, "cap": f"SEAL-{cap}" if cap is not None else None,
            "requires_ack": bool(morde
                                 and not channel_cap_acked(meta, connector.id, t)),
            "ack": channel_ack(meta, connector.id)}


def channel_cap(connector: Connector) -> int | None:
    """The SEAL cap of this connector's channel binding (#405, #638).

    The gateway's own channel types (Telegram) keep their table. Any other
    connector that binds a channel — a pack relay — is capped too, fail
    closed: at its manifest's `relay.seal_cap`, or `DEFAULT_RELAY_SEAL_CAP`.
    Above the cap the owner must acknowledge the downgrade, with the room's
    tier in front of them, exactly as for Telegram.
    """
    from ..topics.service import channel_seal_cap
    from .manifest import DEFAULT_RELAY_SEAL_CAP
    cap = channel_seal_cap(connector.id)
    if cap is not None:
        return cap
    relay = getattr(connector, "relay", None)
    if relay is not None and relay.seal_cap is not None:
        return relay.seal_cap
    return DEFAULT_RELAY_SEAL_CAP


def _bindings(connector_id: str):
    """The channel bindings of ONE connector (clodia-platform#638).

    `channel_bindings` is keyed by connector + chat (#521): a topic action with
    `binding: channel` writes under its OWN connector id. Telegram keeps going
    through its facade (`telegram_bindings`), byte for byte what it did before;
    any other connector uses the same registry, in the same directory — the
    facade's `_base()`, so whatever points Telegram's file elsewhere (the
    tests) moves every connector's bindings with it.
    """
    from ..tools import channel_bindings as cb
    from ..tools import telegram_bindings as tb

    class _View:
        @staticmethod
        def load() -> dict:
            if connector_id == tb.CONNECTOR:
                return tb.load()
            return cb.load(connector_id, base=tb._base())

        @staticmethod
        def get(chat: str):
            if connector_id == tb.CONNECTOR:
                return tb.get(chat)
            return cb.get(connector_id, chat, base=tb._base())

        @staticmethod
        def set_binding(chat: str, instance: str, tier: str, topic: str):
            if connector_id == tb.CONNECTOR:
                return tb.set_binding(chat, instance, tier, topic)
            return cb.set_binding(connector_id, chat, instance, tier, topic,
                                  base=tb._base())

        @staticmethod
        def remove(chat: str) -> bool:
            if connector_id == tb.CONNECTOR:
                return tb.remove(chat)
            return cb.remove(connector_id, chat, base=tb._base())

    return _View


def _bound_chat(connector_id: str, tier: str, name: str) -> str | None:
    """The chat of THIS connector bound to the topic, or None."""
    for cid, b in _bindings(connector_id).load().items():
        if (b.get("tier"), b.get("topic")) == (tier, name):
            return cid
    return None


def _suggestions(connector: Connector, action: TopicAction, tier: str,
                 name: str, bound: str | None) -> list[dict]:
    """Chats the bot joined for this topic by link, ready for the owner (#549).

    Each suggestion is a ready set of field values: approving one is the same
    `connect` the owner would do by typing — with the id Telegram gave, not one
    typed by hand. Nothing here authorises anything.
    """
    # SHORTCUT: like `_bound_chat`, the only joinable channel is Telegram's.
    if connector.id != "telegram" or not action.fields:
        return []
    from ..tools import telegram_join as tj
    campo = action.fields[0].name
    return [{"label": p.get("title") or p["chat_id"],
             "values": {campo: p["chat_id"]},
             "requested_by": p.get("requested_by", ""),
             "added_by": p.get("added_by", ""),
             "at": p.get("at")}
            for p in tj.proposals(tier, name) if p.get("chat_id") != bound]


def _owned_schemes(connector: Connector) -> set[str]:
    """The schemes this connector's actions may write: its own, or — for a
    provider that `extends` a vocabulary — the vocabulary owner's."""
    own = {sch.name for sch in connector.schemes}
    if connector.extends:
        target = _resolved.registry().by_id(connector.extends)
        if target is not None:
            own |= {sch.name for sch in target.schemes}
    return own


def check_uris(connector: Connector, uris: dict[str, list[str]]) -> None:
    """Every URI an action would write, checked BEFORE anything is written.

    Review of #360: the values of free-text fields were not checked at all and
    a template could write any scheme — `adds.egress: ['{url}']` let a topic
    caller whitelist `https://evil.example/*` without the WALLS gate. Now:

    - the scheme must be one the connector owns (refused at load as well);
    - the rest must match one of that scheme's forms (`fullmatch`);
    - the entry must be grantable in its direction (`egress.check_grantable`:
      no `*`, no degenerate entry, no wildcard on a scheme that forbids it).
    """
    from .. import egress as eg
    owned = _owned_schemes(connector)
    for direzione, voci in uris.items():
        for uri in voci:
            scheme, sep, rest = uri.partition(":")
            if not sep or scheme not in owned:
                raise ActionError(
                    f"'{uri}' non è un indirizzo di uno schema del connettore "
                    f"'{connector.id}' ({', '.join(sorted(owned)) or 'nessuno'})")
            if not eg.scheme_form_ok(scheme, rest):
                raise ActionError(
                    f"'{rest}' non ha la forma di un indirizzo '{scheme}:'")
            try:
                eg.check_grantable(direzione, uri)
            except ValueError as e:
                raise ActionError(str(e)[:300])


def apply(connector: Connector, action: TopicAction, tier: str, name: str, *,
          body: dict, principal: str = "") -> dict:
    """Esegue l'azione dichiarata: whitelist, e binding se è dichiarato.

    `body["action"]` sceglie fra `connect` e `disconnect` — gli stessi due verbi
    delle rotte di oggi, perché un connettore si attacca e si stacca, e un terzo
    stato non esiste.

    Ordine (review di #360): tutto si VERIFICA prima di scrivere qualunque cosa
    (valori, forme, schemi, cap SEAL, chat già collegata altrove); poi la
    whitelist; il binding per ULTIMO, così un errore sulla whitelist non lascia
    un binding orfano.
    """
    from .. import egress as eg
    from ..topics.service import TopicError
    from ..topics_api import _service

    verso = str((body or {}).get("action") or "connect").strip()
    if verso not in ("connect", "disconnect"):
        raise ActionError(f"azione sconosciuta: {verso}")
    # Il topic deve ESISTERE per scriverci: le liste per scope sono chiavi di
    # config, e una voce scritta per un topic non ancora creato sarebbe
    # ereditata da chi un giorno lo creerà con quel nome (review di #310).
    # Togliere invece si può sempre — com'era sulle rotte di prima.
    if verso == "connect":
        try:
            _service().open(tier, name)
        except TopicError as e:
            raise TopicMissing(f"topic {tier}/{name} inesistente: {str(e)[:160]}")

    scope = f"{tier}/{name}"
    if verso == "disconnect" and action.binding == "channel":
        return _disconnect_channel(connector, action, tier, name, scope)

    values = resolve_values(action, body or {})
    uris = render(action, values)
    check_uris(connector, uris)
    chat = ""
    if verso == "connect" and action.binding == "channel":
        chat = _prepare_channel(connector, tier, name, values, body or {},
                                principal=principal)
    try:
        for direzione, voci in (("ingress", uris["ingress"]),
                                ("egress", uris["egress"])):
            for uri in voci:
                if verso == "connect":
                    eg.scope_allow(direzione, scope, uri)
                else:
                    eg.scope_revoke(direzione, scope, uri)
    except ValueError as e:
        raise ActionError(str(e)[:200])
    if chat:
        _bindings(connector.id).set_binding(chat, "messaggero", tier, name)
        if connector.id == "telegram":
            from ..tools import telegram_join as tj
            tj.drop(tier, name, chat)
    return state(connector, action, tier, name)


class TopicMissing(ActionError):
    """The topic an action would write into does not exist."""


class ConnectorNotAllowed(ActionError):
    """The edition's profile excludes the connector (`integrations.connectors`)."""


def _prepare_channel(connector: Connector, tier: str, name: str,
                     values: dict, body: dict, *, principal: str = "") -> str:
    """Le verifiche del binding di canale, PRIMA di scrivere qualunque cosa.

    Il binding vero (`tb.set_binding`) lo fa `apply` per ultimo: sono due passi
    e vanno insieme — senza il secondo il messaggero non riporta niente anche
    con la whitelist scritta (Davide, 23 set 2026) — ma un errore sulla
    whitelist non deve lasciare un binding senza le sue voci.
    """
    from ..topics.service import TopicError, _check_channel_cap
    from ..topics_api import _service

    chat = next((v for k, v in values.items() if k != "account" and v), "")
    if not chat:
        raise ActionError("richiesto l'identificativo della chat")
    # One chat → one topic, per connector: the binding lives under the
    # action's own connector id (#638).
    esistente = _bindings(connector.id).get(chat)
    if esistente and (esistente.get("tier"), esistente.get("topic")) != (tier, name):
        raise ActionError(
            f"chat {chat} già collegata a {esistente.get('tier')}/"
            f"{esistente.get('topic')}: disconnettila lì prima "
            f"(una chat → un solo topic)")
    svc = _service()
    try:
        # Presa d'atto dell'owner sul cap SEAL (#405): PRIMA della verifica,
        # perché è ciò che la rende superabile. Qui il principal è l'umano
        # owner del topic — la rotta è owner-only — quindi è l'unico punto
        # della piattaforma in cui quel consenso può nascere.
        # Telegram passes no cap and reads the table, exactly as before; a
        # pack relay passes its own (`channel_cap`, #638), never none.
        cap = None if connector.id == "telegram" else channel_cap(connector)
        if body.get("accept_seal_downgrade"):
            svc.accept_channel_cap(tier, name, connector.id, by=principal or "",
                                   **({"cap": cap} if cap is not None else {}))
        meta = svc.open(tier, name).get("meta", {})
        _check_channel_cap({"type": connector.id}, meta.get("tier", tier), meta,
                           **({"cap": cap} if cap is not None else {}))
    except TopicError as e:
        raise ActionError(str(e)[:400])
    return chat


def _disconnect_channel(connector: Connector, action: TopicAction, tier: str,
                        name: str, scope: str) -> dict:
    """Stacca il canale: binding, presa d'atto e voci che l'azione aveva scritto.

    La presa d'atto muore col collegamento anche quando il binding non c'era
    più: è il gesto «questa stanza non parla con quel canale», e lasciarla in
    piedi farebbe passare il prossimo aggancio in silenzio.
    """
    from .. import egress as eg
    from ..topics.service import TopicError
    from ..topics_api import _service

    try:
        _service().revoke_channel_cap_ack(tier, name, connector.id)
    except TopicError:
        pass
    chat = _bound_chat(connector.id, tier, name)
    if chat is not None:
        _bindings(connector.id).remove(chat)
        for direzione, voci in render(action, {f.name: chat
                                               for f in action.fields}).items():
            for uri in voci:
                eg.scope_revoke(direzione, scope, uri)
    return state(connector, action, tier, name)

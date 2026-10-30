"""Riclassificazione di un topic a un nuovo livello SEAL (clodia-platform#426).

Il livello sta nel path del topic e in ogni stato che lo indicizza con
`<tier>/<nome>`. Riclassificare è quindi due cose, nell'ordine:

1. spostare il topic (`TopicService.set_tier`: cartella + meta + cronologia);
2. RIPORTARE, identiche, le voci che il gateway tiene sotto la vecchia chiave:
   - le liste ingress/egress del topic (`scope_source_allow`/`scope_egress_allow`);
   - i binding di canale di OGNI connettore (`channel_bindings`: Telegram e i
     relay dei pack, #638);
   - lo stato di contaminazione (`taint`).

Il punto 2 NON è una modifica dei muri — decisione di Davide (28 set 2026):
«nessun egress/ingress viene modificato, è responsabilità dell'owner
verificare prima della riclassificazione». È ciò che impedisce che lo diventi:
senza, le voci resterebbero sotto `SEAL-1/<nome>`, che nessuno legge più, e il
topic perderebbe i suoi muri in silenzio. Stesso discorso per il taint: spostare
un topic non deve ripulirne la contaminazione.

Tutto o niente: se un passo fallisce, quelli già fatti si annullano.
"""
from __future__ import annotations

import copy
import logging

LOG = logging.getLogger("clodia-tools.retier")


def _rekey_scope_lists(old: str, new: str) -> None:
    from .. import egress as eg
    from .. import whitelist as wl
    vecchia, nuova = eg._norm_scope_key(old), eg._norm_scope_key(new)
    cambiato = False
    for key in eg._SCOPE_KEYS.values():
        per = dict(wl.CONFIG.get(key) or {})
        voci: list = []
        for k in [k for k in per if eg._norm_scope_key(str(k)) == vecchia]:
            voci.extend(per.pop(k) or [])
        if not voci:
            continue
        dest = list(per.get(nuova) or [])
        per[nuova] = dest + [v for v in voci if v not in dest]
        wl.CONFIG[key] = per
        cambiato = True
    if cambiato:
        wl.save_config()


def _all_bindings() -> dict:
    """`{connector: {chat: binding}}` of every connector, in the registry's
    directory (the Telegram facade's `_base()`, as `connectors.actions`)."""
    from ..tools import channel_bindings as cb
    from ..tools import telegram_bindings as tb
    return cb.load(base=tb._base())


def _bound_connectors(tier: str, name: str) -> dict[str, list[str]]:
    """`{connector: [chat…]}` bound to this topic, every connector."""
    out: dict[str, list[str]] = {}
    for conn, chats in _all_bindings().items():
        for chat, b in (chats or {}).items():
            if (b.get("tier"), b.get("topic")) == (tier, name):
                out.setdefault(conn, []).append(chat)
    return out


def _rekey_bindings(tier: str, new: str, name: str) -> list[str]:
    """Move EVERY connector's bindings of the topic (#638). Telegram's chats
    are returned bare, as before; another connector's as `<connector>:<chat>`."""
    from ..tools import channel_bindings as cb
    from ..tools import telegram_bindings as tb
    spostati = []
    for conn, chats in _all_bindings().items():
        for cid, b in (chats or {}).items():
            if (b.get("tier"), b.get("topic")) != (tier, name):
                continue
            if conn == tb.CONNECTOR:
                tb.set_binding(cid, b.get("instance") or "messaggero", new, name)
                spostati.append(cid)
            else:
                cb.set_binding(conn, cid, b.get("instance") or "messaggero", new,
                               name, base=tb._base())
                spostati.append(f"{conn}:{cid}")
    return spostati


def _relay_caps_crossed(tier: str, new_tier: str, name: str) -> list[tuple[str, int]]:
    """The pack channels bound to the topic whose SEAL cap `new_tier` exceeds:
    `[(connector, cap)]`. Same rule as binding (`actions.channel_cap`): a
    room may not climb above a pack relay's cap without the owner's ack.

    Telegram is left out on purpose: its retier behaviour is unchanged
    (its ack still does not survive an upward retier — `channel_cap_acked`
    compares the tier — but the retier itself is not refused).
    """
    from ..connectors import actions as ca
    from ..connectors import resolved
    from ..connectors.manifest import DEFAULT_RELAY_SEAL_CAP
    from .service import _tier_rank
    out = []
    for conn in _bound_connectors(tier, name):
        if conn == "telegram":
            continue
        try:
            connector = resolved.registry().by_id(conn)
        except Exception:  # noqa: BLE001 — unknown: the default, fail closed
            connector = None
        cap = ca.channel_cap(connector) if connector is not None \
            else DEFAULT_RELAY_SEAL_CAP
        if _tier_rank(new_tier) > cap:
            out.append((conn, cap))
    return out


def _rekey_taint(old: str, new: str) -> bool:
    from .. import taint
    d = taint._load()
    vecchia, nuova = taint.channel_of(old), taint.channel_of(new)
    if not vecchia or vecchia not in d:
        return False
    d[nuova] = d.pop(vecchia)
    taint._save(d)
    return True


def apply(svc, tier: str, name: str, new_tier: str, *, by: str, reason: str,
          accept_seal_downgrade: bool = False) -> dict:
    """Esegue la riclassificazione. Solleva `TopicError` (o l'errore del passo)
    se non si può fare; in quel caso nulla resta cambiato.

    A room bound to a pack relay whose SEAL cap `new_tier` exceeds is refused
    unless `accept_seal_downgrade` — the owner's acknowledgement, recorded per
    connector at the new tier, exactly as when binding (#638)."""
    from .. import whitelist as wl
    from ..tools import telegram_bindings as tb
    from .. import taint
    # #590: a topic cannot go below the level of the data it imports.
    from ..topic_data import DataError, check_retier
    try:
        check_retier((svc._read_meta(tier, name)[0]), new_tier)
    except DataError as e:
        from .service import TopicError
        raise TopicError(str(e)) from e
    from .service import TopicError, _normalize_tier
    superati = _relay_caps_crossed(tier, _normalize_tier(new_tier), name)
    if superati and not accept_seal_downgrade:
        nomi = ", ".join(f"'{c}' (SEAL-{cap})" for c, cap in superati)
        raise TopicError(
            f"il topic è collegato a canali con un cap SEAL inferiore a {new_tier}: "
            f"{nomi}. L'owner può riclassificarlo lo stesso prendendo atto del "
            f"downgrade (accept_seal_downgrade), oppure scollegare prima i canali")
    wl.reload_config()
    cfg_prima = copy.deepcopy({k: wl.CONFIG.get(k) for k in ("scope_source_allow",
                                                           "scope_egress_allow")})
    bindings_prima = copy.deepcopy(_all_bindings())
    taint_prima = copy.deepcopy(taint._load())

    esito = svc.set_tier(tier, name, new_tier, by=by, reason=reason)
    old, new = f"{esito['from']}/{name}", f"{esito['to']}/{name}"
    try:
        _rekey_scope_lists(old, new)
        esito["bindings"] = _rekey_bindings(esito["from"], esito["to"], name)
        esito["taint_moved"] = _rekey_taint(old, new)
        for conn, cap in superati:
            # Recorded at the NEW tier, per connector: the consent the owner
            # just gave, for the downgrade it is about.
            svc.accept_channel_cap(esito["to"], name, conn, by=by, cap=cap)
    except Exception:
        LOG.exception("riclassificazione %s → %s: riallineamento fallito, annullo", old, new)
        for k, v in cfg_prima.items():
            if v is None:
                wl.CONFIG.pop(k, None)
            else:
                wl.CONFIG[k] = v
        wl.save_config()
        from ..tools import channel_bindings as cb
        tb._save(bindings_prima.get(tb.CONNECTOR) or {})
        for conn in set(_all_bindings()) | set(bindings_prima):
            if conn != tb.CONNECTOR:
                cb.replace(conn, bindings_prima.get(conn) or {}, base=tb._base())
        taint._save(taint_prima)
        svc.s.move(svc._dir(esito["to"], name), svc._dir(esito["from"], name))
        meta, ver = svc._read_meta(esito["from"], name)
        meta["tier"] = esito["from"]
        meta["tier_history"] = (meta.get("tier_history") or [])[:-1]
        # Any acknowledgement this retier wrote goes with it.
        from .service import CHANNEL_SEAL_ACK, channel_acks
        acks = channel_acks(meta)
        for conn, _cap in superati:
            acks.pop(conn, None)
        if acks:
            meta[CHANNEL_SEAL_ACK] = acks
        else:
            meta.pop(CHANNEL_SEAL_ACK, None)
        svc._write_meta(esito["from"], name, meta, base_version=ver)
        raise
    LOG.warning("topic riclassificato %s → %s da %s: %s", old, new, by, reason[:200])
    # The authoritative record of a re-classification (clodia-platform#439);
    # `tier_history` in meta.json stays as a readable projection of it. The
    # reason is the decider's free text: its hash here.
    from ..audit import control as _control
    from ..audit.record import content_hash
    _control.safe(_control.emit, "topic_tier", "reclassify", f"{esito['to']}/{name}",
                  before=esito["from"], after=esito["to"], by=by,
                  reason_hash=content_hash(reason) if reason else None,
                  responsibility_accepted=True)
    return esito

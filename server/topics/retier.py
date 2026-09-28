"""Riclassificazione di un topic a un nuovo livello SEAL (clodia-platform#426).

Il livello sta nel path del topic e in ogni stato che lo indicizza con
`<tier>/<nome>`. Riclassificare è quindi due cose, nell'ordine:

1. spostare il topic (`TopicService.set_tier`: cartella + meta + cronologia);
2. RIPORTARE, identiche, le voci che il gateway tiene sotto la vecchia chiave:
   - le liste ingress/egress del topic (`scope_source_allow`/`scope_egress_allow`);
   - il binding del gruppo Telegram (`telegram_bindings`);
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


def _rekey_bindings(tier: str, new: str, name: str) -> list[str]:
    from ..tools import telegram_bindings as tb
    spostati = []
    for cid, b in tb.load().items():
        if (b.get("tier"), b.get("topic")) == (tier, name):
            tb.set_binding(cid, b.get("instance") or "messaggero", new, name)
            spostati.append(cid)
    return spostati


def _rekey_taint(old: str, new: str) -> bool:
    from .. import taint
    d = taint._load()
    vecchia, nuova = taint.channel_of(old), taint.channel_of(new)
    if not vecchia or vecchia not in d:
        return False
    d[nuova] = d.pop(vecchia)
    taint._save(d)
    return True


def apply(svc, tier: str, name: str, new_tier: str, *, by: str, reason: str) -> dict:
    """Esegue la riclassificazione. Solleva `TopicError` (o l'errore del passo)
    se non si può fare; in quel caso nulla resta cambiato."""
    from .. import whitelist as wl
    from ..tools import telegram_bindings as tb
    from .. import taint
    wl.reload_config()
    cfg_prima = copy.deepcopy({k: wl.CONFIG.get(k) for k in ("scope_source_allow",
                                                           "scope_egress_allow")})
    bindings_prima = copy.deepcopy(tb.load())
    taint_prima = copy.deepcopy(taint._load())

    esito = svc.set_tier(tier, name, new_tier, by=by, reason=reason)
    old, new = f"{esito['from']}/{name}", f"{esito['to']}/{name}"
    try:
        _rekey_scope_lists(old, new)
        esito["bindings"] = _rekey_bindings(esito["from"], esito["to"], name)
        esito["taint_moved"] = _rekey_taint(old, new)
    except Exception:
        LOG.exception("riclassificazione %s → %s: riallineamento fallito, annullo", old, new)
        for k, v in cfg_prima.items():
            if v is None:
                wl.CONFIG.pop(k, None)
            else:
                wl.CONFIG[k] = v
        wl.save_config()
        tb._save(bindings_prima)
        taint._save(taint_prima)
        svc.s.move(svc._dir(esito["to"], name), svc._dir(esito["from"], name))
        meta, ver = svc._read_meta(esito["from"], name)
        meta["tier"] = esito["from"]
        meta["tier_history"] = (meta.get("tier_history") or [])[:-1]
        svc._write_meta(esito["from"], name, meta, base_version=ver)
        raise
    LOG.warning("topic riclassificato %s → %s da %s: %s", old, new, by, reason[:200])
    return esito

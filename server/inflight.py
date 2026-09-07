"""Quanto è carico il gateway adesso, e chi lo teneva quando si è fermato
(clodia-platform#316).

## Perché esiste

Il 7 set 2026, fra 10:47 e 10:56 UTC, `agent-server` ha registrato 33 «gateway
topics irraggiungibile» contro una baseline di 1-2 al giorno. Si è risolto da
solo, e la causa non si è potuta nominare: nei log del gateway c'era una raffica
di `POST /internal/mint` + `GET /internal/gate/pending`, e nient'altro con cui
distinguere «chi stava chiamando» da «chi stava aspettando».

La raffica, misurata, non poteva essere la causa: coniare un token costa 0,062 ms
e verificarne uno 0,199 ms, quindi trenta coppie concorrenti sono ~8 ms di
lavoro. C'è di più: `mint` e `gate/pending` rispondono **inline**, mentre tutto
ciò che è andato in timeout (`/internal/topics*`, il dispatch dei topic e di
github, telegram, `web.fetch`) passa da `asyncio.to_thread`. Se il pool dei
thread si esaurisce, gli endpoint inline continuano a rispondere 200 in pochi ms
e quelli offloadati si accodano: la raffica era l'ultima strada aperta, non la
causa.

Questo modulo è ciò che serve per non rifare l'archeologia dei log una terza
volta:

- un registro delle richieste **in volo** con rotta, chiamante e anzianità;
- una riga quando la concorrenza per rotta supera una soglia, o quando una
  singola richiesta dura troppo;
- un watchdog che misura il ritardo dell'event loop e, quando il gateway è
  fermo, scrive UNA riga con chi era in volo e quanto è profonda la coda di
  offload. È l'equivalente tenibile-sempre-accesso del «dump dei thread nel
  momento esatto della saturazione» chiesto dalla issue, e scatta *durante* lo
  stallo invece che dopo;
- il pool di offload **dimensionato**: è anche la mitigazione, vedi sotto.

## La mitigazione, e perché è una riga

`asyncio.to_thread` usa l'executor di default, che nessuno crea: asyncio lo
istanzia al primo uso con `min(32, cpu_count + 4)` thread. Su un'istanza da 2
vCPU sono **6 thread** per tutto il gateway — un tetto implicito, derivato dal
numero di CPU, per lavoro che è I/O-bound e non CPU-bound. Prendendoci
l'executor il tetto diventa dichiarato, uguale su ogni host, e (questo è il
punto) **misurabile**: senza possedere l'oggetto non si può nemmeno dire quanti
thread sono occupati.

Le due alternative più vistose sono state scartate con una ragione, non per
prudenza: `uvicorn workers>1` moltiplicherebbe i processi su uno stato
decisionale letto-modificato-riscritto senza lock (`clodia-tools-gate*.json`,
`clodia-tools-config.yaml`, `delegations/active.jsonl`) — corruzione di
whitelist e consensi, cioè un cambio di disegno travestito da mitigazione; e un
limitatore con `429` su `mint`/`pending` strozzerebbe l'unico percorso che
durante l'incidente ha continuato a funzionare, verso un chiamante che oggi non
sa leggere un `429`.
"""
from __future__ import annotations

import asyncio
import itertools
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextvars import ContextVar
from dataclasses import dataclass

LOG = logging.getLogger("clodia-tools.inflight")

#: Thread di offload. 32 è il tetto che asyncio usa come massimo sulle macchine
#: grandi: qui diventa il valore su TUTTE, perché il lavoro offloadato aspetta
#: disco e rete, non calcola. Alzarlo o abbassarlo resta una decisione — ma una
#: decisione presa qui, non ereditata da `cpu_count` dell'host.
DEFAULT_OFFLOAD_WORKERS = 32

_DEFAULT_INFLIGHT_WARN = 12
_DEFAULT_SLOW_REQUEST_S = 5.0
_DEFAULT_LAG_WARN_S = 1.0
#: Anti-rumore: la stessa riga non si ripete più spesso di così. Una misura che
#: parla a regime è una misura che nessuno legge il giorno che ha ragione.
_REPEAT_EVERY_S = 30.0


def _env_int(name: str, default: int) -> int:
    try:
        return int((os.environ.get(name) or "").strip() or default)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float((os.environ.get(name) or "").strip() or default)
    except ValueError:
        return default


@dataclass
class _Req:
    """Una richiesta in volo. `caller` è mutabile di proposito: all'ingresso si
    sa solo da che IP arriva, e chi ha già risolto l'identità la attacca dopo
    (vedi `attribute`)."""
    id: int
    route: str
    caller: str
    started: float


_LOCK = threading.Lock()
_ACTIVE: dict[int, _Req] = {}
_PEAK: dict[str, int] = {}
_SEQ = itertools.count(1)
_LAST_SAID: dict[str, float] = {}
_CURRENT: ContextVar[_Req | None] = ContextVar("clodia_inflight_current", default=None)
_POOL: ThreadPoolExecutor | None = None


def reset() -> None:
    """Svuota registro, massimi e anti-rumore. Serve ai test: fra due misure lo
    stato di quella prima è rumore."""
    with _LOCK:
        _ACTIVE.clear()
        _PEAK.clear()
        _LAST_SAID.clear()
    _CURRENT.set(None)


def _said_recently(key: str, now: float) -> bool:
    last = _LAST_SAID.get(key)
    if last is not None and (now - last) < _REPEAT_EVERY_S:
        return True
    _LAST_SAID[key] = now
    return False


def route_label(path: str) -> str:
    """Etichetta di ROTTA, non di URL: `/internal/topics/SEAL-1/ops` e
    `/internal/topics/SEAL-1/hedge-iot-new` sono lo stesso endpoint, e contarli
    separati nasconderebbe proprio la concorrenza che si vuole vedere.

    SHORTCUT: normalizzazione per posizione (oltre il terzo segmento il path è
              dato, non endpoint), non per rotta matchata da Starlette — che
              all'ingresso del middleware non è ancora nota. Regge finché le
              rotte interne hanno questa forma; se un giorno servisse la rotta
              vera, la strada è leggere `scope["route"]` DOPO il routing, non
              allungare questa funzione.
    """
    parti = [p for p in (path or "/").split("/") if p]
    if len(parti) > 3:
        return "/" + "/".join(parti[:2]) + "/*"
    return "/" + "/".join(parti) if parti else "/"


def _caller_of(scope: dict) -> str:
    """Chi chiama, per quel che se ne sa all'ingresso: l'header dedicato se il
    chiamante si presenta, altrimenti l'IP. Le rotte che risolvono un'identità
    la migliorano con `attribute()`."""
    for k, v in scope.get("headers") or []:
        if k.decode().lower() == "x-clodia-caller":
            return v.decode()[:60]
    client = scope.get("client") or ()
    return str(client[0]) if client else "?"


def start(route: str, caller: str) -> _Req:
    """Registra una richiesta in volo e, se la concorrenza su quella rotta supera
    la soglia, lo dice una volta."""
    now = time.monotonic()
    req = _Req(id=next(_SEQ), route=route, caller=caller, started=now)
    with _LOCK:
        _ACTIVE[req.id] = req
        quante = sum(1 for r in _ACTIVE.values() if r.route == route)
        _PEAK[route] = max(_PEAK.get(route, 0), quante)
        soglia = _env_int("CLODIA_INFLIGHT_WARN", _DEFAULT_INFLIGHT_WARN)
        parla = quante >= soglia and not _said_recently(f"conc:{route}", now)
        chiamanti = _by_caller(route) if parla else {}
    _CURRENT.set(req)
    if parla:
        LOG.warning("concorrenza alta su %s: %d richieste in volo (soglia %d) — "
                    "chiamanti: %s", route, quante, soglia,
                    ", ".join(f"{c}×{n}" for c, n in chiamanti.items()))
    return req


def attribute(caller: str) -> None:
    """Chi ho davanti, DAVVERO. L'IP non distingue due tab della webui da un loop
    di retry; il principal sì, e le rotte interne l'hanno già risolto per
    autorizzare — qui lo attaccano alla richiesta in volo, senza un giro di
    crittografia in più. No-op fuori da una richiesta."""
    req = _CURRENT.get()
    if req is not None and caller:
        req.caller = caller[:60]


def _finish(req: _Req) -> None:
    """Chiude la riga del registro. Sempre, anche se l'handler è caduto: un
    registro che perde righe accusa richieste finite da un pezzo."""
    with _LOCK:
        _ACTIVE.pop(req.id, None)
    durata = time.monotonic() - req.started
    limite = _env_float("CLODIA_SLOW_REQUEST_S", _DEFAULT_SLOW_REQUEST_S)
    if durata >= limite and not _said_recently(f"slow:{req.route}", time.monotonic()):
        LOG.warning("richiesta lenta: %s da %s ha tenuto %.2fs (soglia %.2fs)",
                    req.route, req.caller, durata, limite)


def _by_caller(route: str | None = None) -> dict[str, int]:
    out: dict[str, int] = {}
    for r in _ACTIVE.values():
        if route is None or r.route == route:
            out[r.caller] = out.get(r.caller, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def snapshot() -> list[dict]:
    """Le richieste in volo, la più vecchia per prima: è l'ordine in cui si
    guarda uno stallo."""
    now = time.monotonic()
    with _LOCK:
        righe = [{"route": r.route, "caller": r.caller,
                  "age_s": round(now - r.started, 3)} for r in _ACTIVE.values()]
    return sorted(righe, key=lambda r: -r["age_s"])


def peak(route: str) -> int:
    """Massima concorrenza vista su quella rotta da questo processo."""
    return _PEAK.get(route, 0)


def pool_stats() -> dict:
    """Stato del pool di offload: quanti thread esistono, quanti sono occupati,
    quanto è profonda la coda. Senza possedere l'executor non si potrebbe dire."""
    p = _POOL
    if p is None:
        return {"installed": False,
                "max_workers": min(32, (os.cpu_count() or 1) + 4),
                "threads": 0, "busy": 0, "queued": 0}
    q = getattr(p, "_work_queue", None)
    # `threads` sono quelli CREATI (il pool cresce a domanda), `queued` il lavoro
    # che aspetta un thread libero. Gli occupati `ThreadPoolExecutor` non li
    # espone, e non si inventano: «thread = max e coda > 0» è già la frase che
    # serve — il pool è pieno e si sta accodando.
    return {"installed": True, "max_workers": p._max_workers,
            "threads": len(getattr(p, "_threads", ()) or ()),
            "queued": q.qsize() if q is not None else 0}


def install_offload_pool() -> ThreadPoolExecutor:
    """Il gateway si prende il suo executor: `asyncio.to_thread` continua a
    funzionare come prima (usa il default), ma il tetto è dichiarato e lo stato
    del pool diventa leggibile. Nessun call site cambia."""
    global _POOL
    workers = max(1, _env_int("CLODIA_OFFLOAD_WORKERS", DEFAULT_OFFLOAD_WORKERS))
    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="offload")
    asyncio.get_running_loop().set_default_executor(pool)
    _POOL = pool
    LOG.info("pool di offload: %d thread (CLODIA_OFFLOAD_WORKERS)", workers)
    return pool


def report_if_stalled(lag_s: float) -> bool:
    """UNA riga quando il loop è in ritardo: chi è in volo, da quanto, e com'è il
    pool. Ritorna True se ha parlato.

    È il pezzo che all'incidente del 7 set mancava. Il messaggio in log dice
    *che* il gateway non risponde; questa riga dice *chi* lo stava tenendo — e
    senza di essa la prossima occorrenza si legge con gli stessi strumenti di
    questa, cioè per congettura.
    """
    limite = _env_float("CLODIA_LOOP_LAG_WARN_S", _DEFAULT_LAG_WARN_S)
    if lag_s < limite:
        return False
    now = time.monotonic()
    with _LOCK:
        if _said_recently("stall", now):
            return False
    righe = snapshot()
    pool = pool_stats()
    dettaglio = "; ".join(f"{r['route']} da {r['caller']} ({r['age_s']}s)"
                          for r in righe[:10]) or "nessuna richiesta in volo"
    LOG.warning("event loop in ritardo di %.1fs (soglia %.1fs) — offload: "
                "%d/%d thread, coda %d — in volo: %s",
                lag_s, limite, pool["threads"], pool["max_workers"],
                pool["queued"], dettaglio)
    return True


async def watch(interval: float = 0.5) -> None:
    """Misura il ritardo dell'event loop e riferisce quando è troppo.

    Gira per tutta la vita del processo, quindi non muore per un difetto suo: un
    watchdog che si spegne al primo errore toglie la misura proprio nel momento
    in cui serviva.
    """
    while True:
        t0 = time.monotonic()
        await asyncio.sleep(interval)
        lag = time.monotonic() - t0 - interval
        try:
            report_if_stalled(lag)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001 — la misura non rompe il misurato
            LOG.debug("watchdog: report non scritto (%s)", str(e)[:120])


class InflightMiddleware:
    """Conta chi è in volo, per ogni rotta del gateway.

    Sta attorno a TUTTA l'app e non solo alle due rotte della issue: durante
    l'incidente le rotte «innocenti» erano quelle in timeout, e un contatore che
    guarda solo i sospetti misura solo l'alibi.
    """

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        req = start(route_label(scope.get("path", "")), _caller_of(scope))
        try:
            await self.app(scope, receive, send)
        finally:
            _finish(req)

"""Menzioni nel topic → notifica sul gruppo Telegram collegato.

Solo in USCITA. Non è un mirror del topic — quello è il modello abbandonato il
18 luglio — e non porta niente dentro: il relay in ingresso resta quello che è.

**Perché una coda e non una send.** La menzione nasce dentro `post_message`, che
è sul percorso di scrittura di ogni messaggio di ogni canale. Chiamare Telegram
lì significherebbe far dipendere la riuscita di un messaggio nel topic dalla
raggiungibilità di api.telegram.org: un servizio esterno lento fermerebbe la
conversazione. Si accoda, e chi recapita è un altro.

**Chi recapita.** Il messaggero, in un turno breve, con la sua identità e il suo
grant `telegram.*`. Non il gateway di sua iniziativa: un invio senza un agente
dietro è un'azione che nessuno ha fatto, e più tardi nessuno può spiegare.

**Il link.** Ogni notifica ne porta uno alla conversazione. Senza, la notifica
dice a qualcuno che è stato chiamato e lo lascia a cercare dove — su un telefono,
il modo più veloce di rendere inutile un avviso.
"""
from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path

LOG = logging.getLogger("clodia-tools.topics.telegram-notify")

#: Quante notifiche possono restare in attesa. Oltre, si scartano le più
#: vecchie: una coda che cresce senza limite è un modo di riempire un disco, e
#: una notifica di ieri non serve più a nessuno.
_MAX_PENDING = 500
#: Tentativi prima di rinunciare a una singola notifica.
MAX_ATTEMPTS = 5
#: Lunghezza massima dell'estratto, troncato con `…`.
#:
#: Era 280. La notifica si legge su un telefono, in mezzo ad altre notifiche, e
#: il suo compito è far decidere se aprire la conversazione — non sostituirla.
#: Oltre un paio di righe smette di essere un'anteprima e diventa una copia
#: parziale del messaggio fuori dalla stanza, che è la cosa che l'estratto esiste
#: per evitare.
EXCERPT_MAX = 120


def _queue_path() -> Path:
    base = os.environ.get("CLODIA_DATA", "/datadir")
    return Path(base) / "telegram-notify-queue.json"


def webui_url() -> str:
    """Indirizzo pubblico della webui. Vuoto = non configurato."""
    return (os.environ.get("CLODIA_WEBUI_URL") or "").rstrip("/")


def message_link(tier: str, name: str, message_id: str) -> str:
    """Link alla conversazione, sul messaggio.

    L'ancora `#m-<id>` la consuma la pagina del topic. Se un giorno l'ancora
    sparisse, il link resterebbe valido e porterebbe al topic — che è la
    direzione giusta in cui degradare: si perde la precisione, non la meta.
    """
    base = webui_url()
    path = f"/topics/{tier}/{name}#m-{message_id}"
    return f"{base}{path}" if base else path


def _load() -> list:
    p = _queue_path()
    if not p.is_file():
        return []
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
        return d if isinstance(d, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def _save(items: list) -> None:
    p = _queue_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(items[-_MAX_PENDING:], ensure_ascii=False, indent=1),
                   encoding="utf-8")
    tmp.replace(p)


def _excerpt(text: str, chi: str, limite: int) -> str:
    """La riga della menzione, non tutto il messaggio.

    Un messaggio lungo mandato per intero porterebbe fuori dalla stanza molto
    più di quanto la menzione riguardi. Si prende la riga in cui il nome
    compare; se non si trova, l'inizio del testo.
    """
    righe = [r.strip() for r in (text or "").splitlines() if r.strip()]
    ago = f"@{chi}".lower()
    scelta = next((r for r in righe if ago in r.lower()), righe[0] if righe else "")
    scelta = " ".join(scelta.split())
    return scelta if len(scelta) <= limite else scelta[: limite - 1].rstrip() + "…"


def enqueue_for_message(tier: str, name: str, meta: dict, msg: dict,
                        mounts_tg: list) -> int:
    """Accoda una notifica per ogni menzione riconosciuta. Ritorna quante.

    Una menzione che non corrisponde a nessuna persona mappata NON produce
    nulla: avvisare la persona sbagliata è l'unico esito peggiore del silenzio.

    **Solo le menzioni scritte da una PERSONA.** Misurato in coda su venere il
    10 ago 2026: Giovanni sarebbe stato avvisato **otto** volte per una
    conversazione sola — cinque da Davide, e tre da agenti che quella menzione
    l'avevano soltanto citata o discussa (il segretario che verbalizza, il
    guardiano che indaga un turno fallito).

    Un agente che ripete `@giovanni` non sta chiamando Giovanni: Giovanni era
    già stato chiamato. La notifica dice «qualcuno ti cerca», non «il tuo nome è
    comparso» — e la seconda, moltiplicata per gli agenti di una stanza, è il
    modo più rapido per far silenziare il gruppo, cioè per rendere inutile la
    funzione.
    """
    if (msg.get("kind") or "human") != "human":
        return 0
    menzionati = [str(m).lower() for m in (msg.get("mentions") or [])]
    if not menzionati or not mounts_tg:
        return 0
    coda = _load()
    visti = {(i.get("message_id"), i.get("chat_id"), i.get("principal"))
             for i in coda}
    nuovi = 0
    for mount in mounts_tg:
        cfg = mount.get("config") or {}
        chat_id = str(cfg.get("chat_id") or "")
        if not chat_id:
            continue
        modo = cfg.get("mode") or "excerpt"
        # `people` è uid → {principal, username}; qui serve il verso opposto.
        # La forma piatta (uid → "principal") è quella di prima del 10 ago 2026
        # e resta letta: un collegamento già fatto non deve smettere di
        # funzionare perché è cambiata la forma.
        per_nome: dict = {}
        for uid, v in (cfg.get("people") or {}).items():
            if isinstance(v, dict):
                chi, handle = str(v.get("principal") or "").lower(), v.get("username") or ""
            else:
                chi, handle = str(v or "").lower(), ""
            # Una chiave non numerica è l'handle: è così che una persona
            # compila la mappa, perché l'username è quello che conosce. I mount
            # scritti prima del 10 ago 2026 hanno esattamente questa forma, e
            # leggerli come uid faceva uscire il nome di piattaforma.
            u = str(uid)
            if not handle and not u.lstrip("-").isdigit():
                handle = u.lstrip("@")
            if chi:
                per_nome.setdefault(chi, (u, str(handle)))
        for chi in menzionati:
            trovato = per_nome.get(chi)
            if not trovato:
                continue
            uid, handle = trovato
            chiave = (msg.get("id"), chat_id, chi)
            if chiave in visti:
                continue      # una menzione avvisa UNA volta
            visti.add(chiave)
            coda.append({
                "tier": tier, "name": name, "chat_id": chat_id,
                "principal": chi, "uid": uid, "handle": handle,
                "message_id": msg.get("id"), "author": msg.get("author"),
                "title": (meta or {}).get("title") or name,
                "excerpt": (_excerpt(msg.get("text") or "", chi, EXCERPT_MAX)
                            if modo == "excerpt" else ""),
                "link": message_link(tier, name, str(msg.get("id"))),
                "attempts": 0, "at": time.time(),
            })
            nuovi += 1
    if nuovi:
        _save(coda)
    return nuovi


#: Quanto una presenza resta valida. La webui batte ogni 5s; 90 secondi
#: assorbono una rete lenta e una scheda in background senza far passare per
#: presente chi ha chiuso il portatile dieci minuti fa.
PRESENCE_TTL = 90.0


def _presence() -> dict:
    """`{"<principal>|<tier>/<name>": "<iso>"}` — scritto dall'agent-server.

    Illeggibile o assente = nessuno è presente, quindi si notifica. È la
    direzione giusta: il costo di un avviso di troppo è un messaggio in più sul
    telefono; il costo di uno mancato è una persona che non sa di essere stata
    chiamata.
    """
    base = os.environ.get("CLODIA_DATA", "/datadir")
    try:
        d = json.loads((Path(base) / "presence.json").read_text(encoding="utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _era_presente(item: dict, ora: float | None = None) -> bool:
    """Vero se la persona stava guardando QUELLA stanza quando è stata chiamata.

    Il confronto è con il momento del MESSAGGIO, non con adesso: la domanda è
    «l'ha visto?», e chi era davanti allo schermo quando la menzione è arrivata
    l'ha vista. Chi apre la conversazione dieci minuti dopo, invece, va
    avvisato lo stesso — la notifica gli è già dovuta.
    """
    from datetime import datetime, timezone
    chiave = f"{item.get('principal')}|{item.get('tier')}/{item.get('name')}"
    visto = _presence().get(chiave)
    if not visto:
        return False
    try:
        t = datetime.fromisoformat(visto).timestamp()
    except (TypeError, ValueError):
        return False
    quando = float(item.get("at") or 0)
    adesso = ora if ora is not None else time.time()
    # Presente al momento del messaggio (entro il TTL), e ancora fresco adesso:
    # un battito vecchio non è una presenza, è una traccia.
    return (t >= quando - PRESENCE_TTL) and (adesso - t <= PRESENCE_TTL)


def pending(limit: int = 20) -> list:
    """Le notifiche da recapitare, più vecchie prima."""
    return [i for i in _load() if int(i.get("attempts", 0)) < MAX_ATTEMPTS][:limit]


def render(item: dict) -> str:
    """Il testo che arriva sul gruppo.

    La menzione è tradotta: `@giovanni` nel canale diventa `@giocasu75` nel
    gruppo. Scrivere il nome della piattaforma non notificherebbe nessuno su
    Telegram — e non è nemmeno il nome con cui quelle persone si chiamano fra
    loro là. Senza handle mappato resta il nome della piattaforma: si perde la
    notifica push, non il messaggio.
    """
    chi = item.get("handle") or item.get("principal") or "?"
    autore = item.get("author") or "qualcuno"
    titolo = item.get("title") or item.get("name")
    righe = [f"🔔 @{chi} — {autore} ti ha menzionato in «{titolo}»"]
    if item.get("excerpt"):
        righe.append(f"“{item['excerpt']}”")
    righe.append(item.get("link") or "")
    return "\n".join(r for r in righe if r)


def flush(limit: int = 20) -> dict:
    """Recapita le notifiche pendenti. Ritorna il conto di ciò che è successo.

    Perché un verbo e non un turno di agente. Il piano di un job LOGICO è una
    lista STATICA di verbi: non può iterare su una coda di lunghezza variabile.
    L'alternativa era un turno LLM ogni cinque minuti per sempre, per un lavoro
    che non richiede alcun giudizio — il testo è già composto qui, e la skill
    dice all'agente di inviarlo verbatim proprio perché quel giudizio non deve
    esserci.

    Cosa cambia sull'attribuzione, e va detto: l'invio non è più «un turno di
    messaggero» ma «questo job, creato dal suo owner». Non è un invio senza
    padrone — è un attore con un nome, pre-autorizzato alla creazione e
    registrato a ogni esecuzione — ma è un padrone diverso, e chi legge i log
    deve saperlo.

    Un fallimento non ferma gli altri: una chat irraggiungibile non deve
    impedire a un'altra persona di essere avvisata.
    """
    from ..tools import telegram as tg
    fatte = falliti = presenti = 0
    motivi: list[str] = []
    for item in pending(limit):
        if _era_presente(item):
            # Era davanti allo schermo quando l'hanno chiamata: l'ha vista. La
            # notifica è per chi non c'era, e mandarla lo stesso insegna a
            # silenziare il gruppo.
            presenti += 1
            LOG.info("notifica a %s saltata: era sul canale %s/%s",
                     item.get("principal"), item.get("tier"), item.get("name"))
            ack(item["message_id"], item["chat_id"], item["principal"], ok=True)
            continue
        try:
            tg.send_internal(str(item["chat_id"]), render(item))
        except Exception as e:  # noqa: BLE001
            falliti += 1
            motivo = f"{type(e).__name__}: {e}"
            motivi.append(motivo[:160])
            ack(item["message_id"], item["chat_id"], item["principal"],
                ok=False, error=motivo)
            continue
        fatte += 1
        ack(item["message_id"], item["chat_id"], item["principal"], ok=True)
    if fatte or falliti:
        LOG.info("telegram notify flush: %d recapitate, %d fallite", fatte, falliti)
    return {"ok": True, "delivered": fatte, "failed": falliti,
            "skipped_present": presenti,
            "errors": motivi[:5], "still_pending": len(pending(limit))}


def ack(message_id: str, chat_id: str, principal: str, ok: bool = True,
        error: str = "") -> dict:
    """Segna una notifica come recapitata (`ok`) o come fallita.

    Un fallimento NON la cancella: incrementa i tentativi, così una rete che
    torna la recapita. Oltre `MAX_ATTEMPTS` resta in coda ma non viene più
    proposta — e resta leggibile, perché una notifica sparita in silenzio non
    dice a nessuno che quella persona non è stata avvisata.
    """
    coda = _load()
    toccati = 0
    for i in coda:
        if (str(i.get("message_id")) == str(message_id)
                and str(i.get("chat_id")) == str(chat_id)
                and str(i.get("principal")) == str(principal)):
            toccati += 1
            if ok:
                i["delivered_at"] = time.time()
                i["attempts"] = MAX_ATTEMPTS      # non riproporla
            else:
                i["attempts"] = int(i.get("attempts", 0)) + 1
                i["last_error"] = (error or "")[:200]
    if toccati:
        _save(coda)
    return {"ok": True, "updated": toccati}

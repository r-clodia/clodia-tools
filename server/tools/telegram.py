"""Telegram tool exposed via MCP — invio + inbound con lease per-chat.

Modello (deciso 29 giu 2026):
- **Outbound**: un agente scrive solo a chat che hanno già scritto (niente
  rubrica statica) e di cui detiene un *lease* attivo.
- **Inbound con lease per-chat**: un agente acquisisce il lease esclusivo su una
  singola chat per N minuti; finché il lease è valido è l'unico che ne consuma i
  messaggi. Chat diverse → lease indipendenti → agenti diversi in parallelo.

Niente daemon: l'inbound è *lazy*. A ogni `inbox`/`poll`/`send` il gateway fa una
`getUpdates` con offset persistito, serializzata da un lock di processo (singola
istanza), e smista i messaggi in code per-chat nello stato su disco.

Il **bot token** vive nel vault (`telegram_bot_token`, grant-checked) e non
raggiunge mai il modello: lo usa solo questo codice per parlare con l'API
Telegram. Stdlib pura (urllib): nessuna dipendenza esterna.
"""
from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from .. import vault
from ..whitelist import agent_name, tool_allowed

TELEGRAM_CRED = "telegram_bot_token"
_API_BASE = "https://api.telegram.org/bot{token}/{method}"
_DEFAULT_LEASE_MIN = 10
_MAX_LEASE_MIN = 120
# Serializza read-modify-write dello stato + getUpdates (un solo consumer per
# token: due getUpdates concorrenti si ruberebbero gli update via offset).
_LOCK = threading.RLock()


def _state_path() -> Path:
    return Path(os.environ.get("CLODIA_TELEGRAM_STATE")
                or (vault.vault_dir() / "telegram-state.json"))


def _load_state() -> dict:
    p = _state_path()
    if not p.is_file():
        return {"offset": 0, "bot_username": None, "last_error": None, "chats": {}}
    try:
        st = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"offset": 0, "bot_username": None, "last_error": None, "chats": {}}
    st.setdefault("offset", 0)
    st.setdefault("chats", {})
    st.setdefault("bot_username", None)
    st.setdefault("last_error", None)
    return st


def _save_state(st: dict) -> None:
    p = _state_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(p)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _lease_active(chat: dict) -> Optional[dict]:
    """Ritorna il lease se valido (non scaduto), altrimenti None."""
    lease = chat.get("lease")
    if not lease:
        return None
    try:
        exp = datetime.fromisoformat(lease["expiry"])
    except (KeyError, ValueError):
        return None
    return lease if exp > _now() else None


def _token() -> str:
    """Token del bot dal vault (grant-checked sull'agente chiamante)."""
    bundle = vault.get_secret(agent_name(), TELEGRAM_CRED)  # VaultDenied se no grant
    tok = (bundle or {}).get("token", "")
    if not tok:
        raise RuntimeError("telegram: bundle nel vault senza campo 'token'")
    return tok


def api_call(token: str, method: str, params: Optional[dict] = None, timeout: int = 15) -> dict:
    """Chiamata all'API Bot di Telegram. Ritorna il campo `result`; solleva su
    errore. Usata sia dai tool (con token dal vault) sia dal connect (token dal
    body, per validare con getMe)."""
    url = _API_BASE.format(token=token, method=method)
    data = json.dumps(params or {}).encode("utf-8")
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode("utf-8"))
            desc = body.get("description", "")
        except Exception:  # noqa: BLE001
            desc = e.reason
        raise RuntimeError(f"telegram {method} HTTP {e.code}: {desc}") from None
    except urllib.error.URLError as e:
        raise RuntimeError(f"telegram {method} rete: {e.reason}") from None
    if not payload.get("ok"):
        raise RuntimeError(f"telegram {method}: {payload.get('description', 'errore')}")
    return payload.get("result")


def _token_internal() -> str:
    """Token del bot per i flussi INTERNI (channel-runner server-side): letto dal
    vault SENZA grant per-agente. L'autorizzazione è il principal privilegiato del
    router /internal/telegram, non un grant MCP (come /internal/providers)."""
    tok = (vault.read_internal(TELEGRAM_CRED) or {}).get("token", "")
    if not tok:
        raise RuntimeError("telegram: bundle nel vault senza campo 'token'")
    return tok


def drain_internal(chat_id: str) -> dict:
    """Drena (svuota) la coda di UNA chat SENZA lease — per il channel-runner
    server-side, unico consumer dei chat legati a un topic. Fa getUpdates lazy
    (che popola le code di TUTTE le chat: le altre restano per i loro topic)."""
    cid = str(chat_id)
    with _LOCK:
        st = _load_state()
        _refresh(st, _token_internal())
        chat = st["chats"].get(cid)
        msgs = (chat.get("queue") or []) if chat else []
        if chat is not None:
            chat["queue"] = []
        _save_state(st)
    return {"chat_id": cid, "messages": msgs, "count": len(msgs)}


def send_internal(chat_id: str, text: str) -> dict:
    """Invia a una chat SENZA lease/inbox-check — per il channel-runner (trusted,
    unico consumer del binding chat↔topic)."""
    if not str(text).strip():
        raise ValueError("'text' non può essere vuoto")
    cid = _resolve_chat(chat_id)           # accetta chat_id numerico o nome gruppo
    res = api_call(_token_internal(), "sendMessage",
                   {"chat_id": int(cid), "text": str(text)})
    return {"ok": True, "chat_id": cid, "message_id": res.get("message_id")}


def poll_updates(timeout: int = 25) -> list:
    """LONG-POLL: getUpdates con timeout lungo — Telegram trattiene la connessione
    e risponde nell'ISTANTE in cui arriva un messaggio (latenza ~zero, meno carico
    dei poll ripetuti). Ritorna i messaggi nuovi di TUTTE le chat, avanzando
    l'offset. È l'UNICO consumer getUpdates del bot: non usare drain/inbox/poll in
    parallelo (Telegram ammette un solo getUpdates per bot → 409)."""
    with _LOCK:
        offset = _load_state()["offset"]
        token = _token_internal()
    # getUpdates FUORI dal lock: blocca fino a `timeout`s senza congelare send/stato.
    updates = api_call(token, "getUpdates",
                       {"offset": offset, "timeout": timeout, "limit": 100},
                       timeout=timeout + 10)
    out = []
    with _LOCK:
        st = _load_state()
        bot_uname = st.get("bot_username")
        for upd in updates or []:
            st["offset"] = max(st["offset"], int(upd["update_id"]) + 1)
            msg = upd.get("message") or upd.get("edited_message")
            if not msg or "chat" not in msg:
                continue
            frm = msg.get("from") or {}
            # Reply a un messaggio del BOT stesso → conta come menzione diretta.
            rfrm = (msg.get("reply_to_message") or {}).get("from") or {}
            reply_to_bot = bool(rfrm.get("is_bot") and bot_uname
                                and rfrm.get("username") == bot_uname)
            out.append({
                "chat_id": str(msg["chat"]["id"]),
                "chat_title": _chat_title(msg["chat"]),
                "message_id": msg.get("message_id"),
                "from": " ".join(x for x in (frm.get("first_name"), frm.get("last_name")) if x)
                        or (frm.get("username") or str(frm.get("id"))),
                "from_id": frm.get("id"),
                "from_username": frm.get("username"),
                "text": msg.get("text") or msg.get("caption") or "",
                "reply_to_bot": reply_to_bot,
            })
        st["last_error"] = None
        _save_state(st)
    return out


def _chat_title(chat: dict) -> str:
    if chat.get("title"):
        return chat["title"]
    name = " ".join(x for x in (chat.get("first_name"), chat.get("last_name")) if x)
    if chat.get("username"):
        name = f"{name} (@{chat['username']})".strip()
    return name or str(chat.get("id"))


def _resolve_chat(chat: str) -> str:
    """Risolve un riferimento chat a un chat_id. Accetta un chat_id numerico
    (es. `-5279916551`) oppure il NOME/titolo del gruppo (match case-insensitive,
    anche parziale) fra le chat note. Così la delega può usare il nome leggibile."""
    c = str(chat).strip()
    if c.lstrip("-").isdigit():
        return c
    low = c.lower()
    with _LOCK:
        chats = _load_state().get("chats", {})
    # match esatto sul titolo, poi parziale
    for cid, meta in chats.items():
        if str(meta.get("title", "")).lower() == low:
            return cid
    for cid, meta in chats.items():
        if low and low in str(meta.get("title", "")).lower():
            return cid
    raise ValueError(f"chat '{chat}' non trovata (né chat_id numerico né titolo noto)")


def _refresh(st: dict, token: str) -> int:
    """getUpdates lazy: accoda i nuovi messaggi nelle code per-chat, avanza
    l'offset. Ritorna il numero di messaggi accodati. Best-effort: un errore di
    rete viene registrato in last_error ma non rompe l'operazione (le code già
    accumulate restano leggibili)."""
    try:
        updates = api_call(token, "getUpdates",
                           {"offset": st["offset"], "timeout": 0, "limit": 100})
    except RuntimeError as e:
        st["last_error"] = str(e)[:300]
        return 0
    st["last_error"] = None
    n = 0
    for upd in updates or []:
        st["offset"] = max(st["offset"], int(upd["update_id"]) + 1)
        msg = upd.get("message") or upd.get("edited_message")
        if not msg or "chat" not in msg:
            continue
        chat = msg["chat"]
        cid = str(chat["id"])
        slot = st["chats"].setdefault(cid, {"title": "", "queue": [], "lease": None,
                                            "last_preview": "", "type": chat.get("type")})
        slot["title"] = _chat_title(chat)
        slot["type"] = chat.get("type")
        frm = msg.get("from") or {}
        text = msg.get("text") or msg.get("caption") or ""
        entry = {
            "update_id": upd["update_id"],
            "message_id": msg.get("message_id"),
            "from": " ".join(x for x in (frm.get("first_name"), frm.get("last_name")) if x)
                    or (frm.get("username") or str(frm.get("id"))),
            "from_id": frm.get("id"),
            "from_username": frm.get("username"),  # handle stabile (senza @) per
            # mappare il mittente a un principal registrato (channel-adapter);
            # `from` sopra resta la stringa di display per l'etichetta proxy.
            "text": text,
            "date": msg.get("date"),
        }
        slot["queue"].append(entry)
        slot["last_preview"] = (text[:80] + "…") if len(text) > 80 else text
        n += 1
    return n


# ── Tool esposti via MCP ─────────────────────────────────────────────────────

def inbox() -> dict:
    """Chat con messaggi in arrivo (metadati, non consuma): per ognuna chat_id,
    titolo, n. messaggi pendenti, anteprima dell'ultimo, e chi detiene il lease."""
    tool_allowed("telegram.inbox")
    me = agent_name()
    with _LOCK:
        st = _load_state()
        _refresh(st, _token())
        out = []
        for cid, c in st["chats"].items():
            lease = _lease_active(c)
            out.append({
                "chat_id": cid,
                "title": c.get("title"),
                "type": c.get("type"),
                "pending": len(c.get("queue") or []),
                "last_preview": c.get("last_preview"),
                "leased_by": lease["holder"] if lease else None,
                "lease_expiry": lease["expiry"] if lease else None,
                "mine": bool(lease and lease["holder"] == me),
            })
        _save_state(st)
    out.sort(key=lambda x: x["pending"], reverse=True)
    return {"chats": out, "bot_username": st.get("bot_username"),
            "last_error": st.get("last_error")}


def lease_acquire(chat_id: str, minutes: int = _DEFAULT_LEASE_MIN) -> dict:
    """Acquisisce il lease esclusivo su una chat per N minuti. Fallisce se un
    ALTRO agente detiene un lease ancora valido. Solo chat che hanno già scritto."""
    tool_allowed("telegram.lease_acquire")
    cid = str(chat_id)
    minutes = max(1, min(int(minutes or _DEFAULT_LEASE_MIN), _MAX_LEASE_MIN))
    me = agent_name()
    with _LOCK:
        st = _load_state()
        _refresh(st, _token())
        chat = st["chats"].get(cid)
        if chat is None:
            _save_state(st)
            raise ValueError(
                f"chat '{cid}' sconosciuta: un lease si può prendere solo su una "
                f"chat da cui è arrivato almeno un messaggio (vedi telegram.inbox)")
        lease = _lease_active(chat)
        if lease and lease["holder"] != me:
            _save_state(st)
            raise PermissionError(
                f"lease su chat '{cid}' tenuto da '{lease['holder']}' fino a "
                f"{lease['expiry']}")
        expiry = _now() + timedelta(minutes=minutes)
        chat["lease"] = {"holder": me, "expiry": _iso(expiry)}
        _save_state(st)
    return {"chat_id": cid, "holder": me, "expiry": _iso(expiry),
            "minutes": minutes, "pending": len(chat.get("queue") or [])}


def poll(chat_id: str) -> dict:
    """Consuma (e svuota) i messaggi in coda di una chat. Richiede un lease
    attivo del chiamante su quella chat."""
    tool_allowed("telegram.poll")
    cid = str(chat_id)
    me = agent_name()
    with _LOCK:
        st = _load_state()
        _refresh(st, _token())
        chat = st["chats"].get(cid)
        if chat is None:
            _save_state(st)
            raise ValueError(f"chat '{cid}' sconosciuta (nessun messaggio ricevuto)")
        lease = _lease_active(chat)
        if not lease or lease["holder"] != me:
            _save_state(st)
            raise PermissionError(
                f"per consumare i messaggi di '{cid}' devi detenere il lease "
                f"(telegram.lease_acquire); attuale: "
                f"{lease['holder'] if lease else 'nessuno'}")
        msgs = chat.get("queue") or []
        chat["queue"] = []
        _save_state(st)
    return {"chat_id": cid, "messages": msgs, "count": len(msgs),
            "lease_expiry": lease["expiry"]}


def send(chat_id: str, text: str) -> dict:
    """Invia un messaggio a una chat. LEASE-FREE (modello telegram-proxy, 18 lug):
    il messaggero è l'UNICO mittente della colonia, quindi non serve il lease
    esclusivo — sarebbe solo attrito. Vale il vincolo di Telegram: si può scrivere
    solo a chi ha già contattato il bot (o a un gruppo di cui il bot è membro)."""
    tool_allowed("telegram.send")
    if not text:
        raise ValueError("'text' non può essere vuoto")
    cid = _resolve_chat(chat_id)           # accetta chat_id numerico o nome gruppo
    with _LOCK:
        token = _token()
    res = api_call(token, "sendMessage", {"chat_id": int(cid), "text": text})
    return {"ok": True, "chat_id": cid, "message_id": res.get("message_id")}


def lease_release(chat_id: str) -> dict:
    """Rilascia anticipatamente il lease su una chat (no-op se non lo detieni)."""
    tool_allowed("telegram.lease_release")
    cid = str(chat_id)
    me = agent_name()
    with _LOCK:
        st = _load_state()
        chat = st["chats"].get(cid)
        released = False
        if chat and (chat.get("lease") or {}).get("holder") == me:
            chat["lease"] = None
            released = True
        _save_state(st)
    return {"chat_id": cid, "released": released}


# ── Stato per il setup (server-side, NON un tool agente) ─────────────────────

def status() -> dict:
    """Stato non sensibile per la card di setup / app_runtime di Wainston:
    configurato?, @username del bot, n. chat attive, ultimo errore. Mai il token."""
    configured = vault.has_credential(TELEGRAM_CRED)
    st = _load_state()
    active = sum(1 for c in st["chats"].values()
                 if (c.get("queue") or []) or _lease_active(c))
    return {
        "configured": configured,
        "bot_username": st.get("bot_username"),
        "known_chats": len(st["chats"]),
        "active_chats": active,
        "last_error": st.get("last_error"),
    }


def set_bot_username(username: Optional[str]) -> None:
    """Memorizza nello stato l'@username del bot (cache per UI/status). Chiamata
    dal connect dopo getMe."""
    with _LOCK:
        st = _load_state()
        st["bot_username"] = username
        _save_state(st)

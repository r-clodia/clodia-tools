"""Migrazione one-shot: whitelist Telegram del messaggero → fonti dello scope.

    python3 -m server.tools.migrate_telegram_ingress [--json piano.json]

clodia-platform#366, ultimo passo dell'epic #359. Fino al 14 set 2026 chi poteva
interpellare gli agenti da una chat Telegram stava in un blocco JSON ad-hoc
(`<!-- telegram-whitelist -->`) dentro la `MEMORY.md` del messaggero. Dalla #365
il relay non lo legge più: guarda gli **ingress dello scope** legato alla chat.
Senza migrazione ogni utente oggi autorizzato smette di funzionare **in
silenzio** — il modo peggiore in cui un permesso può sparire.

**Questo script non concede niente.** Legge quella lista un'ultima volta e ne
ricava il PIANO delle `topic.ingress_add` da far approvare all'owner, una per
una, con la loro card WALLS. Un `--apply` che scrivesse le liste in blocco
sarebbe esattamente il batch silenzioso che la issue esclude: la decisione su
chi può parlare in una stanza resta di chi la possiede, non di uno script.

Tre cose che il testo della issue non dice, e che decidono il disegno:

1. **La whitelist è del SEED, non dell'istanza.** `memory.memory_dir`
   normalizza `messaggero-3 → messaggero`: tutte le istanze condividono UNA
   lista. Riversarla intera su ogni topic legato sarebbe un allargamento
   silenzioso (chi era autorizzato in una chat diventerebbe fonte di tutti i
   topic). Un uid entra fra le fonti di uno scope **solo se è riconoscibile
   nella chat legata a quello scope**: è la risoluzione uid→handle a fare anche
   l'attribuzione.
2. **`telegram.roster` espone i soli amministratori** — lo dice apertamente:
   Telegram non dà a un bot l'elenco completo dei membri. Da solo lascerebbe
   «non migrabile» ogni utente normale, cioè il caso comune. Seconda fonte,
   per-chat e già autenticata: il buffer del relay
   (`channel-relay-state/chat_<id>.json`), che porta `from_id` +
   `from_username` dal campo `from` dell'API. Dipendenza **soft**: se non c'è,
   l'utente resta non migrabile, non è un errore.
3. **La forma di `tg:` la decide `egress.check_grantable`**, che convalida
   senza concedere. Una seconda regex qui divergerebbe dalla prima: una voce
   «migrata» e inefficace è peggio di una non migrata, perché nessuno la
   rilegge.

Le `MEMORY.md` non vengono toccate: restano il dato sorgente (la migrazione si
rilancia) e la prova di cosa era autorizzato prima. Ciò che è già vagliato è
marcato `already` e non riproposto.

Questo modulo è l'**ultimo lettore** del formato `<!-- telegram-whitelist -->`:
il parser vive qui, dove muore con lo script.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from .. import egress
from . import telegram_bindings as tb

#: Stesso blocco che `channel_relay._parse_whitelist` leggeva fino alla #365.
_WL_RE = re.compile(
    r"<!--\s*telegram-whitelist\s*-->\s*```(?:json)?\s*(\{.*?\})\s*```",
    re.DOTALL | re.IGNORECASE)
_RIGHTS = ("command", "dialogue")


def _data_dir() -> Path:
    return Path(os.environ.get("CLODIA_DATA", "/datadir"))


def _seed_of(instance: str | None) -> str:
    return re.sub(r"-\d+$", "", str(instance or "").strip()) or "messaggero"


def _parse_whitelist(text: str) -> dict:
    m = _WL_RE.search(text or "")
    if not m:
        return {}
    try:
        data = json.loads(m.group(1))
    except (json.JSONDecodeError, TypeError):
        return {}
    return {str(k): v for k, v in data.items() if v in _RIGHTS}


def _whitelist_uids(instance: str | None) -> dict:
    """Gli uid autorizzati dal seed di quell'istanza: `MEMORY.md` + il file
    `telegram_whitelist.json` della retro-compat.

    Le due fonti si **uniscono**, mentre il relay leggeva la seconda solo se la
    prima era vuota: qui l'obiettivo è non perdere un'autorizzazione, e un uid
    migrato di troppo lo vede l'owner nella card, mentre uno perso non lo vede
    nessuno finché non smette di funzionare.
    """
    mdir = _data_dir() / "agents" / _seed_of(instance) / "memory"
    out: dict = {}
    try:
        out.update(_parse_whitelist(
            (mdir / "MEMORY.md").read_text(encoding="utf-8")))
    except OSError:
        pass
    try:
        data = json.loads((mdir / "telegram_whitelist.json").read_text(encoding="utf-8"))
        out.update({str(k): v for k, v in data.items() if v in _RIGHTS})
    except (OSError, json.JSONDecodeError, AttributeError):
        pass
    return out


def _chat_admins(chat_id: str) -> list:
    """Amministratori della chat (l'unica lista di membri che Telegram dà a un
    bot). Isolata in una funzione perché è l'unico punto che parla con la rete."""
    from . import telegram as tg
    return tg.api_call(tg._token_internal(), "getChatAdministrators",
                       {"chat_id": chat_id}) or []


def _buffer_people(chat_id: str) -> tuple[dict, set]:
    """`(uid → handle, uid senza handle)` dal buffer di contesto del relay."""
    p = _data_dir() / "channel-relay-state" / f"chat_{str(chat_id).replace('/', '_')}.json"
    handles: dict = {}
    nohandle: set = set()
    try:
        state = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return handles, nohandle
    for m in (state.get("buffer") or []):
        uid = m.get("from_id")
        if uid is None:
            continue
        h = str(m.get("from_username") or "").strip().lstrip("@")
        if h:
            handles[str(uid)] = h
        else:
            nohandle.add(str(uid))
    return handles, nohandle


def _people(chat_id: str, warnings: list) -> tuple[dict, set]:
    """Chi è riconoscibile in QUESTA chat, dalle due fonti disponibili.

    Il roster vince sul buffer: è lo stato attuale, il buffer è memoria. Un
    roster irraggiungibile (token, rete, bot rimosso dal gruppo) degrada a
    «nessun amministratore noto» con un avviso nel piano — un guasto non deve
    fermare la migrazione delle altre chat, ma nemmeno sparire.
    """
    handles, nohandle = _buffer_people(chat_id)
    try:
        members = _chat_admins(chat_id)
    except Exception as e:  # noqa: BLE001
        warnings.append(f"chat {chat_id}: roster non disponibile ({str(e)[:160]}) "
                        f"— restano i soli utenti già visti nel buffer del relay")
        return handles, nohandle
    for m in members or []:
        u = (m or {}).get("user") or {}
        if u.get("is_bot") or u.get("id") is None:
            continue
        uid = str(u["id"])
        h = str(u.get("username") or "").strip().lstrip("@")
        if h:
            handles[uid] = h
            nohandle.discard(uid)
        elif uid not in handles:
            nohandle.add(uid)
    return handles, nohandle


def _entry(uri: str, scope: str, kind: str, uid: str | None) -> dict:
    return {"uri": uri, "kind": kind, "uid": uid,
            "status": "already" if egress.is_vetted_source(uri, scope) else "pending"}


def plan() -> dict:
    """Il piano di migrazione. Legge soltanto: non scrive liste né memorie."""
    bindings = tb.load()
    warnings: list = []
    scopes: list = []
    not_migrable: list = []
    commands: list = []
    # Un uid può stare nella lista del seed ed essere riconoscibile in UNA sola
    # delle chat legate: la riga «non riconosciuto» va scritta una volta sola,
    # alla fine, e solo per chi non è stato trattato da nessuna parte.
    handled: set = set()
    unresolved: dict = {}

    for chat_id, b in sorted(bindings.items()):
        tier, topic = (b or {}).get("tier"), (b or {}).get("topic")
        if not (tier and topic):
            warnings.append(f"binding {chat_id} senza tier/topic: saltato")
            continue
        scope = f"{tier}/{topic}"
        entries: list = []
        # Il gruppo stesso: il binding esistente è il segnale che VA reso fonte,
        # non la prova che lo sia già (è precisamente il buco chiuso dalla #364).
        try:
            entries.append(_entry(egress.check_grantable("ingress", f"tg:{chat_id}"),
                                  scope, "group", None))
        except ValueError as e:
            warnings.append(f"chat {chat_id}: non registrabile come fonte ({e})")
        handles, nohandle = _people(chat_id, warnings)
        for uid in sorted(_whitelist_uids((b or {}).get("instance")), key=str):
            h = handles.get(str(uid))
            if not h:
                if str(uid) in nohandle:
                    handled.add(str(uid))
                    not_migrable.append({
                        "uid": str(uid), "scope": scope, "chat_id": str(chat_id),
                        "handle": None,
                        "reason": ("visto nella chat ma senza handle Telegram: "
                                   "in ingresso `tg:` registra @handle, non un uid "
                                   "— va chiesto alla persona di impostarne uno")})
                else:
                    unresolved.setdefault(str(uid), []).append(scope)
                continue
            try:
                uri = egress.check_grantable("ingress", f"tg:@{h}")
            except ValueError as e:
                handled.add(str(uid))
                not_migrable.append({
                    "uid": str(uid), "scope": scope, "chat_id": str(chat_id),
                    "handle": h, "reason": str(e)})
                continue
            handled.add(str(uid))
            entries.append(_entry(uri, scope, "person", str(uid)))
        scopes.append({"scope": scope, "tier": tier, "topic": topic,
                       "chat_id": str(chat_id), "instance": (b or {}).get("instance"),
                       "entries": entries})

    for uid, seen_in in sorted(unresolved.items(), key=lambda kv: kv[0]):
        if uid in handled:
            continue
        not_migrable.append({
            "uid": uid, "scope": ", ".join(seen_in), "chat_id": None, "handle": None,
            "reason": ("uid non riconosciuto in nessuna chat legata (né fra gli "
                       "amministratori né nel buffer del relay): handle non "
                       "risolvibile, la persona va identificata a mano")})

    for s in scopes:
        for e in s["entries"]:
            if e["status"] == "pending":
                commands.append(
                    f'topic.ingress_add("{s["tier"]}", "{s["topic"]}", "{e["uri"]}")'
                    + (f'  # uid {e["uid"]}, chat {s["chat_id"]}' if e["uid"]
                       else f'  # il gruppo legato a {s["scope"]}'))

    return {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "applies": False, "scopes": scopes, "not_migrable": not_migrable,
            "commands": commands, "warnings": warnings}


def render(p: dict) -> str:
    """Il piano in forma leggibile. I non migrabili sono una SEZIONE, non un
    log: la issue chiede che siano comunicati esplicitamente, e ciò che finisce
    in un log non lo comunica a nessuno."""
    out: list = [f"# Migrazione whitelist Telegram → ingress  ({p['generated_at']})",
                 "", "Nessuna concessione è stata scritta: ogni riga qui sotto va "
                 "eseguita e approvata dall'owner dello scope.", ""]
    for s in p["scopes"]:
        out.append(f"## {s['scope']}  (chat {s['chat_id']}, istanza {s['instance']})")
        for e in s["entries"]:
            mark = "già fonte" if e["status"] == "already" else "DA APPROVARE"
            uid = f" [uid {e['uid']}]" if e["uid"] else ""
            out.append(f"  - {e['uri']}{uid} — {mark}")
        out.append("")
    out.append(f"## Non migrabili ({len(p['not_migrable'])})")
    if not p["not_migrable"]:
        out.append("  nessuno")
    for n in p["not_migrable"]:
        out.append(f"  - uid {n['uid']} ({n['scope']}): {n['reason']}")
    out.append("")
    out.append(f"## Comandi da eseguire ({len(p['commands'])})")
    if p["commands"]:
        out.extend(f"  {c}" for c in p["commands"])
    else:
        out.append("  nessuno")
    if p["warnings"]:
        out += ["", f"## Avvisi ({len(p['warnings'])})"]
        out.extend(f"  - {w}" for w in p["warnings"])
    return "\n".join(out) + "\n"


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Piano di migrazione whitelist Telegram → ingress dello scope "
                    "(clodia-platform#366). Non concede nulla: prepara le richieste.")
    ap.add_argument("--json", metavar="PATH", help="scrive il piano in JSON")
    args = ap.parse_args(argv)
    p = plan()
    if args.json:
        Path(args.json).write_text(json.dumps(p, ensure_ascii=False, indent=2),
                                   encoding="utf-8")
    print(render(p))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

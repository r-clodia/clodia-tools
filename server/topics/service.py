"""Servizio Topic v2 — i verbi, sopra lo storage astratto.

Backend-agnostico: lavora SOLO tramite l'interfaccia `Storage`. Implementa la
meccanica (file meta.json + summary.md + AGENTS.md opzionale, optimistic lock sul
summary); la disciplina editoriale (cos'è un buon TLDR) sta nella
skill `topic-management`, non qui.

Classificazione a **tier** P0–P3 (sostituisce personal/confidential): è la sola
classe del topic, e coincide col livello di privacy usato dall'enforcement.
    P0 Public · P1 Internal · P2 Confidential · P3 Restricted

Layout per topic nello storage:
    <tier>/<name>/meta.json
    <tier>/<name>/summary.md
    <tier>/<name>/AGENTS.md
"""
from __future__ import annotations

import base64
import json
import threading
import logging
import os
import re
from datetime import datetime, timezone
from typing import Optional

from . import mentions
from .storage import NotFound, Storage, StorageError, VersionConflict

LOG = logging.getLogger("clodia-tools.topics")

SCHEMA_VERSION = 2
TOPIC_STATES = ("active", "on-hold", "done", "archived")
VALID_STATUS = set(TOPIC_STATES)
# Scala SEAL (EC Cloud Sovereignty Framework v1.2.1). Sostituisce P0–P3.
VALID_TIER = ["SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4"]
TIER_NAMES = {
    "SEAL-0": "Public", "SEAL-1": "Internal", "SEAL-2": "Confidential",
    "SEAL-3": "Restricted", "SEAL-4": "Sovereign",
}
DEFAULT_TIER = "SEAL-0"
# Legacy P0–P3 → SEAL-0..3 (compat: dati/clearance non ancora migrati).
_LEGACY_TIER = {"P0": "SEAL-0", "P1": "SEAL-1", "P2": "SEAL-2", "P3": "SEAL-3"}


def _normalize_tier(t: str | None) -> str:
    if not t:
        return DEFAULT_TIER
    u = str(t).strip().upper()
    return _LEGACY_TIER.get(u, u)


def _tier_rank(t: str | None) -> int:
    """Rango numerico del tier (SEAL-N → N); -1 se ignoto."""
    try:
        return VALID_TIER.index(_normalize_tier(t))
    except ValueError:
        return -1


# Cap SEAL per tipo di channel dei MESSAGGI (anello più debole della catena):
# Telegram = SEAL-1 (FZ-LLC Dubai, server non-UE, gruppi non-E2E). Un topic con
# quel channel non può superare il cap. webui = nessun cap (default).
_CHANNEL_SEAL_CAP = {"telegram": 1}
# type/chat_id/bot_ref = legacy; listens/participants/messenger = modello
# telegram-proxy (18 lug): `listens` = chat_id ascoltate dall'istanza messaggero
# partecipe del topic (binding 1:N); `participants` = mappa telegram_uid→diritti
# (command|dialogue) per il giudizio degli agenti; `messenger` = nome dell'istanza.
_CHANNEL_FIELDS = ("type", "chat_id", "bot_ref", "listens", "participants", "messenger")


def _clean_channel(ch: dict) -> dict:
    """Tiene solo i campi ammessi del channel; normalizza gli id a stringa."""
    out = {k: ch.get(k) for k in _CHANNEL_FIELDS if ch.get(k) is not None}
    if "chat_id" in out:
        out["chat_id"] = str(out["chat_id"])
    if "listens" in out:
        # lista di chat_id, stringhe, deduplicata, ordine stabile.
        out["listens"] = list(dict.fromkeys(str(c) for c in (out["listens"] or [])))
    if "participants" in out:
        # mappa uid(str) → "command"|"dialogue"; scarta valori non ammessi.
        out["participants"] = {
            str(uid): rights for uid, rights in (out["participants"] or {}).items()
            if rights in ("command", "dialogue")}
    out.setdefault("bot_ref", "telegram_bot_token")
    return out


def _check_channel_cap(channel: dict, tier: str) -> None:
    """Verifica che il tier del topic rispetti il cap SEAL del channel."""
    ctype = (channel or {}).get("type")
    cap = _CHANNEL_SEAL_CAP.get(ctype)
    if cap is None:
        raise TopicError(f"channel type non supportato: {ctype}")
    if _tier_rank(tier) > cap:
        raise TopicError(
            f"channel '{ctype}' cappa il tier a SEAL-{cap}: topic {tier} non ammesso "
            f"(anello più debole: min(dati, provider, storage, channel))")


class TopicError(RuntimeError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(mtime: float) -> str:
    return datetime.fromtimestamp(mtime, timezone.utc).isoformat(timespec="seconds")


def _tldr(summary_text: str) -> str:
    for line in (summary_text or "").splitlines():
        line = line.strip().lstrip("#").strip()
        if line:
            return line
    return ""


def _action_points(summary_text: str) -> list[str]:
    """Estrae i bullet sotto la sezione '## Prossimi passi' (fino alla prossima
    heading)."""
    out: list[str] = []
    in_section = False
    for raw in (summary_text or "").splitlines():
        line = raw.strip()
        if line.startswith("#"):
            in_section = "prossimi passi" in line.lower()
            continue
        if in_section and line[:1] in ("-", "*", "+"):
            item = line[1:].strip()
            if item:
                out.append(item)
    return out


# Vocabolario unico di status (selezione uguale per tutti). I valori legacy
# vengono normalizzati alla lettura/scrittura del meta.
_STATUS_LEGACY = {
    "idle": "active",
    "await": "on-hold",
    "urgent": "active",
    "attivo": "active",
    "in_attesa": "on-hold",
    "completato": "done",
}


def _norm_status(s: str | None) -> str:
    s = (s or "").strip().lower()
    s = _STATUS_LEGACY.get(s, s)
    return s if s in TOPIC_STATES else "active"


def _validate_status(s: str | None) -> str:
    raw = (s or "").strip().lower()
    st = _STATUS_LEGACY.get(raw, raw)
    if st not in TOPIC_STATES:
        raise TopicError(f"status non valido: {s} (validi: {', '.join(TOPIC_STATES)})")
    return st


# Scadenze nei todo (action_points): una data nel testo del punto (es.
# "inviare LOI entro 2026-07-10" o "20/07/2026"). La card mostra la più vicina.
import re as _re
from datetime import date as _date
_DATE_RXS = [
    (_re.compile(r"\b(\d{4})-(\d{1,2})-(\d{1,2})\b"), (1, 2, 3)),          # YYYY-MM-DD
    (_re.compile(r"\b(\d{1,2})[/.](\d{1,2})[/.](\d{4})\b"), (3, 2, 1)),    # DD/MM/YYYY
]


def _parse_deadline(text: str):
    for rx, (yi, mi, di) in _DATE_RXS:
        m = rx.search(text or "")
        if m:
            try:
                return _date(int(m.group(yi)), int(m.group(mi)), int(m.group(di)))
            except ValueError:
                continue
    return None


def _next_deadline(action_points: list[str]) -> str | None:
    """Scadenza più vicina fra i todo con data: la prima IMMINENTE (>= oggi);
    se sono tutte passate, la più recente (scaduta, ancora rilevante). ISO date."""
    dates = [d for d in (_parse_deadline(a) for a in (action_points or [])) if d]
    if not dates:
        return None
    today = _date.today()
    future = sorted(d for d in dates if d >= today)
    return (future[0] if future else max(dates)).isoformat()


def _norm_deadline(value) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str) or not re.match(r"^\d{4}-\d{2}-\d{2}$", value):
        raise TopicError("deadline non valida: attesa data ISO YYYY-MM-DD o null")
    if _parse_deadline(value) is None:
        raise TopicError("deadline non valida: attesa data ISO reale YYYY-MM-DD")
    return value


def _coerce_deadline(value, ctx: str = "") -> str | None:
    """Versione TOLLERANTE di _norm_deadline per il read-path/migrazione: un
    valore legacy non conforme (testo libero, formato errato) diventa None con un
    warning, MAI un'eccezione. Rifiutare l'input errato è compito dei soli
    endpoint di scrittura (_norm_deadline), non della lettura di un topic."""
    if value in (None, ""):
        return None
    if isinstance(value, str) and re.match(r"^\d{4}-\d{2}-\d{2}$", value) \
            and _parse_deadline(value) is not None:
        return value
    LOG.warning("meta v2%s: deadline legacy non conforme %r → null",
                f" ({ctx})" if ctx else "", value)
    return None


#: Nome del mount quando il metadata legacy non ne ha uno. Il tipo va bene finché
#: i mount sono uno: con due mount dello stesso tipo servirebbe distinguerli, ed è
#: per questo che il nome nuovo si sceglie al collegamento invece di derivarlo.
def _legacy_mount_name(rem: dict) -> str:
    return str(rem.get("type") or "remote").strip().lower() or "remote"


def mounts(meta: dict) -> list:
    """I mount di uno scope, SEMPRE come lista (specification §2.6).

    Uno scope può avere più mount remoti, ognuno di un tipo e con la propria
    credenziale. Il metadata legacy ne aveva uno solo, sotto `remote`: qui viene
    letto e convertito, come si fa per `participants` da lista a mappa — una
    forma sola in memoria, il legacy tradotto al confine.

    Un accessore solo, e questa è la ragione: `meta["remote"]` era letto in
    **dodici** punti. Convertirne undici avrebbe lasciato il dodicesimo a vedere
    una forma che non esiste più, e a fallire per un motivo che non somiglia alla
    causa.
    """
    raw = meta.get("mounts")
    if isinstance(raw, list):
        return [m for m in raw if isinstance(m, dict) and m.get("type")]
    rem = meta.get("remote")
    if isinstance(rem, dict) and rem.get("type"):
        return [dict(rem, name=str(rem.get("name") or _legacy_mount_name(rem)))]
    return []


def _mount_id(voluto: str, meta: dict) -> str:
    """Identificatore del mount: validato, unico nel topic, stabile.

    Il default è il TIPO finché è libero — così `/remote/drive/` resta il caso
    comune — e diventa `drive-2` solo quando serve davvero. Un identificatore
    generato di nascosto sarebbe illeggibile; uno che collide silenziosamente
    sovrascriverebbe un mount che qualcuno ha collegato.
    """
    import re as _re
    base = _re.sub(r"[^a-z0-9-]+", "-", str(voluto or "remote").strip().lower()).strip("-")
    base = base or "remote"
    presi = {str(m.get("name") or "") for m in mounts(meta)}
    if base not in presi:
        return base
    i = 2
    while f"{base}-{i}" in presi:
        i += 1
    return f"{base}-{i}"


def _mount_of_cfg(meta: dict, cfg: dict) -> str | None:
    """Il nome del mount che porta QUESTA config.

    I chiamanti storici passano la config, non il mount: la config l'hanno
    risolta prima. Risalire qui evita di cambiare dieci firme per un dato che
    nel meta c'è già — e evita che nove le cambino e la decima no.
    """
    voluta = (cfg or {}).get("folder")
    for m in mounts(meta):
        if (m.get("config") or {}).get("folder") == voluta:
            return m.get("name")
    return None


def mount_by_name(meta: dict, name: str | None = None) -> dict:
    """Il mount indicato, o il PRIMO se non se ne indica uno.

    Il ripiego sul primo tiene in piedi i verbi che parlano di «il remote» da
    quando ce n'era uno solo. Non è una scelta definitiva: un verbo che agisce
    sul primo mount di tre agisce su uno che chi chiama non ha nominato, e questa
    è la metà del lavoro che resta.
    """
    ms = mounts(meta)
    if not ms:
        return {}
    if not name:
        return ms[0]
    for m in ms:
        if str(m.get("name") or "") == str(name):
            return m
    return {}


def normalize_meta_v2(meta: dict, tier: str) -> dict:
    """Normalizza un meta al formato v2 in modo TOLLERANTE: usato sul read-path
    (open/list/_read_meta) e in migrazione → non deve MAI sollevare per valori
    legacy non conformi, altrimenti un topic diventa non-apribile e sparisce
    dalla lista (list() ingoia TopicError). status sconosciuto → 'active',
    deadline non valida → null. La validazione stretta con errore resta solo
    negli endpoint di scrittura set_status/set_deadline."""
    out = dict(meta or {})
    out.pop("minutes", None)
    out["schema_version"] = SCHEMA_VERSION
    out["tier"] = _normalize_tier(out.get("tier") or tier)
    out["status"] = _norm_status(out.get("status") or "active")
    out["deadline"] = _coerce_deadline(out.get("deadline"), ctx=out.get("name", ""))
    # PORTABILE: i partecipanti lo raggiungono da qualunque altro scope
    # (specification §2.4). Coercizione a bool perché un valore strano non deve
    # rendere un topic non-apribile — ma nemmeno portabile per errore: qualunque
    # cosa non sia vero esplicito vale falso.
    out["portable"] = out.get("portable") is True
    return out


def _remote_unreachable(exc: Exception, tier: str, name: str) -> "TopicError":
    """Traduce il fallimento di un backend remoto in un errore AZIONABILE.

    Senza questo il chiamante riceve l'eccezione grezza della libreria del
    provider (`RefreshError: invalid_grant…`), che diventa un 500 opaco e, in UI,
    un fallimento silenzioso: l'utente vede una cartella vuota e non sa che il
    collegamento è scaduto. Il prefisso `remote-unavailable:` è il marcatore su
    cui i chiamanti (agent-server, webui) distinguono "non ci sono file" da
    "non è stato possibile leggerli".
    """
    txt = str(exc)
    if "invalid_grant" in txt or "expired or revoked" in txt:
        why = ("il collegamento Google di questo topic è scaduto o è stato "
               "revocato: riautorizza l'integrazione Google per riprendere "
               "l'accesso ai file")
    else:
        why = f"storage remoto non raggiungibile ({txt[:120]})"
    LOG.warning("topic %s/%s: %s", tier, name, why)
    return TopicError(f"remote-unavailable: {why}")


class TopicService:
    def __init__(self, storage: Storage):
        self.s = storage          # control-plane local (meta, summary, .messages)
        # Cache dei backend Drive PER THREAD, non condivisa. Il service di
        # google-api-python-client NON è thread-safe: l'oggetto http sottostante
        # tiene lo stato della connessione TLS, e due chiamate concorrenti lo
        # corrompono. Sintomo osservato in produzione il 4 ago 2026, con tre topic
        # Drive e il polling della vista file: `[SSL] record layer failure`
        # seguito da `free(): invalid next size (normal)` — corruzione dello heap
        # glibc, il processo aborta con exit 0 e nessun traceback, docker lo
        # riavvia, e l'utente vede 503 intermittenti.
        #
        # Non un lock: serializzerebbe ogni accesso a Drive fra tutti i topic, e
        # il gateway serve i topic in thread proprio per non bloccare l'event loop.
        # Un service per thread costa una costruzione in più e nulla di condiviso.
        self._drive_local = threading.local()

    # ── routing storage dei FILE (control-plane resta su self.s) ─────────────
    def _drive_service(self, account: str | None, bundle: dict | None = None):
        """Client Drive. Con `bundle` usa QUELLA credenziale, altrimenti l'account
        di piattaforma.

        Il bundle è la credenziale che l'owner ha fornito al mount (§2.7): la
        piattaforma non presta più la propria dove l'owner ne ha messa una. Il
        segreto non raggiunge il modello in nessuno dei due casi — è il gateway
        a costruire il client.
        """
        from .. import vault
        from google.oauth2.credentials import Credentials
        from google.auth.transport.requests import Request as GReq
        from googleapiclient.discovery import build
        if bundle:
            return self._drive_build(bundle)
        names = vault.store_names()
        accts = sorted(
            {n[len("google_"):] for n in names if n.startswith("google_")}
            | {n[len("gworkspace_"):] for n in names
               if n.startswith("gworkspace_")}
        )
        acct = account or (accts[0] if accts else None)
        if not acct:
            raise TopicError("storage drive: nessun account Google Workspace nel vault")
        credential = (f"google_{acct}" if f"google_{acct}" in names
                      else f"gworkspace_{acct}")
        return self._drive_build(vault.get_secret("clodia", credential))

    @staticmethod
    def _drive_build(b: dict):
        """Da bundle OAuth a client Drive. Un punto solo: due costruzioni
        divergono, e la seconda è quella che si dimentica il timeout."""
        # Il controllo PRIMA degli import: una credenziale incompleta è un dato
        # sbagliato, non un problema di libreria, e deve dirlo anche dove le
        # librerie Google non ci sono.
        mancanti = [k for k in ("refresh_token", "client_id", "client_secret")
                    if not (b or {}).get(k)]
        if mancanti:
            raise TopicError(
                f"credenziale Drive incompleta: mancano {', '.join(mancanti)}")
        from google.auth.transport.requests import Request as GReq
        from google.oauth2.credentials import Credentials
        from googleapiclient.discovery import build
        creds = Credentials(token=None, refresh_token=b["refresh_token"],
                            client_id=b["client_id"], client_secret=b["client_secret"],
                            token_uri="https://oauth2.googleapis.com/token",
                            scopes=(b.get("scope") or "").split())
        creds.refresh(GReq())
        # Timeout sull'HTTP di Drive: una chiamata stallata FALLISCE dopo N secondi
        # invece di bloccare per sempre l'event loop del gateway (freeze totale).
        import httplib2
        from google_auth_httplib2 import AuthorizedHttp
        authed = AuthorizedHttp(creds, http=httplib2.Http(timeout=30))
        return build("drive", "v3", http=authed, cache_discovery=False)

    def _provision_drive_folder(self, sc: dict, topic_name: str) -> dict:
        """Risolve la config storage drive alla creazione: usa la cartella indicata
        (link o id) oppure ne crea una nuova. Ritorna {folder, account}."""
        account = sc.get("account")
        raw = (sc.get("folder") or "").strip()
        if raw:
            # estrai l'id da un link Drive (…/folders/<ID>…) o usa l'id diretto.
            m = re.search(r"/folders/([A-Za-z0-9_-]+)", raw)
            folder = m.group(1) if m else raw
        else:
            # crea una cartella nuova dedicata al topic
            svc = self._drive_service(account)
            created = svc.files().create(
                body={"name": sc.get("folder_name") or topic_name,
                      "mimeType": "application/vnd.google-apps.folder"},
                fields="id", supportsAllDrives=True).execute()
            folder = created["id"]
        return {"folder": folder, "account": account}

    def _drive_backend_for(self, tier: str, name: str, cfg: dict,
                           mount: str | None = None):
        """DriveStorage live per la cartella autoritativa del topic.

        La chiave di cache porta la PROVENIENZA della credenziale. Senza, il
        primo client costruito per questa cartella resterebbe in cache anche
        dopo che l'owner ha collegato la propria: lo scope continuerebbe a
        lavorare con l'account di piattaforma credendo di non farlo — un
        privilegio che sopravvive alla sua revoca è peggio che non averlo mai
        tolto, perché la schermata dice il contrario.
        """
        folder = (cfg or {}).get("folder")
        if not folder:
            return None
        from .drive_fs import DriveStorage
        bundle, fonte = self.drive_credential(tier, name, mount)
        key = f"{tier}/{name}:{folder}:{fonte}:{mount or '-'}"
        cache = self._drive_thread_cache()
        ds = cache.get(key)
        if ds is None:
            ds = DriveStorage(
                self._drive_service((cfg or {}).get("account"), bundle=bundle), folder)
            cache[key] = ds
        return ds

    def _drive_thread_cache(self) -> dict:
        """Cache dei backend Drive del thread corrente (vedi `__init__`)."""
        cache = getattr(self._drive_local, "cache", None)
        if cache is None:
            cache = {}
            self._drive_local.cache = cache
        return cache

    def _drive_cache_clear(self) -> None:
        """Svuota la cache del thread corrente.

        Solo del corrente: i backend degli altri thread sono oggetti loro e
        toccarli da qui sarebbe la stessa condivisione che questo cambio elimina.
        Un backend stantio in un altro thread costa una chiamata a vuoto e viene
        ricostruito; toccarlo costerebbe un crash.
        """
        self._drive_thread_cache().clear()

    # Drive remote = source of truth: quando un topic è collegato a una cartella
    # Drive NON si fa alcun upload dei file locali (niente "migrazione"): Drive è
    # già la verità e si naviga direttamente il remoto. Nessun marker "live".
    # I Google Docs nativi (Documenti/Fogli/Presentazioni) NON sono scaricabili
    # come binari: si mostrano come proxy/link e si leggono/editano su Drive.
    _NATIVE_DOC_PREFIX = "application/vnd.google-apps."

    def _drive_pull_tree(self, ds, rel: str, local_base: str) -> None:
        """Materializza Drive in locale quando il remote viene disabilitato."""
        for e in ds.list(rel):
            child = f"{rel}/{e.name}".strip("/")
            if e.kind == "dir":
                self._drive_pull_tree(ds, child, local_base)
            elif e.mime and e.mime.startswith(self._NATIVE_DOC_PREFIX):
                # Doc nativo → stub proxy locale col link al documento remoto.
                stub = {"gdrive_url": e.url or "", "mimeType": e.mime, "name": e.name}
                self.s.write(f"{local_base}/{child}.gdrive.json".strip("/"),
                             json.dumps(stub, ensure_ascii=False).encode())
            else:
                dest = f"{local_base}/{child}".strip("/")
                if self.s.exists(dest):
                    continue  # resume: già in locale → salta (seed ripartibile)
                try:
                    self.s.write(dest, ds.read(child).data)
                except Exception as ex:  # noqa: BLE001 — non scaricabile → salta, non bloccare
                    LOG.warning("drive-seed: salto '%s' (%s)", child, ex)

    @staticmethod
    def _drive_remote_config(meta: dict, mount_name: str | None = None) -> dict | None:
        remote = mount_by_name(meta, mount_name)
        if remote.get("type") == "drive":
            return remote.get("config") or {}
        return None

    def sync_now(self, tier: str, name: str) -> dict:
        return {
            "synced": 0,
            "noop": True,
            "deprecated": True,
            "note": "Drive è live: ogni scrittura è già persistita",
        }

    def _files_backend(self, tier: str, name: str):
        """Storage dei file: Drive live per remote drive, locale negli altri casi."""
        try:
            meta = json.loads(self.s.read(self._meta_p(tier, name)).data.decode())
        except Exception:  # noqa: BLE001 — topic legacy/assente → local
            meta = {}
        if meta.get("storage") == "google-drive" and not mounts(meta):
            self._migrate_legacy_drive(tier, name)
            meta = json.loads(self.s.read(self._meta_p(tier, name)).data.decode())
        cfg = self._drive_remote_config(meta)
        if cfg is not None:
            # Drive è la fonte: si naviga direttamente il remoto, i file locali
            # non sono consultati né caricati.
            ds = self._drive_backend_for(tier, name, cfg, _mount_of_cfg(meta, cfg))
            if ds is None:
                raise TopicError("remote drive: nessuna cartella configurata")
            return ds, ""
        return self.s, f"{self._dir(tier, name)}/files"

    # ── L'albero dei dati: UNA vista, due mount ─────────────────────────────
    #
    # `local/` e `remote/<nome>/` sono due CARTELLE dello stesso albero, ognuna
    # delle quali monta un filesystem. Non due viste affiancate: una sola, in cui
    # nessuno deve scegliere quale aprire.
    #
    # Il montaggio non è decorazione, fissa cosa significa un path. `local/x` e
    # `remote/drive/x` sono file DIVERSI che possono avere lo stesso nome — ed è
    # per questo che la domanda «quale dei due risponde a una lettura?» non si
    # pone: non è esprimibile. Con due viste affiancate lo stesso `x` comparirebbe
    # in entrambe senza modo di dire quale intendesse un agente.
    #
    # Prima di questo, i due piani erano in XOR: collegare Drive faceva SPARIRE i
    # file locali dalla vista (`DRIVE_REMOTE.md`: «Drive è la source of truth […]
    # i file locali spariscono»). Su `proof-of-flex-2` significava 26 file
    # mostrati e 65 invisibili su disco.
    MOUNT_LOCAL = "local"
    MOUNT_REMOTE = "remote"
    _MOUNTS = (MOUNT_LOCAL, MOUNT_REMOTE)

    def _remote_mount_name(self, meta: dict) -> Optional[str]:
        """Nome del mount di un remote. Identificatore stabile, default sul tipo.

        Il `config.name` NON va usato: è un nome di VISUALIZZAZIONE derivato dal
        remote stesso (il titolo della cartella Drive), quindi può essere `None`,
        può contenere spazi e slash, e cambia se qualcuno rinomina la cartella —
        portandosi dietro ogni path memorizzato che lo citava.
        """
        r = mount_by_name(meta)
        if not r:
            return None
        # SOLO i remote che sono davvero un altro FILESYSTEM si montano.
        #
        # Un remote **git** non lo è: i file stanno in locale e vengono spinti,
        # quindi il remoto è lo stesso contenuto in un altro momento — una
        # relazione di sincronizzazione, non un secondo piano. Montarlo produceva
        # una cartella `remote/` annunciata nella radice e non risolvibile:
        # entrandoci, «remote non raggiungibile» → 404 (7 ago 2026, su
        # `proof-of-flex-sviluppo`).
        #
        # È la precisazione che mancava alla voce 17.6: i due piani convivono su
        # Drive, dove il remoto è davvero un filesystem diverso. Su git i due
        # piani sono gli stessi file, ed è per questo che lì la convivenza era già
        # vera prima di A2.
        if str(r.get("type") or "").strip().lower() != "drive":
            return None
        cfg = r.get("config") or {}
        mid = str(cfg.get("id") or r.get("type") or "").strip().lower()
        return mid if re.match(r"^[a-z0-9][a-z0-9-]{0,30}$", mid) else None

    def _local_mount(self, tier: str, name: str):
        """Il mount locale È la cartella `files/` di oggi. Nessun file spostato:
        `local/` è una vista su ciò che c'è già, quindi la migrazione non esiste e
        le chiavi di provenienza già memorizzate continuano a valere."""
        return self.s, f"{self._dir(tier, name)}/files"

    def _remote_mount(self, tier: str, name: str, meta: dict):
        """`(store, base)` del remote, o `None` se il topic non ne ha."""
        cfg = self._drive_remote_config(meta)
        if cfg is None:
            return None
        ds = self._drive_backend_for(tier, name, cfg, _mount_of_cfg(meta, cfg))
        if ds is None:
            raise TopicError("remote drive: nessuna cartella configurata")
        return ds, ""

    def _resolve_data_path(self, tier: str, name: str, relpath: str):
        """`(store, base, sub, mount)` per un path dell'albero dati.

        Tre forme, e la terza è la ragione per cui questa funzione esiste:

        - `local/x`          → mount locale, esplicito;
        - `remote/<n>/x`     → mount del remote `<n>`, esplicito;
        - `files/x` o `x`    → **LEGACY**, e risolve al backend EFFETTIVO, cioè a
          ciò a cui risolveva prima di questa modifica: Drive su un topic con
          remote Drive, locale altrimenti.

        La terza forma non è pigrizia. Mapparla su `local/` avrebbe cambiato in
        silenzio il bersaglio di ogni riferimento già scritto — nei messaggi, nelle
        etichette di provenienza, nella memoria degli agenti — facendo puntare a
        file locali invisibili path che oggi consegnano documenti di Drive. Un
        cambiamento di significato senza errore è il modo peggiore di migrare.
        """
        rel = (relpath or "").strip().lstrip("/")
        if ".." in rel.split("/") or "\\" in rel:
            raise TopicError(f"path non valido: {relpath}")
        meta, _ = self._read_meta(tier, name)
        parts = [x for x in rel.split("/") if x]

        if parts and parts[0] == self.MOUNT_LOCAL:
            store, base = self._local_mount(tier, name)
            return store, base, "/".join(parts[1:]), self.MOUNT_LOCAL

        if parts and parts[0] == self.MOUNT_REMOTE:
            rn = self._remote_mount_name(meta)
            if rn is None:
                raise TopicError(
                    f"il topic {tier}/{name} non ha un remote: `remote/` non è montato")
            if len(parts) == 1:
                raise TopicError(
                    f"`remote/` è un contenitore di mount: usa `remote/{rn}/…`")
            if parts[1] != rn:
                raise TopicError(
                    f"remote '{parts[1]}' non montato su {tier}/{name} "
                    f"(disponibile: '{rn}')")
            rm = self._remote_mount(tier, name, meta)
            if rm is None:
                raise TopicError("remote non raggiungibile")
            store, base = rm
            return store, base, "/".join(parts[2:]), f"{self.MOUNT_REMOTE}/{rn}"

        # LEGACY: `files/x` o `x` → backend effettivo, comportamento invariato.
        _, sub = self._files_rel(rel)
        store, base = self._files_backend(tier, name)
        mount = (f"{self.MOUNT_REMOTE}/{self._remote_mount_name(meta)}"
                 if store is not self.s else self.MOUNT_LOCAL)
        return store, base, sub, mount

    def data_mounts(self, tier: str, name: str) -> list[dict]:
        """I mount dell'albero dati, per la vista file."""
        meta, _ = self._read_meta(tier, name)
        out = [{"name": self.MOUNT_LOCAL, "path": self.MOUNT_LOCAL, "kind": "dir",
                "mount": "local"}]
        rn = self._remote_mount_name(meta)
        if rn:
            out.append({"name": self.MOUNT_REMOTE, "path": self.MOUNT_REMOTE,
                        "kind": "dir", "mount": "remote", "remote_name": rn})
        return out

    # storage drive: livello SEAL massimo (cap). eu-west-1 → SEAL-2.
    _DRIVE_SEAL_CAP = 2

    def _copy_tree(self, src, src_base: str, dst, dst_base: str, rel: str = "") -> tuple[int, list]:
        """Copia ricorsiva di files/ da src a dst. Non sovrascrive: se il file
        esiste già nel dst → conflitto (skippato). Ritorna (copiati, conflitti)."""
        copied, conflicts = 0, []
        sp = f"{src_base}/{rel}".strip("/")
        for e in src.list(sp):
            if e.name.startswith("."):
                continue
            child = f"{rel}/{e.name}".strip("/")
            if e.kind == "dir":
                c, cf = self._copy_tree(src, src_base, dst, dst_base, child)
                copied += c; conflicts += cf
            else:
                dpath = f"{dst_base}/{child}".strip("/")
                if dst.exists(dpath):
                    conflicts.append(child)
                    continue
                dst.write(dpath, src.read(f"{src_base}/{child}".strip("/")).data)
                copied += 1
        return copied, conflicts

    def migrate_storage(self, tier: str, name: str, target: dict) -> dict:
        """Migra i FILE del topic da uno storage all'altro (local↔drive). Copia
        non distruttiva: il vecchio contenuto va nel cestino (recuperabile). Guard
        SEAL: vietato migrare su uno storage con livello inferiore al tier."""
        mp = self._meta_p(tier, name)
        if not self.s.exists(mp):
            raise TopicError(f"topic non trovato: {tier}/{name}")
        meta = json.loads(self.s.read(mp).data.decode())
        cur_storage = ("google-drive" if self._drive_remote_config(meta) is not None
                       else (meta.get("storage") or self.s.capability().name))
        tgt_type = (target or {}).get("type")
        tgt_storage = "google-drive" if tgt_type == "drive" else "local-fs"
        if tgt_storage == cur_storage:
            return {"migrated": 0, "note": f"già su {cur_storage}"}
        # guard SEAL anti-declassamento
        try:
            tier_n = int(_normalize_tier(tier).replace("SEAL-", ""))
        except ValueError:
            tier_n = 0
        if tgt_type == "drive" and tier_n > self._DRIVE_SEAL_CAP:
            raise TopicError(
                f"storage drive ha cap SEAL-{self._DRIVE_SEAL_CAP}: un topic {tier} "
                f"non può migrare su Drive (anti-declassamento)")
        if tgt_type == "drive":
            self.remote_enable(tier, name, "drive", target)
            return {"migrated": 0, "conflicts": [],
                    "from": cur_storage, "to": "google-drive",
                    "backup": "(cartella Drive autoritativa)"}
        if self._drive_remote_config(meta) is not None:
            self.remote_disable(tier, name)
        else:
            meta["storage"] = "local-fs"
            meta.pop("storage_config", None)
            self.s.write(mp, json.dumps(meta, ensure_ascii=False, indent=2).encode())
        return {"migrated": 0, "conflicts": [], "from": cur_storage,
                "to": "local-fs", "backup": "(cartella Drive di origine conservata)"}

    @staticmethod
    def _files_rel(relpath: str) -> tuple[bool, str]:
        """(is_files, rel) — True + path sotto files/ se relpath sta in files/,
        altrimenti False (control-plane: summary/meta)."""
        r = (relpath or "").lstrip("/")
        if r == "files":
            return True, ""
        if r.startswith("files/"):
            return True, r[len("files/"):]
        return False, r

    # ── path helper ────────────────────────────────────────────────────────
    def _dir(self, tier: str, name: str) -> str:
        tier = _normalize_tier(tier)
        if tier not in VALID_TIER:
            raise TopicError(f"tier non valido: {tier} (ammessi: {VALID_TIER})")
        if not re.match(r"^[a-z0-9][a-z0-9_-]{0,60}$", name or ""):
            raise TopicError(f"nome topic non valido: {name}")
        return f"{tier}/{name}"

    def _meta_p(self, tier, name):
        return f"{self._dir(tier, name)}/meta.json"

    def _summary_p(self, tier, name):
        return f"{self._dir(tier, name)}/summary.md"

    def _agents_p(self, tier, name):
        # Istruzioni di scope — control-plane, accanto a meta.json e summary.md,
        # NON in files/. Ci sta per tre ragioni, tutte misurate:
        #
        # 1. In `files/` era scrivibile da QUALUNQUE partecipante con un upload
        #    (`put_file` → stesso store da cui questo file viene letto), cioè
        #    chiunque nella stanza poteva dettare il testo iniettato nel contesto
        #    di ogni agente a ogni turno. È la via d'iniezione più diretta che un
        #    canale abbia.
        # 2. La lettura usava `self.s` mentre `put_file` usa `_files_backend()`:
        #    su un topic con remote Drive l'upload finiva su Drive e la lettura
        #    restava locale, quindi la UI mostrava un file e il sistema ne
        #    iniettava un altro. Un solo posto, un solo backend, elimina lo
        #    scarto.
        # 3. Fuori da `files/` non viene sincronizzato da nessun remote: un
        #    remote non può più riscrivere le istruzioni dello scope.
        #
        # Scrivere questo file è un ATTO DI AUTORITÀ, non una preferenza: passa
        # da `save_agents_md` con optimistic lock, come il summary.
        return f"{self._dir(tier, name)}/AGENTS.md"

    def _legacy_agents_p(self, tier, name):
        # Posizione storica. Letta ancora in fallback finché la migrazione non è
        # passata su tutti i topic: un topic non migrato deve continuare a
        # funzionare, non a perdere silenziosamente le sue istruzioni.
        return f"{self._dir(tier, name)}/files/AGENTS.md"

    def _read_agents_md(self, tier, name) -> tuple[str | None, str | None]:
        """Testo e versione delle istruzioni di scope. `(None, None)` se assenti.

        Preferisce SEMPRE la posizione nuova: se un topic ha entrambi i file —
        perché qualcuno ha ricaricato il vecchio dopo la migrazione — vince il
        control-plane, altrimenti l'upload di un partecipante tornerebbe a
        sovrascrivere l'autorità.
        """
        try:
            r = self.s.read(self._agents_p(tier, name))
            return r.data.decode("utf-8", "replace"), r.version
        except NotFound:
            pass
        try:
            r = self.s.read(self._legacy_agents_p(tier, name))
            return r.data.decode("utf-8", "replace"), None
        except NotFound:
            return None, None

    def _recap_history_p(self, tier, name):
        # Storia dei recap (TLDR) del topic — control-plane, NON in files/ → non
        # sincronizzata dai remote git/drive.
        return f"{self._dir(tier, name)}/.recap-history.jsonl"

    # ── verbi ──────────────────────────────────────────────────────────────
    #: Il topic di CONFIGURAZIONE (voce 22). Uno solo, con un nome noto: se
    #: fosse designato da un campo, due topic potrebbero dichiararsi tali e
    #: nessuno saprebbe quale vince.
    CONFIG_TIER = "SEAL-4"
    CONFIG_NAME = "configuration"

    def config_agents_md(self) -> str | None:
        """Le istruzioni dichiarate nel topic di configurazione, se esiste."""
        try:
            text, _ = self._read_agents_md(self.CONFIG_TIER, self.CONFIG_NAME)
        except Exception:  # noqa: BLE001 — assente o illeggibile: nessuna eredità
            return None
        # `strip()` solo per decidere se c'è qualcosa: il testo va ereditato
        # com'è. Normalizzarlo qui farebbe divergere la copia dall'originale per
        # un dettaglio che nessuno ha chiesto.
        return text if (text or "").strip() else None

    def _inherit_config_agents_md(self, tier: str, name: str) -> None:
        """Un topic nuovo nasce con le istruzioni del topic di configurazione.

        Il caso più semplice della voce 22, e quello che Davide ha nominato:
        «l'AGENTS.md di questo topic è ereditato da tutti i nuovi topic».

        **Copia alla creazione, non lettura viva.** La parola è «nuovi», ed è la
        lettura con il profilo di rischio più basso: i topic esistenti non
        ricevono nulla e una modifica successiva non si propaga. La lettura viva
        sarebbe il metascope della voce 9 — un file solo capace di cambiare il
        comportamento di ogni agente in ogni stanza nello stesso istante, la
        superficie più potente del sistema, e meriterebbe un gate suo.

        Non sovrascrive: un topic creato CON istruzioni proprie le tiene. E il
        topic di configurazione non eredita da sé stesso.
        """
        if (tier, name) == (self.CONFIG_TIER, self.CONFIG_NAME):
            return
        try:
            if self.s.exists(self._agents_p(tier, name)):
                return                                  # istruzioni proprie
            text = self.config_agents_md()
            if not text:
                return
            self.s.write(self._agents_p(tier, name), text.encode("utf-8"))
        except Exception as e:  # noqa: BLE001
            # Best-effort come il remote Drive: un problema qui non deve
            # impedire la creazione del topic. Un topic senza istruzioni
            # ereditate è utilizzabile; un topic non creato no.
            import logging
            logging.getLogger("clodia-tools.topics").warning(
                "eredità AGENTS.md per %s/%s fallita (topic creato lo stesso): %s",
                tier, name, e)

    def new(self, tier: str | None, name: str, meta: dict | None = None) -> dict:
        """Scaffold idempotente: se il topic esiste già ritorna il suo meta."""
        tier = _normalize_tier(tier or DEFAULT_TIER)
        mp = self._meta_p(tier, name)
        # Lo slug è anche l'id del webhook: deve identificare un solo topic in
        # tutta la piattaforma, indipendentemente dal tier.
        for other_tier in VALID_TIER:
            if other_tier != tier and self.s.exists(self._meta_p(other_tier, name)):
                raise TopicError(
                    f"nome topic globale già usato: {other_tier}/{name}")
        if self.s.exists(mp):
            return self.open(tier, name)["meta"]
        meta = dict(meta or {})
        meta.setdefault("title", name)
        meta.setdefault("type", "progetto")
        # tier = unica classe del topic + livello di privacy per l'enforcement.
        meta["tier"] = tier
        meta.setdefault("status", "active")
        meta.setdefault("hook_enabled", True)
        # Il control-plane resta locale. I file sono locali per default; con un
        # remote Drive vengono serviti direttamente dalla cartella remota.
        sc = meta.get("storage_config") or {}
        want_drive = meta.get("storage") == "google-drive" or sc.get("type") == "drive"
        meta["storage"] = self.s.capability().name
        meta.pop("storage_config", None)
        # Channel dei MESSAGGI (default: webui, implicito). Se dichiarato (es.
        # telegram) → cap del tier all'anello più debole (SEAL-cap del channel).
        ch = meta.get("channel")
        if ch:
            _check_channel_cap(ch, tier)
            meta["channel"] = _clean_channel(ch)
        meta.setdefault("tags", [])
        meta.setdefault("people", [])
        from .. import instance_profile as _iprof0
        meta.setdefault("contact_agent", _iprof0.topic_default_contact_agent())
        # Canale (Slack-like): owner = chi amministra il canale (invita/rimuove);
        # participants = agenti (umani/AI) abilitati a parlare nel canale.
        if (tier, name) == (self.CONFIG_TIER, self.CONFIG_NAME) and not meta.get("owner"):
            # La configurazione non può essere di un agente: ne sbloccherebbe i
            # propri gate (voce 24, precisazione 2). Se non c'è un umano
            # proprietario dell'istanza si lascia il campo VUOTO invece di
            # ripiegare su `clodia` — meglio un topic senza owner, che si vede,
            # di un topic il cui owner è l'agente che dovrebbe esserne soggetto.
            from .. import human as _hu
            meta["owner"] = _hu.instance_owner() or ""
        meta.setdefault("owner", meta.get("contact_agent", "clodia"))
        # Partecipanti di default dell'edizione (terraformazione): UNIONE con
        # gli espliciti — "sempre partecipanti ai topic nuovi". ECCEZIONE: i DM
        # (chat 1:1 umano↔agente) sono a DUE e basta → NON si aggiungono i default
        # (altrimenti clodia si intrufola in ogni DM, es. dm-avvocato--davide).
        from .. import instance_profile as _iprof
        is_dm = (meta.get("kind") == "dm") or (meta.get("type") == "dm")
        # Il topic di CONFIGURAZIONE non prende i partecipanti di default, e non
        # è un dettaglio: è l'unico controllo reale della voce 22. Se un agente
        # vi fosse partecipante avrebbe `topic.put` sulla configurazione — il
        # confused deputy nella forma più pura, l'agente ha il verbo, l'admin ha
        # l'autorità, e il file è la config. «Solo admin» significa zero
        # partecipanti agenti, e la terraformazione ce li metterebbe da sola.
        is_config = (tier, name) == (self.CONFIG_TIER, self.CONFIG_NAME)
        _defaults = [] if (is_dm or is_config) else _iprof.topic_default_participants()
        explicit = meta.get("participants") or []
        meta["participants"] = list(dict.fromkeys(
            [x for x in [meta["owner"], *explicit, *_defaults] if x]))
        meta = normalize_meta_v2(meta, tier)
        meta["created_at"] = _now().isoformat(timespec="seconds")
        self.s.write(mp, json.dumps(meta, ensure_ascii=False, indent=2).encode())
        if not self.s.exists(self._summary_p(tier, name)):
            self.s.write(self._summary_p(tier, name),
                         f"{meta.get('title', name)}\n\n## Prossimi passi\n".encode())
        self._inherit_config_agents_md(tier, name)
        if want_drive:
            # Remote Drive dalla nascita: risolve/crea la cartella e abilita la
            # vista live. Best-effort: un problema Drive non
            # deve impedire la creazione del topic (resta local pulito).
            try:
                # Si rilegge il meta invece di restituire l'esito dell'enable:
                # `create` promette il meta del topic, e l'esito di un mount è
                # un'altra cosa. Finché la forma era `{"ok":…,"remote":…}` la
                # differenza passava inosservata; con più mount smetterebbe.
                self.remote_enable(tier, name, "drive", dict(sc))
                meta, _ = self._read_meta(tier, name)
            except Exception as e:  # noqa: BLE001
                import logging
                logging.getLogger("clodia-tools.topics").warning(
                    "remote drive alla creazione di %s/%s fallito (topic resta "
                    "local): %s", tier, name, e)
        return meta

    def set_portable(self, tier: str, name: str, portable: bool) -> dict:
        """Dichiara (o revoca) la portabilità di un topic.

        È un atto sui MURI dello scope, non una preferenza: rende i contenuti
        raggiungibili dai propri partecipanti in ogni altra stanza. Quindi è
        dell'owner (classe `walls`, voce 24) e non di un partecipante qualunque.

        Revocarla è immediato e non lascia strascichi: la portabilità è valutata
        a ogni accesso, non concessa una volta.
        """
        meta, ver = self._read_meta(tier, name)
        meta["portable"] = bool(portable)
        self._write_meta(tier, name, meta, base_version=ver)
        return {"ok": True, "portable": bool(portable)}


    # ── Un gruppo Telegram come mount dello scope ────────────────────────────
    #
    # È una RISORSA che l'owner porta dentro lo scope, come un repository o una
    # cartella Drive: la forma è la stessa (`{name, type, config}`), e per questo
    # sta in `mounts` invece che in un campo suo. La differenza è che non è un
    # filesystem — e non serve dirlo da nessuna parte, perché la vista dei file
    # monta già solo i tipi che lo sono (`_remote_mount_name`): un mount `git`
    # era escluso per la stessa ragione dal 7 agosto.
    TELEGRAM_MOUNT = "telegram"
    #: Cosa esce dal topic verso il gruppo.
    #: `notify` = il fatto (chi ti ha menzionato, dove) · `excerpt` = anche la
    #: riga della menzione, troncata. Entrambe portano SEMPRE il link.
    TELEGRAM_MODES = ("notify", "excerpt")
    _EXCERPT_MAX = 280

    @staticmethod
    def _webui_url() -> str:
        from . import telegram_notify as _tn
        return _tn.webui_url()

    def telegram_bind(self, tier: str, name: str, chat_id: str,
                      mode: str = "excerpt", people: dict | None = None,
                      mount_name: str | None = None) -> dict:
        """Collega un gruppo Telegram a questo topic.

        Cinque verifiche prima di scrivere, e ognuna esiste per un caso che
        altrimenti si scopre tardi:

        1. **il cap SEAL.** Telegram è capped a SEAL-1 (server non-UE, gruppi
           non-E2E). Il rifiuto arriva al collegamento, non alla prima notifica.
        2. **l'URL della webui.** Ogni notifica porta un link alla conversazione:
           senza `CLODIA_WEBUI_URL` il link sarebbe relativo, cioè un vicolo
           cieco su un telefono. Meglio rifiutare di configurare che consegnare
           link morti.
        3. **il bot è nel gruppo.** È il presupposto della funzione, e un
           presupposto non verificato diventa un errore il giorno in cui
           qualcuno rimuove il bot.
        4. **le persone sono mappate.** `people` lega uid Telegram → principal
           della piattaforma. Senza mappa non si notifica nessuno, e un
           collegamento che non notifica nessuno sembra funzionare.
        5. **i nomi sono principal veri**, non stringhe libere: una mappa verso
           un nome che non esiste è una notifica che non partirà mai, e lo si
           scoprirebbe solo dal silenzio.

        Il gruppo entra anche nella lista **egress dello scope** come
        `tg:<chat_id>`: da lì in poi è una destinazione dichiarata, vagliata per
        costruzione, non un'eccezione.
        """
        modo = (mode or "excerpt").strip().lower()
        if modo not in self.TELEGRAM_MODES:
            raise TopicError(
                f"modo '{mode}' non ammesso: {' | '.join(self.TELEGRAM_MODES)}")
        cid = str(chat_id or "").strip()
        if not cid:
            raise TopicError("chat_id del gruppo mancante")

        cap = _CHANNEL_SEAL_CAP.get("telegram")
        try:
            tier_n = int(_normalize_tier(tier).replace("SEAL-", ""))
        except (ValueError, AttributeError):
            tier_n = 0
        if cap is not None and tier_n > cap:
            raise TopicError(
                f"Telegram ha cap SEAL-{cap}: un topic {tier} non può collegare "
                f"un gruppo (i server non sono UE e i gruppi non sono E2E)")

        if not self._webui_url():
            raise TopicError(
                "CLODIA_WEBUI_URL non è impostata: ogni notifica porta un link "
                "alla conversazione, e senza un indirizzo pubblico il link è "
                "relativo — inutile dentro Telegram. Impostala e riprova")

        mappa = self._clean_people(people)
        if not mappa:
            raise TopicError(
                "nessuna persona mappata: `people` lega uid Telegram → nome "
                "utente su Clodia. Senza, il collegamento non avviserebbe "
                "nessuno. `telegram.roster(chat_id)` elenca i membri del gruppo")
        self._require_known_principals(mappa.values())
        self._require_bot_in_group(cid)

        meta, ver = self._read_meta(tier, name)
        mount_id = _mount_id(mount_name or self.TELEGRAM_MOUNT, meta)
        voce = {"name": mount_id, "type": self.TELEGRAM_MOUNT,
                "config": {"chat_id": cid, "mode": modo, "people": mappa}}
        altri = [m for m in mounts(meta) if m.get("name") != mount_id]
        meta["mounts"] = altri + [voce]
        meta.pop("remote", None)
        self._write_meta(tier, name, meta, base_version=ver)
        self._declare_egress(tier, name, f"tg:{cid}")
        return {"ok": True, "mount": voce}

    def telegram_unbind(self, tier: str, name: str,
                        mount_name: str | None = None) -> dict:
        """Scollega il gruppo. La voce di egress NON viene tolta in automatico.

        Toglierla sembrerebbe pulizia ed è invece una decisione sul perimetro:
        la stessa destinazione può essere stata autorizzata anche per altro. Chi
        vuole restringere lo fa dalla lista, dove la cosa ha un nome.
        """
        meta, ver = self._read_meta(tier, name)
        tg = [m for m in mounts(meta) if m.get("type") == self.TELEGRAM_MOUNT]
        if not tg:
            raise TopicError("questo topic non ha un gruppo Telegram collegato")
        via = mount_name or tg[0].get("name")
        if via not in {m.get("name") for m in tg}:
            raise TopicError(
                f"nessun gruppo Telegram '{via}' (ci sono: "
                f"{', '.join(str(m.get('name')) for m in tg)})")
        meta["mounts"] = [m for m in mounts(meta) if m.get("name") != via]
        meta.pop("remote", None)
        self._write_meta(tier, name, meta, base_version=ver)
        return {"ok": True, "unbound": via}

    def telegram_mounts(self, meta: dict) -> list:
        """I gruppi Telegram collegati a questo topic."""
        return [m for m in mounts(meta) if m.get("type") == self.TELEGRAM_MOUNT]

    @staticmethod
    def _clean_people(people: dict | None) -> dict:
        """`{uid: {principal, username}}` normalizzato. Voci incomplete SCARTATE.

        Scartare e non correggere: una mappa mezza scritta è una notifica verso
        la persona sbagliata, che è l'unico esito peggiore del silenzio.

        Tre cose, non due. Il `principal` è il nome nella piattaforma — è quello
        che compare come `@giovanni` nel canale. Lo `username` è il suo handle
        Telegram, `giocasu75`, ed è quello che deve comparire nel gruppo:
        scriverci `@giovanni` non notifica nessuno su Telegram e non è nemmeno
        il nome con cui quelle persone si chiamano fra loro là.

        La forma piatta `{uid: "principal"}` resta accettata: è quella scritta
        prima del 10 ago 2026, e rifiutarla farebbe smettere di funzionare i
        collegamenti già fatti. Senza username la menzione resta il nome della
        piattaforma — degradata, non rotta.
        """
        out: dict = {}
        for uid, v in (people or {}).items():
            u = str(uid).strip()
            if not u:
                continue
            if isinstance(v, dict):
                chi = str(v.get("principal") or "").strip().lower()
                handle = str(v.get("username") or "").strip().lstrip("@")
            else:
                chi, handle = str(v or "").strip().lower(), ""
            if not chi:
                continue
            # La CHIAVE può essere un uid numerico o un handle. Chiedere l'uid
            # era corretto sul piano tecnico — è l'identificatore stabile, un
            # username si cambia — e sbagliato sul piano umano: l'handle è
            # quello che una persona conosce e sa copiare, l'uid no. Davide ha
            # compilato la mappa con `@giocasu75`, che è la cosa naturale da
            # fare, e il codice ha reso `@giovanni`.
            #
            # Si accettano entrambi: una chiave non numerica È l'handle. Meglio
            # incontrare chi compila dove si trova che avere ragione su una
            # mappa vuota.
            if not u.lstrip("-").isdigit() and not handle:
                handle = u.lstrip("@")
            voce = {"principal": chi}
            if handle:
                voce["username"] = handle
            out[u] = voce
        return out

    @staticmethod
    def _require_known_principals(nomi) -> None:
        from .. import human as _h
        ignoti = []
        for n in nomi:
            try:
                if not _h.is_human(n):
                    ignoti.append(n)
            except Exception:  # noqa: BLE001 — registro illeggibile: non si giudica
                return
        if ignoti:
            raise TopicError(
                f"nomi utente sconosciuti su Clodia: {', '.join(sorted(set(ignoti)))}. "
                f"Una mappa verso un nome che non esiste è una notifica che non "
                f"partirà mai, e lo scopriresti solo dal silenzio")

    @staticmethod
    def _require_bot_in_group(chat_id: str) -> None:
        """Il bot dev'essere già nel gruppo. Verificato, non supposto.

        `api_call` restituisce **il campo `result` già spacchettato** e solleva
        sugli errori: leggere `.get("result")` sulla sua risposta dà `None`
        sempre, anche quando è andata benissimo. È il contratto di un aiutante
        che avevo dato per scontato invece di leggerlo, ed è costato un
        collegamento rifiutato su un gruppo che esiste (10 ago 2026).
        """
        from ..tools import telegram as tg
        try:
            tok = tg._token_internal()
            uid = (tg.api_call(tok, "getMe") or {}).get("id")
            if not uid:
                raise RuntimeError("getMe non ha restituito l'id del bot")
            stato = ((tg.api_call(tok, "getChatMember",
                                  {"chat_id": chat_id, "user_id": uid}) or {})
                     .get("status") or "").lower()
        except Exception as e:  # noqa: BLE001
            # Il MOTIVO, non il tipo dell'eccezione. «RuntimeError» non dice se
            # il gruppo non esiste, se il bot è fuori o se il token è di un
            # altro bot — e sono tre rimedi diversi.
            raise TopicError(
                f"non riesco a verificare che il bot sia nel gruppo {chat_id}: "
                f"{e}. Il collegamento si ferma qui invece di riuscire e non "
                f"funzionare") from e
        if stato in ("left", "kicked", ""):
            raise TopicError(
                f"il bot non è membro del gruppo {chat_id} (stato: "
                f"{stato or 'sconosciuto'}). Aggiungilo al gruppo e riprova")

    def _declare_egress(self, tier: str, name: str, uri: str) -> None:
        """Aggiunge una destinazione alla lista egress DI QUESTO SCOPE."""
        try:
            from .. import egress as _eg
            _eg.scope_allow("egress", f"{_normalize_tier(tier)}/{name}", uri)
        except Exception as e:  # noqa: BLE001
            LOG.warning("egress %s per %s/%s non dichiarata: %s", uri, tier, name, e)

    def set_channel(self, tier: str, name: str, channel: dict | None) -> dict:
        """Configura/rimuove il channel dei messaggi di un topic esistente.
        `channel=None` o `{}` → rimuove (torna a webui). Applica il cap SEAL."""
        meta, ver = self._read_meta(tier, name)
        if not channel:
            meta.pop("channel", None)
        else:
            _check_channel_cap(channel, meta.get("tier", tier))
            meta["channel"] = _clean_channel(channel)
        self._write_meta(tier, name, meta, base_version=ver)
        return meta

    def _chat_owner_topic(self, chat_id: str, exclude: tuple | None = None):
        """(tier, name) del topic che già ascolta `chat_id`, o None. Garantisce
        l'invariante UNA chat → UN solo topic (evita il drain distruttivo condiviso:
        chi draga per primo consuma il messaggio, gli altri lo perdono)."""
        cid = str(chat_id)
        for row in self.list(None, include_archived=True):
            ch = row.get("channel") or {}
            if cid in (ch.get("listens") or []):
                key = (row.get("tier"), row.get("name"))
                if key != exclude:
                    return key
        return None

    def channel_listen(self, tier: str, name: str, chat_id: str,
                       listen: bool = True, messenger: str | None = None) -> dict:
        """Aggiunge/rimuove una chat_id dall'insieme `listens` del channel
        Telegram del topic (modello telegram-proxy). Crea il channel telegram se
        assente (applicando la SEAL-cap). `listen=False` → unlisten. `messenger` =
        istanza messaggero che ha stabilito il binding. Ritorna il meta aggiornato.
        Invariante: una chat può essere ascoltata da UN solo topic."""
        cid = str(chat_id)
        if listen:
            owner = self._chat_owner_topic(cid, exclude=(tier, name))
            if owner is not None:
                raise TopicError(
                    f"chat {cid} già in ascolto sul topic {owner[0]}/{owner[1]}: "
                    f"fai prima telegram.unlisten lì (una chat → un solo topic)")
        meta, ver = self._read_meta(tier, name)
        ch = dict(meta.get("channel") or {})
        if not ch:
            ch = {"type": "telegram"}
        if ch.get("type") != "telegram":
            raise TopicError(f"channel del topic {tier}/{name} non è telegram")
        _check_channel_cap(ch, meta.get("tier", tier))
        cur = list(ch.get("listens") or [])
        if listen:
            if cid not in cur:
                cur.append(cid)
            if messenger:
                ch["messenger"] = messenger
        else:
            cur = [c for c in cur if c != cid]
        ch["listens"] = cur
        meta["channel"] = _clean_channel(ch)
        self._write_meta(tier, name, meta, base_version=ver)
        return meta

    # ── Remote pluggable (git/drive): storage sempre local, sync opzionale ─────
    def _abs(self, tier: str, name: str, sub: str = "") -> str:
        """Path filesystem ASSOLUTO del topic (le Remote git/drive vi operano)."""
        root = getattr(self.s, "root", None)
        if root is None:
            raise TopicError("remote non supportato: storage non locale")
        p = root / self._dir(tier, name)
        return str(p / sub) if sub else str(p)

    def _remote_drive_factory(self, account, folder):
        from .drive_fs import DriveStorage
        key = f"remote:{account or ''}:{folder}"
        cache = self._drive_thread_cache()
        ds = cache.get(key)
        if ds is None:
            ds = DriveStorage(self._drive_service(account), folder)
            cache[key] = ds
        return ds

    def _remote_for(self, tier: str, name: str, meta: dict,
                    mount_name: str | None = None):
        from .remote import make_remote
        r = mount_by_name(meta, mount_name)
        if not r.get("type"):
            return None
        # Solo per i remote git su github.com iniettiamo il PAT del vault (scoping:
        # il token non deve raggiungere altri host).
        gh_token = None
        if r["type"] == "git" and "github.com" in ((r.get("config") or {}).get("url") or ""):
            gh_token, _fonte = self.git_credential(tier, name, r.get("name"))
        return make_remote(r["type"], self._abs(tier, name, "files"),
                           self._abs(tier, name, ".remote-drive.json"),
                           drive_factory=self._remote_drive_factory,
                           github_token=gh_token)

    @staticmethod
    def scope_credential_name(tier: str, name: str, kind: str = "git",
                              mount: str | None = None) -> str:
        """Nome nel vault della credenziale legata a UNO scope.

        Derivato dallo scope e non scelto da chi la deposita: se il nome fosse
        libero, due topic potrebbero puntare alla stessa credenziale senza che
        nessuno lo veda, e il confinamento sarebbe una convenzione invece di una
        proprietà.

        La credenziale è del MOUNT, non dello scope: due mount dello stesso
        topic possono appartenere a owner diversi, e una credenziale sola li
        renderebbe di nuovo lo stesso perimetro — cioè annullerebbe la ragione
        per cui esistono due mount (voce 33).

        Senza `mount` il nome resta quello storico: è la credenziale già
        depositata sui topic esistenti, e cambiarne il nome la farebbe sparire
        senza dirlo, con ripiego silenzioso sul token di piattaforma.
        """
        t = _normalize_tier(tier).replace("-", "").lower()
        base = f"scope_{kind}__{t}__{name}"
        if not mount:
            return base
        import re as _re
        m = _re.sub(r"[^a-z0-9-]+", "-", str(mount).strip().lower()).strip("-")
        return f"{base}__{m}" if m else base

    def git_credential(self, tier: str, name: str,
                       mount: str | None = None) -> tuple[str | None, str]:
        """`(token, provenienza)` per il remote git di questo topic.

        Provenienza è `scope` o `platform`, e viene restituita perché DEVE essere
        visibile: un topic senza credenziale propria ricade su quella della
        piattaforma, e un ripiego silenzioso è il modo in cui ci si convince di
        essere isolati quando non lo si è.

        Perché lo scope viene prima. Il PAT di piattaforma è letto con
        `read_internal` — nessun controllo di grant — e viene iniettato in OGNI
        remote git di OGNI topic: un token raggiunge tutti i repo per cui ha
        scope, da qualunque stanza. Una credenziale di scope ne raggiunge uno.
        """
        from .. import vault
        # Prima quella del mount, poi quella storica dello scope, infine la
        # piattaforma. L'ordine è dal perimetro più stretto al più largo: il
        # contrario farebbe usare il token che raggiunge più repo anche quando
        # ne esiste uno che ne raggiunge uno solo.
        candidati = []
        if mount:
            candidati.append((self.scope_credential_name(tier, name, "git", mount), "mount"))
        candidati.append((self.scope_credential_name(tier, name, "git"), "scope"))
        for cred, fonte in candidati:
            try:
                bundle = vault.read_internal(cred) or {}
                tok = bundle.get("value")
                if tok:
                    return tok, fonte
            except Exception:  # noqa: BLE001 — assente o illeggibile → ripiego
                pass
        return self._platform_github_token(), "platform"

    def drive_credential(self, tier: str, name: str,
                         mount: str | None = None) -> tuple[dict | None, str]:
        """`(bundle, provenienza)` per il mount Drive di questo topic.

        Stesso ordine della git — mount → scope → piattaforma — e per la stessa
        ragione: dal perimetro più stretto al più largo. Qui però il salto è più
        grande. La credenziale di piattaforma è un ACCOUNT Google intero: usarla
        dove l'owner ne ha fornita una significherebbe dare a quello scope
        l'intero Drive dell'account condiviso.

        `None` = nessuna credenziale di scope, e chi chiama ricade sull'account
        di piattaforma. Non è un errore: è il comportamento storico, e la
        provenienza restituita lo rende leggibile invece che silenzioso.
        """
        from .. import vault
        candidati = []
        if mount:
            candidati.append((self.scope_credential_name(tier, name, "drive", mount), "mount"))
        candidati.append((self.scope_credential_name(tier, name, "drive"), "scope"))
        for cred, fonte in candidati:
            try:
                b = vault.read_internal(cred) or {}
                if b.get("refresh_token"):
                    return b, fonte
            except Exception:  # noqa: BLE001 — assente o illeggibile → ripiego
                pass
        return None, "platform"

    def set_drive_credential(self, tier: str, name: str, bundle: dict | None,
                             mount: str | None = None) -> dict:
        """Deposita (o toglie) la credenziale Drive di un mount.

        Il bundle è un consenso OAuth dell'owner: `refresh_token`, `client_id`,
        `client_secret`, `scope`. Non lo si valida contro Google qui — una
        credenziale che il gateway non riesce a usare deve fallire quando la si
        usa, con l'errore di Google, non con un nostro giudizio anticipato.
        """
        from .. import vault
        cred = self.scope_credential_name(tier, name, "drive", mount)
        if not (bundle or {}).get("refresh_token"):
            try:
                vault.remove(cred)
            except Exception:  # noqa: BLE001 — già assente
                pass
            _, fonte = self.drive_credential(tier, name, mount)
            return {"credential": None, "source": fonte}
        tenuti = ("refresh_token", "client_id", "client_secret", "scope", "account")
        vault.deposit(cred, {k: bundle[k] for k in tenuti if k in bundle},
                      cred_type="google-oauth", grant_agents=[], actions=[])
        return {"credential": cred, "source": "mount" if mount else "scope"}

    def set_git_credential(self, tier: str, name: str, token: str | None,
                           mount: str | None = None) -> dict:
        """Deposita (o rimuove) la credenziale git di questo scope.

        `grant_agents=[]`: nessun agente la legge. La usa il GATEWAY quando
        esegue un verbo remote per QUESTO topic — è legata allo scope, non a un
        agente, ed è la prima credenziale del sistema a esserlo.
        """
        from .. import vault
        cred = self.scope_credential_name(tier, name, "git", mount)
        if not (token or "").strip():
            try:
                vault.remove(cred)
            except Exception:  # noqa: BLE001 — già assente
                pass
            # Togliere la credenziale di un mount NON lo lascia scoperto: sotto
            # c'è ancora quella dello scope, e sotto ancora la piattaforma. Chi
            # la toglie deve leggere su cosa è ricaduto, non dedurlo.
            _, fonte = self.git_credential(tier, name, mount)
            return {"credential": None, "source": fonte}
        vault.deposit(cred, {"value": token.strip()},
                      cred_type="git-token", grant_agents=[], actions=[])
        return {"credential": cred, "source": "mount" if mount else "scope"}

    def _platform_github_token(self) -> str | None:
        """PAT GitHub dal vault (deposto da tools_api.github_connect come
        {'value': pat}); None se assente."""
        from .. import vault
        try:
            return (vault.read_internal("github_pat") or {}).get("value") or None
        except Exception:  # noqa: BLE001
            return None

    def _remote_or_err(self, tier: str, name: str, mount_name: str | None = None):
        meta, _ = self._read_meta(tier, name)
        rem = self._remote_for(tier, name, meta, mount_name)
        if rem is None:
            noti = [m.get("name") for m in mounts(meta)]
            if mount_name and noti:
                # Nominare i mount esistenti: con più mount, «non configurato»
                # su un nome sbagliato si legge come «il topic non ha remote»,
                # che è una diagnosi diversa e manda a rifare il collegamento.
                raise TopicError(
                    f"il topic non ha un mount '{mount_name}' (ci sono: {', '.join(noti)})")
            raise TopicError("il topic non ha un remote configurato (topic.remote_enable)")
        return rem

    def _remote_display_name(self, rtype: str, config: dict) -> str | None:
        """Nome umano del remote per la UI: nome della cartella Drive o del repo
        git. Best-effort: su errore (Drive irraggiungibile, URL anomalo) → None."""
        try:
            if rtype == "drive" and config.get("folder"):
                svc = self._drive_service(config.get("account"))
                got = svc.files().get(fileId=config["folder"], fields="name",
                                      supportsAllDrives=True).execute()
                return got.get("name") or None
            if rtype == "git" and config.get("url"):
                tail = str(config["url"]).rstrip("/").split("/")[-1]
                tail = tail.split(":")[-1]           # git@host:org/repo(.git)
                return re.sub(r"\.git$", "", tail) or None
        except Exception:  # noqa: BLE001
            return None
        return None

    def remote_status(self, tier: str, name: str,
                      mount_name: str | None = None) -> dict:
        meta, ver = self._read_meta(tier, name)
        rem = self._remote_for(tier, name, meta, mount_name)
        # Backfill lazy del nome remoto sui topic pre-esistenti (config senza
        # `name`): risolto qui una volta e persistito. Best-effort.
        r = mount_by_name(meta, mount_name)
        if rem is not None and r and "name" not in (r.get("config") or {}):
            display = self._remote_display_name(r["type"], r.get("config") or {})
            try:
                r["config"]["name"] = display
                self._write_meta(tier, name, meta, base_version=ver)
            except Exception:  # noqa: BLE001 — race sul meta: riproverà al prossimo status
                pass
        st = rem.status() if rem else {"enabled": False}
        # L'ELENCO dei mount, sempre, anche quando se ne interroga uno. Uno
        # stato che descrive solo il mount interrogato lascia la sidebar a
        # mostrare il primo e a tacere degli altri — cioè lo stesso difetto
        # dell'oggetto singolo, spostato dal meta alla UI.
        st["mounts"] = [{"name": m.get("name"), "type": m.get("type"),
                         "label": (m.get("config") or {}).get("name")}
                        for m in mounts(meta)]
        st["mount"] = r.get("name")
        # QUALE credenziale usa questo remote, sempre. Un topic senza credenziale
        # propria ricade su quella della piattaforma, e il ripiego silenzioso è il
        # modo in cui ci si convince di essere isolati quando non lo si è: chi
        # guarda lo stato deve poter distinguere «ha la sua» da «usa quella di
        # tutti». Il VALORE non compare mai — solo la provenienza.
        if r.get("type") == "git":
            tok, fonte = self.git_credential(tier, name, r.get("name"))
            st["credential_source"] = fonte if tok else "none"
        elif r.get("type") == "drive":
            # Anche per Drive la provenienza si vede sempre. Qui il salto fra
            # «la sua» e «quella di tutti» è più grande che su git: la
            # credenziale di piattaforma è un ACCOUNT Google intero.
            _b, fonte = self.drive_credential(tier, name, r.get("name"))
            st["credential_source"] = fonte
        return st

    #: Marcatore nel messaggio d'errore: dice alla UI che questo rifiuto è
    #: CONFERMABILE, non definitivo. Senza un marcatore il frontend dovrebbe
    #: riconoscere il caso dal testo italiano, che è il modo di rompere la
    #: conferma alla prima riformulazione della frase.
    CONFIRMABLE_HIDES_LOCAL = "confirmable:hides-local"

    @staticmethod
    def _require_approved_repo(url: str | None, tier: str, name: str) -> None:
        """Un repository è una VOCE DI WHITELIST, non un remote (voce 31).

        Stessa forma della cartella Drive, e per la stessa ragione: chi può
        collegare un remote non deve poterlo puntare ovunque arrivi la
        credenziale di piattaforma. Finché il concetto di remote git esiste —
        la voce 31 lo fa sparire, ed è la #28 — questo è il perimetro.

        Il confronto è per **prefisso di repository**, non per host. Un cap per
        host direbbe solo «github sì», che con una credenziale di piattaforma
        significa ogni repository che quel token raggiunge: il perimetro sarebbe
        nominale. La voce che serve è quella che il vocabolario già rende,
        `https://github.com/<owner>/<repo>`.
        """
        u = str(url or "").strip()
        if not u:
            return
        from .. import egress as _eg

        def _e_un_repo(entry: str) -> bool:
            """Una voce approva un repository solo se NE HA LA FORMA.

            `https` sta in lista anche per il web, e una voce di host — un
            `https://github.com/` ammesso per una fetch — approverebbe altrimenti
            *ogni* repository di quell'host. Servono owner e repo: due segmenti
            di path non vuoti.
            """
            resto = entry.split("://", 1)[-1]
            pezzi = [p for p in resto.split("/")[1:] if p]
            return len(pezzi) >= 2

        approvati = [str(r).lower().rstrip("/") for r in _eg.effective_uris("egress")
                     if str(r).lower().startswith(("https://", "http://"))
                     and _e_un_repo(str(r).lower())]
        if not approvati:
            return                      # nessun perimetro dichiarato: come prima
        norm = _eg.canonical(u.removesuffix(".git")).lower().rstrip("/")
        for r in approvati:
            if norm == r or norm.startswith(r + "/"):
                return
        raise TopicError(
            f"il repository '{u}' non è fra quelli approvati: collegarlo a "
            f"{tier}/{name} allargherebbe il perimetro fino a tutto ciò che la "
            f"credenziale raggiunge. Approvarlo è un atto di chi amministra — "
            f"va aggiunto alla lista egress (globale o dello scope).")

    @staticmethod
    def _require_approved_folder(folder: str | None, tier: str, name: str) -> None:
        """Una cartella Drive è una VOCE DI WHITELIST, non un sottoalbero.

        Correzione di Davide, 7 ago 2026: «non esiste questo concetto di root per
        devnullboxx, devnull è un account google al quale condivido file e
        cartelle in modo sparso». Un account condiviso non ha una radice: le
        cartelle arrivano da «Condivisi con me», ognuna di un proprietario
        diverso, senza antenato comune. Non c'è tetto da mettere — e forzarne uno
        proteggerebbe niente (troppo largo) o bloccherebbe tutto (troppo
        stretto).

        Questa è la seconda metà della voce 24. Un owner può spostare i muri del
        proprio scope, ma solo verso cartelle **già approvate**: approvarne una
        nuova resta un atto di chi amministra. È il caso di Davide del 30 lug —
        Giovanni crea un topic suo, invita clodia, e chiede i documenti che
        Davide ha condiviso con `devnullboxx`.

        Se NESSUNA cartella è dichiarata, non si confina: è il comportamento
        storico e la direzione giusta della retrocompatibilità. Una lista vuota
        che chiudesse tutto verrebbe spenta il giorno stesso, e allora non
        proteggerebbe niente.
        """
        fid = str(folder or "").strip()
        if not fid:
            return
        from ..tools import gdrive_root as _gr
        approvate = _gr.approved_folders()
        if not approvate:
            return
        if fid not in approvate:
            raise TopicError(
                f"la cartella Drive '{fid}' non è fra quelle approvate: "
                f"collegarla a {tier}/{name} allargherebbe il perimetro. "
                f"Approvarla è un atto di chi amministra — va aggiunta come "
                f"`gdrive:folder/{fid}` alla lista egress (globale o dello "
                f"scope), poi il collegamento passa.")

    def remote_enable(self, tier: str, name: str, rtype: str, config: dict | None = None,
                      confirm_hides_local: bool = False,
                      credential: str | None = None,
                      mount_name: str | None = None) -> dict:
        """`credential`: PAT valido SOLO per questo scope. Opzionale — senza, il
        topic ricade sulla credenziale di piattaforma, e `remote_status` lo dice.

        Il momento del collegamento è quello giusto per chiederla: è l'unico in
        cui chi la fornisce sa a quale repository serve, e una credenziale
        ristretta a un repo limita il danno di una stanza compromessa a quel
        repo — invece che a tutto ciò che il token di piattaforma raggiunge.
        """
        if rtype not in ("git", "drive"):
            raise TopicError(f"remote type non supportato: {rtype}")
        if rtype == "git":
            self._require_approved_repo((config or {}).get("url"), tier, name)
        # Guard SEAL sul VERO punto di attivazione di Drive (non solo in
        # migrate_storage): dati confidenziali di tier > cap non devono finire su
        # Google come filesystem live (#45 review, Prima Legge/GDPR). Copre anche
        # new() (che chiama qui) e la migrazione legacy.
        if rtype == "drive":
            try:
                tier_n = int(_normalize_tier(tier).replace("SEAL-", ""))
            except (ValueError, AttributeError):
                tier_n = 0
            if tier_n > self._DRIVE_SEAL_CAP:
                raise TopicError(
                    f"storage drive ha cap SEAL-{self._DRIVE_SEAL_CAP}: un topic "
                    f"{tier} non può usare Drive come storage live (anti-declassamento)")
            # Guardia anti-nascondimento: collegare Drive rende Drive la fonte e i
            # file locali NON vengono caricati (nessun push). Se il topic ha
            # contenuti solo in locale, collegarlo li renderebbe invisibili →
            # rifiuta. Va prima popolata la cartella Drive, o si resta local-fs.
            try:
                existing = [e for e in self.s.list(f"{self._dir(tier, name)}/files")
                            if not e.name.startswith(".")
                            and not e.name.endswith(".gdrive.json")]
            except Exception:  # noqa: BLE001 — files/ assente → topic vuoto, ok
                existing = []
            if existing and not confirm_hides_local:
                # NON un rifiuto definitivo: una conferma. I file locali non
                # vengono cancellati — restano su disco e `remote_disable` li
                # ripristina — ma spariscono dal topic finché Drive è la fonte.
                # Dirlo con precisione: un avviso che dice «persi» quando i file
                # tornano insegna a non fidarsi degli avvisi.
                raise TopicError(
                    f"{self.CONFIRMABLE_HIDES_LOCAL}: collegando Drive, i "
                    f"{len(existing)} file già presenti in {tier}/{name} non "
                    f"saranno più visibili nel topic: Drive diventa la fonte e i "
                    f"locali NON vengono caricati. Restano su disco e ricompaiono "
                    f"se scolleghi il remote, ma se ti servono su Drive vanno "
                    f"copiati prima. Fai una copia se hai dubbi.")
        meta, ver = self._read_meta(tier, name)
        config = dict(config or {})
        if rtype == "drive":
            config.update(self._provision_drive_folder(config, name))  # risolve/crea la cartella
            self._require_approved_folder(config.get("folder"), tier, name)
        config["name"] = self._remote_display_name(rtype, config)
        keep = ("url", "branch", "folder", "account", "user_name", "user_email", "message", "name")
        # Il mount ha un NOME che lo identifica nell'albero (`/remote/<nome>/`).
        # È un identificatore, non il nome visualizzato: quello può mancare,
        # contenere uno slash, e cambiare quando la cartella viene rinominata —
        # e ogni path memorizzato che lo citasse si romperebbe (§2.6).
        mount_id = _mount_id(mount_name or rtype, meta)
        voce = {"name": mount_id, "type": rtype,
                "config": {k: v for k, v in config.items() if k in keep}}
        altri = [m for m in mounts(meta) if m.get("name") != mount_id]
        meta["mounts"] = altri + [voce]
        meta.pop("remote", None)          # una forma sola: il legacy è convertito
        meta["storage"] = self.s.capability().name   # storage torna esplicitamente local
        meta.pop("storage_config", None)
        self._write_meta(tier, name, meta, base_version=ver)
        if credential is not None and rtype == "git":
            # Dopo che il mount esiste, non prima: la credenziale è depositata
            # sotto il NOME del mount, e un deposito anticipato lascerebbe in
            # giro una credenziale per un mount che l'abilitazione non ha
            # creato. È anche ciò che il commento qui prometteva da sempre.
            self.set_git_credential(tier, name, credential, mount_id)
        rem = self._remote_for(tier, name, meta, mount_id)
        rem.enable(voce["config"])
        # Nessun upload: Drive è già la fonte (cartella appena provisionata o
        # pre-popolata). Da qui i verbi file proxano direttamente a Drive.
        return {"ok": True, "mount": voce, "mounts": meta["mounts"],
                "status": rem.status()}

    def remote_disable(self, tier: str, name: str,
                       mount_name: str | None = None) -> dict:
        meta, ver = self._read_meta(tier, name)
        rem = self._remote_for(tier, name, meta, mount_name)
        cfg = self._drive_remote_config(meta, mount_name)
        if cfg is not None:
            ds = self._drive_backend_for(tier, name, cfg, mount_name)
            if ds is None:
                raise TopicError("remote drive: nessuna cartella configurata")
            local_base = f"{self._dir(tier, name)}/files"
            # Scollegare Drive = materializzare il contenuto remoto in locale, così
            # il topic torna local-fs con i suoi file. Pull ripartibile, nessun
            # clear preventivo: se fallisce a metà, Drive resta la fonte.
            self._drive_pull_tree(ds, "", local_base)
        if rem is not None:
            rem.disable()
        # Si stacca il mount indicato, non «il remote»: con più mount, togliere
        # tutto sarebbe scollegare cose che nessuno ha nominato.
        via = mount_by_name(meta, mount_name).get("name")
        meta["mounts"] = [m for m in mounts(meta) if m.get("name") != via]
        meta.pop("remote", None)
        self._write_meta(tier, name, meta, base_version=ver)
        self._drive_cache_clear()
        return {"ok": True}

    def remote_add(self, tier: str, name: str, path: str,
                   mount_name: str | None = None) -> dict:
        self._remote_or_err(tier, name, mount_name).add(path)
        return {"ok": True}

    def remote_unstage(self, tier: str, name: str, path: str = "",
                       mount_name: str | None = None) -> dict:
        """Toglie dallo staging (path vuoto = tutto)."""
        self._remote_or_err(tier, name, mount_name).unstage(path or "")
        return {"ok": True}

    def remote_commit(self, tier: str, name: str, msg: str = "",
                      mount_name: str | None = None) -> dict:
        res = self._remote_or_err(tier, name, mount_name).commit(msg) or {}
        return {"ok": True, **res}

    def remote_push(self, tier: str, name: str,
                    mount_name: str | None = None) -> dict:
        return self._remote_or_err(tier, name, mount_name).push()

    def remote_pull(self, tier: str, name: str,
                    mount_name: str | None = None) -> dict:
        return self._remote_or_err(tier, name, mount_name).pull()

    def _migrate_legacy_drive(self, tier: str, name: str) -> None:
        """One-shot: legacy storage=google-drive → remote Drive live."""
        meta, ver = self._read_meta(tier, name)
        if meta.get("storage") != "google-drive" or mounts(meta):
            return
        sc = meta.get("storage_config") or {}
        meta["mounts"] = [{"name": "drive", "type": "drive",
                           "config": {"folder": sc.get("folder"),
                                      "account": sc.get("account")}}]
        meta["storage"] = self.s.capability().name
        meta.pop("storage_config", None)
        rem = self._remote_for(tier, name, meta)
        try:
            rem.enable(meta["mounts"][0]["config"])
            self._write_meta(tier, name, meta, base_version=ver)
            # storage=google-drive significa che i file vivevano GIÀ su Drive: la
            # conversione a remote:drive è solo metadata. Nessun upload/clear.
        except Exception:  # noqa: BLE001 — la migrazione non deve rompere open()
            LOG.warning("migrazione drive→remote fallita per %s/%s (locale intatto)",
                        tier, name)

    @staticmethod
    def _assert_content_available(meta: dict) -> None:
        if _norm_status(meta.get("status")) == "archived":
            raise TopicError(
                "topic archiviato: riattivalo prima di leggere o modificare il contenuto"
            )

    def open(self, tier: str, name: str) -> dict:
        return self._open(tier, name, allow_archived=False)

    def _open(self, tier: str, name: str, *, allow_archived: bool) -> dict:
        """Read-only: meta + summary (+ summary_version per optimistic lock)."""
        initial_meta, _ = self._read_meta(tier, name)
        if not allow_archived:
            self._assert_content_available(initial_meta)
        # Migrazione one-shot legacy storage=google-drive → remote drive.
        try:
            self._migrate_legacy_drive(tier, name)
        except Exception:  # noqa: BLE001
            LOG.warning("migrazione storage→remote fallita per %s/%s", tier, name)
        try:
            meta_r = self.s.read(self._meta_p(tier, name))
        except NotFound:
            raise TopicError(f"topic non trovato: {tier}/{name}")
        meta = normalize_meta_v2(json.loads(meta_r.data.decode()), tier)
        meta.setdefault("storage", self.s.capability().name)
        try:
            sumr = self.s.read(self._summary_p(tier, name))
            summary, summary_version = sumr.data.decode(), sumr.version
        except NotFound:
            summary, summary_version = "", None
        d = self._dir(tier, name)
        # updated_at = mtime più recente tra meta, summary e AGENTS.md (nuova
        # posizione o legacy: un topic non ancora migrato non deve sembrare più
        # vecchio di quanto è).
        mts: list[float] = []
        for p in (self._meta_p(tier, name), self._summary_p(tier, name),
                  self._agents_p(tier, name), self._legacy_agents_p(tier, name)):
            st = self.s.stat(p)
            if st:
                mts.append(st.mtime)
        updated_at = _iso(max(mts)) if mts else None
        # recent_files = up to 3 files from the effective source (live Drive or
        # local). BEST-EFFORT on purpose: this is a decoration for the card, and
        # it must never be able to make `open` fail. A topic whose remote is
        # unreachable — expired OAuth token, Drive down, network gone — still has
        # meta and summary in the local control plane, so it stays readable.
        # Letting the exception through made a single revoked Google token take
        # down `topic.open` for that topic AND the whole topic list with it.
        # `files_unavailable` tells the caller the difference between "no files"
        # and "files could not be listed", so the UI can say so instead of
        # silently showing an empty topic.
        fmt: list[tuple[float, str]] = []
        files_unavailable = False
        try:
            files_store, files_base = self._files_backend(tier, name)
            is_drive_live = files_store is not self.s
            for e in files_store.list(files_base):
                if e.kind != "file":
                    continue
                st = None if is_drive_live else files_store.stat(
                    f"{files_base}/{e.name}".strip("/"))
                fmt.append((st.mtime if st else 0.0, e.name))
        except Exception as exc:  # noqa: BLE001 - never fatal for open()
            files_unavailable = True
            LOG.warning("topic %s/%s: file backend unreachable (%s) - opening "
                        "with meta and summary only", tier, name, str(exc)[:160])
        fmt.sort(reverse=True)
        recent_files = [{"name": n, "path": f"files/{n}", "mtime_iso": _iso(mt)}
                        for mt, n in fmt[:3]]
        agents_md, agents_md_version = self._read_agents_md(tier, name)
        return {
            "tier": meta["tier"], "tier_name": TIER_NAMES.get(meta["tier"], meta["tier"]), "name": name,
            "meta": meta, "summary": summary, "summary_version": summary_version,
            "tldr": _tldr(summary), "minutes": [], "agents_md": agents_md,
            "agents_md_version": agents_md_version,
            "updated_at": updated_at, "recent_files": recent_files,
            # True when the file backend could not be listed: the caller must not
            # read an empty `recent_files` as "this topic has no files".
            "files_unavailable": files_unavailable,
            "recap_history": self.recap_history(tier, name),
        }

    def read_file(self, tier: str, name: str, relpath: str) -> bytes:
        """Legge un file dentro il topic (es. files/foo.md). Anti-traversal.
        I path sotto files/ vanno sullo storage del topic (local o drive)."""
        meta, _ = self._read_meta(tier, name)
        self._assert_content_available(meta)
        rel = (relpath or "").lstrip("/")
        if not rel or ".." in rel.split("/"):
            raise TopicError(f"path non valido: {relpath}")
        first = rel.split("/", 1)[0]
        if first in self._MOUNTS or self._files_rel(rel)[0]:
            try:
                store, base, sub, _mount = self._resolve_data_path(tier, name, rel)
            except TopicError:
                raise
            except Exception as exc:  # noqa: BLE001 - remote backend down
                raise _remote_unreachable(exc, tier, name) from exc
            return store.read(f"{base}/{sub}".strip("/")).data
        # Fuori dai mount: control-plane (summary.md, meta.json, AGENTS.md), che
        # si legge ma non si naviga come dato.
        return self.s.read(f"{self._dir(tier, name)}/{rel}").data

    def save_summary(self, tier: str, name: str, text: str,
                     base_version: str | None) -> dict:
        """Scrive il summary in optimistic lock. base_version = la versione letta
        con open(); se è cambiata → VersionConflict (il chiamante escala)."""
        meta, _ = self._read_meta(tier, name)
        self._assert_content_available(meta)
        # Se non c'è ancora storia ma esiste un summary, registra il recap PRECEDENTE
        # (una tantum) col mtime del summary → la timeline mostra la transizione.
        try:
            hp = self._recap_history_p(tier, name)
            sp = self._summary_p(tier, name)
            if not self.s.exists(hp) and self.s.exists(sp):
                prev = self.s.read(sp)
                st = self.s.stat(sp)
                pts = _iso(st.mtime) if st else None
                self._append_recap(tier, name, _tldr(prev.data.decode("utf-8", "replace")), ts=pts)
        except Exception:  # noqa: BLE001 — lo storico non deve mai rompere il save
            pass
        new_v = self.s.write(self._summary_p(tier, name), (text or "").encode(),
                             if_version=base_version)
        try:
            self._append_recap(tier, name, _tldr(text))
        except Exception:  # noqa: BLE001
            pass
        return {"summary_version": new_v, "tldr": _tldr(text)}

    def save_agents_md(self, tier: str, name: str, text: str,
                       base_version: str | None) -> dict:
        """Scrive le istruzioni di scope in optimistic lock, come il summary.

        `text` vuoto RIMUOVE le istruzioni: senza questa via l'unico modo per
        toglierle sarebbe lasciarci un file vuoto che continua a occupare spazio
        nel contesto di ogni turno.

        La migrazione lascia dietro di sé la copia legacy in `files/`; qui viene
        cestinata, perché due file con lo stesso nome e autorità diversa sono
        precisamente ciò che questa modifica esiste per eliminare.
        """
        meta, _ = self._read_meta(tier, name)
        self._assert_content_available(meta)
        p = self._agents_p(tier, name)
        if (text or "").strip():
            new_v = self.s.write(p, (text or "").encode(), if_version=base_version)
        else:
            if self.s.exists(p):
                self.s.delete(p)
            new_v = None
        self._retire_legacy_agents_md(tier, name)
        return {"agents_md_version": new_v, "removed": not (text or "").strip()}

    def _retire_legacy_agents_md(self, tier: str, name: str) -> bool:
        """Toglie di mezzo `files/AGENTS.md`, se c'è. Best-effort.

        Non cancella: sposta nel cestino del topic, così un contenuto che
        qualcuno aveva scritto resta recuperabile — una migrazione non deve poter
        perdere il lavoro di nessuno.

        Agisce su `self.s` e NON via `delete_file`, di proposito: `delete_file`
        passa da `_files_backend()`, che su un topic con remote Drive punta a
        Drive. Il file legacy che ci interessa è quello LOCALE — è l'unico che
        veniva davvero letto e iniettato — quindi delegare avrebbe cercato di
        cancellare un file su Drive lasciando in piedi proprio quello che stiamo
        ritirando.
        """
        try:
            lp = self._legacy_agents_p(tier, name)
            if not self.s.exists(lp):
                return False
            ts = _now().strftime("%Y%m%d-%H%M%S")
            self.s.move(lp, f"{self._dir(tier, name)}/.trash/{ts}/files/AGENTS.md")
            return True
        except Exception as e:  # noqa: BLE001 — mai fatale
            LOG.warning("topic %s/%s: AGENTS.md legacy non ritirato (%s)",
                        tier, name, str(e)[:120])
        return False

    def migrate_agents_md(self, tier: str | None = None) -> dict:
        """One-shot: `files/AGENTS.md` → `AGENTS.md` nel control-plane.

        Idempotente. Un topic che ha già il file nella posizione nuova viene
        saltato senza toccare nulla: la posizione nuova è autorevole e non deve
        essere sovrascritta da una copia vecchia rimasta indietro.
        """
        moved, skipped, failed = [], [], []
        # Enumerazione diretta dallo storage, non via `list()`: quella apre ogni
        # topic e scarta quelli che non si aprono, mentre una migrazione deve
        # passare anche sui topic rotti o archiviati — sono esattamente quelli
        # che nessuno guarderà mai più e in cui un file dimenticato resterebbe.
        for t in ([_normalize_tier(tier)] if tier else list(VALID_TIER)):
            for e in self.s.list(t):
                if e.kind != "dir":
                    continue
                n = e.name
                try:
                    if self.s.exists(self._agents_p(t, n)):
                        if self._retire_legacy_agents_md(t, n):
                            skipped.append(f"{t}/{n}")
                        continue
                    lp = self._legacy_agents_p(t, n)
                    if not self.s.exists(lp):
                        continue
                    data = self.s.read(lp).data
                    self.s.write(self._agents_p(t, n), data, if_version=None)
                    self._retire_legacy_agents_md(t, n)
                    moved.append(f"{t}/{n}")
                except Exception as e:  # noqa: BLE001
                    failed.append({"topic": f"{t}/{n}", "error": str(e)[:160]})
                    LOG.warning("migrate_agents_md %s/%s: %s", t, n, str(e)[:160])
        return {"moved": moved, "skipped_already_migrated": skipped,
                "failed": failed, "moved_count": len(moved)}

    def _read_recap_entries(self, tier: str, name: str) -> list[dict]:
        p = self._recap_history_p(tier, name)
        if not self.s.exists(p):
            return []
        out = []
        for line in self.s.read(p).data.decode("utf-8", "replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except (json.JSONDecodeError, ValueError):
                continue
        return out

    def _append_recap(self, tier: str, name: str, tldr: str, ts: str | None = None) -> None:
        """Appende un recap alla storia SOLO se diverso dall'ultimo (no duplicati)."""
        tldr = (tldr or "").strip()
        if not tldr:
            return
        entries = self._read_recap_entries(tier, name)
        if entries and (entries[-1].get("tldr") or "").strip() == tldr:
            return
        entry = {"ts": ts or _iso(_now().timestamp()), "tldr": tldr}
        p = self._recap_history_p(tier, name)
        existing = self.s.read(p).data.decode("utf-8", "replace") if self.s.exists(p) else ""
        self.s.write(p, (existing + json.dumps(entry, ensure_ascii=False) + "\n").encode())

    def recap_history(self, tier: str, name: str) -> list[dict]:
        """Storia dei recap (TLDR), dal più recente. Se non c'è ancora storia ma
        esiste un summary, restituisce l'entry corrente come seed (di sola lettura,
        datato col mtime del summary)."""
        entries = self._read_recap_entries(tier, name)
        if entries:
            return list(reversed(entries))
        sp = self._summary_p(tier, name)
        if self.s.exists(sp):
            tldr = _tldr(self.s.read(sp).data.decode("utf-8", "replace"))
            if tldr.strip():
                st = self.s.stat(sp)
                return [{"ts": _iso(st.mtime) if st else _iso(_now().timestamp()),
                         "tldr": tldr, "seed": True}]
        return []

    def add_minute(self, tier: str, name: str, text: str) -> dict:
        """Compat legacy: minutes è rimosso dallo schema topic v2."""
        raise TopicError("minutes rimosso dallo schema topic v2: usa summary.md o AGENTS.md")

    # ── canale: partecipanti / messaggi / file ──────────────────────────────
    def _read_meta(self, tier: str, name: str) -> tuple[dict, str | None]:
        try:
            r = self.s.read(self._meta_p(tier, name))
        except NotFound:
            raise TopicError(f"topic non trovato: {tier}/{name}")
        return normalize_meta_v2(json.loads(r.data.decode()), tier), r.version

    def _write_meta(self, tier: str, name: str, meta: dict, base_version: str | None) -> None:
        meta = normalize_meta_v2(meta, tier)
        self.s.write(self._meta_p(tier, name),
                     json.dumps(meta, ensure_ascii=False, indent=2).encode(),
                     if_version=base_version)

    # ── Appartenenza graduata (system-notebook 25) ─────────────────────────
    #
    # Fino al 7 ago 2026 l'appartenenza era BINARIA: dieci endpoint, una guardia
    # sola, owner e partecipante trattati allo stesso modo. Un invitato poteva
    # azzerare la memoria conversazionale del canale e caricare l'`AGENTS.md`
    # iniettato nel contesto di ogni agente a ogni turno.
    #
    # Tre ruoli, insieme CHIUSO. Non una lista di verbi per persona per scope:
    # sarebbe l'argomento della #128 moltiplicato — là erano quattordici agenti e
    # lo stesso indirizzo chiesto quattordici volte, qui sarebbero 156 topic per N
    # persone, e nessuno saprebbe più dire cosa può fare qualcuno senza aprire 156
    # file. Un insieme di tre si legge; una lista no.
    ROLE_OWNER = "owner"
    ROLE_CONTRIBUTOR = "contributor"
    ROLE_READER = "reader"
    ROLES = (ROLE_OWNER, ROLE_CONTRIBUTOR, ROLE_READER)

    @staticmethod
    def participants_map(meta: dict) -> dict:
        """`{nome: ruolo}` dai partecipanti, qualunque forma abbiano nel meta.

        Una LISTA legacy diventa tutta `contributor`, non `reader`. La direzione
        conta: `reader` sarebbe più stretta ma toglierebbe di colpo a ogni
        partecipante di ogni topic la possibilità di scrivere — una rottura
        silenziosa mascherata da irrigidimento. Il comportamento resta quello di
        oggi, e la novità è poter DICHIARARE un lettore.
        """
        raw = meta.get("participants")
        owner = meta.get("owner")
        out: dict = {}
        if isinstance(raw, dict):
            for k, v in raw.items():
                r = str(v or "").strip().lower()
                out[str(k)] = r if r in TopicService.ROLES else TopicService.ROLE_CONTRIBUTOR
        elif isinstance(raw, list):
            for k in raw:
                out[str(k)] = TopicService.ROLE_CONTRIBUTOR
        if owner:
            # L'owner è owner ovunque compaia, e anche se non compare: il campo
            # `owner` resta la fonte di verità per la proprietà dello scope.
            out[str(owner)] = TopicService.ROLE_OWNER
        return out

    @staticmethod
    def participant_role(meta: dict, chi: str | None) -> str | None:
        """Ruolo di `chi` in questo scope, o `None` se non è partecipante."""
        if not chi:
            return None
        return TopicService.participants_map(meta).get(str(chi))

    @staticmethod
    def may_mutate(meta: dict, chi: str | None) -> bool:
        """Può MUTARE qualcosa dentro lo scope? Owner e contributor sì.

        Un reader parla ma non muta (voce 26): la sua richiesta viene comunque
        risposta, e se implica una mutazione diventa un gate rivolto all'owner —
        non un rifiuto secco, che sarebbe scortese verso una richiesta legittima.
        """
        return TopicService.participant_role(meta, chi) in (
            TopicService.ROLE_OWNER, TopicService.ROLE_CONTRIBUTOR)

    @staticmethod
    def participant_names(meta: dict) -> list[str]:
        """Solo i nomi, per chi non ha bisogno dei ruoli — e per i chiamanti che
        si aspettano ancora una lista."""
        return list(TopicService.participants_map(meta).keys())

    @staticmethod
    def _require_human_owner(owner: str, tier: str, name: str) -> None:
        """**Un owner di scope è sempre umano** (specification §2.9, invariante 1).

        Non è una preferenza di disegno: dal 7 ago l'owner **sblocca i gate del
        proprio scope** (voce 24). Uno scope di proprietà di un agente
        sbloccherebbe quindi i propri gate — il confused deputy nella sua forma
        più pulita, e per giunta legittimato dal disegno invece che sfuggito.

        L'invariante era scritta nella specifica e non asserita da nulla. È stata
        imposta il 7 ago per il solo topic di configurazione, dove l'owner
        sarebbe altrimenti stato `clodia`; qui vale per ogni scope.

        **Un principal sconosciuto non è rifiutato.** Non tutti gli owner
        legittimi sono nel registro degli umani — un'istanza appena reclamata, un
        principal creato fuori banda — e rifiutare l'ignoto trasformerebbe una
        lacuna del registro in un topic senza owner. Si rifiuta ciò che si sa
        essere un agente, non ciò che non si riconosce: è la direzione in cui un
        errore costa meno.
        """
        chi = str(owner or "").strip()
        if not chi:
            return
        try:
            from .. import human as _h
            if _h.is_human(chi):
                return
            from ..whitelist import CONFIG
            e_agente = chi in ((CONFIG or {}).get("agents") or {})
        except Exception:  # noqa: BLE001 — registro illeggibile: non si decide
            return
        if e_agente:
            raise TopicError(
                f"'{chi}' è un agente e non può essere owner di {tier}/{name}: "
                f"l'owner sblocca i gate del proprio scope, quindi un agente "
                f"owner sbloccherebbe i propri. L'owner di uno scope è una "
                f"persona.")

    def set_owner(self, tier: str, name: str, owner: str) -> dict:
        self._require_human_owner(owner, tier, name)
        meta, v = self._read_meta(tier, name)
        meta["owner"] = owner
        # L'owner NON si duplica fra i partecipanti: `participants_map` lo
        # aggiunge leggendo il campo `owner`, e tenerlo in due posti significa
        # poterli far divergere.
        if isinstance(meta.get("participants"), dict):
            meta["participants"].pop(owner, None)
        elif isinstance(meta.get("participants"), list):
            meta["participants"] = [p for p in meta["participants"] if p != owner]
        self._write_meta(tier, name, meta, v)
        return {"owner": owner, "participants": meta.get("participants")}

    def add_participant(self, tier: str, name: str, agent: str,
                        role: str | None = None) -> dict:
        """Invita, con un ruolo. Default `contributor`: è ciò che «invitato»
        significava finora, e cambiarlo di nascosto renderebbe muti gli invitati
        di ieri."""
        meta, v = self._read_meta(tier, name)
        self._assert_content_available(meta)
        r = (role or self.ROLE_CONTRIBUTOR).strip().lower()
        if r not in self.ROLES:
            raise TopicError(f"ruolo non valido: {role} (ammessi: {', '.join(self.ROLES)})")
        if r == self.ROLE_OWNER:
            raise TopicError(
                "l'owner non si aggiunge fra i partecipanti: si imposta col campo "
                "`owner`, che è la proprietà dello scope e non un grado di accesso")
        mappa = self.participants_map(meta)
        added = agent not in mappa
        cambiato = added or mappa.get(agent) != r
        mappa[agent] = r
        if cambiato:
            # Si riscrive SEMPRE come mappa: convertire alla prima modifica evita
            # una migrazione a tappeto e lascia intatti i topic che nessuno tocca.
            meta["participants"] = {k: val for k, val in mappa.items()
                                    if k != meta.get("owner")}
            self._write_meta(tier, name, meta, v)
            if added:
                self.post_message(
                    tier, name, "system",
                    f"{agent} è entrato nel topic come {r}", kind="system")
        return {"participants": meta.get("participants"), "added": added, "role": r}

    def remove_participant(self, tier: str, name: str, agent: str) -> dict:
        meta, v = self._read_meta(tier, name)
        self._assert_content_available(meta)
        mappa = self.participants_map(meta)
        if agent in mappa and agent != meta.get("owner"):
            mappa.pop(agent, None)
            meta["participants"] = {k: val for k, val in mappa.items()
                                    if k != meta.get("owner")}
            self._write_meta(tier, name, meta, v)
        return {"participants": meta.get("participants")}

    def post_message(self, tier: str, name: str, author: str, text: str,
                     kind: str = "human", attachments: list[str] | None = None) -> dict:
        """Posta un messaggio nel canale (append-only file in `.messages/` →
        niente contesa). `kind` = human|ai|system. `attachments` = nomi file in files/.
        `mentions` = destinatari strutturati estratti al write-time (issue#83, D1)."""
        meta, _ = self._read_meta(tier, name)
        self._assert_content_available(meta)
        now = _now()
        token = base64.urlsafe_b64encode(os.urandom(4)).decode().rstrip("=")
        msg = {
            "id": f"{now.strftime('%Y%m%d-%H%M%S')}-{token}",
            "author": author, "kind": kind, "text": text or "",
            "attachments": attachments or [], "ts": now.isoformat(timespec="seconds"),
            "mentions": mentions.extract_mentions(text or ""),
        }
        self.s.write(f"{self._dir(tier, name)}/.messages/{msg['id']}.json",
                     json.dumps(msg, ensure_ascii=False).encode())
        # Menzioni → coda per il gruppo Telegram collegato. Best-effort e DOPO
        # la scrittura: un messaggio nel topic non deve dipendere dalla
        # raggiungibilità di un servizio esterno, e un difetto qui non deve
        # impedire a qualcuno di parlare nella propria stanza.
        try:
            tg = self.telegram_mounts(meta)
            if tg:
                from . import telegram_notify as _tn
                _tn.enqueue_for_message(_normalize_tier(tier), name, meta, msg, tg)
        except Exception as e:  # noqa: BLE001
            LOG.warning("notifica telegram non accodata per %s/%s: %s",
                        tier, name, str(e)[:160])
        return msg

    def list_messages(self, tier: str, name: str, limit: int = 200) -> list[dict]:
        d = self._dir(tier, name)
        out: list[dict] = []
        for e in self.s.list(f"{d}/.messages"):
            if e.kind != "file" or not e.name.endswith(".json"):
                continue
            try:
                out.append(json.loads(self.s.read(f"{d}/.messages/{e.name}").data.decode()))
            except Exception:  # noqa: BLE001
                continue
        out.sort(key=lambda m: m.get("ts", ""))
        return out[-limit:] if limit else out

    # ------------------------------------------------------------------ #
    # Menzioni consultabili (client MCP di una persona)
    #
    # MCP è domanda-risposta: non esiste un push verso il client di Giovanni.
    # Chi vuole essere svegliato ha Telegram; chi lavora da Claude Code CHIEDE.
    # I due canali non competono — uno spinge, l'altro si consulta — ed è la
    # ragione per cui questo non prova a essere una notifica.
    #
    # Il segnaposto è per (topic, persona) e tiene il timestamp dell'ultimo
    # messaggio visto. Non un elenco di id visti: quello cresce senza fine e
    # rende «già letto» una cosa da mantenere. Un istante basta, perché i
    # messaggi sono append-only e ordinati.
    # ------------------------------------------------------------------ #

    def _seen_path(self, tier: str, name: str, chi: str) -> str:
        safe = "".join(c for c in (chi or "") if c.isalnum() or c in "-_") or "-"
        # Fuori da `.messages/`, non dentro: `list_messages` prende OGNI `.json`
        # di quella cartella e un segnaposto vi comparirebbe come un messaggio
        # senza autore né testo. Sarebbe passato inosservato a lungo — un
        # messaggio vuoto in fondo alla chat somiglia a un difetto di rendering.
        return f"{self._dir(tier, name)}/.seen/{safe}.json"

    def last_seen(self, tier: str, name: str, chi: str) -> str:
        try:
            data = json.loads(self.s.read(self._seen_path(tier, name, chi)).data.decode())
            return str(data.get("ts") or "")
        except Exception:  # noqa: BLE001 — mai visto nulla: tutto è nuovo
            return ""

    def my_mentions(self, tier: str, name: str, chi: str,
                    limit: int = 50, only_unseen: bool = True) -> dict:
        """Messaggi che menzionano `chi`, dal più recente segnaposto in poi.

        Ritorna anche `seen_through`, così il client può marcare esattamente ciò
        che ha ricevuto invece di marcare «adesso»: fra la lettura e la marcatura
        può essere arrivato un altro messaggio, e marcare l'istante lo farebbe
        sparire senza che nessuno l'abbia visto.
        """
        chi_l = (chi or "").lower()
        soglia = self.last_seen(tier, name, chi) if only_unseen else ""
        out: list[dict] = []
        for m in self.list_messages(tier, name, limit=0):
            if chi_l not in [x.lower() for x in (m.get("mentions") or [])]:
                continue
            if soglia and str(m.get("ts") or "") <= soglia:
                continue
            out.append(m)
        out = out[-limit:] if limit else out
        return {"topic": f"{_normalize_tier(tier)}/{name}", "principal": chi,
                "mentions": out, "count": len(out),
                "seen_through": out[-1]["ts"] if out else soglia}

    def mark_seen(self, tier: str, name: str, chi: str, ts: str = "") -> dict:
        """Sposta il segnaposto in AVANTI e mai indietro: riletture e client
        concorrenti non devono poter far riapparire una menzione già archiviata
        — né, peggio, farne sparire una mai vista."""
        corrente = self.last_seen(tier, name, chi)
        nuovo = str(ts or _now().isoformat(timespec="seconds"))
        if corrente and nuovo < corrente:
            nuovo = corrente
        self.s.write(self._seen_path(tier, name, chi),
                     json.dumps({"ts": nuovo}, ensure_ascii=False).encode())
        return {"principal": chi, "seen_through": nuovo}

    def list_files(self, tier: str, name: str, subpath: str = "") -> list[dict]:
        """Elenca <subpath> a partire dalla ROOT del topic (non da files/): così
        il navigator mostra la struttura reale — summary.md, meta.json, files/,
        files/ — e si naviga nelle sottocartelle. subpath relativo alla root del
        topic (anti-traversal). I file/cartelle interni (dotfile, es. .messages)
        sono nascosti. path nelle voci = relativo alla root del topic."""
        meta, _ = self._read_meta(tier, name)
        self._assert_content_available(meta)
        rel = (subpath or "").strip("/")
        if ".." in rel.split("/") or "\\" in rel:
            raise TopicError(f"subpath non valido: {subpath}")
        try:
            _meta = json.loads(self.s.read(self._meta_p(tier, name)).data.decode())
        except Exception:  # noqa: BLE001
            _meta = {}
        if _meta.get("storage") == "google-drive" and not _meta.get("remote"):
            self._migrate_legacy_drive(tier, name)
            _meta = json.loads(self.s.read(self._meta_p(tier, name)).data.decode())
        _is_drive = self._drive_remote_config(_meta) is not None
        out: list[dict] = []
        # `remote/` senza nome è il CONTENITORE dei mount: elenca i mount, non
        # delega a un backend. Senza questo ramo, navigare in `remote/` darebbe un
        # errore là dove l'utente si aspetta di vedere cosa c'è montato.
        if rel == self.MOUNT_REMOTE:
            rn = self._remote_mount_name(_meta)
            return ([{"name": rn, "path": f"{self.MOUNT_REMOTE}/{rn}", "kind": "dir",
                      "mount": "remote"}] if rn else [])
        first = rel.split("/", 1)[0] if rel else ""
        is_files = bool(rel) and (first in self._MOUNTS or self._files_rel(rel)[0])
        sub = ""
        prov_map = {}
        if is_files:
            try:
                store, base, sub, mount = self._resolve_data_path(tier, name, rel)
            except TopicError:
                raise
            except Exception as exc:  # noqa: BLE001 — backend remoto giù
                # Un token Drive revocato deve dare un errore AZIONABILE, non una
                # traccia di stack: è la ragione per cui `_remote_unreachable`
                # esiste. Catturare solo TopicError qui lo aggirava.
                raise _remote_unreachable(exc, tier, name) from exc
            # La provenienza è etichettata sui file del mount LOCALE: quelli del
            # remote non l'hanno, e mostrarla come `unknown` sarebbe corretto ma
            # inutile — sul remote la domanda «chi l'ha messo qui» ha una risposta
            # che non passa da noi.
            prov_map = (self.provenance_map(tier, name)
                        if mount == self.MOUNT_LOCAL else {})
            _is_drive = mount != self.MOUNT_LOCAL
        # I path emessi portano il prefisso del MOUNT, non `files/`: è ciò che
        # rende la vista una sola. Un path senza mount sarebbe ambiguo appena i
        # mount diventano due, ed è esattamente l'ambiguità che questo disegno
        # elimina.
        def _mp(subdir: str, nome: str) -> str:
            return f"{mount}/" + (f"{subdir}/" if subdir else "") + nome

        if is_files:
            try:
                entries = list(store.list(f"{base}/{sub}".strip("/")))
            except TopicError:
                raise
            except Exception as exc:  # noqa: BLE001 — backend remoto giù
                raise _remote_unreachable(exc, tier, name) from exc
            for e in entries:
                if e.name.startswith("."):
                    continue
                # KIND BEFORE MIME, and the order is the whole point. A Drive
                # folder has mime `application/vnd.google-apps.folder`, which
                # matches _NATIVE_DOC_PREFIX: classified by mime first, every
                # subfolder came out as a remote FILE with a webViewLink, so the
                # UI rendered a link to the Drive web app and in-app navigation
                # stopped at the first level (#117). `url` is kept on the entry
                # so opening Drive stays available as an explicit choice.
                if e.kind == "dir":
                    out.append({"name": e.name,
                                "path": _mp(sub, e.name),
                                "kind": "dir", "url": e.url or ""})
                    continue
                if e.mime and e.mime.startswith(self._NATIVE_DOC_PREFIX):
                    p = _mp(sub, e.name)
                    out.append({"name": e.name, "path": p, "kind": "file",
                                "remote": True, "url": e.url or "", "mime": e.mime,
                                "size": e.size, "md5": e.version})
                    continue
                if e.name.endswith(".gdrive.json"):
                    # stub proxy di un Google Doc nativo → voce REMOTA (link a Drive)
                    try:
                        info = json.loads(store.read(f"{base}/{sub}/{e.name}".strip("/")).data.decode())
                    except Exception:  # noqa: BLE001
                        info = {}
                    real = e.name[:-len(".gdrive.json")]
                    out.append({"name": real,
                                "path": _mp(sub, real),
                                "kind": "file", "remote": True,
                                "url": info.get("gdrive_url") or "",
                                "mime": info.get("mimeType")})
                    continue
                # dirs are handled above, so this is a plain file
                p = _mp(sub, e.name)
                st = None if _is_drive else store.stat(
                    f"{base}/{sub}/{e.name}".strip("/"))
                rel_in_files = (f"{sub}/" if sub else "") + e.name
                out.append({"name": e.name, "path": p, "kind": "file",
                            "size": (getattr(st, "size", None) if st else e.size),
                            "mtime_iso": _iso(st.mtime) if st else None,
                            "md5": (getattr(st, "md5", None) if st else e.version),
                            # Etichetta assente = file caricato prima della §3:
                            # `unknown`, non `trusted`. Un default rassicurante
                            # su dati storici è la direzione d'errore sbagliata.
                            "provenance": (prov_map.get(rel_in_files) or {}).get(
                                "provenance", "unknown")})
        elif not rel:
            # LA RADICE DELL'ALBERO DEI DATI: solo i mount.
            #
            # Prima mostrava anche il control-plane — `meta.json`, `summary.md` e
            # perfino i `meta.json.bak-*` lasciati da vecchie migrazioni. Erano
            # rumore in un browser di file: nessuno naviga un topic per leggere
            # il JSON dei suoi metadati, e i backup non li aveva chiesti nessuno.
            #
            # E non è solo estetica: la voce 17.6 dice che il control-plane NON
            # ha un path in questo albero. Mostrarcelo insegnava il contrario, cioè
            # che quei file sono raggiungibili per path come tutti gli altri —
            # esattamente l'idea da cui A1 li ha tolti.
            #
            # Dove si leggono adesso: stato e deadline nella sezione Meta della
            # sidebar, il TLDR nell'intestazione, `AGENTS.md` nel suo pannello.
            # Ognuno col suo verbo, che è il punto.
            out.extend(self.data_mounts(tier, name))
        else:
            # Sotto-path fuori dai mount: control-plane indirizzato
            # esplicitamente. Resta leggibile per chi sa cosa cerca — non è più
            # raggiungibile navigando.
            d = self._dir(tier, name)
            base = f"{d}/{rel}"
            seen_files = False
            for e in self.s.list(base):
                if e.name.startswith("."):
                    continue
                if e.name == "files":
                    # `files/` non compare più come cartella: al suo posto la
                    # radice espone i MOUNT. Il contenuto non si è spostato — è lo
                    # stesso, raggiunto da `local/`.
                    seen_files = True
                    continue
                p = f"{rel}/{e.name}" if rel else e.name
                if e.kind == "dir":
                    out.append({"name": e.name, "path": p, "kind": "dir"})
                else:
                    st = self.s.stat(f"{base}/{e.name}")
                    out.append({"name": e.name, "path": p, "kind": "file",
                                "size": getattr(st, "size", None) if st else None,
                                "mtime_iso": _iso(st.mtime) if st else None,
                                "md5": getattr(st, "md5", None) if st else None})

        dirs = sorted((f for f in out if f.get("kind") == "dir"),
                      key=lambda f: f.get("name", "").lower())
        files = sorted((f for f in out if f.get("kind") != "dir"),
                       key=lambda f: f.get("mtime_iso") or "", reverse=True)
        return dirs + files

    #: Sidecar della provenienza: relpath sotto files/ → {provenance, at, by}.
    #: Dotfile, quindi nascosto dal navigator. Un file per topic invece di un
    #: sidecar per file: l'etichetta SEGUE il file senza dover riscrivere path
    #: (#104 §3, «quarantena fisica solo se serve»), e `files/` resta uno solo.
    _PROV_FILE = ".provenance.json"

    def _prov_path(self, tier: str, name: str) -> str:
        return f"{self._dir(tier, name)}/{self._PROV_FILE}"

    def provenance_map(self, tier: str, name: str) -> dict:
        try:
            return json.loads(self.s.read(self._prov_path(tier, name)).data.decode()) or {}
        except Exception:  # noqa: BLE001 — assente o illeggibile = nessuna etichetta
            return {}

    def set_provenance(self, tier: str, name: str, relpath: str,
                       provenance: str, by: str = "") -> dict:
        """Etichetta la provenienza di un file sotto files/.

        È una CLASSIFICAZIONE, non un'autorizzazione (#104 §3): dice da dove
        viene il file, non se si può leggere. La lettura resta libera e
        CONTAMINA il canale — bloccarla renderebbe impossibile il caso d'uso
        principale («riassumi questo PDF del cliente») e produrrebbe due gate al
        posto di uno.
        """
        m = self.provenance_map(tier, name)
        m[relpath] = {"provenance": provenance, "at": _now().isoformat(timespec="seconds"),
                      "by": by}
        self.s.write(self._prov_path(tier, name),
                     json.dumps(m, ensure_ascii=False, indent=1).encode())
        return m[relpath]

    def put_file(self, tier: str, name: str, filename: str, data: bytes,
                 provenance: str = "untrusted", by: str = "") -> dict:
        """Carica/sovrascrive un file in files/ (upload umano o output agente).
        `filename` può includere sottocartelle (es. 'archivio/foto/1.jpg') per
        organizzare i file; le dir padre vengono create. Anti-traversal per segmento.

        `provenance` = `trusted` | `untrusted` | `agent`. **Default `untrusted`**
        (#104 §3): il costo di sbagliare per difetto deve restare basso — una
        approvazione in più a valle — non alto, cioè un file illeggibile. I file
        introdotti da un verbo (allegati mail, download Drive) sono untrusted
        d'ufficio: non c'è nessuno da interrogare.
        """
        meta, _ = self._read_meta(tier, name)
        self._assert_content_available(meta)
        rel = (filename or "").strip().strip("/")
        # Normalizza il prefisso 'files/' ridondante: gli agenti spesso passano il
        # path completo che vedono (es. 'files/x.pdf') invece del nome relativo a
        # files/ → senza questo si crea files/files/x.pdf (annidamento + duplicati).
        # Prefissi ammessi in ingresso. `local/` e `remote/<n>/` sono le forme
        # esplicite; `files/` resta accettato perché gli agenti lo scrivono per
        # abitudine e compare in messaggi già inviati. Il mount di destinazione
        # viene deciso da `_resolve_data_path` sotto, che per la forma legacy
        # conserva il bersaglio di oggi.
        mount_prefix = ""
        while rel == "files" or rel.startswith("files/"):
            rel = rel[len("files"):].strip("/")
        if rel == self.MOUNT_LOCAL or rel.startswith(self.MOUNT_LOCAL + "/"):
            mount_prefix = self.MOUNT_LOCAL
            rel = rel[len(self.MOUNT_LOCAL):].strip("/")
        elif rel == self.MOUNT_REMOTE or rel.startswith(self.MOUNT_REMOTE + "/"):
            resto = rel[len(self.MOUNT_REMOTE):].strip("/")
            rn, _, resto = resto.partition("/")
            mount_prefix = f"{self.MOUNT_REMOTE}/{rn}"
            rel = resto.strip("/")
        if not rel or "\\" in rel:
            raise TopicError(f"nome file non valido: {filename}")
        parts = rel.split("/")
        if any(p in ("", ".", "..") or p.startswith(".") for p in parts):
            raise TopicError(f"nome file non valido: {filename}")
        # `files/AGENTS.md` NON è più un file: è il control-plane dello scope.
        # Il rifiuto è qui e non a valle perché questa è la riga che rendeva la
        # vulnerabilità reale — chiunque partecipi a un topic poteva caricare il
        # testo che entra nel contesto di ogni agente a ogni turno. Solo la
        # radice: `files/procedure/AGENTS.md` è un documento come un altro e non
        # viene iniettato da nessuno.
        if len(parts) == 1 and parts[0].upper() == "AGENTS.MD":
            raise TopicError(
                "AGENTS.md non è un file del topic ma le sue ISTRUZIONI di scope: "
                "vive nel control-plane e si scrive con `topic.save_agents_md` "
                "(optimistic lock, come il summary). Un upload lo lascerebbe "
                "scrivibile da qualunque partecipante.")
        store, base, sub, mount = self._resolve_data_path(
            tier, name, f"{mount_prefix}/{rel}".strip("/") if mount_prefix else rel)
        store.write(f"{base}/{sub}".strip("/"), data)
        prov = (provenance or "untrusted").strip().lower()
        if prov not in ("trusted", "untrusted", "agent"):
            prov = "untrusted"
        # La provenienza è etichettata SOLO sul mount locale: sul remote il file
        # non l'ha messo lì il nostro upload, e attribuirgliene una sarebbe una
        # classificazione inventata.
        if mount == self.MOUNT_LOCAL:
            self.set_provenance(tier, name, sub, prov, by=by)
        return {"name": parts[-1], "path": f"{mount}/{sub}", "provenance": prov}

    def delete_file(self, tier: str, name: str, relpath: str) -> dict:
        """SOFT-DELETE: NON cancella mai davvero. Sposta un file o una cartella
        (dentro files/) nel cestino del topic `.trash/<timestamp>/<path>`, creato
        se non esiste → sempre recuperabile. La struttura del topic (meta, summary,
        .messages e control-plane sono protetti: si agisce solo sotto files/, simmetrico a
        put_file. Anti-traversal per segmento."""
        meta, _ = self._read_meta(tier, name)
        self._assert_content_available(meta)
        rel = (relpath or "").strip().strip("/")
        parts = rel.split("/")
        if not rel or "\\" in rel or any(p in ("", ".", "..") for p in parts):
            raise TopicError(f"path non valido: {relpath}")
        if parts[0] not in self._MOUNTS and parts[0] != "files":
            raise TopicError(
                "puoi rimuovere solo file dentro i mount del topic — "
                f"`{self.MOUNT_LOCAL}/…` o `{self.MOUNT_REMOTE}/<nome>/…` "
                "(meta, summary e AGENTS.md sono control-plane e non si "
                "cancellano da qui)")
        store, base, sub, _mount = self._resolve_data_path(tier, name, rel)
        if not sub:
            raise TopicError("un mount non si cancella: indica un file dentro di esso")
        target = f"{base}/{sub}".strip("/")
        if not store.exists(target):
            raise TopicError(f"non trovato: {relpath}")
        if store is self.s:
            # local → soft-delete nel cestino del topic `.trash/<ts>/files/<sub>`
            # (recuperabile; `.trash` è dotfile → nascosto nel browser).
            ts = _now().strftime("%Y%m%d-%H%M%S")
            trash_rel = f".trash/{ts}/{rel}"
            self.s.move(target, f"{self._dir(tier, name)}/{trash_rel}")
            return {"trashed": rel, "trash_path": trash_rel, "recoverable": True}
        # drive → trash nativo di Drive (recuperabile dal Cestino dell'account).
        store.delete(target)
        return {"trashed": rel, "trash_path": "Drive/Cestino", "recoverable": True}

    def archive(self, tier: str, name: str) -> dict:
        """Imposta status=archived nel meta (NON sposta su storage inferiore)."""
        meta, ver = self._read_meta(tier, name)
        meta["status"] = "archived"
        self._write_meta(tier, name, meta, base_version=ver)
        return {"status": "archived"}

    def list(self, tier: str | None = None, include_archived: bool = False) -> list[dict]:
        """Elenco topic con riga sintetica. In P1 legge i meta dallo storage."""
        out: list[dict] = []
        tiers = [_normalize_tier(tier)] if tier else list(VALID_TIER)
        for tr in tiers:
            for e in self.s.list(tr):
                if e.kind != "dir":
                    continue
                try:
                    info = self._open(tr, e.name, allow_archived=True)
                except TopicError:
                    continue
                m = info["meta"]
                status = _norm_status(m.get("status"))
                if status == "archived" and not include_archived:
                    continue
                aps = _action_points(info["summary"])
                out.append({
                    "tier": tr, "tier_name": TIER_NAMES.get(tr, tr),
                    "name": e.name, "title": m.get("title"),
                    "status": status, "tldr": info["tldr"],
                    "deadline": m.get("deadline"),
                    # scadenza più vicina fra i todo (action_points) con data
                    "next_deadline": _next_deadline(aps),
                    "contact_agent": m.get("contact_agent", "clodia"),
                    "kind": m.get("kind"),
                    "owner": m.get("owner"),
                    "participants": m.get("participants", []),
                    "action_points": aps,
                    "storage": m.get("storage", self.s.capability().name),
                    "channel": m.get("channel"),
                    "updated_at": info["updated_at"],
                    "recent_files": info["recent_files"],
                })
        return out

    def set_status(self, tier: str, name: str, status: str) -> dict:
        """Imposta lo status del topic (vocabolario TOPIC_STATES). Ritorna lo
        status normalizzato applicato."""
        st = _validate_status(status)
        meta, ver = self._read_meta(tier, name)
        meta["status"] = st
        self._write_meta(tier, name, meta, base_version=ver)
        return {"status": st}

    def set_deadline(self, tier: str, name: str, deadline) -> dict:
        """Imposta la deadline del topic in formato ISO YYYY-MM-DD, oppure null."""
        dl = _norm_deadline(deadline)
        meta, ver = self._read_meta(tier, name)
        meta["deadline"] = dl
        self._write_meta(tier, name, meta, base_version=ver)
        return {"deadline": dl}

    def search(self, query: str, mode: str = "lexical") -> list[dict]:
        """P1: ricerca lessicale (substring) su meta/summary/AGENTS.md. 'semantic' = P2."""
        q = (query or "").strip().lower()
        if not q:
            return []
        hits: list[dict] = []
        for tr in VALID_TIER:
            for e in self.s.list(tr):
                if e.kind != "dir":
                    continue
                # Best-effort: un topic con contenuto corrotto/non-UTF8 non deve far
                # fallire l'INTERA ricerca — lo si salta (con warning) e si prosegue.
                try:
                    info = self.open(tr, e.name)
                    parts = [json.dumps(info["meta"], ensure_ascii=False), info["summary"]]
                    if info.get("agents_md"):
                        parts.append(info["agents_md"])
                    if q in "\n".join(parts).lower():
                        # `participants` e `owner` NON sono un extra: sono i campi su
                        # cui il chiamante decide se questa riga gli spetta. Senza,
                        # il filtro need-to-know a valle non ha nulla da valutare e
                        # (per come era scritto) lasciava passare tutto.
                        hits.append({"tier": tr, "name": e.name,
                                     "title": info["meta"].get("title"),
                                     "tldr": info["tldr"],
                                     "owner": info["meta"].get("owner"),
                                     "participants": list(info["meta"].get("participants") or [])})
                except (TopicError, UnicodeDecodeError, ValueError) as ex:
                    LOG.warning("search: topic %s/%s saltato (contenuto non leggibile): %s",
                                tr, e.name, str(ex)[:120])
                    continue
        return hits

"""Servizio Topic v2 — i verbi, sopra lo storage astratto.

Backend-agnostico: lavora SOLO tramite l'interfaccia `Storage`. Implementa la
meccanica (file meta.json + summary.md + files/AGENTS.md opzionale, optimistic lock sul
summary); la disciplina editoriale (cos'è un buon TLDR) sta nella
skill `topic-management`, non qui.

Classificazione a **tier** P0–P3 (sostituisce personal/confidential): è la sola
classe del topic, e coincide col livello di privacy usato dall'enforcement.
    P0 Public · P1 Internal · P2 Confidential · P3 Restricted

Layout per topic nello storage:
    <tier>/<name>/meta.json
    <tier>/<name>/summary.md
    <tier>/<name>/files/AGENTS.md
"""
from __future__ import annotations

import base64
import json
import logging
import os
import re
from datetime import datetime, timezone

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


def normalize_meta_v2(meta: dict, tier: str) -> dict:
    out = dict(meta or {})
    out.pop("minutes", None)
    out["schema_version"] = SCHEMA_VERSION
    out["tier"] = _normalize_tier(out.get("tier") or tier)
    out["status"] = _validate_status(out.get("status") or "active")
    out["deadline"] = _norm_deadline(out.get("deadline"))
    return out


class TopicService:
    def __init__(self, storage: Storage):
        self.s = storage          # control-plane local (meta, summary, .messages)
        self._drive_cache: dict = {}

    # ── routing storage dei FILE (control-plane resta su self.s) ─────────────
    def _drive_service(self, account: str | None):
        """Costruisce (e cache) il client Drive dalle credenziali gworkspace nel
        vault. Lato gateway → principal di sistema 'clodia'. Il segreto non
        raggiunge il modello."""
        from .. import vault
        from google.oauth2.credentials import Credentials
        from google.auth.transport.requests import Request as GReq
        from googleapiclient.discovery import build
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
        b = vault.get_secret("clodia", credential)
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

    def _drive_backend_for(self, tier: str, name: str, cfg: dict):
        """DriveStorage live per la cartella autoritativa del topic."""
        folder = (cfg or {}).get("folder")
        if not folder:
            return None
        from .drive_fs import DriveStorage
        key = f"{tier}/{name}:{folder}"
        ds = self._drive_cache.get(key)
        if ds is None:
            ds = DriveStorage(self._drive_service((cfg or {}).get("account")), folder)
            self._drive_cache[key] = ds
        return ds

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
    def _drive_remote_config(meta: dict) -> dict | None:
        remote = meta.get("remote") or {}
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
        if meta.get("storage") == "google-drive" and not meta.get("remote"):
            self._migrate_legacy_drive(tier, name)
            meta = json.loads(self.s.read(self._meta_p(tier, name)).data.decode())
        cfg = self._drive_remote_config(meta)
        if cfg is not None:
            # Drive è la fonte: si naviga direttamente il remoto, i file locali
            # non sono consultati né caricati.
            ds = self._drive_backend_for(tier, name, cfg)
            if ds is None:
                raise TopicError("remote drive: nessuna cartella configurata")
            return ds, ""
        return self.s, f"{self._dir(tier, name)}/files"

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

    def _recap_history_p(self, tier, name):
        # Storia dei recap (TLDR) del topic — control-plane, NON in files/ → non
        # sincronizzata dai remote git/drive.
        return f"{self._dir(tier, name)}/.recap-history.jsonl"

    # ── verbi ──────────────────────────────────────────────────────────────
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
        meta.setdefault("owner", meta.get("contact_agent", "clodia"))
        # Partecipanti di default dell'edizione (terraformazione): UNIONE con
        # gli espliciti — "sempre partecipanti ai topic nuovi". ECCEZIONE: i DM
        # (chat 1:1 umano↔agente) sono a DUE e basta → NON si aggiungono i default
        # (altrimenti clodia si intrufola in ogni DM, es. dm-avvocato--davide).
        from .. import instance_profile as _iprof
        is_dm = (meta.get("kind") == "dm") or (meta.get("type") == "dm")
        _defaults = [] if is_dm else _iprof.topic_default_participants()
        explicit = meta.get("participants") or []
        meta["participants"] = list(dict.fromkeys(
            [meta["owner"], *explicit, *_defaults]))
        meta = normalize_meta_v2(meta, tier)
        meta["created_at"] = _now().isoformat(timespec="seconds")
        self.s.write(mp, json.dumps(meta, ensure_ascii=False, indent=2).encode())
        if not self.s.exists(self._summary_p(tier, name)):
            self.s.write(self._summary_p(tier, name),
                         f"{meta.get('title', name)}\n\n## Prossimi passi\n".encode())
        if want_drive:
            # Remote Drive dalla nascita: risolve/crea la cartella e abilita la
            # vista live. Best-effort: un problema Drive non
            # deve impedire la creazione del topic (resta local pulito).
            try:
                meta = self.remote_enable(tier, name, "drive", dict(sc))
            except Exception as e:  # noqa: BLE001
                import logging
                logging.getLogger("clodia-tools.topics").warning(
                    "remote drive alla creazione di %s/%s fallito (topic resta "
                    "local): %s", tier, name, e)
        return meta

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
        ds = self._drive_cache.get(key)
        if ds is None:
            ds = DriveStorage(self._drive_service(account), folder)
            self._drive_cache[key] = ds
        return ds

    def _remote_for(self, tier: str, name: str, meta: dict):
        from .remote import make_remote
        r = meta.get("remote") or {}
        if not r.get("type"):
            return None
        # Solo per i remote git su github.com iniettiamo il PAT del vault (scoping:
        # il token non deve raggiungere altri host).
        gh_token = None
        if r["type"] == "git" and "github.com" in ((r.get("config") or {}).get("url") or ""):
            gh_token = self._github_token()
        return make_remote(r["type"], self._abs(tier, name, "files"),
                           self._abs(tier, name, ".remote-drive.json"),
                           drive_factory=self._remote_drive_factory,
                           github_token=gh_token)

    def _github_token(self) -> str | None:
        """PAT GitHub dal vault (deposto da tools_api.github_connect come
        {'value': pat}); None se assente."""
        from .. import vault
        try:
            return (vault.read_internal("github_pat") or {}).get("value") or None
        except Exception:  # noqa: BLE001
            return None

    def _remote_or_err(self, tier: str, name: str):
        meta, _ = self._read_meta(tier, name)
        rem = self._remote_for(tier, name, meta)
        if rem is None:
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

    def remote_status(self, tier: str, name: str) -> dict:
        meta, ver = self._read_meta(tier, name)
        rem = self._remote_for(tier, name, meta)
        # Backfill lazy del nome remoto sui topic pre-esistenti (config senza
        # `name`): risolto qui una volta e persistito. Best-effort.
        r = meta.get("remote") or {}
        if rem is not None and r and "name" not in (r.get("config") or {}):
            display = self._remote_display_name(r["type"], r.get("config") or {})
            try:
                r["config"]["name"] = display
                self._write_meta(tier, name, meta, base_version=ver)
            except Exception:  # noqa: BLE001 — race sul meta: riproverà al prossimo status
                pass
        return rem.status() if rem else {"enabled": False}

    def remote_enable(self, tier: str, name: str, rtype: str, config: dict | None = None) -> dict:
        if rtype not in ("git", "drive"):
            raise TopicError(f"remote type non supportato: {rtype}")
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
            if existing:
                raise TopicError(
                    f"collegare Drive a {tier}/{name} nasconderebbe {len(existing)} "
                    f"file locali: Drive diventa la fonte e i locali NON vengono "
                    f"caricati. Popola prima la cartella Drive, oppure lascia il "
                    f"topic su local-fs.")
        meta, ver = self._read_meta(tier, name)
        config = dict(config or {})
        if rtype == "drive":
            config.update(self._provision_drive_folder(config, name))  # risolve/crea la cartella
        config["name"] = self._remote_display_name(rtype, config)
        keep = ("url", "branch", "folder", "account", "user_name", "user_email", "message", "name")
        meta["remote"] = {"type": rtype, "config": {k: v for k, v in config.items() if k in keep}}
        meta["storage"] = self.s.capability().name   # storage torna esplicitamente local
        meta.pop("storage_config", None)
        self._write_meta(tier, name, meta, base_version=ver)
        rem = self._remote_for(tier, name, meta)
        rem.enable(meta["remote"]["config"])
        # Nessun upload: Drive è già la fonte (cartella appena provisionata o
        # pre-popolata). Da qui i verbi file proxano direttamente a Drive.
        return {"ok": True, "remote": meta["remote"], "status": rem.status()}

    def remote_disable(self, tier: str, name: str) -> dict:
        meta, ver = self._read_meta(tier, name)
        rem = self._remote_for(tier, name, meta)
        cfg = self._drive_remote_config(meta)
        if cfg is not None:
            ds = self._drive_backend_for(tier, name, cfg)
            if ds is None:
                raise TopicError("remote drive: nessuna cartella configurata")
            local_base = f"{self._dir(tier, name)}/files"
            # Scollegare Drive = materializzare il contenuto remoto in locale, così
            # il topic torna local-fs con i suoi file. Pull ripartibile, nessun
            # clear preventivo: se fallisce a metà, Drive resta la fonte.
            self._drive_pull_tree(ds, "", local_base)
        if rem is not None:
            rem.disable()
        meta.pop("remote", None)
        self._write_meta(tier, name, meta, base_version=ver)
        self._drive_cache.clear()
        return {"ok": True}

    def remote_add(self, tier: str, name: str, path: str) -> dict:
        self._remote_or_err(tier, name).add(path)
        return {"ok": True}

    def remote_unstage(self, tier: str, name: str, path: str = "") -> dict:
        """Toglie dallo staging (path vuoto = tutto)."""
        self._remote_or_err(tier, name).unstage(path or "")
        return {"ok": True}

    def remote_commit(self, tier: str, name: str, msg: str = "") -> dict:
        res = self._remote_or_err(tier, name).commit(msg) or {}
        return {"ok": True, **res}

    def remote_push(self, tier: str, name: str) -> dict:
        return self._remote_or_err(tier, name).push()

    def remote_pull(self, tier: str, name: str) -> dict:
        return self._remote_or_err(tier, name).pull()

    def _migrate_legacy_drive(self, tier: str, name: str) -> None:
        """One-shot: legacy storage=google-drive → remote Drive live."""
        meta, ver = self._read_meta(tier, name)
        if meta.get("storage") != "google-drive" or meta.get("remote"):
            return
        sc = meta.get("storage_config") or {}
        meta["remote"] = {"type": "drive",
                          "config": {"folder": sc.get("folder"), "account": sc.get("account")}}
        meta["storage"] = self.s.capability().name
        meta.pop("storage_config", None)
        rem = self._remote_for(tier, name, meta)
        try:
            rem.enable(meta["remote"]["config"])
            self._write_meta(tier, name, meta, base_version=ver)
            # storage=google-drive significa che i file vivevano GIÀ su Drive: la
            # conversione a remote:drive è solo metadata. Nessun upload/clear.
        except Exception:  # noqa: BLE001 — la migrazione non deve rompere open()
            LOG.warning("migrazione drive→remote fallita per %s/%s (locale intatto)",
                        tier, name)

    def open(self, tier: str, name: str) -> dict:
        """Read-only: meta + summary (+ summary_version per optimistic lock)."""
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
        # updated_at = mtime più recente tra meta, summary e files/AGENTS.md
        mts: list[float] = []
        agents_path = f"{d}/files/AGENTS.md"
        for p in (self._meta_p(tier, name), self._summary_p(tier, name), agents_path):
            st = self.s.stat(p)
            if st:
                mts.append(st.mtime)
        updated_at = _iso(max(mts)) if mts else None
        # recent_files = fino a 3 file dalla sorgente effettiva (Drive live o locale)
        fmt: list[tuple[float, str]] = []
        files_store, files_base = self._files_backend(tier, name)
        is_drive_live = files_store is not self.s
        for e in files_store.list(files_base):
            if e.kind != "file":
                continue
            st = None if is_drive_live else files_store.stat(
                f"{files_base}/{e.name}".strip("/"))
            fmt.append((st.mtime if st else 0.0, e.name))
        fmt.sort(reverse=True)
        recent_files = [{"name": n, "path": f"files/{n}", "mtime_iso": _iso(mt)}
                        for mt, n in fmt[:3]]
        try:
            agents_md = self.s.read(agents_path).data.decode("utf-8", "replace")
        except NotFound:
            agents_md = None
        return {
            "tier": meta["tier"], "tier_name": TIER_NAMES.get(meta["tier"], meta["tier"]), "name": name,
            "meta": meta, "summary": summary, "summary_version": summary_version,
            "tldr": _tldr(summary), "minutes": [], "agents_md": agents_md,
            "updated_at": updated_at, "recent_files": recent_files,
            "recap_history": self.recap_history(tier, name),
        }

    def read_file(self, tier: str, name: str, relpath: str) -> bytes:
        """Legge un file dentro il topic (es. files/foo.md). Anti-traversal.
        I path sotto files/ vanno sullo storage del topic (local o drive)."""
        rel = (relpath or "").lstrip("/")
        if not rel or ".." in rel.split("/"):
            raise TopicError(f"path non valido: {relpath}")
        is_files, sub = self._files_rel(rel)
        if is_files:
            store, base = self._files_backend(tier, name)
            return store.read(f"{base}/{sub}".strip("/")).data
        return self.s.read(f"{self._dir(tier, name)}/{rel}").data

    def save_summary(self, tier: str, name: str, text: str,
                     base_version: str | None) -> dict:
        """Scrive il summary in optimistic lock. base_version = la versione letta
        con open(); se è cambiata → VersionConflict (il chiamante escala)."""
        if not self.s.exists(self._meta_p(tier, name)):
            raise TopicError(f"topic non trovato: {tier}/{name}")
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
        raise TopicError("minutes rimosso dallo schema topic v2: usa summary.md o files/AGENTS.md")

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

    def set_owner(self, tier: str, name: str, owner: str) -> dict:
        meta, v = self._read_meta(tier, name)
        meta["owner"] = owner
        if owner not in meta.get("participants", []):
            meta.setdefault("participants", []).append(owner)
        self._write_meta(tier, name, meta, v)
        return {"owner": owner, "participants": meta.get("participants", [])}

    def add_participant(self, tier: str, name: str, agent: str) -> dict:
        meta, v = self._read_meta(tier, name)
        parts = meta.setdefault("participants", [])
        added = agent not in parts
        if added:
            parts.append(agent)
            self._write_meta(tier, name, meta, v)
            self.post_message(
                tier, name, "system", f"{agent} è entrato nel topic", kind="system"
            )
        return {"participants": parts, "added": added}

    def remove_participant(self, tier: str, name: str, agent: str) -> dict:
        meta, v = self._read_meta(tier, name)
        parts = meta.setdefault("participants", [])
        if agent in parts:
            parts.remove(agent)
            self._write_meta(tier, name, meta, v)
        return {"participants": parts}

    def post_message(self, tier: str, name: str, author: str, text: str,
                     kind: str = "human", attachments: list[str] | None = None) -> dict:
        """Posta un messaggio nel canale (append-only file in `.messages/` →
        niente contesa). `kind` = human|ai|system. `attachments` = nomi file in files/."""
        if not self.s.exists(self._meta_p(tier, name)):
            raise TopicError(f"topic non trovato: {tier}/{name}")
        now = _now()
        token = base64.urlsafe_b64encode(os.urandom(4)).decode().rstrip("=")
        msg = {
            "id": f"{now.strftime('%Y%m%d-%H%M%S')}-{token}",
            "author": author, "kind": kind, "text": text or "",
            "attachments": attachments or [], "ts": now.isoformat(timespec="seconds"),
        }
        self.s.write(f"{self._dir(tier, name)}/.messages/{msg['id']}.json",
                     json.dumps(msg, ensure_ascii=False).encode())
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

    def list_files(self, tier: str, name: str, subpath: str = "") -> list[dict]:
        """Elenca <subpath> a partire dalla ROOT del topic (non da files/): così
        il navigator mostra la struttura reale — summary.md, meta.json, files/,
        files/ — e si naviga nelle sottocartelle. subpath relativo alla root del
        topic (anti-traversal). I file/cartelle interni (dotfile, es. .messages)
        sono nascosti. path nelle voci = relativo alla root del topic."""
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
        is_files, sub = self._files_rel(rel) if rel else (False, "")
        if rel and is_files:
            # dentro files/ → storage del topic (local o drive)
            store, base = self._files_backend(tier, name)
            for e in store.list(f"{base}/{sub}".strip("/")):
                if e.name.startswith("."):
                    continue
                if e.mime and e.mime.startswith(self._NATIVE_DOC_PREFIX):
                    p = "files/" + (f"{sub}/" if sub else "") + e.name
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
                                "path": "files/" + (f"{sub}/" if sub else "") + real,
                                "kind": "file", "remote": True,
                                "url": info.get("gdrive_url") or "",
                                "mime": info.get("mimeType")})
                    continue
                p = "files/" + (f"{sub}/" if sub else "") + e.name
                if e.kind == "dir":
                    out.append({"name": e.name, "path": p, "kind": "dir"})
                else:
                    st = None if _is_drive else store.stat(
                        f"{base}/{sub}/{e.name}".strip("/"))
                    out.append({"name": e.name, "path": p, "kind": "file",
                                "size": (getattr(st, "size", None) if st else e.size),
                                "mtime_iso": _iso(st.mtime) if st else None,
                                "md5": (getattr(st, "md5", None) if st else e.version)})
        else:
            # root o control-plane (summary/meta) → local
            d = self._dir(tier, name)
            base = f"{d}/{rel}" if rel else d
            seen_files = False
            for e in self.s.list(base):
                if e.name.startswith("."):
                    continue
                if e.name == "files":
                    seen_files = True
                p = f"{rel}/{e.name}" if rel else e.name
                if e.kind == "dir":
                    out.append({"name": e.name, "path": p, "kind": "dir"})
                else:
                    st = self.s.stat(f"{base}/{e.name}")
                    out.append({"name": e.name, "path": p, "kind": "file",
                                "size": getattr(st, "size", None) if st else None,
                                "mtime_iso": _iso(st.mtime) if st else None,
                                "md5": getattr(st, "md5", None) if st else None})
            # topic drive: espone sempre 'files/' come dir navigabile, anche se il
            # cartella locale è vuota (così si può entrare e caricare).
            if not rel and not seen_files and _is_drive:
                out.append({"name": "files", "path": "files", "kind": "dir"})
        dirs = sorted((f for f in out if f.get("kind") == "dir"),
                      key=lambda f: f.get("name", "").lower())
        files = sorted((f for f in out if f.get("kind") != "dir"),
                       key=lambda f: f.get("mtime_iso") or "", reverse=True)
        return dirs + files

    def put_file(self, tier: str, name: str, filename: str, data: bytes) -> dict:
        """Carica/sovrascrive un file in files/ (upload umano o output agente).
        `filename` può includere sottocartelle (es. 'archivio/foto/1.jpg') per
        organizzare i file; le dir padre vengono create. Anti-traversal per segmento."""
        if not self.s.exists(self._meta_p(tier, name)):
            raise TopicError(f"topic non trovato: {tier}/{name}")
        rel = (filename or "").strip().strip("/")
        # Normalizza il prefisso 'files/' ridondante: gli agenti spesso passano il
        # path completo che vedono (es. 'files/x.pdf') invece del nome relativo a
        # files/ → senza questo si crea files/files/x.pdf (annidamento + duplicati).
        while rel == "files" or rel.startswith("files/"):
            rel = rel[len("files"):].strip("/")
        if not rel or "\\" in rel:
            raise TopicError(f"nome file non valido: {filename}")
        parts = rel.split("/")
        if any(p in ("", ".", "..") or p.startswith(".") for p in parts):
            raise TopicError(f"nome file non valido: {filename}")
        store, base = self._files_backend(tier, name)
        store.write(f"{base}/{rel}".strip("/"), data)
        return {"name": parts[-1], "path": f"files/{rel}"}

    def delete_file(self, tier: str, name: str, relpath: str) -> dict:
        """SOFT-DELETE: NON cancella mai davvero. Sposta un file o una cartella
        (dentro files/) nel cestino del topic `.trash/<timestamp>/<path>`, creato
        se non esiste → sempre recuperabile. La struttura del topic (meta, summary,
        .messages e control-plane sono protetti: si agisce solo sotto files/, simmetrico a
        put_file. Anti-traversal per segmento."""
        if not self.s.exists(self._meta_p(tier, name)):
            raise TopicError(f"topic non trovato: {tier}/{name}")
        rel = (relpath or "").strip().strip("/")
        parts = rel.split("/")
        if not rel or "\\" in rel or any(p in ("", ".", "..") for p in parts):
            raise TopicError(f"path non valido: {relpath}")
        if parts[0] != "files" or len(parts) < 2:
            raise TopicError(
                "puoi rimuovere solo file/cartelle dentro 'files/' del topic "
                "(meta, summary e messaggi sono protetti)")
        sub = "/".join(parts[1:])   # path sotto files/
        store, base = self._files_backend(tier, name)
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
                    info = self.open(tr, e.name)
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
                        hits.append({"tier": tr, "name": e.name,
                                     "title": info["meta"].get("title"), "tldr": info["tldr"]})
                except (TopicError, UnicodeDecodeError, ValueError) as ex:
                    LOG.warning("search: topic %s/%s saltato (contenuto non leggibile): %s",
                                tr, e.name, str(ex)[:120])
                    continue
        return hits

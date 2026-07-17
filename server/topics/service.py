"""Servizio Topic v2 — i verbi, sopra lo storage astratto.

Backend-agnostico: lavora SOLO tramite l'interfaccia `Storage`. Implementa la
meccanica (file meta.json + summary.md + minutes append-only, optimistic lock sul
summary); la disciplina editoriale (cos'è un buon TLDR, quando minutare) sta nella
skill `topic-management`, non qui.

Classificazione a **tier** P0–P3 (sostituisce personal/confidential): è la sola
classe del topic, e coincide col livello di privacy usato dall'enforcement.
    P0 Public · P1 Internal · P2 Confidential · P3 Restricted

Layout per topic nello storage:
    <tier>/<name>/meta.json
    <tier>/<name>/summary.md
    <tier>/<name>/minutes/<AAAAMMGG-hhmmss-token>.md
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

VALID_STATUS = {"active", "await", "idle", "archived"}
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
_CHANNEL_FIELDS = ("type", "chat_id", "bot_ref")


def _clean_channel(ch: dict) -> dict:
    """Tiene solo i campi ammessi del channel; normalizza chat_id a stringa."""
    out = {k: ch.get(k) for k in _CHANNEL_FIELDS if ch.get(k) is not None}
    if "chat_id" in out:
        out["chat_id"] = str(out["chat_id"])
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


# Vocabolario unico di status (selezione uguale per tutti). `urgent` = da fare
# subito. I valori legacy (idle, IT) sono migrati alla lettura.
TOPIC_STATES = ("await", "active", "archived", "urgent")
_STATUS_LEGACY = {"idle": "active", "attivo": "active",
                  "in_attesa": "await", "completato": "active"}


def _norm_status(s: str | None) -> str:
    s = (s or "").strip().lower()
    s = _STATUS_LEGACY.get(s, s)
    return s if s in TOPIC_STATES else "active"


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


class TopicService:
    def __init__(self, storage: Storage):
        import threading
        self.s = storage          # control-plane local (meta, summary, minutes, .messages)
        self._drive_cache: dict = {}   # (account → DriveStorage) cache per-cartella topic
        # local-first drive: i file di un topic drive vivono in LOCALE (letture
        # veloci, mai bloccanti); Drive è un MIRROR aggiornato in background dopo
        # le scritture (debounce) e su richiesta (sync_now). Il push è push-only:
        # non cancella mai file su Drive. La copia locale è la sorgente di verità.
        self._mirror_timers: dict = {}
        self._mirror_lock = threading.Lock()

    # ── routing storage dei FILE (control-plane resta su self.s) ─────────────
    def _drive_service(self, account: str | None):
        """Costruisce (e cache) il client Drive dalle credenziali gworkspace nel
        vault. Lato gateway → principal di sistema 'clodia'. Il segreto non
        raggiunge il modello."""
        from .. import vault
        from google.oauth2.credentials import Credentials
        from google.auth.transport.requests import Request as GReq
        from googleapiclient.discovery import build
        accts = sorted(n[len("gworkspace_"):] for n in vault.store_names()
                       if n.startswith("gworkspace_"))
        acct = account or (accts[0] if accts else None)
        if not acct:
            raise TopicError("storage drive: nessun account Google Workspace nel vault")
        b = vault.get_secret("clodia", f"gworkspace_{acct}")
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

    def _resolve_backend(self, tier: str, name: str, storage: str | None, cfg: dict):
        """(storage_obj, base_path) per i FILE del topic. LOCAL-FIRST: sia i topic
        `local-fs` sia `google-drive` tengono i file in LOCALE (`<dir>/files`) →
        letture/liste/scritture veloci e mai bloccanti. Per i topic drive, Drive è
        un mirror aggiornato a parte (seed pull-once + push su write / sync_now)."""
        return self.s, f"{self._dir(tier, name)}/files"

    def _drive_backend_for(self, tier: str, name: str, cfg: dict):
        """DriveStorage per la cartella-mirror del topic (seed/push). None se il
        topic non ha una folder Drive configurata."""
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

    # ── local-first drive: seed (pull-once) + mirror (push) ───────────────────
    def _seed_marker_p(self, tier: str, name: str) -> str:
        return f"{self._dir(tier, name)}/.drive-seeded"

    def _ensure_drive_seeded(self, tier: str, name: str, meta: dict) -> None:
        """Pull-once: la PRIMA volta che si accede ai file di un topic drive i cui
        file vivono ancora SU Drive, li scarica in locale (copia, NON distruttiva su
        Drive) e scrive un marker idempotente. Poi il topic è local-first."""
        if meta.get("storage") != "google-drive":
            return
        if self.s.exists(self._seed_marker_p(tier, name)):
            return
        ds = self._drive_backend_for(tier, name, meta.get("storage_config") or {})
        if ds is None:
            return
        local_base = f"{self._dir(tier, name)}/files"
        self._drive_pull_tree(ds, "", local_base)
        self.s.write(self._seed_marker_p(tier, name), b"1")
        LOG.info("drive-seed: %s/%s seminato in locale da Drive", tier, name)

    # I Google Docs nativi (Documenti/Fogli/Presentazioni) NON sono scaricabili
    # come binari: si mostrano come proxy/link e si leggono/editano su Drive.
    _NATIVE_DOC_PREFIX = "application/vnd.google-apps."

    def _drive_pull_tree(self, ds, rel: str, local_base: str) -> None:
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

    def sync_now(self, tier: str, name: str) -> dict:
        """Push on-demand: mirror di tutti i file locali → Drive. Push-only: NON
        cancella mai file su Drive. Salta i file già identici (md5)."""
        try:
            meta = json.loads(self.s.read(self._meta_p(tier, name)).data.decode())
        except Exception:  # noqa: BLE001
            return {"synced": 0, "note": "meta assente"}
        if meta.get("storage") != "google-drive":
            return {"synced": 0, "note": "topic non drive"}
        ds = self._drive_backend_for(tier, name, meta.get("storage_config") or {})
        if ds is None:
            return {"synced": 0, "note": "nessun folder drive"}
        n = self._drive_push_tree(ds, "", f"{self._dir(tier, name)}/files")
        return {"synced": n}

    def _drive_push_tree(self, ds, rel: str, local_base: str) -> int:
        import hashlib
        n = 0
        for e in self.s.list(f"{local_base}/{rel}".strip("/")):
            if e.name.startswith(".") or e.name.endswith(".gdrive.json"):
                continue  # dotfile o stub proxy di Doc nativo → non si pusha
            child = f"{rel}/{e.name}".strip("/")
            if e.kind == "dir":
                n += self._drive_push_tree(ds, child, local_base)
                continue
            data = self.s.read(f"{local_base}/{child}".strip("/")).data
            try:
                cur = ds.stat(child)
                if cur and cur.md5 == hashlib.md5(data).hexdigest():
                    continue  # già identico su Drive → skip
            except Exception:  # noqa: BLE001
                pass
            ds.write(child, data)
            n += 1
        return n

    def _schedule_mirror(self, tier: str, name: str) -> None:
        """Debounce: dopo una scrittura/cancellazione locale su un topic drive,
        programma un push a Drive in background (thread), coalescendo le scritture
        ravvicinate. Non blocca mai il chiamante. No-op sui topic non-drive."""
        import threading
        try:
            meta = json.loads(self.s.read(self._meta_p(tier, name)).data.decode())
        except Exception:  # noqa: BLE001
            return
        if meta.get("storage") != "google-drive":
            return
        key = f"{tier}/{name}"
        with self._mirror_lock:
            old = self._mirror_timers.get(key)
            if old:
                old.cancel()
            t = threading.Timer(5.0, self._mirror_fire, args=(tier, name))
            t.daemon = True
            self._mirror_timers[key] = t
            t.start()

    def _mirror_fire(self, tier: str, name: str) -> None:
        with self._mirror_lock:
            self._mirror_timers.pop(f"{tier}/{name}", None)
        try:
            self.sync_now(tier, name)
        except Exception:  # noqa: BLE001
            LOG.warning("drive-mirror: push a Drive fallito per %s/%s",
                        tier, name, exc_info=True)

    def _files_backend(self, tier: str, name: str):
        """Storage dei FILE del topic, dal meta (control-plane). Local-first: per i
        topic drive assicura il seed pull-once da Drive prima di servire i file."""
        try:
            meta = json.loads(self.s.read(self._meta_p(tier, name)).data.decode())
        except Exception:  # noqa: BLE001 — topic legacy/assente → local
            meta = {}
        self._ensure_drive_seeded(tier, name, meta)
        return self._resolve_backend(tier, name, meta.get("storage"),
                                     meta.get("storage_config") or {})

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
        cur_storage = meta.get("storage") or self.s.capability().name
        cur_cfg = meta.get("storage_config") or {}
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
        # Local-first: i FILE vivono SEMPRE in locale. La migrazione cambia solo se
        # Drive fa da mirror (→drive) o no (→local); i file locali non si spostano.
        if tgt_type == "drive":
            # → drive: file già in locale; configura la folder, marca seminato
            #   (niente pull) e pusha su Drive. Nessuno spostamento distruttivo.
            new_cfg = self._provision_drive_folder(target, name)
            meta["storage"] = "google-drive"
            meta["storage_config"] = new_cfg
            self.s.write(mp, json.dumps(meta, ensure_ascii=False, indent=2).encode())
            self._drive_cache.clear()
            self.s.write(self._seed_marker_p(tier, name), b"1")
            res = self.sync_now(tier, name)
            return {"migrated": res.get("synced", 0), "conflicts": [],
                    "from": cur_storage, "to": "google-drive",
                    "backup": "(file locali conservati come sorgente di verità)"}
        # → local: assicura il seed (pull da Drive se non ancora), poi togli il
        #   mirror. La cartella Drive di origine resta (non distruttivo).
        self._ensure_drive_seeded(tier, name, meta)
        meta["storage"] = "local-fs"
        meta.pop("storage_config", None)
        self.s.write(mp, json.dumps(meta, ensure_ascii=False, indent=2).encode())
        self._drive_cache.clear()
        self.s.delete(self._seed_marker_p(tier, name))
        return {"migrated": 0, "conflicts": [], "from": cur_storage,
                "to": "local-fs", "backup": "(cartella Drive di origine conservata)"}

    @staticmethod
    def _files_rel(relpath: str) -> tuple[bool, str]:
        """(is_files, rel) — True + path sotto files/ se relpath sta in files/,
        altrimenti False (control-plane: summary/minutes/meta)."""
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
        if self.s.exists(mp):
            return self.open(tier, name)["meta"]
        meta = dict(meta or {})
        meta.setdefault("title", name)
        meta.setdefault("type", "progetto")
        # tier = unica classe del topic + livello di privacy per l'enforcement.
        meta["tier"] = tier
        meta.setdefault("status", "active")
        # Storage dei FILE del topic (control-plane = sempre local). Default local;
        # se richiesto drive (meta.storage_config.type=drive) si lega/crea la cartella.
        # Modello remote-pluggable (2 lug): lo storage è SEMPRE locale; "drive"
        # alla creazione = remote drive abilitato dalla nascita (fix 6 lug: prima
        # marcava google-drive senza wiring → il topic restava di fatto locale).
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
        # gli espliciti, non fallback — "sempre partecipanti ai topic nuovi"
        # vale anche quando il chiamante (es. channel_create della webui)
        # passa la propria lista [utente, contact_agent]. Rimuoverli dopo
        # resta possibile (participant_remove).
        from .. import instance_profile as _iprof
        _defaults = _iprof.topic_default_participants()
        explicit = meta.get("participants") or []
        meta["participants"] = list(dict.fromkeys(
            [meta["owner"], *explicit, *_defaults]))
        meta.setdefault("deadline", None)
        meta["created_at"] = _now().isoformat(timespec="seconds")
        self.s.write(mp, json.dumps(meta, ensure_ascii=False, indent=2).encode())
        if not self.s.exists(self._summary_p(tier, name)):
            self.s.write(self._summary_p(tier, name),
                         f"{meta.get('title', name)}\n\n## Prossimi passi\n".encode())
        if want_drive:
            # remote drive dalla nascita: risolve/crea la cartella e abilita il
            # sync (add/commit/push/pull). Best-effort: un problema Drive non
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
        return DriveStorage(self._drive_service(account), folder)

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
        return {"ok": True, "remote": meta["remote"], "status": rem.status()}

    def remote_disable(self, tier: str, name: str) -> dict:
        meta, ver = self._read_meta(tier, name)
        rem = self._remote_for(tier, name, meta)
        if rem is not None:
            rem.disable()          # local clean, file PRESERVATI
        meta.pop("remote", None)
        self._write_meta(tier, name, meta, base_version=ver)
        return {"ok": True}

    def remote_add(self, tier: str, name: str, path: str) -> dict:
        self._remote_or_err(tier, name).add(path)
        return {"ok": True}

    def remote_unstage(self, tier: str, name: str, path: str = "") -> dict:
        """Toglie dallo staging (path vuoto = tutto)."""
        self._remote_or_err(tier, name).unstage(path or "")
        return {"ok": True}

    def remote_commit(self, tier: str, name: str, msg: str = "") -> dict:
        self._remote_or_err(tier, name).commit(msg)
        return {"ok": True}

    def remote_push(self, tier: str, name: str) -> dict:
        return self._remote_or_err(tier, name).push()

    def remote_pull(self, tier: str, name: str) -> dict:
        return self._remote_or_err(tier, name).pull()

    def _migrate_legacy_drive(self, tier: str, name: str) -> None:
        """One-shot: legacy storage=google-drive → remote drive (local+sync).
        Non distruttivo: i file locali restano, si popola la sola sync-list."""
        meta, ver = self._read_meta(tier, name)
        if meta.get("storage") != "google-drive" or meta.get("remote"):
            return
        sc = meta.get("storage_config") or {}
        meta["remote"] = {"type": "drive",
                          "config": {"folder": sc.get("folder"), "account": sc.get("account")}}
        meta["storage"] = self.s.capability().name
        meta.pop("storage_config", None)
        self._write_meta(tier, name, meta, base_version=ver)
        rem = self._remote_for(tier, name, meta)
        try:
            rem.enable(meta["remote"]["config"])
            base = self._abs(tier, name, "files")
            paths = []
            for r, _dirs, fnames in os.walk(base):
                for fn in fnames:
                    rel = os.path.relpath(os.path.join(r, fn), base)
                    if not rel.startswith("."):
                        paths.append(rel)
            if hasattr(rem, "seed"):
                rem.seed(paths)
        except Exception:  # noqa: BLE001 — la migrazione non deve rompere open()
            LOG.warning("seed migrazione drive fallito per %s/%s", tier, name)

    def open(self, tier: str, name: str) -> dict:
        """Read-only: meta + summary (+ summary_version per optimistic lock) + minutes."""
        # Migrazione one-shot legacy storage=google-drive → remote drive.
        try:
            self._migrate_legacy_drive(tier, name)
        except Exception:  # noqa: BLE001
            LOG.warning("migrazione storage→remote fallita per %s/%s", tier, name)
        try:
            meta_r = self.s.read(self._meta_p(tier, name))
        except NotFound:
            raise TopicError(f"topic non trovato: {tier}/{name}")
        meta = json.loads(meta_r.data.decode())
        meta.setdefault("tier", tier)
        meta["tier"] = _normalize_tier(meta.get("tier"))
        meta.setdefault("storage", self.s.capability().name)
        try:
            sumr = self.s.read(self._summary_p(tier, name))
            summary, summary_version = sumr.data.decode(), sumr.version
        except NotFound:
            summary, summary_version = "", None
        d = self._dir(tier, name)
        minutes = [e.name for e in self.s.list(f"{d}/minutes") if e.kind == "file"]
        # updated_at = mtime più recente tra meta, summary e minute
        mts: list[float] = []
        for p in (self._meta_p(tier, name), self._summary_p(tier, name)):
            st = self.s.stat(p)
            if st:
                mts.append(st.mtime)
        for mn in minutes:
            st = self.s.stat(f"{d}/minutes/{mn}")
            if st:
                mts.append(st.mtime)
        updated_at = _iso(max(mts)) if mts else None
        # recent_files = fino a 3 file in files/, per mtime desc
        fmt: list[tuple[float, str]] = []
        for e in self.s.list(f"{d}/files"):
            if e.kind != "file":
                continue
            st = self.s.stat(f"{d}/files/{e.name}")
            fmt.append((st.mtime if st else 0.0, e.name))
        fmt.sort(reverse=True)
        recent_files = [{"name": n, "path": f"files/{n}", "mtime_iso": _iso(mt)}
                        for mt, n in fmt[:3]]
        return {
            "tier": tier, "tier_name": TIER_NAMES.get(tier, tier), "name": name,
            "meta": meta, "summary": summary, "summary_version": summary_version,
            "tldr": _tldr(summary), "minutes": sorted(minutes),
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
        """Aggiunge una minuta come FILE NUOVO (append-only → niente contesa)."""
        if not self.s.exists(self._meta_p(tier, name)):
            raise TopicError(f"topic non trovato: {tier}/{name}")
        ts = _now().strftime("%Y%m%d-%H%M%S")
        token = base64.urlsafe_b64encode(os.urandom(3)).decode().rstrip("=")
        fname = f"{ts}-{token}.md"
        self.s.write(f"{self._dir(tier, name)}/minutes/{fname}", (text or "").encode())
        return {"minute": fname}

    # ── canale: partecipanti / messaggi / file ──────────────────────────────
    def _read_meta(self, tier: str, name: str) -> tuple[dict, str | None]:
        try:
            r = self.s.read(self._meta_p(tier, name))
        except NotFound:
            raise TopicError(f"topic non trovato: {tier}/{name}")
        return json.loads(r.data.decode()), r.version

    def _write_meta(self, tier: str, name: str, meta: dict, base_version: str | None) -> None:
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
        if agent not in parts:
            parts.append(agent)
            self._write_meta(tier, name, meta, v)
        return {"participants": parts}

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
        niente contesa). `kind` = human|ai. `attachments` = nomi file in files/."""
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
        il navigator mostra la struttura reale — summary.md, meta.yaml, minutes/,
        files/ — e si naviga nelle sottocartelle. subpath relativo alla root del
        topic (anti-traversal). I file/cartelle interni (dotfile, es. .messages)
        sono nascosti. path nelle voci = relativo alla root del topic."""
        rel = (subpath or "").strip("/")
        if ".." in rel.split("/") or "\\" in rel:
            raise TopicError(f"subpath non valido: {subpath}")
        # local-first: assicura il seed (pull-once) dei file drive prima di elencare.
        try:
            _meta = json.loads(self.s.read(self._meta_p(tier, name)).data.decode())
        except Exception:  # noqa: BLE001
            _meta = {}
        self._ensure_drive_seeded(tier, name, _meta)
        _is_drive = _meta.get("storage") == "google-drive"
        out: list[dict] = []
        is_files, sub = self._files_rel(rel) if rel else (False, "")
        if rel and is_files:
            # dentro files/ → storage del topic (local o drive)
            store, base = self._files_backend(tier, name)
            for e in store.list(f"{base}/{sub}".strip("/")):
                if e.name.startswith("."):
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
                    st = store.stat(f"{base}/{sub}/{e.name}".strip("/"))
                    out.append({"name": e.name, "path": p, "kind": "file",
                                "size": getattr(st, "size", None) if st else None,
                                "mtime_iso": _iso(st.mtime) if st else None,
                                "md5": getattr(st, "md5", None) if st else None})
        else:
            # root o control-plane (summary/minutes) → local
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
            # mirror locale è ancora vuoto (così si può entrare e caricare).
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
        self._schedule_mirror(tier, name)  # local-first: mirror a Drive in background
        return {"name": parts[-1], "path": f"files/{rel}"}

    def delete_file(self, tier: str, name: str, relpath: str) -> dict:
        """SOFT-DELETE: NON cancella mai davvero. Sposta un file o una cartella
        (dentro files/) nel cestino del topic `.trash/<timestamp>/<path>`, creato
        se non esiste → sempre recuperabile. La struttura del topic (meta, summary,
        minutes/, .messages) è protetta: si agisce solo sotto files/, simmetrico a
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
                "(meta, summary, minutes sono protetti)")
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
        mp = self._meta_p(tier, name)
        try:
            r = self.s.read(mp)
        except NotFound:
            raise TopicError(f"topic non trovato: {tier}/{name}")
        meta = json.loads(r.data.decode())
        meta["status"] = "archived"
        self.s.write(mp, json.dumps(meta, ensure_ascii=False, indent=2).encode(),
                     if_version=r.version)
        return {"status": "archived"}

    def list(self, tier: str | None = None, include_archived: bool = False) -> list[dict]:
        """Elenco topic con riga sintetica. In P1 legge i meta dallo storage."""
        out: list[dict] = []
        tiers = [tier] if tier else list(VALID_TIER)
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
        st = _norm_status(status)
        if st not in TOPIC_STATES:
            raise TopicError(f"status non valido: {status} (validi: {', '.join(TOPIC_STATES)})")
        meta, ver = self._read_meta(tier, name)
        meta["status"] = st
        self._write_meta(tier, name, meta, base_version=ver)
        return {"status": st}

    def search(self, query: str, mode: str = "lexical") -> list[dict]:
        """P1: ricerca lessicale (substring) su meta/summary/minute. 'semantic' = P2."""
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
                    for mn in info["minutes"]:
                        try:
                            parts.append(self.s.read(
                                f"{self._dir(tr, e.name)}/minutes/{mn}"
                            ).data.decode("utf-8", "replace"))
                        except StorageError:
                            pass
                    if q in "\n".join(parts).lower():
                        hits.append({"tier": tr, "name": e.name,
                                     "title": info["meta"].get("title"), "tldr": info["tldr"]})
                except (TopicError, UnicodeDecodeError, ValueError) as ex:
                    LOG.warning("search: topic %s/%s saltato (contenuto non leggibile): %s",
                                tr, e.name, str(ex)[:120])
                    continue
        return hits

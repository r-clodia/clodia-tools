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
import os
import re
from datetime import datetime, timezone

from .storage import NotFound, Storage, StorageError, VersionConflict

VALID_STATUS = {"active", "await", "idle", "archived"}
VALID_TIER = ["P0", "P1", "P2", "P3"]
TIER_NAMES = {"P0": "Public", "P1": "Internal", "P2": "Confidential", "P3": "Restricted"}
DEFAULT_TIER = "P0"


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


class TopicService:
    def __init__(self, storage: Storage):
        self.s = storage

    # ── path helper ────────────────────────────────────────────────────────
    def _dir(self, tier: str, name: str) -> str:
        if tier not in VALID_TIER:
            raise TopicError(f"tier non valido: {tier} (ammessi: {VALID_TIER})")
        if not re.match(r"^[a-z0-9][a-z0-9_-]{0,60}$", name or ""):
            raise TopicError(f"nome topic non valido: {name}")
        return f"{tier}/{name}"

    def _meta_p(self, tier, name):
        return f"{self._dir(tier, name)}/meta.json"

    def _summary_p(self, tier, name):
        return f"{self._dir(tier, name)}/summary.md"

    # ── verbi ──────────────────────────────────────────────────────────────
    def new(self, tier: str | None, name: str, meta: dict | None = None) -> dict:
        """Scaffold idempotente: se il topic esiste già ritorna il suo meta."""
        tier = tier or DEFAULT_TIER
        mp = self._meta_p(tier, name)
        if self.s.exists(mp):
            return self.open(tier, name)["meta"]
        meta = dict(meta or {})
        meta.setdefault("title", name)
        meta.setdefault("type", "progetto")
        # tier = unica classe del topic + livello di privacy per l'enforcement.
        meta["tier"] = tier
        meta.setdefault("status", "active")
        # backend che CONTIENE il topic (routing multi-backend + tiering storage↔topic).
        meta["storage"] = self.s.capability().name
        meta.setdefault("tags", [])
        meta.setdefault("people", [])
        meta.setdefault("contact_agent", "clodia")
        # Canale (Slack-like): owner = chi amministra il canale (invita/rimuove);
        # participants = agenti (umani/AI) abilitati a parlare nel canale.
        meta.setdefault("owner", meta.get("contact_agent", "clodia"))
        meta.setdefault("participants", [meta["owner"]])
        meta.setdefault("deadline", None)
        meta["created_at"] = _now().isoformat(timespec="seconds")
        self.s.write(mp, json.dumps(meta, ensure_ascii=False, indent=2).encode())
        if not self.s.exists(self._summary_p(tier, name)):
            self.s.write(self._summary_p(tier, name),
                         f"{meta.get('title', name)}\n\n## Prossimi passi\n".encode())
        return meta

    def open(self, tier: str, name: str) -> dict:
        """Read-only: meta + summary (+ summary_version per optimistic lock) + minutes."""
        try:
            meta_r = self.s.read(self._meta_p(tier, name))
        except NotFound:
            raise TopicError(f"topic non trovato: {tier}/{name}")
        meta = json.loads(meta_r.data.decode())
        meta.setdefault("tier", tier)
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
        }

    def read_file(self, tier: str, name: str, relpath: str) -> bytes:
        """Legge un file dentro il topic (es. files/foo.md). Anti-traversal."""
        rel = (relpath or "").lstrip("/")
        if not rel or ".." in rel.split("/"):
            raise TopicError(f"path non valido: {relpath}")
        return self.s.read(f"{self._dir(tier, name)}/{rel}").data

    def save_summary(self, tier: str, name: str, text: str,
                     base_version: str | None) -> dict:
        """Scrive il summary in optimistic lock. base_version = la versione letta
        con open(); se è cambiata → VersionConflict (il chiamante escala)."""
        if not self.s.exists(self._meta_p(tier, name)):
            raise TopicError(f"topic non trovato: {tier}/{name}")
        new_v = self.s.write(self._summary_p(tier, name), (text or "").encode(),
                             if_version=base_version)
        return {"summary_version": new_v, "tldr": _tldr(text)}

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
        d = self._dir(tier, name)
        base = f"{d}/{rel}" if rel else d
        out: list[dict] = []
        for e in self.s.list(base):
            if e.name.startswith("."):   # nascondi .messages e altri interni
                continue
            p = f"{rel}/{e.name}" if rel else e.name
            if e.kind == "dir":
                out.append({"name": e.name, "path": p, "kind": "dir"})
            else:
                st = self.s.stat(f"{base}/{e.name}")
                out.append({"name": e.name, "path": p, "kind": "file",
                            "size": getattr(st, "size", None) if st else None,
                            "mtime_iso": _iso(st.mtime) if st else None})
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
        if not rel or "\\" in rel:
            raise TopicError(f"nome file non valido: {filename}")
        parts = rel.split("/")
        if any(p in ("", ".", "..") or p.startswith(".") for p in parts):
            raise TopicError(f"nome file non valido: {filename}")
        self.s.write(f"{self._dir(tier, name)}/files/{rel}", data)
        return {"name": parts[-1], "path": f"files/{rel}"}

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
                if m.get("status") == "archived" and not include_archived:
                    continue
                out.append({
                    "tier": tr, "tier_name": TIER_NAMES.get(tr, tr),
                    "name": e.name, "title": m.get("title"),
                    "status": m.get("status"), "tldr": info["tldr"],
                    "deadline": m.get("deadline"),
                    "contact_agent": m.get("contact_agent", "clodia"),
                    "kind": m.get("kind"),
                    "owner": m.get("owner"),
                    "participants": m.get("participants", []),
                    "action_points": _action_points(info["summary"]),
                    "storage": m.get("storage", self.s.capability().name),
                    "updated_at": info["updated_at"],
                    "recent_files": info["recent_files"],
                })
        return out

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
                try:
                    info = self.open(tr, e.name)
                except TopicError:
                    continue
                parts = [json.dumps(info["meta"], ensure_ascii=False), info["summary"]]
                for mn in info["minutes"]:
                    try:
                        parts.append(self.s.read(
                            f"{self._dir(tr, e.name)}/minutes/{mn}").data.decode())
                    except StorageError:
                        pass
                if q in "\n".join(parts).lower():
                    hits.append({"tier": tr, "name": e.name,
                                 "title": info["meta"].get("title"), "tldr": info["tldr"]})
        return hits

"""Signed checkpoints, exported off-system (clodia-platform#431).

A hash chain proves that the middle of the log was not altered. It cannot prove
that the TAIL was not cut: delete the last N lines and what remains is still a
valid chain. A checkpoint — `{seq, hash}` of the head, signed with the audit
key — closes that gap only if a copy lives where the gateway cannot rewrite
it. Hence the exporters:

* `dir`  — a directory given by `CLODIA_AUDIT_EXPORT_DIR` (a different volume,
  ideally append-only or on another host). Files are created with O_EXCL and
  never rewritten.
* `s3`   — an S3 / S3-compatible bucket with **Object Lock**, configured by the
  vault credential `audit_worm_config`. Every checkpoint is a new object, PUT
  with a retention date (COMPLIANCE mode by default) and `If-None-Match: *`,
  so not even the credential holder can shorten or overwrite it.

With no exporter configured, checkpoints are still written locally, and the
status says `off_system: false` in plain words instead of looking healthy.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, urlparse

from . import record
from .keys import Signer

LOG = logging.getLogger("clodia-tools.audit")

SCHEMA = "clodia.audit.checkpoint/1"
WORM_CRED = "audit_worm_config"
LOCAL_NAME = "checkpoints.jsonl"


def make(seq: int, head_hash: str, signer: Signer, gateway_version: str) -> dict:
    cp = {"schema": SCHEMA, "seq": seq, "hash": head_hash,
          "timestamp": record.now_iso(), "key_id": signer.key_id,
          "gateway_version": gateway_version}
    cp["signature"] = signer.sign(record.canonical_json(cp))
    return cp


def unsigned(cp: dict) -> bytes:
    body = {k: v for k, v in cp.items() if k != "signature"}
    return record.canonical_json(body)


def object_name(cp: dict) -> str:
    return f"checkpoint-{cp['seq']:012d}-{cp['hash'][:16]}.json"


# ── exporters ────────────────────────────────────────────────────────────────
class DirExporter:
    name = "dir"

    def __init__(self, path: Path):
        self.path = path

    def describe(self) -> dict:
        return {"type": self.name, "target": str(self.path)}

    def export(self, cp: dict) -> None:
        self.path.mkdir(parents=True, exist_ok=True)
        target = self.path / object_name(cp)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        with os.fdopen(fd, "wb") as fh:
            fh.write(record.canonical_json(cp))


class S3Exporter:
    """PUT one object per checkpoint, under Object Lock retention."""

    name = "s3"

    def __init__(self, cfg: dict, http=None):
        self.endpoint = (cfg.get("endpoint") or "").rstrip("/")
        self.bucket = cfg["bucket"]
        self.region = cfg.get("region") or "us-east-1"
        self.prefix = (cfg.get("prefix") or "audit-checkpoints").strip("/")
        self.access_key = cfg["access_key_id"]
        self.secret_key = cfg["secret_access_key"]
        self.mode = (cfg.get("mode") or "COMPLIANCE").upper()
        self.retention_days = int(cfg.get("retention_days") or 400)
        self._http = http
        if not self.endpoint:
            self.endpoint = f"https://s3.{self.region}.amazonaws.com"

    def describe(self) -> dict:
        # Never the credentials.
        return {"type": self.name, "target": f"{self.endpoint}/{self.bucket}/{self.prefix}",
                "mode": self.mode, "retention_days": self.retention_days}

    def request(self, cp: dict, now: datetime | None = None) -> tuple[str, dict, bytes]:
        from . import sigv4
        now = now or datetime.now(timezone.utc)
        body = record.canonical_json(cp)
        key = f"{self.prefix}/{object_name(cp)}"
        u = urlparse(self.endpoint)
        path = "/" + quote(self.bucket, safe="") + "/" + quote(key, safe="/-_.~")
        until = (now + timedelta(days=self.retention_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        headers = {
            "content-type": "application/json",
            "content-md5": base64.b64encode(hashlib.md5(body).digest()).decode(),  # noqa: S324 - required by S3 Object Lock, not used for security
            "x-amz-content-sha256": hashlib.sha256(body).hexdigest(),
            "x-amz-object-lock-mode": self.mode,
            "x-amz-object-lock-retain-until-date": until,
            "if-none-match": "*",
        }
        signed = sigv4.sign("PUT", u.netloc, path, {}, headers, body,
                            access_key=self.access_key, secret_key=self.secret_key,
                            region=self.region, service="s3",
                            amz_date=now.strftime("%Y%m%dT%H%M%SZ"))
        return f"{u.scheme}://{u.netloc}{path}", signed, body

    def export(self, cp: dict) -> None:
        import httpx
        url, headers, body = self.request(cp)
        client = self._http or httpx
        resp = client.put(url, headers=headers, content=body, timeout=30)
        if resp.status_code >= 300:
            raise RuntimeError(f"S3 PUT {resp.status_code}: {resp.text[:200]}")


def exporters() -> list:
    """The exporters configured on this instance (may be empty)."""
    out: list = []
    d = (os.environ.get("CLODIA_AUDIT_EXPORT_DIR") or "").strip()
    if d:
        out.append(DirExporter(Path(d)))
    try:
        from .. import vault
        if vault.has_credential(WORM_CRED):
            out.append(S3Exporter(vault.read_internal(WORM_CRED)))
    except Exception as exc:  # noqa: BLE001 - a broken config is reported, not fatal
        LOG.error("audit: WORM exporter not usable (%s)", type(exc).__name__)
    return out


# ── local record of checkpoints ──────────────────────────────────────────────
def local_path(root: Path) -> Path:
    return root / LOCAL_NAME


def append_local(root: Path, cp: dict, exports: list[dict]) -> None:
    line = json.dumps({"checkpoint": cp, "exports": exports}, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False) + "\n"
    fd = os.open(local_path(root), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, line.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


def last_local(root: Path) -> dict | None:
    p = local_path(root)
    if not p.is_file():
        return None
    last = None
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                last = json.loads(line)
    return last

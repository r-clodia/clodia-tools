"""Append-only, hash-chained, signed event store (clodia-platform#431).

Layout of the store directory:

    events-YYYYMMDD.jsonl   one canonical event per line, UTC day of append
    checkpoints.jsonl       signed checkpoints (also exported off-system)
    audit.pub.pem           public key, for verifiers
    .lock                   inter-process lock

Every event gets `integrity = {seq, previous_hash, key_id, hash, signature}`:
`seq` counts from 1 with no gaps, `previous_hash` is the `hash` of the event
before (the genesis value for the first), `hash` covers the whole record
except `hash`/`signature`, and `signature` is the audit key's ed25519 signature
over the raw bytes of `hash`. Altering, removing or reordering an event breaks
the chain at that point; cutting the tail is caught by the checkpoints exported
off-system (see `checkpoint.py`), which a chain alone cannot do.

Appends are serialised by a thread lock and an `flock`, and the chain head is
re-read from disk under the lock, so two processes on the same volume cannot
fork the chain. Each line is written with one `write` and `fsync`ed before the
append returns.
"""
from __future__ import annotations

import fcntl
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from . import record
from .keys import Signer

_TAIL = 256 * 1024


class StoreError(RuntimeError):
    """The store could not append (I/O, corrupt tail)."""


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def _segment_name(day: datetime) -> str:
    return f"events-{day:%Y%m%d}.jsonl"


class AuditStore:
    def __init__(self, root: Path, signer: Signer):
        self.root = root
        self.signer = signer
        self._lock = threading.Lock()
        root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(root, 0o700)
        except OSError:
            pass

    # ── reading ──────────────────────────────────────────────────────────────
    def segments(self) -> list[Path]:
        return sorted(self.root.glob("events-*.jsonl"))

    @staticmethod
    def _last_line(path: Path) -> str | None:
        size = path.stat().st_size
        if size == 0:
            return None
        with path.open("rb") as fh:
            fh.seek(max(0, size - _TAIL))
            chunk = fh.read()
        lines = [ln for ln in chunk.split(b"\n") if ln.strip()]
        return lines[-1].decode("utf-8") if lines else None

    def head(self) -> tuple[int, str]:
        """(seq, hash) of the last event, or (0, GENESIS) on an empty store."""
        for seg in reversed(self.segments()):
            line = self._last_line(seg)
            if line is None:
                continue
            try:
                integ = json.loads(line)["integrity"]
                return int(integ["seq"]), str(integ["hash"])
            except (ValueError, KeyError, TypeError) as exc:
                raise StoreError(f"corrupt tail in {seg.name}: {exc}") from exc
        return 0, record.GENESIS

    def iter_events(self):
        for seg in self.segments():
            with seg.open("r", encoding="utf-8") as fh:
                for n, line in enumerate(fh, 1):
                    if line.strip():
                        yield seg.name, n, line

    # ── writing ──────────────────────────────────────────────────────────────
    def append(self, rec: dict) -> dict:
        """Chain, sign and persist `rec` (a `record.build()` result)."""
        with self._lock:
            lock_path = self.root / ".lock"
            with lock_path.open("a") as lk:
                fcntl.flock(lk, fcntl.LOCK_EX)
                try:
                    seq, prev = self.head()
                    rec = dict(rec)
                    rec["integrity"] = {"seq": seq + 1, "previous_hash": prev,
                                        "key_id": self.signer.key_id}
                    h = record.event_hash(rec)
                    rec["integrity"]["hash"] = h
                    rec["integrity"]["signature"] = self.signer.sign(bytes.fromhex(h))
                    line = record.canonical_json(rec) + b"\n"
                    seg = self.root / _segment_name(datetime.now(timezone.utc))
                    fd = os.open(seg, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                    try:
                        _write_all(fd, line)
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    return rec
                finally:
                    fcntl.flock(lk, fcntl.LOCK_UN)

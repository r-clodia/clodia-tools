"""Idempotent ingest of agent-server events (clodia-platform#466).

The agent-server keeps an outbox for events it must not lose (PKI revocations,
clodia-logic #491) and re-sends one whose answer it did not see. A lost
response is not a lost event: the gateway may have recorded it. Such an event
carries its own `event_id` (a uuid minted by the agent-server), and the gateway
admits each id once.

The ids admitted are kept in a bounded window — the last `MAX_IDS`, and none
older than `MAX_AGE_S` — persisted next to the store (`ingest-ids.jsonl`, in the
gateway state dir the agent-server does not mount), so a restart of the gateway
does not re-admit a replay. The window is a bound on how late a replay can
arrive, not on how long evidence lives: the events themselves are in the chain.
"""
from __future__ import annotations

import json
import re
import threading
import time
from collections import OrderedDict
from pathlib import Path

MAX_IDS = 10_000
MAX_AGE_S = 7 * 86400
FILE = "ingest-ids.jsonl"

_UUID = re.compile(r"^[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$")


def normalize(event_id) -> str | None:
    """The id as it is compared (lower hex, no dashes), or None if not a uuid."""
    if not isinstance(event_id, str):
        return None
    v = event_id.strip().lower()
    return v.replace("-", "") if _UUID.match(v) else None


class Window:
    """Ids admitted recently, with the event id the gateway recorded for each."""

    def __init__(self, path: Path, max_ids: int = MAX_IDS, max_age_s: float = MAX_AGE_S):
        self.path, self.max_ids, self.max_age_s = path, max_ids, max_age_s
        self._ids: "OrderedDict[str, tuple[float, str | None]]" = OrderedDict()
        self._lock = threading.Lock()
        self._lines = 0
        self._load()

    def _load(self) -> None:
        try:
            raw = self.path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return
        for line in raw:
            try:
                row = json.loads(line)
                self._ids[row["id"]] = (float(row["at"]), row.get("event_id"))
                self._ids.move_to_end(row["id"])
            except (ValueError, KeyError, TypeError):
                continue
        self._lines = len(raw)
        self._trim(time.time())

    def _trim(self, now: float) -> None:
        while self._ids:
            k, (at, _) = next(iter(self._ids.items()))
            if len(self._ids) > self.max_ids or now - at > self.max_age_s:
                self._ids.pop(k)
            else:
                break

    def _persist(self, key: str, at: float, recorded: str | None) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self._lines >= 2 * self.max_ids:
            # Compact: rewrite the window, atomically.
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text("".join(json.dumps({"id": k, "at": a, "event_id": e}) + "\n"
                                   for k, (a, e) in self._ids.items()), encoding="utf-8")
            tmp.replace(self.path)
            self._lines = len(self._ids)
            return
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"id": key, "at": at, "event_id": recorded}) + "\n")
        self._lines += 1

    def seen(self, event_id) -> tuple[bool, str | None]:
        """Whether `event_id` was admitted already, and the event it became."""
        key = normalize(event_id)
        if key is None:
            return False, None
        with self._lock:
            self._trim(time.time())
            hit = self._ids.get(key)
            return (True, hit[1]) if hit else (False, None)

    def admit(self, event_id: str, record) -> tuple[bool, dict | None, str | None]:
        """Run `record()` unless `event_id` was admitted already.

        Returns `(duplicate, record_result, recorded_event_id)`. Check, record
        and remember happen under one lock: two copies of the same event sent
        at once cannot both pass."""
        key = normalize(event_id)
        if key is None:
            rec = record()
            return False, rec, (rec or {}).get("event_id")
        with self._lock:
            now = time.time()
            self._trim(now)
            if key in self._ids:
                return True, None, self._ids[key][1]
            rec = record()
            if rec is None:
                return False, None, None   # not recorded: a re-send must be admitted
            recorded = rec.get("event_id")
            self._ids[key] = (now, recorded)
            self._trim(now)
            try:
                self._persist(key, now, recorded)
            except OSError:
                pass  # the id is still held in memory; the event is in the chain
            return False, rec, recorded


_window: Window | None = None
_window_path: Path | None = None
_wlock = threading.Lock()


def window() -> Window:
    """The process-wide window, next to the store (re-created if it moves: tests)."""
    global _window, _window_path
    from .. import audit
    path = audit.root_dir() / FILE
    with _wlock:
        if _window is None or _window_path != path:
            _window, _window_path = Window(path), path
        return _window

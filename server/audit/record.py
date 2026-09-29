"""The canonical audit event (clodia-platform#425 §1.3).

One record shape for every event the gateway certifies. The trail holds
METADATA and HASHES only: content (prompts, message text, file bytes, tool
payloads) lives in the evidence store and is referenced by hash (#425 §2.3).
`build()` refuses a record that carries content under a well-known key, so a
caller cannot leak it into the trail by accident.

Hashing is over a canonical JSON serialisation (sorted keys, no whitespace,
UTF-8), with `integrity.hash` and `integrity.signature` removed: the hash
covers everything else, including `integrity.seq` and `integrity.previous_hash`,
which is what chains one event to the one before.
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any

SCHEMA = "clodia.audit/1"

#: Top-level sections of the canonical record, in the order of #425 §1.3.
SECTIONS = ("scope", "actor", "agent", "model", "event", "input", "decision",
            "authorization", "tool", "result", "provenance", "security")

#: Keys that name CONTENT, not metadata. A record carrying one of them (at any
#: depth) is rejected: the trail must be safe to hand to an auditor who is not
#: cleared for the data it describes.
CONTENT_KEYS = frozenset({
    "text", "content", "body", "prompt", "prompts", "message", "messages",
    "arguments", "args", "payload", "response_text", "output", "password",
    "secret", "secrets", "token", "bearer", "api_key", "private_key",
})

_TYPE_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$")
_ZERO_HASH = "0" * 64
GENESIS = _ZERO_HASH


class RecordError(ValueError):
    """The record does not satisfy the canonical shape."""


def now_iso() -> str:
    """UTC, millisecond precision, `Z` suffix — one format for every event."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def content_hash(data: bytes | str) -> str:
    """`sha256:<hex>` of the content, the only form content takes in the trail."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _reject_content(obj: Any, path: str = "") -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in CONTENT_KEYS:
                raise RecordError(f"content key '{path}{k}' in an audit record: "
                                  "record its hash instead")
            _reject_content(v, f"{path}{k}.")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _reject_content(v, f"{path}{i}.")


def _prune(obj: Any) -> Any:
    """Drop None and empty containers, so absent fields are absent, not null."""
    if isinstance(obj, dict):
        out = {k: _prune(v) for k, v in obj.items()}
        return {k: v for k, v in out.items() if v is not None and v != {} and v != []}
    if isinstance(obj, list):
        return [_prune(v) for v in obj]
    return obj


def build(event_type: str, *, action: str | None = None, resource: str | None = None,
          trace_id: str | None = None, span_id: str | None = None,
          parent_span_id: str | None = None, links: list | None = None,
          timestamp: str | None = None, **sections: dict | None) -> dict:
    """A canonical event, without `integrity` (the store adds it on append).

    `sections` are the blocks of #425 §1.3 (`scope=`, `actor=`, `tool=` …).
    `event.type/action/resource` come from the positional arguments so that
    every record has a type, and it is well formed.
    """
    if not _TYPE_RE.match(event_type or ""):
        raise RecordError(f"event type {event_type!r} is not 'family.name'")
    unknown = set(sections) - set(SECTIONS)
    if unknown:
        raise RecordError(f"unknown section(s): {sorted(unknown)}")
    if "event" in sections:
        raise RecordError("'event' is built from event_type/action/resource")
    rec: dict = {
        "schema": SCHEMA,
        "event_id": uuid.uuid4().hex,
        "trace_id": trace_id,
        "span_id": span_id,
        "parent_span_id": parent_span_id,
        "links": links,
        "timestamp": timestamp or now_iso(),
        "event": {"type": event_type, "action": action, "resource": resource},
    }
    for name in SECTIONS:
        if name in sections and sections[name] is not None:
            rec[name] = sections[name]
    _reject_content(rec)
    return _prune(rec)


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def event_hash(rec: dict) -> str:
    """Hex sha256 of the record without `integrity.hash` / `integrity.signature`."""
    integ = dict(rec.get("integrity") or {})
    integ.pop("hash", None)
    integ.pop("signature", None)
    body = dict(rec)
    body["integrity"] = integ
    return hashlib.sha256(canonical_json(body)).hexdigest()

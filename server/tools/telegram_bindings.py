"""Binding Telegram: `messaggero-#N ↔ chat_id` (modello telegram-proxy corretto).

Il legame vive sull'ISTANZA del messaggero, NON nel meta del topic (che
resusciterebbe il vecchio accoppiamento topic↔chat del mirror). Un file unico
nel datadir condiviso gateway↔backend:

    <CLODIA_DATA>/telegram-bindings.json
    { "<chat_id>": { "instance": "messaggero-1", "tier": "SEAL-1", "topic": "hedge-iot-new" } }

Invariante: una chat → un solo binding (un solo istanza/topic). Il gateway lo
scrive (verbi telegram.listen/unlisten); il relay del backend lo legge.
"""
from __future__ import annotations

import json
import os
from pathlib import Path


def _path() -> Path:
    base = os.environ.get("CLODIA_DATA", "/datadir")
    return Path(base) / "telegram-bindings.json"


def load() -> dict:
    p = _path()
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except (OSError, json.JSONDecodeError):
        return {}


def _save(d: dict) -> None:
    p = _path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(p)


def get(chat_id: str) -> dict | None:
    return load().get(str(chat_id))


def set_binding(chat_id: str, instance: str, tier: str, topic: str) -> dict:
    d = load()
    d[str(chat_id)] = {"instance": instance, "tier": tier, "topic": topic}
    _save(d)
    return d[str(chat_id)]


def remove(chat_id: str) -> bool:
    d = load()
    if str(chat_id) in d:
        del d[str(chat_id)]
        _save(d)
        return True
    return False

"""Profilo d'istanza (Modular Distro, F1b) — lettore gateway di `profile.yaml`.

Stesso file letto dall'agent-server (`CLODIA_DATA/profile.yaml`, vedi spec nel
topic clodia-modular-distro v0.2). Qui il gateway applica le feature che
vivono dal suo lato del confine:

- `rag: off|single|full`  — off = verbi rag.*/eu_corpus.* non esposti né
  invocabili; single = una SOLA collection ammessa (quella del profilo);
  full = multi-collection come oggi.
- `integrations: off|fixed|full` — off = nessun mount di MCP esterni;
  fixed = whitelist chiusa (`integrations.allowed`); full = self-service.
- `topics: single` — creazione topic limitata al workspace unico (i DM
  restano permessi: sono la webchat, non topic di lavoro).

Regole: file assente = FULL; file invalido = fallback FULL con warning
prominente (availability-first, rischio documentato in spec). Loader
dependency-light (yaml + dict), cache di modulo con `force` per i test.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Optional

import yaml

LOG = logging.getLogger("clodia-tools.instance_profile")

PROFILE_FILENAME = "profile.yaml"

_FEATURE_DEFAULTS: dict[str, Any] = {
    "jobs": True,
    "topics": "full",
    "rag": "full",
    "integrations": "full",
    "channels": True,
    "packs_ui": True,
    "providers_ui": True,
    "activity": True,
    "pwa": True,
    "helpdesk": True,
    "kanban": False,
    "colony": False,
}
_TRISTATE = {"topics": ("off", "single", "full"),
             "rag": ("off", "single", "full"),
             "integrations": ("off", "fixed", "full")}

_CACHE: Optional[dict] = None


def _profile_path() -> Path:
    # Lazy: risolta a ogni load, così i test possono cambiare CLODIA_DATA.
    return Path(os.environ.get("CLODIA_DATA", "/datadir")) / PROFILE_FILENAME


def _full() -> dict:
    return {
        "edition": "full",
        "features": dict(_FEATURE_DEFAULTS),
        "rag": {"collection": ""},
        "integrations": {"allowed": []},
        "topics_single": {"name": "workspace", "tier": "SEAL-1"},
    }


def load(force: bool = False) -> dict:
    """Profilo normalizzato (cache di modulo; `force=True` per rileggere)."""
    global _CACHE
    if _CACHE is not None and not force:
        return _CACHE
    path = _profile_path()
    prof = _full()
    if path.is_file():
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if not isinstance(raw, dict):
                raise ValueError("profile.yaml deve essere un mapping")
            feats = raw.get("features") or {}
            if not isinstance(feats, dict):
                raise ValueError("'features' deve essere un mapping")
            for key, val in feats.items():
                if key not in _FEATURE_DEFAULTS:
                    # Chiave che questo lettore non conosce (schema del profilo
                    # condiviso con l'agent-server, che può essere più nuovo):
                    # NON è un errore — ignora con warning. Un fallback FULL
                    # qui spegnerebbe TUTTO il gating per una chiave altrui
                    # (successo con features.pwa, 6 lug).
                    LOG.warning("profile.yaml: feature '%s' ignorata (non gestita dal gateway)", key)
                    continue
                if key in _TRISTATE:
                    # Gotcha YAML 1.1: `off` non quotato = booleano False.
                    if isinstance(val, bool):
                        val = "full" if val else "off"
                    if val not in _TRISTATE[key]:
                        raise ValueError(f"features.{key}: valore '{val}' non valido")
                else:
                    val = bool(val)
                prof["features"][key] = val
            prof["edition"] = str(raw.get("edition") or "full")
            for section in ("rag", "integrations", "topics_single"):
                sec = raw.get(section)
                if isinstance(sec, dict):
                    prof[section].update(sec)
            LOG.info("profilo istanza '%s' caricato da %s", prof["edition"], path)
        except Exception as e:  # noqa: BLE001
            LOG.error(
                "⚠️  profile.yaml INVALIDO (%s): fallback al profilo FULL — "
                "tutte le feature attive. Correggere il file e riavviare.", e)
            prof = _full()
    _CACHE = prof
    return prof


# ── helper per i punti di enforcement ────────────────────────────────────────

def rag_mode() -> str:
    return load()["features"]["rag"]


def rag_enabled() -> bool:
    return rag_mode() != "off"


def rag_check_collection(collection: str) -> None:
    """Vincolo strutturale del profilo (vale anche per i super-agent):
    off → nessun accesso; single → solo la collection del profilo."""
    mode = rag_mode()
    if mode == "off":
        raise PermissionError("feature 'rag' disabilitata dal profilo dell'istanza")
    if mode == "single":
        allowed = str(load()["rag"].get("collection") or "")
        if collection != allowed:
            raise PermissionError(
                f"profilo rag:single — unica collection ammessa: '{allowed}'")


def integrations_mode() -> str:
    return load()["features"]["integrations"]


def integrations_check(slug: str) -> None:
    """Guard per il mount di MCP esterni (register_mcp / github_connect).

    In mode fixed, `integrations.allow_manual_mcp: true` (decisione di
    terraformazione, spec v0.3 §4b.4) consente all'admin il paste manuale di
    MCP fuori whitelist dalla UI."""
    mode = integrations_mode()
    if mode == "off":
        raise PermissionError(
            "feature 'integrations' disabilitata dal profilo dell'istanza")
    if mode == "fixed":
        conf = load()["integrations"]
        if bool(conf.get("allow_manual_mcp")):
            return
        allowed = [str(s) for s in conf.get("allowed") or []]
        if slug not in allowed:
            raise PermissionError(
                f"profilo integrations:fixed — MCP ammessi: {allowed or 'nessuno'}")


def connectors_allowed() -> list[str] | None:
    """Connettori NATIVI dell'edizione (gmail, mailboxes, trello, …).
    None = tutti (storico); lista = solo quelli (terraformazione, gap-1
    edizione acme-min, 6 lug)."""
    conf = load()["integrations"]
    val = conf.get("connectors")
    if val is None:
        return None
    return [str(x) for x in (val or [])]


def connector_check(cid: str) -> None:
    allowed = connectors_allowed()
    if allowed is not None and cid not in allowed:
        raise PermissionError(
            f"connettore '{cid}' non previsto dall'edizione (connectors: {allowed})")


def topics_mode() -> str:
    return load()["features"]["topics"]


def topics_single_conf() -> dict:
    return dict(load()["topics_single"])


def topic_creation_check(name: str) -> None:
    """Guard su topic.new / POST /internal/topics quando topics: single.

    I DM (`dm-*`) restano permessi: sono la webchat coi singoli agenti, non
    topic di lavoro."""
    if topics_mode() != "single":
        return
    ws = str(topics_single_conf().get("name") or "workspace")
    if name == ws or str(name).startswith("dm-"):
        return
    raise PermissionError(
        f"profilo topics:single — unico topic di lavoro ammesso: '{ws}'")

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
- `connectors: {<id>: native|pack}` — RETIRED (clodia-platform#526): the
  connectors of the epic #527 are always served by their first-party pack.
  The key is still read so that an old profile keeps loading; a `native`
  value is ignored with one boot warning (`retired_connector_switch`).

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

#: The value the retired switch used to accept for "the gateway implements
#: it" (clodia-platform#522–#526). Nothing implements it any more: a profile
#: still saying so is reported once (`retired_connector_switch`) and ignored.
RETIRED_CONNECTOR_MODE = "native"

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
        "topics_defaults": {},
        "connectors": {},
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
            for section in ("rag", "integrations", "topics_single",
                            "topics_defaults", "connectors"):
                sec = raw.get(section)
                if isinstance(sec, dict):
                    prof[section].update(sec)
            if prof["connectors"]:
                # The switch is retired (#526): every connector it named is
                # pack-served. Kept, never validated — an old profile must
                # keep loading, and an invalid value here would throw the
                # WHOLE profile back to FULL over a key that decides nothing.
                LOG.info("profile.yaml: `connectors:` is retired (#526) and "
                         "ignored: %s", sorted(map(str, prof["connectors"])))
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
    """The connectors of the edition (`integrations.connectors`, written by
    clodia-build: `[mailboxes]`, `[]`, …), as written. None = all (the
    historical default). Read through `connector_allowed`, never compared
    directly: the names written there are not all registry ids."""
    conf = load()["integrations"]
    val = conf.get("connectors")
    if val is None:
        return None
    return [str(x) for x in (val or [])]


#: Names an edition profile may use for a connector, mapped to the registry id
#: (clodia-platform#526). `integrations.connectors` predates the registry and
#: speaks the ids of the Tools card snapshot: `mailboxes` is the `mail`
#: connector, and its topic button `mailbox-link`.
CONNECTOR_ALIASES: dict[str, str] = {
    "mailboxes": "mail",
    "gmail": "mail-gmail",
    "gworkspace": "google",
    "openai": "openai-images",
}


def canonical_connector(cid: str) -> str:
    """The registry id behind a profile or snapshot name (`CONNECTOR_ALIASES`)."""
    return CONNECTOR_ALIASES.get(str(cid), str(cid))


def connector_allowed(cid: str) -> bool:
    """Does the edition admit connector `cid` (a registry id or an alias)?

    The ONE decision behind every surface of a connector (#526): the Tools
    snapshot, the registry listing, the connect route, topic actions and the
    routes of the pack's gateway component. Never filtered: the schema-only
    builtins (`core`, `datastore`), whose schemes every whitelist is written
    in. A family member is admitted with its head (`builtin.CONNECTOR_FAMILY`:
    `google` admits google-sheets/docs/calendar and `mail-gmail`).
    """
    allowed = connectors_allowed()
    if allowed is None:
        return True
    from .connectors import builtin as _builtin
    cid = canonical_connector(cid)
    if cid in _builtin.SCHEMA_ONLY_CONNECTORS:
        return True
    names = {canonical_connector(a) for a in allowed}
    return cid in names or _builtin.CONNECTOR_FAMILY.get(cid) in names


def retired_connector_switch() -> list[str]:
    """The connector ids the profile still puts on `native`, sorted.

    The switch of clodia-platform#522 is retired (#526): those connectors have
    no native implementation and are served by their pack whatever the profile
    says. Read for the ONE boot warning that says so; never an exception.
    """
    try:
        conf = load().get("connectors") or {}
    except Exception:  # noqa: BLE001
        return []
    if not isinstance(conf, dict):
        return []
    return sorted(str(cid) for cid, mode in conf.items()
                  if str(mode) == RETIRED_CONNECTOR_MODE)


def connector_check(cid: str) -> None:
    """`connector_allowed` as a `PermissionError`."""
    if not connector_allowed(cid):
        raise PermissionError(
            f"connettore '{cid}' non previsto dall'edizione "
            f"(connectors: {connectors_allowed()})")


def topic_default_participants() -> list[str]:
    """Partecipanti di default dei topic APPENA creati (terraformazione).
    Chiave profilo: topics_defaults.participants — default [clodia, segretario]
    (il segretario verbalizza/mantiene lo stato di ogni topic sin dalla nascita)."""
    conf = load().get("topics_defaults") or {}
    val = conf.get("participants")
    if val is None:
        return ["clodia", "segretario"]
    return [str(x) for x in (val or [])]


def topic_default_contact_agent() -> str:
    """Contact agent di default dei topic nuovi (terraformazione).
    Chiave profilo: topics_defaults.contact_agent — default clodia."""
    conf = load().get("topics_defaults") or {}
    return str(conf.get("contact_agent") or "clodia")


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

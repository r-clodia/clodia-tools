"""Datastore dichiarati dai pack installati — unica fonte di lettura.

`CLODIA_DATA/plugins/*/plugin.yaml` porta un campo `datastores:` (dichiarazione
curated del pack developer, propagata dall'import a partire da plugin.json/
pack.yaml — vedi clodia-logic `plugin_import.py::_sanitize_datastores`). Questo
modulo è il solo punto che lo percorre nel gateway: prima viveva duplicato
dentro `backup.py` (che lo usava per il perimetro di backup), ora serve anche
`_datastore_authorize` in `main.py` (the catalog entry the scope import is
checked against, clodia-platform#669: no seed allowlist). Una lettura sola,
due consumatori.
"""
from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path

DATADIR = os.environ.get("CLODIA_DATA", "/datadir")
LOG = logging.getLogger("clodia-tools.datastores")

#: The pseudo-pack of the datastores an admin creates from the Databases page
#: (clodia-platform#671): `platform/<name>`, file `CLODIA_DATA/datastores/<name>.db`.
#: A pack cannot take this name (`plugin_import` refuses it, and `declared`
#: below skips a pack folder called so).
PLATFORM = "platform"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


def platform_dir() -> Path:
    return Path(DATADIR) / "datastores"


def _platform_registry() -> Path:
    return platform_dir() / "registry.json"


def platform_registry() -> dict:
    """`{name: {purpose, pii, clearance, created_by, created_at}}`."""
    try:
        data = json.loads(_platform_registry().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        LOG.error("platform datastores: registry unreadable (%s)", type(e).__name__)
        return {}


def save_platform_registry(data: dict) -> None:
    p = _platform_registry()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True, ensure_ascii=False),
                   encoding="utf-8")
    tmp.replace(p)


def _platform_declared() -> list[dict]:
    out = []
    for name, meta in sorted(platform_registry().items()):
        if not NAME_RE.match(str(name)) or not isinstance(meta, dict):
            continue
        out.append({
            "pack": PLATFORM, "name": name, "path": f"{name}.db",
            "abs_path": str((platform_dir() / f"{name}.db").resolve()),
            "purpose": str(meta.get("purpose") or ""), "pii": bool(meta.get("pii", False)),
            "backup": True, "clearance": str(meta.get("clearance") or "SEAL-4"),
            "seeds": [],
        })
    return out


def _tombstoned_keys() -> set[str]:
    try:
        from . import data_catalog
        return {k.split(":", 1)[1] for k in data_catalog.tombstones()
                if k.startswith("datastore:")}
    except Exception:  # noqa: BLE001 — no tombstones readable, none applied
        return set()


def declared() -> list[dict]:
    """Ogni entry: `{pack, name, path, abs_path, purpose, pii, backup,
    clearance}`. `path` è relativo alla cartella del pack; `abs_path` è già
    risolto sotto `CLODIA_DATA/plugins/<pack>/`. `clearance` mancante nel
    manifest → `SEAL-4`, fail-closed. A `seeds:` list in an older manifest is
    ignored (clodia-platform#669)."""
    import yaml

    found: list[dict] = []
    for manifest in sorted(Path(DATADIR).glob("plugins/*/plugin.yaml")):
        try:
            meta = yaml.safe_load(manifest.read_text()) or {}
        except Exception:
            continue
        if not isinstance(meta, dict):
            continue
        pack = manifest.parent.name
        if pack == PLATFORM:
            continue
        for ds in meta.get("datastores") or []:
            if not isinstance(ds, dict) or not ds.get("path"):
                continue
            rel = str(ds["path"])
            name = str(ds.get("name") or Path(rel).stem)
            found.append({
                "pack": pack,
                "name": name,
                "path": rel,
                "abs_path": str((manifest.parent / rel).resolve()),
                "purpose": str(ds.get("purpose") or ""),
                "pii": bool(ds.get("pii", False)),
                "backup": bool(ds.get("backup", True)),
                "clearance": str(ds.get("clearance") or "SEAL-4"),
            })
    # The datastores created from the Databases page, then the tombstones:
    # a datastore deleted on purpose is not declared any more, even if its
    # pack still names it (#671).
    found += _platform_declared()
    dead = _tombstoned_keys()
    return [ds for ds in found if f"{ds['pack']}/{ds['name']}" not in dead]


def declared_collections() -> dict[str, dict]:
    """RAG collections declared by the installed packs (`rag_collections:` in
    `plugins/*/plugin.yaml`): `{name: {pack, tier}}`. `tier` is the declared
    level, `None` when missing or not a SEAL level — never a default. The pack
    provisioner may create and feed only these (clodia-platform#669: the
    exception is for initial provisioning). A manifest that does not parse
    declares nothing; for one name declared twice the first pack in
    alphabetical order wins (collection names are global in the RAG service)."""
    import yaml

    found: dict[str, dict] = {}
    for manifest in sorted(Path(DATADIR).glob("plugins/*/plugin.yaml")):
        try:
            meta = yaml.safe_load(manifest.read_text()) or {}
        except Exception:
            continue
        if not isinstance(meta, dict):
            continue
        for col in meta.get("rag_collections") or []:
            if not isinstance(col, dict):
                continue
            name = str(col.get("name") or "").strip()
            if not name or name in found:
                continue
            raw = str(col.get("tier") or "").strip().upper()
            raw = {"P0": "SEAL-0", "P1": "SEAL-1", "P2": "SEAL-2", "P3": "SEAL-3"}.get(raw, raw)
            tier = raw if raw in ("SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4") else None
            found[name] = {"pack": manifest.parent.name, "tier": tier}
    return found


def find(pack: str, name: str) -> dict | None:
    """Un'entry per `<pack>/<name>` esatti, o `None`."""
    for ds in declared():
        if ds["pack"] == pack and ds["name"] == name:
            return ds
    return None


def parse_key(key: str) -> tuple[str, str]:
    """`"<pack>/<name>"` → `(pack, name)`. Stessa forma delle chiavi di scope
    egress/topic (`<tier>/<name>`), per coerenza col resto del gateway."""
    s = (key or "").strip()
    if "/" not in s:
        raise ValueError(
            f"datastore non valido: '{key}' — atteso '<pack>/<nome>' "
            f"(es. 'base-pack/contacts')")
    pack, name = s.split("/", 1)
    if not pack or not name:
        raise ValueError(f"datastore non valido: '{key}'")
    return pack, name

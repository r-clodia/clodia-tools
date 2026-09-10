"""Datastore dichiarati dai pack installati — unica fonte di lettura.

`CLODIA_DATA/plugins/*/plugin.yaml` porta un campo `datastores:` (dichiarazione
curated del pack developer, propagata dall'import a partire da plugin.json/
pack.yaml — vedi clodia-logic `plugin_import.py::_sanitize_datastores`). Questo
modulo è il solo punto che lo percorre nel gateway: prima viveva duplicato
dentro `backup.py` (che lo usava per il perimetro di backup), ora serve anche
`_datastore_authorize` in `main.py` (clearance + seed allowlist sui verbi
`datastore.read`/`datastore.write`). Una lettura sola, due consumatori.
"""
from __future__ import annotations

import os
from pathlib import Path

DATADIR = os.environ.get("CLODIA_DATA", "/datadir")


def declared() -> list[dict]:
    """Ogni entry: `{pack, name, path, abs_path, purpose, pii, backup,
    clearance, seeds}`. `path` è relativo alla cartella del pack; `abs_path`
    è già risolto sotto `CLODIA_DATA/plugins/<pack>/`. `clearance`/`seeds`
    mancanti nel manifest → più restrittivo possibile (`SEAL-4`, nessun seed):
    un datastore dichiarato prima che questi campi esistessero non concede
    nulla finché qualcuno non li scrive esplicitamente — fail-closed, non un
    default permissivo silenzioso."""
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
        for ds in meta.get("datastores") or []:
            if not isinstance(ds, dict) or not ds.get("path"):
                continue
            rel = str(ds["path"])
            name = str(ds.get("name") or Path(rel).stem)
            seeds = ds.get("seeds")
            found.append({
                "pack": pack,
                "name": name,
                "path": rel,
                "abs_path": str((manifest.parent / rel).resolve()),
                "purpose": str(ds.get("purpose") or ""),
                "pii": bool(ds.get("pii", False)),
                "backup": bool(ds.get("backup", True)),
                "clearance": str(ds.get("clearance") or "SEAL-4"),
                "seeds": list(seeds) if isinstance(seeds, list) else [],
            })
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

"""Collection RAG dichiarate dai pack installati — unica fonte di lettura.

Fratello di `server/datastores.py`, e per la stessa ragione: `CLODIA_DATA/
plugins/*/plugin.yaml` porta un campo `rag_collections:` (dichiarazione curated
del pack developer, sanificata all'import da clodia-logic
`plugin_import.py::_sanitize_rag_collections`), e il gateway deve poterlo
leggere in un punto solo. Qui serve a `_rag_authorize` in `main.py`, che fino a
`clodia-platform#343` conosceva solo due assi: il tier della collection e i
grant `rag_read`/`rag_write` del seed. Il primo è un livello, i secondi stanno
scritti sul seed: nessuno dei due permetteva a una collection di dire di sé
«questi seed, e nessun altro».

`seeds` è `None` quando il manifest NON si pronuncia, ed è la distinzione che
regge tutto il comportamento a valle: dichiarato = vincolante (restringe: serve
la membership IN PIÙ al grant), non dichiarato = regime dei soli grant. Negare
in assenza — la lettura letterale del criterio 2 di #343 — avrebbe spento il
RAG di ogni agente al deploy, perché oggi nessun manifest dichiara il campo e
ogni collection viva si raggiunge per grant. Una dichiarazione qui può solo
togliere accesso, mai darne.
"""
from __future__ import annotations

import os
from pathlib import Path

DATADIR = os.environ.get("CLODIA_DATA", "/datadir")


def declared() -> list[dict]:
    """Ogni entry: `{pack, name, tier, seeds}`.

    `seeds` = lista di nomi seed, oppure `None` se il manifest non dichiara il
    campo (o lo dichiara malformato: una stringa, una lista di soli spazi). Una
    lista vuota collassa su `None` per coerenza col sanitizer a monte, che
    scarta `seeds: []` invece di persisterlo — un `[]` lasciato passare si
    leggerebbe «nessuno è autorizzato», che nessun pack ha mai voluto dire
    scrivendolo.

    `tier` resta quello dichiarato (default `SEAL-0`, come in clodia-logic): qui
    NON si irrigidisce a `SEAL-4` come fa `datastores.declared()` per un
    `clearance` mancante, perché il tier autorevole di una collection lo tiene
    il servizio RAG (`eu_corpus.collection_tier`) ed è quello che il gate usa.
    Questo campo è informativo.
    """
    import yaml

    found: list[dict] = []
    for manifest in sorted(Path(DATADIR).glob("plugins/*/plugin.yaml")):
        try:
            meta = yaml.safe_load(manifest.read_text()) or {}
        except Exception:
            # Un manifest illeggibile NON è «nessun membro dichiarato» detto
            # con più enfasi: è una collection che semplicemente non compare, e
            # il gate resta al regime dei grant. Alzare qui farebbe dipendere
            # l'accesso a `eu-normativa` dalla sintassi dello yaml di un pack
            # che non c'entra.
            continue
        if not isinstance(meta, dict):
            continue
        pack = manifest.parent.name
        for col in meta.get("rag_collections") or []:
            if not isinstance(col, dict):
                continue
            name = str(col.get("name") or "").strip()
            if not name:
                continue
            raw_seeds = col.get("seeds")
            seeds = None
            if isinstance(raw_seeds, list):
                clean = [str(s).strip() for s in raw_seeds if str(s).strip()]
                seeds = clean or None
            found.append({
                "pack": pack,
                "name": name,
                "tier": str(col.get("tier") or "SEAL-0"),
                "seeds": seeds,
            })
    return found


def find(name: str) -> dict | None:
    """L'entry dichiarata per la collection `name`, o `None` se nessun pack
    installato la dichiara (collection orfana, o creata a mano).

    SHORTCUT: se due pack dichiarano lo stesso nome vince il primo in ordine
              alfabetico di pack. Regge finché i nomi di collection sono unici
              — e lo sono per costruzione, perché il nome è la chiave globale
              in pgvector, quindi due dichiarazioni sono già un conflitto di
              provisioning. Se un giorno non lo fossero, la risposta giusta è
              l'INTERSEZIONE delle member list (la più restrittiva), non la
              prima trovata.
    """
    key = (name or "").strip()
    if not key:
        return None
    for col in declared():
        if col["name"] == key:
            return col
    return None

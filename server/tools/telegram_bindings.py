"""Binding Telegram: `messaggero-#N ↔ chat_id` (modello telegram-proxy corretto).

Il legame vive sull'ISTANZA del messaggero, NON nel meta del topic (che
resusciterebbe il vecchio accoppiamento topic↔chat del mirror).

**Dal 14 ott 2026 (clodia-platform#521) questo modulo non ha più un file suo**:
è la vista Telegram del registro generale dei binding di canale,
`channel_bindings` (`<CLODIA_DATA>/channel-bindings.json`, chiave connettore +
chat). Resta come facciata perché i suoi chiamanti — `telegram.listen/unlisten`,
`telegram.send_file`, la rotta `…/telegram-link`, la riclassificazione di un
topic, lo scollegamento su `ingress_remove` — parlano di Telegram e continueranno
a farlo finché #522 non porterà il connettore nel comms-pack. Un'unica riga di
traduzione qui vale meno di sette chiamanti riscritti due volte.

Invariante invariata: una chat → un solo binding (una sola istanza/topic). Il
gateway lo scrive; il relay del backend lo legge.
"""
from __future__ import annotations

from pathlib import Path

from . import channel_bindings as cb

#: Il connettore sotto cui vivono questi binding nel registro generale.
CONNECTOR = cb.LEGACY_CONNECTOR


def _path() -> Path:
    """Il file STORICO (`telegram-bindings.json`).

    Non è più dove si legge o si scrive: è la sorgente della migrazione one-shot
    e — attraverso la sua cartella — il modo in cui i test puntano l'intero
    registro a un datadir temporaneo, com'è sempre stato.
    """
    return cb._legacy_path()


def _base() -> Path:
    """La cartella del registro: quella di `_path()`, così chi patcha `_path`
    sposta insieme il file nuovo e quello vecchio da cui si migra."""
    return _path().parent


def load() -> dict:
    return cb.load(CONNECTOR, base=_base())


def _save(d: dict) -> None:
    """Scrittura in blocco dei soli binding Telegram (ripristino di `retier`)."""
    cb.replace(CONNECTOR, d, base=_base())


def get(chat_id: str) -> dict | None:
    return cb.get(CONNECTOR, chat_id, base=_base())


def get_for_topic(tier: str, topic: str) -> str | None:
    """L'inverso di `get`: il chat_id legato a QUESTO topic, o None.

    Un vincolo del modello (`set_binding`: una chat → un solo topic) rende
    la ricerca inequivocabile — al più un risultato. Serve a `telegram.send`
    per risolvere «manda un messaggio qui» senza che il chiamante debba
    conoscere/indovinare il chat_id o il titolo esatto del gruppo — la causa
    del 23 set 2026: due gruppi con nomi quasi identici ("Davide & Clodia" e
    "Davide & Clodia Colony Blogging") e nessun modo di dire "quello di
    questo topic" hanno prodotto ripetuti invii al gruppo sbagliato."""
    for cid, b in load().items():
        if (b.get("tier"), b.get("topic")) == (tier, topic):
            return cid
    return None


def set_binding(chat_id: str, instance: str, tier: str, topic: str) -> dict:
    return cb.set_binding(CONNECTOR, chat_id, instance, tier, topic, base=_base())


def remove(chat_id: str) -> bool:
    return cb.remove(CONNECTOR, chat_id, base=_base())

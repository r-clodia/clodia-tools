"""Il diritto di parlare in un canale arriva dal floor, non dal nome.

`topic.post_message` era riservato con un elenco di nomi — «messaggero e i
super-agent». Misurato su marte e venere, produceva due errori **opposti**:

    sysadmin     dichiara=True   passa_il_check=False   ⚠ dichiara e non può
    clodia       dichiara=False  passa_il_check=True    può senza dichiararlo
    ophelia      dichiara=False  passa_il_check=True    può senza dichiararlo

Cioè la dichiarazione non contava in nessuna delle due direzioni. Oggi
`topic.post_message` è nel floor dell'archseed: ogni agente può parlare nella
propria stanza e chi deve restare muto lo sottrae esplicitamente con
`denied_tools`. Il nome non decide in nessuno dei due versi.
"""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from . import main as m, whitelist as w

CFG = {"agents": {
    "sysadmin": {"allowed_tools": ["topic.post_message", "topic.open"]},
    "ordinario": {"allowed_tools": ["topic.open"]},
    "muto": {"allowed_tools": ["topic.open"],
             "denied_tools": ["topic.post_message"]},
    "postino": {"allowed_tools": ["topic.*"]},
}}


def _post_as(agent):
    """Ritorna il TESTO restituito dal dispatch.

    Non un'eccezione: `call_tool` cattura e RITORNA l'errore come contenuto —
    il primo harness cercava un raise e leggeva None su un rifiuto, cioè
    concludeva «autorizzato» proprio nel caso negato. Verificato guardando il
    valore di ritorno invece di assumerne la forma.
    """
    with patch.object(w, "CONFIG", CFG), \
            patch.object(w, "agent_name", lambda: agent), \
            patch.object(m, "agent_name", lambda: agent), \
            patch.object(m, "_unattended_denial", lambda _n: None), \
            patch.object(m.origin, "evaluate", return_value={"action": "allow"}), \
            patch.object(m, "_dispatch_topic", return_value={"posted": True}), \
            patch.object(m._taint, "note_verb"), \
            patch.object(m._tlm, "record"):
        out = asyncio.run(m.call_tool(
            "topic.post_message", {"tier": "SEAL-1", "name": "x", "text": "ciao"}))
    return out[0].text


def _refused(testo: str) -> bool:
    """Rifiuto di AUTORIZZAZIONE, distinto da un errore d'esecuzione.

    Serve perché in test l'esecuzione fallisce comunque (la datadir non è
    scrivibile): senza distinguere, «autorizzato ma esploso dopo» si leggerebbe
    come «negato», e il test passerebbe qualunque cosa faccia il controllo.
    """
    return testo.startswith("DENIED:") or "non in whitelist" in testo


class DeclarationDecidesTests(unittest.TestCase):
    def test_an_agent_that_declares_it_may_speak(self):
        """Il difetto misurato: sysadmin lo dichiarava e veniva rifiutato."""
        t = _post_as("sysadmin")
        self.assertFalse(_refused(t), f"sysadmin dichiara il verbo e resta muto: {t}")

    def test_a_wildcard_declaration_also_counts(self):
        self.assertFalse(_refused(_post_as("postino")))

    def test_an_ordinary_agent_inherits_the_right_to_speak(self):
        self.assertFalse(_refused(_post_as("ordinario")))

    def test_an_agent_explicitly_denied_is_refused(self):
        """Omettere non sottrae il floor: il silenzio deve essere dichiarato.

        È la ragione per cui il controllo sul nome è stato rimosso e non
        riscritto: la regola esiste già in un posto, e una seconda copia
        divergerebbe. Il primo tentativo di fix aggiungeva quella copia — questo
        test l'ha reso evidente perché il ramo nuovo era irraggiungibile.
        """
        t = _post_as("muto")
        self.assertTrue(_refused(t), "un agente col deny non deve poter postare")
        self.assertIn("escluso deliberatamente", t)

    def test_the_refusal_does_not_name_who_is_allowed(self):
        """Un rifiuto che elenca i nomi ammessi invita a chiedere a uno di loro —
        cioè a delegare — invece di dichiarare il verbo."""
        t = _post_as("muto")
        self.assertNotIn("messaggero", t)

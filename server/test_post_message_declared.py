"""Il diritto di parlare in un canale si DICHIARA, non si eredita dal nome.

`topic.post_message` era riservato con un elenco di nomi — «messaggero e i
super-agent». Misurato su marte e venere, produceva due errori **opposti**:

    sysadmin     dichiara=True   passa_il_check=False   ⚠ dichiara e non può
    clodia       dichiara=False  passa_il_check=True    può senza dichiararlo
    ophelia      dichiara=False  passa_il_check=True    può senza dichiararlo

Cioè la dichiarazione non contava in nessuna delle due direzioni. Un controllo
per nome va anche tenuto aggiornato a mano ogni volta che nasce un agente che
deve rispondere in chat, e nessuno se ne ricorda: `sysadmin` è entrato nei canali
con la modalità debug e il suo diritto di parlare è rimasto indietro.
"""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from . import main as m, whitelist as w

CFG = {"agents": {
    "sysadmin": {"allowed_tools": ["topic.post_message", "topic.open"]},
    "muto": {"allowed_tools": ["topic.open"]},
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
            patch.object(m, "agent_name", lambda: agent):
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

    def test_an_agent_that_does_not_declare_it_is_refused_by_the_whitelist(self):
        """E lo rifiuta il DISPATCH, non un secondo controllo nel verbo.

        È la ragione per cui il controllo sul nome è stato rimosso e non
        riscritto: la regola esiste già in un posto, e una seconda copia
        divergerebbe. Il primo tentativo di fix aggiungeva quella copia — questo
        test l'ha reso evidente perché il ramo nuovo era irraggiungibile.
        """
        t = _post_as("muto")
        self.assertTrue(_refused(t), "un agente senza il verbo non deve poter postare")
        self.assertIn("whitelist", t)

    def test_the_refusal_does_not_name_who_is_allowed(self):
        """Un rifiuto che elenca i nomi ammessi invita a chiedere a uno di loro —
        cioè a delegare — invece di dichiarare il verbo."""
        t = _post_as("muto")
        self.assertNotIn("messaggero", t)

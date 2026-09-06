"""Il verbo negato dentro un turno arriva al run record. Metà gateway di #206.

L'altra metà sta in `clodia-logic` (`scheduler/refusals.py`, che tiene il
registro e declassa il `success` dichiarato). Qui si misura la sola cosa che
questo repo può sbagliare: che un rifiuto DECISO dal gateway parta davvero
verso l'agent-server, con il nome del verbo e la classe del motivo, e che il
tentativo non peggiori mai il messaggio che l'agente riceve.

Il difetto che questi test presidiano è per costruzione silenzioso: se la nota
non parte non fallisce niente e non si rompe niente — semplicemente il run si
chiude verde su un lavoro che non è avvenuto. È esattamente la forma di
clodia-platform#206, ed è la ragione per cui il controllo dev'essere qui e non
in una verifica manuale.
"""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from . import main as M
from . import whitelist
from .tools import runtime


class _InTurno:
    """Una sessione agent con un `chat` firmato, come dentro un run schedulato."""

    def __init__(self, chat: str | None = "chat-42"):
        self.chat = chat

    def __enter__(self):
        self._tok = whitelist.set_current_chat(self.chat)
        return self

    def __exit__(self, *exc):
        whitelist.reset_current_chat(self._tok)
        return False


def _nega(verbo: str = "email.send", *, chat: str | None = "chat-42",
          esplode: bool = False):
    """Fa negare `verbo` dal dispatch e riferisce (testo, note partite).

    Il rifiuto scelto è quello della whitelist per-agente: è il primo controllo
    di `call_tool`, quindi il percorso è corto e il test non dipende da nessuno
    degli strati successivi.
    """
    note: list = []

    def _finto_post(*, chat_id, verb, why=""):
        note.append({"chat_id": chat_id, "verb": verb, "why": why})
        if esplode:
            raise RuntimeError("agent-server irraggiungibile")
        return {"ok": True}

    with _InTurno(chat), \
            patch.object(M, "agent_name", lambda: "avvocato"), \
            patch.object(M, "is_on_behalf", lambda: False), \
            patch.object(M, "_is_super", lambda _a: False), \
            patch.object(M, "_agent_tool_reachable", lambda *_a: False), \
            patch.object(M._tlm, "record"), \
            patch.object(runtime, "note_run_refusal", _finto_post):
        out = asyncio.run(M.call_tool(verbo, {}))
    return out[0].text, note


class IlRifiutoArrivaAlRunRecordTests(unittest.TestCase):
    """Rosso prima del fix: il dispatch negava e non lo diceva a nessuno."""

    def test_un_verbo_negato_parte_verso_l_agent_server(self):
        testo, note = _nega()
        self.assertIn("DENIED", testo)
        self.assertEqual(len(note), 1,
                         "il rifiuto è rimasto nella telemetria locale: il run "
                         "record non lo vedrà mai")

    def test_la_nota_NOMINA_il_verbo(self):
        """«l'agente non ha dichiarato l'esito» è vero e non azionabile;
        `email.send (whitelist)` lo è. Il nome è tutto il valore della nota."""
        _, note = _nega("email.send")
        self.assertEqual(note[0]["verb"], "email.send")

    def test_la_nota_porta_la_CLASSE_del_motivo_non_il_messaggio(self):
        """I messaggi di diniego contengono nomi di agente, di file e indirizzi.
        Il run record è storico che resta: deve dire perché, non chi e dove."""
        _, note = _nega()
        self.assertEqual(note[0]["why"], "whitelist")
        self.assertNotIn("avvocato", note[0]["why"])

    def test_il_chat_id_e_quello_della_sessione_non_un_argomento(self):
        _, note = _nega(chat="chat-notturna")
        self.assertEqual(note[0]["chat_id"], "chat-notturna")


class LaNotaNonPeggioraIlRifiutoTests(unittest.TestCase):
    """Sta su un percorso di errore: non può diventare essa stessa l'errore."""

    def test_un_agent_server_irraggiungibile_non_cambia_il_messaggio(self):
        """Se sollevasse, l'agente riceverebbe un `ERROR:` che non nomina più il
        permesso mancante — cioè si perderebbe la spiegazione proprio nel caso
        in cui serve per correggersi."""
        testo, note = _nega(esplode=True)
        self.assertEqual(len(note), 1, "la nota non è nemmeno stata tentata")
        self.assertIn("DENIED", testo)
        self.assertNotIn("ERROR", testo)
        self.assertNotIn("irraggiungibile", testo)

    def test_fuori_da_un_turno_non_si_annota_nulla(self):
        """Il registro di là è per turno. Un rifiuto senza `chat` non appartiene
        a nessun run, e annotarlo lo farebbe consumare dal primo run che passa."""
        _, note = _nega(chat=None)
        self.assertEqual(note, [])


class LaFormaDellaNotaTests(unittest.TestCase):
    """Il contratto con la rotta interna dell'agent-server."""

    def test_la_rotta_e_quella_interna(self):
        with patch.object(runtime, "_post", return_value={"ok": True}) as p:
            runtime.note_run_refusal(chat_id="c1", verb="email.send",
                                     why="denied_tools")
        self.assertEqual(p.call_args[0][0], "/clodia/jobs/refusal/internal")
        self.assertEqual(p.call_args[0][1], {
            "chat_id": "c1", "verb": "email.send", "why": "denied_tools"})

    def test_il_timeout_e_piu_stretto_di_quello_generale(self):
        """Chi attraversa questa riga sta già aspettando un `DENIED:`: un
        agent-server lento non deve aggiungere secondi a un verbo già negato."""
        with patch.object(runtime, "_post", return_value={"ok": True}) as p:
            runtime.note_run_refusal(chat_id="c1", verb="email.send")
        stretto = p.call_args[1]["timeout"]
        self.assertLess(stretto.read, runtime._TIMEOUT.read)
        self.assertLess(stretto.connect, runtime._TIMEOUT.connect)

    def test_il_ritorno_dice_se_la_nota_e_partita(self):
        with patch.object(runtime, "note_run_refusal", return_value={"ok": True}):
            with _InTurno():
                self.assertTrue(M._note_run_refusal("email.send", "whitelist"))
        with patch.object(runtime, "note_run_refusal",
                          side_effect=RuntimeError("giù")):
            with _InTurno():
                self.assertFalse(M._note_run_refusal("email.send", "whitelist"))


if __name__ == "__main__":
    unittest.main()

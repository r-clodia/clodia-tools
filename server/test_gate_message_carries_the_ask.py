"""Il messaggio del gate PORTA la richiesta, non un puntatore a essa.

Conteneva il solo marcatore `<!-- gate=agent|instance|verbo -->`, e tutto ciò che
si leggeva in chat — chi chiede, cosa, perché — veniva reso in diretta dalla coda
dei pending. Alla decisione la richiesta esce dalla coda, e in chat restava **un
riquadro vuoto**: il motivo per cui qualcuno aveva chiesto quella cosa spariva
nel momento esatto in cui diventava una decisione da ricordare.

Peggio dopo un ricarico della pagina: senza la coda e senza memoria locale, un
gate già deciso tornava a somigliare a uno aperto, con i bottoni.

La regola generale è che **la traccia durevole sta nel messaggio**, non in una
coda che si svuota per costruzione. Il marcatore resta per i bottoni finché la
richiesta è viva; il testo resta per sempre.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

import asyncio

from . import gate as G
from . import main as M


class _Svc:
    def __init__(self):
        self.posted = []

    def post_message(self, tier, name, author, text, kind="ai", **k):
        self.posted.append({"tier": tier, "name": name, "author": author,
                            "text": text, "kind": kind})
        return {"id": "m1"}


def _posta(gate_key="egress:email:mailto:hr@x.io", reason="rispondo all'offerta",
           agent="messaggero"):
    svc = _Svc()
    # Il gate è async e attende una decisione: qui interessa solo il MESSAGGIO
    # che viene postato prima dell'attesa, quindi la si interrompe subito.
    with patch.object(M, "_topics", lambda: svc), \
         patch.object(M, "current_chat", lambda: "chan:SEAL-2:acme:messaggero"), \
         patch.object(M, "current_principal", lambda: "davide"), \
         patch.object(M, "current_spawn", lambda: None, create=True), \
         patch.object(G, "active", lambda *a, **k: False), \
         patch.object(G, "request", lambda *a, **k: {"id": f"{agent}|-|{gate_key}"}), \
         patch.object(G, "delegation_for", lambda *a, **k: None, create=True):
        try:
            asyncio.run(asyncio.wait_for(
                M._require_gate_consent(agent, gate_key, consume=True,
                                        reason=reason), timeout=0.4))
        except Exception:  # noqa: BLE001 — oltre il post non interessa
            pass
    return svc.posted


class TheMessageSaysWhatWasAskedTests(unittest.TestCase):
    def test_it_names_who_and_what(self):
        p = _posta()
        self.assertTrue(p, "nessun messaggio postato nel canale")
        t = p[0]["text"]
        self.assertIn("messaggero", t)
        self.assertIn("egress:email:mailto:hr@x.io", t)

    def test_it_carries_the_reason(self):
        """Il pezzo che sparisce per primo e serve di più: PERCHÉ. Un
        «approvato» senza il motivo racconta che qualcuno ha premuto un bottone,
        non cosa ha concesso."""
        self.assertIn("rispondo all'offerta", _posta()[0]["text"])

    def test_without_a_reason_it_does_not_invent_one(self):
        t = _posta(reason="")[0]["text"]
        self.assertIn("messaggero", t)
        self.assertNotIn("—  ", t)      # nessun trattino orfano

    def test_the_marker_is_still_there_for_the_buttons(self):
        """Il testo è la traccia, il marcatore è il comando: toglierlo
        spegnerebbe i bottoni."""
        self.assertIn("<!-- gate=messaggero|-|egress:email:mailto:hr@x.io -->",
                      _posta()[0]["text"])

    def test_a_topic_access_gate_reads_as_a_topic(self):
        """`topic-access:SEAL-1/x` come verbo è un dettaglio interno: in chat si
        legge come «accedere al topic»."""
        t = _posta(gate_key="topic-access:SEAL-1/acme", reason="")[0]["text"]
        self.assertIn("accedere al topic SEAL-1/acme", t)
        self.assertNotIn("topic-access:", t.split("<!--")[0])

    def test_a_channel_gate_also_notifies_the_principal_outside_the_room(self):
        notified = []
        svc = _Svc()
        with patch.object(M, "_topics", lambda: svc), \
             patch.object(M, "current_chat", lambda: "chan:SEAL-2:acme:messaggero"), \
             patch.object(M, "current_principal", lambda: "davide"), \
             patch.object(G, "active", lambda *a, **k: False), \
             patch.object(G, "request", lambda *a, **k: {"id": "messaggero|-|github.issue_write"}), \
             patch.object(G, "request_pending", lambda *a, **k: True), \
             patch.object(G, "resolve_request", lambda *a, **k: None), \
             patch.object(M, "_gate_notify_principal",
                          lambda agent, key, principal: notified.append((agent, key, principal)) or True), \
             patch.dict("os.environ", {"GATE_WAIT_LOOPS": "0"}):
            with self.assertRaises(PermissionError):
                asyncio.run(M._require_gate_consent(
                    "messaggero", "github.issue_write", consume=True))
        self.assertEqual(notified, [("messaggero", "github.issue_write", "davide")])
        self.assertTrue(svc.posted, "la card nel canale resta presente")

    def test_a_channel_gate_times_out_with_a_gate_message_before_the_caller(self):
        with patch.object(M, "_topics", lambda: _Svc()), \
             patch.object(M, "current_chat", lambda: "chan:SEAL-2:acme:messaggero"), \
             patch.object(M, "current_principal", lambda: "davide"), \
             patch.object(G, "active", lambda *a, **k: False), \
             patch.object(G, "request", lambda *a, **k: {"id": "messaggero|-|github.issue_write"}), \
             patch.object(G, "request_pending", lambda *a, **k: True), \
             patch.object(G, "resolve_request", lambda *a, **k: None), \
             patch.object(M, "_gate_notify_principal", lambda *a, **k: True), \
             patch.dict("os.environ", {"GATE_WAIT_LOOPS": "0"}):
            with self.assertRaises(PermissionError) as ctx:
                asyncio.run(M._require_gate_consent(
                    "messaggero", "github.issue_write", consume=True))
        self.assertIn("gate: 'github.issue_write' non approvato entro il tempo limite",
                      str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

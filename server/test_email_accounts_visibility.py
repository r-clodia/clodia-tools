"""Un account che esiste ma non ti è concesso: si dice, non si tace.

Il difetto (clodia-platform#176): una casella aggiunta dalla UI risultava
«operativa» — ed era vero, la credenziale c'era e funzionava — ma l'agente non la
vedeva. `email.folders` elenca solo gli account che l'agente può materializzare
dal vault, quindi per lui la casella semplicemente non esisteva. Concludeva «non
c'è» e si fermava; un restart non cambiava niente, perché non c'era niente da
ricaricare.

È il difetto ricorrente «qualcosa di dichiarato che nessuno porta»: aggiungere
una credenziale e concederla a un agente sono due atti distinti, e il secondo non
lo compiva nessuno.

**La correzione non è concedere di più.** Concedere in automatico a tutti gli
agenti sarebbe consegnare una casella di posta a ogni seed dell'istanza — il
contrario del compartimento. La correzione è che l'assenza smetta di essere
ambigua: `accounts_not_granted` dice cosa esiste e non è tuo, così l'agente può
chiederlo invece di dedurre un nome sbagliato.

Chiamare l'account per nome, del resto, produceva già un rifiuto ottimo. Il buco
era l'ELENCO: chi non sa che una cosa esiste non può chiederla.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from .tools import email


DIAGNOSTICA = [
    {"credential": "google_devnullboxx", "account": "devnullboxx",
     "kind": "google", "operational": True, "missing": [], "error": None},
    {"credential": "mailbox_team", "account": "team",
     "kind": "mailbox", "operational": True, "missing": [], "error": None},
    {"credential": "mailbox_rotta", "account": "rotta",
     "kind": "mailbox", "operational": False, "missing": ["password"], "error": None},
]

GRANT = {
    "messaggero": ["google_devnullboxx"],
    "clodia": ["google_devnullboxx", "mailbox_team"],
    "nuovo": [],
}


class _Vault:
    @staticmethod
    def grants_for(agent):
        return GRANT.get(agent, [])


def _con_finti(fn, *a, **k):
    with patch.object(email, "credential_diagnostics", lambda: DIAGNOSTICA), \
         patch.object(email, "vault", _Vault), \
         patch.object(email, "_legacy_accounts", lambda: set()):
        return fn(*a, **k)


class WhatAnAgentSeesTests(unittest.TestCase):
    def test_only_what_it_can_actually_use(self):
        self.assertEqual(_con_finti(email.available_accounts, "messaggero"),
                         ["devnullboxx"])

    def test_what_exists_and_is_not_granted_is_named(self):
        """La riga che ripara il difetto: `team` esiste, funziona, e non è di
        messaggero. Prima era indistinguibile da un account inesistente."""
        self.assertEqual(_con_finti(email.accounts_not_granted, "messaggero"),
                         ["team"])

    def test_an_agent_with_the_grant_has_nothing_pending(self):
        self.assertEqual(_con_finti(email.accounts_not_granted, "clodia"), [])
        self.assertEqual(sorted(_con_finti(email.available_accounts, "clodia")),
                         ["devnullboxx", "team"])

    def test_a_broken_account_is_not_offered_as_askable(self):
        """Una casella non operativa non è «chiedi il permesso»: è rotta, e
        indicarla manderebbe a chiedere un grant che non risolverebbe niente."""
        for ag in ("messaggero", "clodia", "nuovo"):
            self.assertNotIn("rotta", _con_finti(email.accounts_not_granted, ag))

    def test_the_two_lists_never_overlap(self):
        """«Disponibile» e «esiste ma non concesso» sono stati esclusivi: uno
        stesso account in entrambe direbbe due cose opposte nella stessa
        risposta."""
        for ag in GRANT:
            a = set(_con_finti(email.available_accounts, ag))
            b = set(_con_finti(email.accounts_not_granted, ag))
            self.assertEqual(a & b, set(), ag)


class WhatTheToolAnswersTests(unittest.TestCase):
    """Il verbo deve DIRLO, non solo saperlo."""

    def _folders(self, agente):
        with patch.object(email, "credential_diagnostics", lambda: DIAGNOSTICA), \
             patch.object(email, "vault", _Vault), \
             patch.object(email, "_legacy_accounts", lambda: set()), \
             patch.object(email, "tool_allowed", lambda n: None), \
             patch.object(email, "agent_name", lambda: agente), \
             patch.object(email, "_run_json", lambda *a, **k: ["INBOX"]):
            return email.folders("devnullboxx")

    def test_the_answer_names_what_is_missing_and_the_remedy(self):
        r = self._folders("messaggero")
        self.assertEqual(r["accounts_not_granted"], ["team"])
        # Il rimedio, non solo il fatto: senza, l'agente sa che esiste e non sa
        # cosa fare — e un'informazione senza rimedio si trasforma in una scusa.
        self.assertIn("Integrazioni", r["note"])
        self.assertIn("owner", r["note"])

    def test_nothing_pending_nothing_said(self):
        """Una nota vuota attaccata a ogni risposta insegnerebbe a ignorarla."""
        r = self._folders("clodia")
        self.assertNotIn("accounts_not_granted", r)
        self.assertNotIn("note", r)


class SendOnlyIsAShapeNotAFaultTests(unittest.TestCase):
    """`team@uncommon-digital.it` è un alias: ha SMTP e nessuna casella dietro.

    Davide ha chiesto se si potesse «ignorare l'errore IMAP e consentire almeno
    l'invio». Ignorarlo sarebbe stato il rimedio sbagliato per la ragione giusta:
    assorbendo il fallimento, un guasto VERO del server diventerebbe
    indistinguibile da una scelta di configurazione, e una lettura risponderebbe
    «nessun messaggio» — che ha la stessa forma di una verità.

    Quindi il solo-invio è una **forma dichiarata**: si riconosce dall'assenza
    del server IMAP, si dice nella diagnostica e nell'elenco, e la lettura viene
    rifiutata nominando la causa. L'invio funziona senza eccezioni da fare.
    """

    def test_a_mailbox_without_imap_is_operational(self):
        """Il minimo per esistere è saper spedire. Prima l'IMAP era obbligatorio,
        e un alias risultava «non operativo»: un giudizio falso su una
        configurazione legittima, che poi lo nascondeva agli agenti."""
        with patch.object(email.vault, "store_names", return_value=["mailbox_team"]), \
             patch.object(email.vault, "read_internal", return_value={
                 "email": "team@uncommon-digital.it", "password": "x",
                 "smtp_server": "smtp.ionos.it", "smtp_port": 587}):
            r = email.credential_diagnostics()[0]
        self.assertTrue(r["operational"])
        self.assertTrue(r["send_only"])
        self.assertEqual(r["missing"], [])

    def test_a_mailbox_with_imap_is_not_send_only(self):
        with patch.object(email.vault, "store_names", return_value=["mailbox_studio"]), \
             patch.object(email.vault, "read_internal", return_value={
                 "email": "s@x.it", "password": "x", "imap_server": "imap.x.it",
                 "imap_port": 993, "smtp_server": "smtp.x.it", "smtp_port": 587}):
            r = email.credential_diagnostics()[0]
        self.assertTrue(r["operational"])
        self.assertFalse(r["send_only"])

    def test_reading_a_send_only_mailbox_is_refused_with_the_reason(self):
        """Non una lista vuota, non un errore IMAP grezzo: il motivo. «Alias
        senza casella» è un fatto sull'indirizzo, non un guasto da riprovare —
        e chi legge la chat mesi dopo deve poterlo capire."""
        with patch.object(email.vault, "has_credential", lambda c: c == "mailbox_team"), \
             patch.object(email.vault, "read_internal", return_value={
                 "email": "team@x.it", "smtp_server": "smtp.x.it"}):
            with self.assertRaises(PermissionError) as e:
                email._assert_readable("team")
        msg = str(e.exception)
        self.assertIn("SOLO INVIO", msg)
        self.assertIn("alias", msg)
        self.assertIn("CC", msg)   # il rimedio pratico per tenere traccia

    def test_a_readable_mailbox_passes(self):
        with patch.object(email.vault, "has_credential", lambda c: c == "mailbox_studio"), \
             patch.object(email.vault, "read_internal", return_value={
                 "email": "s@x.it", "imap_server": "imap.x.it"}):
            email._assert_readable("studio")   # non solleva

    def test_a_google_account_is_untouched(self):
        """Nessuna credenziale `mailbox_*` → la guardia non ha opinioni: gli
        account Google e i legacy si leggono come prima."""
        with patch.object(email.vault, "has_credential", lambda c: False):
            email._assert_readable("devnullboxx")

    def test_the_guard_sits_where_every_read_passes(self):
        """In `_run_json`, non nei sei verbi: sei copie della stessa regola sono
        cinque occasioni di divergere, e il settimo verbo nascerebbe senza."""
        import inspect
        self.assertIn("_assert_readable", inspect.getsource(email._run_json))
        # `send` NON passa da lì, ed è il punto: spedire resta possibile.
        self.assertNotIn("_assert_readable", inspect.getsource(email.send))


if __name__ == "__main__":
    unittest.main()

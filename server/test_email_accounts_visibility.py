"""Un account che esiste ma la cui casella non è in whitelist: si dice, non si tace.

Il difetto originale (clodia-platform#176): una casella aggiunta dalla UI
risultava «operativa» — vero, la credenziale c'era e funzionava — ma l'agente
non la vedeva, perché `email.folders` elencava solo gli account per cui aveva
un GRANT sul vault. Concludeva «non c'è» e si fermava.

Con il refactor whitelist-mailbox (18 set 2026) il grant-per-agente è stato
eliminato: `available_accounts` elenca ora tutto ciò che esiste ed è
operativo, a prescindere da chi chiama — non è più una domanda su CHI, ma su
DOVE. La domanda «posso usare questa casella qui» si è spostata sulla
whitelist `inbox:`/`outbox:` per-scope (`accounts_not_allowed`), verificata
al momento della chiamata reale (`_secrets_env`), non più nell'elenco.

Chiamare l'account per nome produceva già un rifiuto ottimo. Il buco era
l'ELENCO: chi non sa che una cosa esiste non può chiederla — e questo resta
vero identico nel nuovo modello.
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

_ADDR = {"google_devnullboxx": "devnullboxx@gmail.com",
        "mailbox_team": "team@x.it", "mailbox_rotta": "rotta@x.it"}


def _con_finti(allowed_inbox, fn, *a, **k):
    with patch.object(email, "credential_diagnostics", lambda: DIAGNOSTICA), \
         patch.object(email, "_legacy_accounts", lambda: set()), \
         patch.object(email.vault, "read_internal",
                      lambda cred: {"email": _ADDR.get(cred, cred)}), \
         patch("server.egress.mailbox_allowed",
               lambda direction, addr, scope=None: addr in allowed_inbox):
        return fn(*a, **k)


class WhatExistsTests(unittest.TestCase):
    def test_available_accounts_lists_everything_operational(self):
        """L'elenco non filtra più per chi chiama: esistenza, non permesso."""
        self.assertEqual(sorted(_con_finti(set(), email.available_accounts, "chiunque")),
                         ["devnullboxx", "team"])

    def test_what_is_not_in_the_inbox_whitelist_is_named(self):
        """La riga che ripara il difetto: `team` esiste, funziona, e la sua
        casella non è nella whitelist — prima era indistinguibile da un
        account inesistente."""
        self.assertEqual(
            _con_finti({"devnullboxx@gmail.com"}, email.accounts_not_allowed, "inbox"),
            ["team"])

    def test_nothing_pending_when_everything_is_whitelisted(self):
        self.assertEqual(
            _con_finti({"devnullboxx@gmail.com", "team@x.it"},
                      email.accounts_not_allowed, "inbox"),
            [])

    def test_a_broken_account_is_not_offered_as_askable(self):
        """Una casella non operativa non è «manca la whitelist»: è rotta, e
        indicarla manderebbe a chiedere un permesso che non risolverebbe
        niente."""
        self.assertNotIn("rotta", _con_finti(set(), email.accounts_not_allowed, "inbox"))

    def test_not_allowed_accounts_are_still_listed_as_existing(self):
        """`accounts_not_allowed` è un sottoinsieme di `available_accounts`:
        dice «esiste ma non è in whitelist», non «non esiste»."""
        esistenti = set(_con_finti(set(), email.available_accounts, "chiunque"))
        non_ammessi = set(_con_finti(set(), email.accounts_not_allowed, "inbox"))
        self.assertTrue(non_ammessi <= esistenti)


class WhatTheToolAnswersTests(unittest.TestCase):
    """Il verbo deve DIRLO, non solo saperlo."""

    def _folders(self, allowed_inbox):
        with patch.object(email, "credential_diagnostics", lambda: DIAGNOSTICA), \
             patch.object(email, "_legacy_accounts", lambda: set()), \
             patch.object(email.vault, "read_internal",
                          lambda cred: {"email": _ADDR.get(cred, cred)}), \
             patch("server.egress.mailbox_allowed",
                   lambda direction, addr, scope=None: addr in allowed_inbox), \
             patch.object(email, "tool_allowed", lambda n: None), \
             patch.object(email, "agent_name", lambda: "messaggero"), \
             patch.object(email, "_run_json", lambda *a, **k: ["INBOX"]):
            return email.folders("devnullboxx")

    def test_the_answer_names_what_is_missing_and_the_remedy(self):
        r = self._folders({"devnullboxx@gmail.com"})
        self.assertEqual(r["accounts_not_allowed"], ["team"])
        # Il rimedio, non solo il fatto: senza, l'agente sa che esiste e non sa
        # cosa fare — e un'informazione senza rimedio si trasforma in una scusa.
        self.assertIn("inbox:", r["note"])
        self.assertIn("owner", r["note"])

    def test_nothing_pending_nothing_said(self):
        """Una nota vuota attaccata a ogni risposta insegnerebbe a ignorarla."""
        r = self._folders({"devnullboxx@gmail.com", "team@x.it"})
        self.assertNotIn("accounts_not_allowed", r)
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

"""Rimuovere una casella dal vault ritira anche le sue autorizzazioni
(clodia-platform#411).

`email_mailbox_remove` cancellava `mailbox_<account>` dal vault e si fermava lì:
le voci `inbox:<addr>`/`outbox:<addr>` già scritte nelle liste — per scope e
globale — restavano, e nominavano una casella che non esiste più. Il difetto era
teorico finché il collegamento si faceva a mano; con il connettore Mailbox di
#406 (un click, `scope_allow` in DUE direzioni su ogni canale) le voci orfane si
accumulano, e una whitelist che non descrive più la realtà è peggio del rumore:
se domani quell'indirizzo viene riconfigurato per un altro uso, si ritrova
autorizzato in stanze che nessuno ha più scelto.

La pulizia sta in `egress.forget_mailbox` — dove vivono le liste — e non nella
rotta: è il punto condiviso per chiunque, domani, rimuova una casella da
un'altra strada.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.testclient import TestClient

from . import egress as eg
from . import tools_api
from . import whitelist as w
from .tools import email as email_tool

_H = {"Authorization": "Bearer ckt1.finto"}

#: Due caselle, indirizzo DIVERSO dal nome dell'account: nelle liste finisce
#: l'indirizzo, ed è l'unica cosa con cui si possono ritrovare le voci.
_VAULT = {
    "mailbox_studio": {"email": "Studio@Example.com", "password": "x",
                       "imap_server": "imap.example.com",
                       "smtp_server": "smtp.example.com"},
    "mailbox_altra": {"email": "altra@example.com", "password": "x",
                      "smtp_server": "smtp.example.com"},
}


def _config_piena() -> dict:
    """Le due caselle collegate a due canali, più una globale: lo stato che il
    connettore di #406 produce con qualche click."""
    return {
        "source_allow": ["inbox:studio@example.com", "mailfrom:tizio@example.com"],
        "egress_allow": ["outbox:studio@example.com"],
        "scope_source_allow": {
            "SEAL-1/acme": ["inbox:studio@example.com", "inbox:altra@example.com"],
            "SEAL-2/beta": ["inbox:studio@example.com"],
            "SEAL-1/gamma": ["inbox:altra@example.com"],
        },
        "scope_egress_allow": {
            "SEAL-1/acme": ["outbox:studio@example.com", "mailto:cliente@example.com"],
            "SEAL-2/beta": ["outbox:studio@example.com"],
        },
    }


class ForgetMailboxTests(unittest.TestCase):
    """L'invariante: dopo la rimozione, l'indirizzo non compare PIÙ in nessuna
    lista — né globale né di scope — e nient'altro si muove."""

    def setUp(self):
        self.cfg = _config_piena()
        p = [patch.object(w, "CONFIG", self.cfg),
             patch.object(w, "save_config", lambda: None)]
        for x in p:
            x.start()
        self.addCleanup(lambda: [x.stop() for x in reversed(p)])

    def test_the_address_disappears_from_every_list(self):
        esito = eg.forget_mailbox("studio@example.com")
        rimaste = [str(u) for u in self.cfg["source_allow"] + self.cfg["egress_allow"]]
        for voci in list(self.cfg["scope_source_allow"].values()) + \
                list(self.cfg["scope_egress_allow"].values()):
            rimaste.extend(str(u) for u in voci)
        self.assertEqual([u for u in rimaste if "studio@example.com" in u], [])
        # E lo dice: quali stanze sono state toccate, non solo «fatto».
        self.assertEqual(esito["scopes"], ["SEAL-1/acme", "SEAL-2/beta"])
        self.assertEqual(sorted(esito["global"]),
                         ["inbox:studio@example.com", "outbox:studio@example.com"])

    def test_nothing_else_is_touched(self):
        """Il controllo che conta: una pulizia troppo larga toglierebbe
        autorizzazioni che nessuno ha revocato — un danno silenzioso e peggiore
        del rumore che si voleva togliere."""
        eg.forget_mailbox("studio@example.com")
        self.assertEqual(self.cfg["source_allow"], ["mailfrom:tizio@example.com"])
        self.assertEqual(self.cfg["scope_source_allow"]["SEAL-1/acme"],
                         ["inbox:altra@example.com"])
        self.assertEqual(self.cfg["scope_source_allow"]["SEAL-1/gamma"],
                         ["inbox:altra@example.com"])
        self.assertEqual(self.cfg["scope_egress_allow"]["SEAL-1/acme"],
                         ["mailto:cliente@example.com"])

    def test_the_address_is_matched_in_canonical_form(self):
        """Una voce scritta a mano con le maiuscole è la stessa casella: se il
        confronto fosse letterale resterebbe orfana proprio nel caso in cui
        l'owner ha editato `config.yaml` a mano."""
        self.cfg["scope_source_allow"]["SEAL-1/acme"] = ["inbox:Studio@Example.com"]
        esito = eg.forget_mailbox("Studio@Example.com")
        self.assertEqual(self.cfg["scope_source_allow"]["SEAL-1/acme"], [])
        self.assertIn("SEAL-1/acme", esito["scopes"])

    def test_an_unknown_address_changes_nothing(self):
        prima = _config_piena()
        esito = eg.forget_mailbox("mai-vista@example.com")
        self.assertEqual(esito["scopes"], [])
        self.assertEqual(esito["global"], [])
        self.assertEqual(self.cfg, prima)

    def test_an_empty_address_is_a_no_op(self):
        """Difesa esplicita: con l'indirizzo vuoto un confronto per sottostringa
        svuoterebbe le liste. Meglio dirlo con un test che scoprirlo in
        produzione."""
        prima = _config_piena()
        self.assertEqual(eg.forget_mailbox("")["scopes"], [])
        self.assertEqual(self.cfg, prima)


class RemoveRouteTests(unittest.TestCase):
    """La rotta che l'owner usa davvero: DELETE della casella dalla UI."""

    def setUp(self):
        self.cfg = _config_piena()
        self.rimosse: list[str] = []
        p = [
            patch.object(tools_api, "_authorized", lambda _r: True),
            patch.object(tools_api.vault, "remove",
                         side_effect=lambda n: (self.rimosse.append(n), True)[1]),
            patch.object(email_tool.vault, "store_names", return_value=list(_VAULT)),
            patch.object(email_tool.vault, "read_internal",
                         side_effect=lambda n: dict(_VAULT[n])),
            patch.object(w, "CONFIG", self.cfg),
            patch.object(w, "save_config", lambda: None),
        ]
        for x in p:
            x.start()
        self.addCleanup(lambda: [x.stop() for x in reversed(p)])
        self.client = TestClient(Starlette(routes=tools_api.routes))

    def test_delete_revokes_the_orphan_entries_and_says_where(self):
        r = self.client.delete("/tools/email/mailboxes/studio", headers=_H)
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body["removed"], True)
        # Il rapporto all'owner: quante stanze sono cambiate sotto i suoi piedi.
        self.assertEqual(body["scopes"], ["SEAL-1/acme", "SEAL-2/beta"])
        self.assertEqual(body["topics_cleaned"], 2)
        self.assertEqual(self.cfg["scope_egress_allow"]["SEAL-2/beta"], [])
        self.assertEqual(self.cfg["egress_allow"], [])

    def test_the_credential_is_still_removed(self):
        """La pulizia è un'aggiunta, non un sostituto: il vault va svuotato."""
        self.client.delete("/tools/email/mailboxes/studio", headers=_H)
        self.assertEqual(self.rimosse, ["mailbox_studio"])

    def test_a_mailbox_the_vault_does_not_have_revokes_nothing(self):
        """Senza credenziale non si conosce l'indirizzo: indovinarlo dal nome
        dell'account revocherebbe la casella sbagliata."""
        prima = _config_piena()
        r = self.client.delete("/tools/email/mailboxes/ignota", headers=_H)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["scopes"], [])
        self.assertEqual(self.cfg, prima)

    def test_unauthorized_is_still_refused(self):
        with patch.object(tools_api, "_authorized", lambda _r: False):
            r = self.client.delete("/tools/email/mailboxes/studio", headers=_H)
        self.assertEqual(r.status_code, 401)
        self.assertEqual(self.cfg["scope_source_allow"]["SEAL-2/beta"],
                         ["inbox:studio@example.com"])


class RevocaCanonicaTests(unittest.TestCase):
    """La revoca confronta le voci in forma canonica, come già fa la scrittura.

    Non è una rifinitura per #411: lo stesso difetto colpisce il ✕ del
    connettore Mailbox (`scope_revoke` da `mailbox_link`) e ogni `egress.revoke`
    su una lista editata a mano. Correggerlo nel punto condiviso vale per tutti
    i chiamanti; correggerlo dentro `forget_mailbox` avrebbe lasciato rotto il
    bottone accanto.
    """

    def test_scope_revoke_removes_a_hand_written_uppercase_entry(self):
        cfg = {"scope_egress_allow": {"SEAL-1/acme": ["outbox:Studio@Example.com"]}}
        with patch.object(w, "CONFIG", cfg), patch.object(w, "save_config", lambda: None):
            esito = eg.scope_revoke("egress", "SEAL-1/acme", "outbox:studio@example.com")
        self.assertTrue(esito["removed"])
        self.assertEqual(cfg["scope_egress_allow"]["SEAL-1/acme"], [])

    def test_revoke_removes_a_hand_written_uppercase_entry(self):
        cfg = {"source_allow": ["inbox:Studio@Example.com"]}
        with patch.object(w, "CONFIG", cfg), patch.object(w, "save_config", lambda: None):
            esito = eg.revoke("ingress", "inbox:studio@example.com")
        self.assertTrue(esito["removed"])
        self.assertEqual(cfg["source_allow"], [])

    def test_a_different_address_is_left_alone(self):
        cfg = {"source_allow": ["inbox:altra@example.com"]}
        with patch.object(w, "CONFIG", cfg), patch.object(w, "save_config", lambda: None):
            self.assertFalse(eg.revoke("ingress", "inbox:studio@example.com")["removed"])
        self.assertEqual(cfg["source_allow"], ["inbox:altra@example.com"])


class MailboxAddressTests(unittest.TestCase):
    def setUp(self):
        p = [patch.object(email_tool.vault, "store_names", return_value=list(_VAULT)),
             patch.object(email_tool.vault, "read_internal",
                          side_effect=lambda n: dict(_VAULT[n]))]
        for x in p:
            x.start()
        self.addCleanup(lambda: [x.stop() for x in reversed(p)])

    def test_address_is_normalized(self):
        self.assertEqual(email_tool.mailbox_address("studio"), "studio@example.com")

    def test_missing_mailbox_has_no_address(self):
        """`None`, non il nome dell'account: un nome non è un indirizzo, e
        scambiarli qui significa revocare una voce che non c'entra."""
        self.assertIsNone(email_tool.mailbox_address("ignota"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

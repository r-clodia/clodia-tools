"""`/internal/topics/{tier}/{name}/mailbox-link` — il connettore «Mailbox» di
un canale (clodia-platform#406).

Richiesta di Davide: oltre a Telegram, Drive e Cartella Mac serve poter
scegliere una delle caselle GIÀ configurate nel sistema e vederla diventare
ingress ed egress del canale in un colpo solo. Oggi la stessa cosa si ottiene
solo scrivendo a mano `inbox:<addr>` e `outbox:<addr>` nelle liste locali del
topic, o con un gate ad-hoc sulla singola casella.

Il collegamento qui è SOLO autorizzazione: nessun binding, nessun relay — la
posta continua a entrare nel topic per mano dei verbi email, che però prima di
materializzare le credenziali chiedono a `egress.mailbox_allowed` esattamente
le due voci che questa rotta scrive.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.testclient import TestClient

from . import topics_api
from .tools import email as email_tool
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicService

_H = {"Authorization": "Bearer ckt1.finto"}

#: Due caselle nella vault: una completa, una di solo invio (alias SMTP senza
#: IMAP). Entrambe operative — `send_only` è una forma dichiarata, non un
#: guasto — e con indirizzo DIVERSO dal nome dell'account, che è il punto: nella
#: whitelist finisce l'indirizzo.
_VAULT = {
    "mailbox_studio": {
        "email": "Studio@Example.com",
        "password": "x",
        "imap_server": "imap.example.com",
        "imap_port": 993,
        "smtp_server": "smtp.example.com",
        "smtp_port": 587,
    },
    "mailbox_alias": {
        "email": "team@example.com",
        "password": "x",
        "smtp_server": "smtp.example.com",
        "smtp_port": 587,
    },
}


class Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="mailbox-link-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.svc = TopicService(LocalFsStorage(str(self.root)))
        self.svc.new("SEAL-1", "acme", {"title": "Acme", "owner": "davide"})

        self._p = [
            patch.object(topics_api, "_svc", self.svc),
            patch.object(topics_api, "_authorize", lambda _r: ("davide", None)),
            patch.object(email_tool.vault, "store_names", return_value=list(_VAULT)),
            patch.object(email_tool.vault, "read_internal",
                         side_effect=lambda n: dict(_VAULT[n])),
            # Il legacy `secrets/email_config.json` non deve entrare nell'elenco
            # e non deve nemmeno dipendere dal filesystem della macchina di chi
            # esegue i test.
            patch.object(email_tool, "_legacy_accounts", return_value=set()),
        ]
        for p in self._p:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in reversed(self._p)])
        self.client = TestClient(Starlette(routes=topics_api.routes))

    def righe(self, payload: dict) -> dict:
        return {r["account"]: r for r in payload["mailboxes"]}


class ElencoTests(Base):
    def test_get_lists_system_mailboxes_with_their_address(self):
        from . import whitelist as w
        with patch.object(w, "CONFIG", {}):
            r = self.client.get("/internal/topics/SEAL-1/acme/mailbox-link", headers=_H)
        self.assertEqual(r.status_code, 200)
        righe = self.righe(r.json())
        self.assertEqual(sorted(righe), ["alias", "studio"])
        # L'indirizzo, normalizzato: è la forma che `mailbox_allowed` confronta.
        self.assertEqual(righe["studio"]["email"], "studio@example.com")
        self.assertTrue(righe["alias"]["send_only"])
        self.assertFalse(righe["studio"]["send_only"])
        # Niente è autorizzato finché non lo si collega.
        self.assertEqual(
            [righe["studio"]["inbox"], righe["studio"]["outbox"], righe["studio"]["local"]],
            [False, False, False])

    def test_a_globally_allowed_mailbox_is_authorized_but_not_local(self):
        """`local` distingue «tolgo da qui» da «è permessa altrove».

        Senza, il ✕ del pannello comparirebbe su una voce che sta nella lista
        GLOBALE, dove questa rotta non scrive: un bottone che non cambia nulla.
        """
        from . import whitelist as w
        cfg = {"source_allow": ["inbox:studio@example.com"],
               "egress_allow": ["outbox:studio@example.com"]}
        with patch.object(w, "CONFIG", cfg):
            r = self.client.get("/internal/topics/SEAL-1/acme/mailbox-link", headers=_H)
        riga = self.righe(r.json())["studio"]
        self.assertEqual([riga["inbox"], riga["outbox"]], [True, True])
        self.assertFalse(riga["local"])


class ConnectTests(Base):
    def test_connect_authorizes_the_mailbox_in_both_directions_at_once(self):
        from . import whitelist as w
        with patch.object(w, "CONFIG", {}), patch.object(w, "save_config", lambda: None):
            r = self.client.post("/internal/topics/SEAL-1/acme/mailbox-link",
                                 headers=_H, json={"action": "connect", "account": "studio"})
            self.assertEqual(r.status_code, 200)
            self.assertIn("inbox:studio@example.com",
                          w.CONFIG["scope_source_allow"]["SEAL-1/acme"])
            self.assertIn("outbox:studio@example.com",
                          w.CONFIG["scope_egress_allow"]["SEAL-1/acme"])
            riga = self.righe(r.json())["studio"]
            self.assertEqual([riga["inbox"], riga["outbox"], riga["local"]],
                             [True, True, True])
            # L'altra casella non è stata toccata: si autorizza quella scelta.
            self.assertFalse(self.righe(r.json())["alias"]["outbox"])

    def test_connect_writes_the_scope_list_not_the_global_one(self):
        from . import whitelist as w
        with patch.object(w, "CONFIG", {}), patch.object(w, "save_config", lambda: None):
            self.client.post("/internal/topics/SEAL-1/acme/mailbox-link",
                             headers=_H, json={"action": "connect", "account": "studio"})
            self.assertEqual(w.CONFIG.get("egress_allow"), None)
            self.assertEqual(w.CONFIG.get("source_allow"), None)

    def test_an_account_the_system_does_not_have_is_refused(self):
        from . import whitelist as w
        with patch.object(w, "CONFIG", {}), patch.object(w, "save_config", lambda: None):
            r = self.client.post("/internal/topics/SEAL-1/acme/mailbox-link",
                                 headers=_H, json={"action": "connect", "account": "ignota"})
            self.assertEqual(r.status_code, 400)
            self.assertNotIn("scope_egress_allow", w.CONFIG)

    def test_the_address_comes_from_the_vault_not_from_the_request(self):
        """Un `email` nel corpo non autorizza niente: l'indirizzo lo decide il
        sistema, se no la whitelist la scriverebbe chi ne è soggetto."""
        from . import whitelist as w
        with patch.object(w, "CONFIG", {}), patch.object(w, "save_config", lambda: None):
            self.client.post("/internal/topics/SEAL-1/acme/mailbox-link", headers=_H,
                             json={"action": "connect", "account": "studio",
                                   "email": "chiunque@evil.example"})
            voci = w.CONFIG["scope_egress_allow"]["SEAL-1/acme"]
            self.assertEqual(voci, ["outbox:studio@example.com"])

    def test_connect_without_account_is_refused(self):
        r = self.client.post("/internal/topics/SEAL-1/acme/mailbox-link",
                             headers=_H, json={"action": "connect"})
        self.assertEqual(r.status_code, 400)

    def test_unknown_action_is_refused(self):
        r = self.client.post("/internal/topics/SEAL-1/acme/mailbox-link",
                             headers=_H, json={"action": "boh", "account": "studio"})
        self.assertEqual(r.status_code, 400)


class DisconnectTests(Base):
    def test_disconnect_removes_both_entries(self):
        from . import whitelist as w
        with patch.object(w, "CONFIG", {}), patch.object(w, "save_config", lambda: None):
            self.client.post("/internal/topics/SEAL-1/acme/mailbox-link",
                             headers=_H, json={"action": "connect", "account": "studio"})
            r = self.client.post("/internal/topics/SEAL-1/acme/mailbox-link",
                                 headers=_H, json={"action": "disconnect", "account": "studio"})
            self.assertEqual(r.status_code, 200)
            self.assertEqual(w.CONFIG["scope_source_allow"]["SEAL-1/acme"], [])
            self.assertEqual(w.CONFIG["scope_egress_allow"]["SEAL-1/acme"], [])
            riga = self.righe(r.json())["studio"]
            self.assertEqual([riga["inbox"], riga["outbox"], riga["local"]],
                             [False, False, False])

    def test_disconnect_of_a_mailbox_never_connected_is_a_no_op(self):
        from . import whitelist as w
        with patch.object(w, "CONFIG", {}), patch.object(w, "save_config", lambda: None):
            r = self.client.post("/internal/topics/SEAL-1/acme/mailbox-link",
                                 headers=_H, json={"action": "disconnect", "account": "alias"})
            self.assertEqual(r.status_code, 200)
            self.assertFalse(self.righe(r.json())["alias"]["outbox"])


class ScopeTests(Base):
    def test_another_topic_is_not_authorized_by_this_one(self):
        """L'asse della lista è la STANZA: collegare la casella qui non la
        apre altrove, che è la ragione per cui le liste per scope esistono."""
        from . import whitelist as w
        with patch.object(w, "CONFIG", {}), patch.object(w, "save_config", lambda: None):
            self.client.post("/internal/topics/SEAL-1/acme/mailbox-link",
                             headers=_H, json={"action": "connect", "account": "studio"})
            self.svc.new("SEAL-1", "altro", {"title": "Altro", "owner": "davide"})
            r = self.client.get("/internal/topics/SEAL-1/altro/mailbox-link", headers=_H)
            riga = self.righe(r.json())["studio"]
            self.assertEqual([riga["inbox"], riga["outbox"]], [False, False])


if __name__ == "__main__":
    unittest.main()

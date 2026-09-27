"""`/internal/topics/{tier}/{name}/telegram-link` — connetti/disconnetti in un
click, non due passi scollegati.

Difetto riportato da Davide (23 set 2026): aveva aggiunto `tg:<chat_id>` alla
whitelist egress/ingress del topic (l'icona rapida Telegram esistente) ma il
messaggero continuava a dire «nessuna chat collegata». Causa: la whitelist
autorizza la DESTINAZIONE, il binding (`telegram_bindings.json`, l'equivalente
di `telegram.listen`) è un passo SEPARATO che nessuna icona faceva. Questa rotta
fa entrambi insieme, in entrambe le direzioni (connect/disconnect).
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
from .tools import telegram_bindings as tb
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicService

_H = {"Authorization": "Bearer ckt1.finto"}


class Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="telegram-link-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.svc = TopicService(LocalFsStorage(str(self.root)))
        self.svc.new("SEAL-1", "acme", {"title": "Acme", "owner": "davide"})

        self.bindings_dir = Path(tempfile.mkdtemp(prefix="telegram-bindings-"))
        self.addCleanup(shutil.rmtree, self.bindings_dir, ignore_errors=True)

        self._p = [
            patch.object(topics_api, "_svc", self.svc),
            patch.object(tb, "_path", lambda: self.bindings_dir / "telegram-bindings.json"),
            patch.object(topics_api, "_authorize", lambda _r: ("davide", None)),
        ]
        for p in self._p:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in reversed(self._p)])
        self.client = TestClient(Starlette(routes=topics_api.routes))

    def scope(self, tier="SEAL-1", name="acme"):
        return f"{tier}/{name}"


class ConnectTests(Base):
    def test_connect_writes_both_the_binding_and_the_whitelist(self):
        from . import whitelist as w
        with patch.object(w, "CONFIG", {}), patch.object(w, "save_config", lambda: None):
            r = self.client.post("/internal/topics/SEAL-1/acme/telegram-link",
                                 headers=_H, json={"action": "connect", "chat_id": "-100"})
            self.assertEqual(r.status_code, 200)
            # `seal` è additivo (clodia-platform#405): la risposta dice sempre a
            # che punto sta il cap, così la UI non deve duplicarne la regola.
            self.assertEqual(
                {k: v for k, v in r.json().items() if k != "seal"},
                {"connected": True, "chat_id": "-100"})
            self.assertEqual(tb.get("-100"), {"instance": "messaggero",
                                              "tier": "SEAL-1", "topic": "acme"})
            self.assertIn("tg:-100", w.CONFIG["scope_egress_allow"]["SEAL-1/acme"])
            self.assertIn("tg:-100", w.CONFIG["scope_source_allow"]["SEAL-1/acme"])

    def test_connect_refuses_a_chat_already_bound_elsewhere(self):
        tb.set_binding("-200", "messaggero", "SEAL-1", "altro-topic")
        r = self.client.post("/internal/topics/SEAL-1/acme/telegram-link",
                             headers=_H, json={"action": "connect", "chat_id": "-200"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("altro-topic", r.json()["error"])
        self.assertEqual(tb.get("-200")["topic"], "altro-topic")  # invariato

    def test_connect_without_chat_id_is_refused(self):
        r = self.client.post("/internal/topics/SEAL-1/acme/telegram-link",
                             headers=_H, json={"action": "connect"})
        self.assertEqual(r.status_code, 400)


class DisconnectTests(Base):
    def test_disconnect_removes_both_the_binding_and_the_whitelist(self):
        from . import whitelist as w
        with patch.object(w, "CONFIG", {}), patch.object(w, "save_config", lambda: None):
            self.client.post("/internal/topics/SEAL-1/acme/telegram-link",
                             headers=_H, json={"action": "connect", "chat_id": "-300"})
            r = self.client.post("/internal/topics/SEAL-1/acme/telegram-link",
                                 headers=_H, json={"action": "disconnect"})
            self.assertEqual(r.status_code, 200)
            self.assertEqual(
                {k: v for k, v in r.json().items() if k != "seal"},
                {"connected": False, "chat_id": None})
            self.assertIsNone(tb.get("-300"))
            self.assertNotIn("tg:-300", w.CONFIG.get("scope_egress_allow", {}).get("SEAL-1/acme", []))

    def test_disconnect_with_nothing_connected_is_a_no_op(self):
        r = self.client.post("/internal/topics/SEAL-1/acme/telegram-link",
                             headers=_H, json={"action": "disconnect"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(
            {k: v for k, v in r.json().items() if k != "seal"},
            {"connected": False, "chat_id": None})


class StatusTests(Base):
    def test_get_reflects_no_connection(self):
        r = self.client.get("/internal/topics/SEAL-1/acme/telegram-link", headers=_H)
        self.assertEqual(
            {k: v for k, v in r.json().items() if k != "seal"},
            {"connected": False, "chat_id": None})

    def test_get_reflects_an_existing_binding(self):
        tb.set_binding("-400", "messaggero", "SEAL-1", "acme")
        r = self.client.get("/internal/topics/SEAL-1/acme/telegram-link", headers=_H)
        self.assertEqual(
            {k: v for k, v in r.json().items() if k != "seal"},
            {"connected": True, "chat_id": "-400"})

    def test_get_on_an_uncapped_topic_asks_for_nothing(self):
        r = self.client.get("/internal/topics/SEAL-1/acme/telegram-link", headers=_H)
        self.assertEqual(r.json()["seal"],
                         {"tier": "SEAL-1", "cap": "SEAL-1",
                          "requires_ack": False, "ack": None})


class SealCapTests(Base):
    """clodia-platform#405 — l'owner deve poter collegare Telegram anche su un
    canale SEAL-2.

    Fino a qui il cap del channel (`telegram` → SEAL-1, provider extra-UE e
    gruppi non E2E) era un rifiuto secco: su un topic SEAL-2 la rotta rispondeva
    400 e non esisteva nessun gesto, per nessuno, che lo superasse — nemmeno per
    l'owner, che è chi il tier lo assegna e chi il rischio lo porta.

    Il cap non sparisce: diventa una domanda. Senza la presa d'atto esplicita
    dell'owner la risposta resta identica a prima; con quella, il collegamento
    passa e RESTA SCRITTO nel meta del topic — chi il downgrade lo ha accettato,
    quando, e per quale tier. Un permesso che non si rilegge è un permesso che
    nessuno può revocare.
    """

    def setUp(self):
        super().setUp()
        self.svc.new("SEAL-2", "preventivi", {"title": "P", "owner": "davide"})

    def _connect(self, **extra):
        return self.client.post("/internal/topics/SEAL-2/preventivi/telegram-link",
                                headers=_H,
                                json={"action": "connect", "chat_id": "-1001", **extra})

    def test_get_says_that_the_owner_has_to_acknowledge(self):
        r = self.client.get("/internal/topics/SEAL-2/preventivi/telegram-link",
                            headers=_H)
        self.assertEqual(r.json()["seal"],
                         {"tier": "SEAL-2", "cap": "SEAL-1",
                          "requires_ack": True, "ack": None})

    def test_connect_without_the_acknowledgement_is_still_refused(self):
        from . import whitelist as w
        with patch.object(w, "CONFIG", {}), patch.object(w, "save_config", lambda: None):
            r = self._connect()
            self.assertEqual(r.status_code, 400)
            self.assertIn("SEAL-2", r.json()["error"])
            # L'errore deve dire il gesto che sblocca, non solo che è vietato.
            self.assertIn("accept_seal_downgrade", r.json()["error"])
            self.assertTrue(r.json()["seal"]["requires_ack"])
            self.assertIsNone(tb.get("-1001"))
            self.assertNotIn("SEAL-2/preventivi", w.CONFIG.get("scope_egress_allow", {}))

    def test_connect_with_the_acknowledgement_links_and_records_it(self):
        from . import whitelist as w
        with patch.object(w, "CONFIG", {}), patch.object(w, "save_config", lambda: None):
            r = self._connect(accept_seal_downgrade=True)
            self.assertEqual(r.status_code, 200)
            self.assertTrue(r.json()["connected"])
            self.assertEqual(tb.get("-1001")["topic"], "preventivi")
            self.assertIn("tg:-1001", w.CONFIG["scope_egress_allow"]["SEAL-2/preventivi"])
            self.assertIn("tg:-1001", w.CONFIG["scope_source_allow"]["SEAL-2/preventivi"])
        ack = self.svc.open("SEAL-2", "preventivi")["meta"]["channel_seal_ack"]
        self.assertEqual(ack["channel"], "telegram")
        self.assertEqual(ack["tier"], "SEAL-2")
        self.assertEqual(ack["cap"], "SEAL-1")
        self.assertEqual(ack["by"], "davide")
        self.assertTrue(ack["at"])
        # Una volta presa, la presa d'atto non si richiede più.
        r2 = self.client.get("/internal/topics/SEAL-2/preventivi/telegram-link",
                             headers=_H)
        self.assertFalse(r2.json()["seal"]["requires_ack"])
        self.assertEqual(r2.json()["seal"]["ack"]["by"], "davide")

    def test_disconnect_takes_the_acknowledgement_back(self):
        from . import whitelist as w
        with patch.object(w, "CONFIG", {}), patch.object(w, "save_config", lambda: None):
            self._connect(accept_seal_downgrade=True)
            self.client.post("/internal/topics/SEAL-2/preventivi/telegram-link",
                             headers=_H, json={"action": "disconnect"})
        meta = self.svc.open("SEAL-2", "preventivi")["meta"]
        self.assertNotIn("channel_seal_ack", meta)
        # E la prossima connessione torna a chiedere.
        r = self.client.get("/internal/topics/SEAL-2/preventivi/telegram-link",
                            headers=_H)
        self.assertTrue(r.json()["seal"]["requires_ack"])


class SealAckScopeTests(unittest.TestCase):
    """La presa d'atto vale per il tier PER CUI è stata data, e non è un campo
    che si possa scrivere da fuori la rotta dell'owner."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="telegram-ack-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.svc = TopicService(LocalFsStorage(str(self.root)))

    def test_an_agent_cannot_grant_it_to_itself_at_creation(self):
        from .topics.service import TopicError
        finto = {"channel": "telegram", "tier": "SEAL-2", "cap": "SEAL-1",
                 "by": "io", "at": "2026-09-27T00:00:00+00:00"}
        meta = self.svc.new("SEAL-2", "furbo",
                            {"owner": "davide", "channel_seal_ack": finto})
        self.assertNotIn("channel_seal_ack", meta)
        with self.assertRaises(TopicError):
            self.svc.channel_listen("SEAL-2", "furbo", "-7")

    def test_it_does_not_survive_a_retier_upwards(self):
        from .topics.service import TopicError
        self.svc.new("SEAL-2", "p", {"owner": "davide"})
        self.svc.accept_channel_cap("SEAL-2", "p", "telegram", by="davide")
        self.svc.channel_listen("SEAL-2", "p", "-8")  # ammesso: c'è la presa d'atto
        meta, ver = self.svc._read_meta("SEAL-2", "p")
        meta["tier"] = "SEAL-3"
        self.svc._write_meta("SEAL-2", "p", meta, base_version=ver)
        with self.assertRaises(TopicError):
            self.svc.channel_listen("SEAL-2", "p", "-9")


if __name__ == "__main__":
    unittest.main()

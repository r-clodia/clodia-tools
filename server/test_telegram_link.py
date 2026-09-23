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
            self.assertEqual(r.json(), {"connected": True, "chat_id": "-100"})
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
            self.assertEqual(r.json(), {"connected": False, "chat_id": None})
            self.assertIsNone(tb.get("-300"))
            self.assertNotIn("tg:-300", w.CONFIG.get("scope_egress_allow", {}).get("SEAL-1/acme", []))

    def test_disconnect_with_nothing_connected_is_a_no_op(self):
        r = self.client.post("/internal/topics/SEAL-1/acme/telegram-link",
                             headers=_H, json={"action": "disconnect"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), {"connected": False, "chat_id": None})


class StatusTests(Base):
    def test_get_reflects_no_connection(self):
        r = self.client.get("/internal/topics/SEAL-1/acme/telegram-link", headers=_H)
        self.assertEqual(r.json(), {"connected": False, "chat_id": None})

    def test_get_reflects_an_existing_binding(self):
        tb.set_binding("-400", "messaggero", "SEAL-1", "acme")
        r = self.client.get("/internal/topics/SEAL-1/acme/telegram-link", headers=_H)
        self.assertEqual(r.json(), {"connected": True, "chat_id": "-400"})


if __name__ == "__main__":
    unittest.main()

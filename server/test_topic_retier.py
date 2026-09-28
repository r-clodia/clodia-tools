"""Riclassificazione di un topic a un nuovo livello SEAL (clodia-platform#426).

Proprietà fissate qui:
- il topic si SPOSTA (il livello è nel path) e il meta registra chi, quando,
  da dove a dove e perché;
- i muri non cambiano: le liste ingress/egress del topic, il binding Telegram e
  la contaminazione vengono riportati IDENTICI sotto la nuova chiave;
- tutto o niente: se un passo fallisce, nulla resta cambiato;
- stesso livello, motivazione vuota e destinazione occupata si rifiutano.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.testclient import TestClient

from . import taint, topics_api
from . import whitelist as w
from .tools import telegram_bindings as tb
from .topics import retier
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicError, TopicService


class Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="retier-"))
        with patch("server.instance_profile.topic_default_participants", return_value=[]):
            self.svc = TopicService(LocalFsStorage(str(self.root)))
            self.svc.new("SEAL-1", "acme", {"title": "Acme", "owner": "davide"})
        self.svc.put_file("SEAL-1", "acme", "offerta.txt", b"ciao")
        stato = Path(tempfile.mkdtemp(prefix="retier-state-"))
        self.cfg = {"scope_source_allow": {"SEAL-1/acme": ["inbox:info@tomato.blue", "tg:-5411149155"],
                                           "SEAL-1/altro": ["tg:-1"]},
                    "scope_egress_allow": {"SEAL-1/acme": ["tg:-5411149155", "gdrive:folder/1xxBOdhf4Vz2lgHAsxIBOEfyY9ymJn_NT"]}}
        self._p = [
            patch.object(w, "CONFIG", self.cfg),
            patch.object(w, "save_config", lambda: None),
            patch.object(w, "reload_config", lambda: None),
            patch.object(tb, "_path", lambda: stato / "telegram-bindings.json"),
            patch.object(taint, "_path", lambda: stato / "taint.json"),
            patch.object(topics_api, "_svc", self.svc),
            patch.object(topics_api, "_authorize", lambda _r: ("clodia", None)),
        ]
        for p in self._p:
            p.start()
        self.addCleanup(lambda: [p.stop() for p in reversed(self._p)])
        tb.set_binding("-5411149155", "messaggero", "SEAL-1", "acme")
        taint.mark("chan:SEAL-1:acme:clodia", "verb", "web.fetch", "clodia")


class ApplyTests(Base):
    def test_the_topic_moves_and_the_history_says_who_why_when(self):
        esito = retier.apply(self.svc, "SEAL-1", "acme", "SEAL-2", by="davide",
                             reason="contiene il preventivo del cliente")
        self.assertEqual((esito["from"], esito["to"]), ("SEAL-1", "SEAL-2"))
        self.assertFalse((self.root / "SEAL-1" / "acme").exists())
        meta = self.svc.open("SEAL-2", "acme")["meta"]
        self.assertEqual(meta["tier"], "SEAL-2")
        voce = meta["tier_history"][-1]
        self.assertEqual((voce["from"], voce["to"], voce["by"]), ("SEAL-1", "SEAL-2", "davide"))
        self.assertIn("preventivo", voce["reason"])
        self.assertTrue(voce["at"])
        self.assertTrue(any((self.root / "SEAL-2" / "acme").rglob("offerta.txt")),
                        "i file seguono il topic")

    def test_the_walls_move_identical_and_nothing_else_changes(self):
        retier.apply(self.svc, "SEAL-1", "acme", "SEAL-3", by="davide", reason="x")
        self.assertEqual(self.cfg["scope_source_allow"]["SEAL-3/acme"],
                         ["inbox:info@tomato.blue", "tg:-5411149155"])
        self.assertEqual(self.cfg["scope_egress_allow"]["SEAL-3/acme"],
                         ["tg:-5411149155", "gdrive:folder/1xxBOdhf4Vz2lgHAsxIBOEfyY9ymJn_NT"])
        self.assertNotIn("SEAL-1/acme", self.cfg["scope_source_allow"])
        self.assertEqual(self.cfg["scope_source_allow"]["SEAL-1/altro"], ["tg:-1"],
                         "le liste degli altri topic non si toccano")
        self.assertEqual(tb.get("-5411149155")["tier"], "SEAL-3")

    def test_moving_a_topic_does_not_clean_its_contamination(self):
        retier.apply(self.svc, "SEAL-1", "acme", "SEAL-0", by="davide", reason="x")
        self.assertTrue(taint.status("chan:SEAL-0:acme:clodia")["tainted"])
        self.assertFalse(taint.status("chan:SEAL-1:acme:clodia")["tainted"])

    def test_all_or_nothing(self):
        with patch.object(retier, "_rekey_bindings", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                retier.apply(self.svc, "SEAL-1", "acme", "SEAL-2", by="davide", reason="x")
        meta = self.svc.open("SEAL-1", "acme")["meta"]
        self.assertEqual(meta["tier"], "SEAL-1")
        self.assertFalse(meta.get("tier_history"))
        self.assertFalse((self.root / "SEAL-2" / "acme").exists())
        self.assertIn("SEAL-1/acme", self.cfg["scope_source_allow"])
        self.assertEqual(tb.get("-5411149155")["tier"], "SEAL-1")

    def test_refusals(self):
        with self.assertRaises(TopicError):
            retier.apply(self.svc, "SEAL-1", "acme", "SEAL-1", by="davide", reason="x")
        with self.assertRaises(TopicError):
            retier.apply(self.svc, "SEAL-1", "acme", "SEAL-2", by="davide", reason="  ")
        with self.assertRaises(TopicError):
            retier.apply(self.svc, "SEAL-1", "acme", "SEAL-9", by="davide", reason="x")
        (self.root / "SEAL-2" / "acme").mkdir(parents=True)
        (self.root / "SEAL-2" / "acme" / "meta.json").write_text(json.dumps({"tier": "SEAL-2"}))
        with self.assertRaises(TopicError):
            retier.apply(self.svc, "SEAL-1", "acme", "SEAL-2", by="davide", reason="x")


class RouteTests(Base):
    def test_the_route_moves_the_topic_and_posts_the_trace(self):
        c = TestClient(Starlette(routes=topics_api.routes))
        r = c.post("/internal/topics/SEAL-1/acme/tier",
                   json={"tier": "SEAL-2", "by": "davide", "reason": "dati del cliente"})
        self.assertEqual(r.status_code, 200, r.text)
        msgs = self.svc.list_messages("SEAL-2", "acme")
        self.assertTrue(any("riclassificato da SEAL-1 a SEAL-2" in m["text"] for m in msgs))

    def test_the_route_requires_who_and_why(self):
        c = TestClient(Starlette(routes=topics_api.routes))
        r = c.post("/internal/topics/SEAL-1/acme/tier", json={"tier": "SEAL-2", "by": "davide"})
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":
    unittest.main()

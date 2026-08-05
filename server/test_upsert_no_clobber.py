"""`upsert_agent` non deve sovrascrivere modifiche fatte da un altro processo.

Accaduto davvero: `profile_tools` scritto nella config da uno script è sparito al
primo `upsert_agent` del gateway — perché `save_config()` serializza l'INTERO
CONFIG in memoria, e quello in memoria era di prima. Un vincolo di sicurezza
rimosso da un'operazione che non c'entrava: l'update di un pack.

E il caso gemello: un chiamante che manda `gated_tools: []` invece di omettere il
campo azzera i gate. L'assenza significa «non mi pronuncio», la lista vuota
significa «azzerale», e la differenza è fra un aggiornamento innocuo e un
allargamento di autorità.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from . import whitelist as wl


class NoClobberTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "config.yaml"
        self._orig = wl.CONFIG_PATH
        wl.CONFIG_PATH = self.path
        self.addCleanup(lambda: setattr(wl, "CONFIG_PATH", self._orig))
        self._write({"agents": {"clodia": {"allowed_tools": ["*"],
                                           "gated_tools": ["topic.remote_push"],
                                           "profile_tools": ["topic.open"]}},
                     "workspace_root": "/tmp"})

    def _write(self, data):
        self.path.write_text(yaml.safe_dump(data), encoding="utf-8")
        wl.reload_config()

    def _read(self):
        return yaml.safe_load(self.path.read_text())["agents"]["clodia"]

    def test_a_field_written_by_another_process_survives(self):
        """Il caso reale: qualcun altro scrive `profile_tools`, poi arriva un
        upsert per un motivo diverso."""
        # un altro processo aggiunge un campo, senza passare da questo CONFIG
        d = yaml.safe_load(self.path.read_text())
        d["agents"]["clodia"]["profile_tools"] = ["topic.open", "topic.files"]
        self.path.write_text(yaml.safe_dump(d), encoding="utf-8")
        # ...e questo processo, che ha in memoria la versione VECCHIA, fa un upsert
        wl.upsert_agent("clodia", allowed_tools=["*"])
        self.assertEqual(self._read()["profile_tools"], ["topic.open", "topic.files"])

    def test_gates_written_elsewhere_survive_an_unrelated_upsert(self):
        d = yaml.safe_load(self.path.read_text())
        d["agents"]["clodia"]["gated_tools"] = ["topic.remote_push", "web.post"]
        self.path.write_text(yaml.safe_dump(d), encoding="utf-8")
        wl.upsert_agent("clodia", allowed_tools=["*"])
        self.assertEqual(self._read()["gated_tools"], ["topic.remote_push", "web.post"])

    def test_an_explicit_empty_list_DOES_clear(self):
        """La lista vuota resta un'istruzione valida: «non ha gate». Serve per
        poterli togliere davvero."""
        wl.upsert_agent("clodia", allowed_tools=["*"], gated_tools=[])
        self.assertEqual(self._read()["gated_tools"], [])

    def test_absent_does_not_clear(self):
        wl.upsert_agent("clodia", allowed_tools=["*"], gated_tools=None)
        self.assertEqual(self._read()["gated_tools"], ["topic.remote_push"])

    def test_a_new_agent_is_still_created(self):
        wl.upsert_agent("nuovo", allowed_tools=["topic.open"])
        d = yaml.safe_load(self.path.read_text())["agents"]
        self.assertIn("nuovo", d)
        self.assertEqual(d["nuovo"]["allowed_tools"], ["topic.open"])
        self.assertIn("clodia", d, "l'agente preesistente non deve sparire")


if __name__ == "__main__":
    unittest.main()

"""Stato decisionale del gateway fuori dalla datadir condivisa (clodia-platform#80).

Il test protegge tre proprietà:
  * con `CLODIA_TOOLS_STATE_DIR` impostata, whitelist/gate/deleghe NON stanno
    più sotto `CLODIA_DATA` (che l'agent-server monta);
  * senza quella env il comportamento è identico a prima (nessuna rottura dei
    deploy non aggiornati né del dev locale);
  * la migrazione della copia legacy avviene una volta sola e non riporta
    indietro uno stato riscritto sul volume condiviso — che è esattamente il
    vettore dell'issue.
"""
from __future__ import annotations

import importlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import state_paths


class StateDirTests(unittest.TestCase):
    def test_falls_back_to_shared_datadir_when_unset(self) -> None:
        with tempfile.TemporaryDirectory() as data:
            with patch.dict("os.environ", {"CLODIA_DATA": data}, clear=False):
                import os
                os.environ.pop("CLODIA_TOOLS_STATE_DIR", None)
                self.assertEqual(state_paths.state_dir(), Path(data))
                self.assertFalse(state_paths.is_isolated())
                self.assertTrue(state_paths.configured())
                self.assertEqual(state_paths.state_path("clodia-tools-gate.json"),
                                 Path(data) / "clodia-tools-gate.json")

    def test_isolated_when_state_dir_set(self) -> None:
        with tempfile.TemporaryDirectory() as data, tempfile.TemporaryDirectory() as state:
            with patch.dict("os.environ", {"CLODIA_DATA": data,
                                           "CLODIA_TOOLS_STATE_DIR": state}):
                self.assertTrue(state_paths.is_isolated())
                for name in state_paths.STATE_FILES:
                    p = state_paths.state_path(name)
                    self.assertTrue(str(p).startswith(state), f"{name} → {p}")
                    self.assertNotIn(data, str(p))

    def test_not_configured_without_env(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            self.assertFalse(state_paths.configured())


class MigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._data = tempfile.TemporaryDirectory()
        self._state = tempfile.TemporaryDirectory()
        self.data = Path(self._data.name)
        self.state = Path(self._state.name)
        self.env = patch.dict("os.environ", {"CLODIA_DATA": str(self.data),
                                             "CLODIA_TOOLS_STATE_DIR": str(self.state)})
        self.env.start()

    def tearDown(self) -> None:
        self.env.stop()
        self._data.cleanup()
        self._state.cleanup()

    def test_legacy_file_is_migrated_once_and_neutralised(self) -> None:
        legacy = self.data / "clodia-tools-gate.json"
        legacy.write_text(json.dumps({"consenso": "vero"}), encoding="utf-8")

        target = state_paths.state_path("clodia-tools-gate.json")

        self.assertEqual(target, self.state / "clodia-tools-gate.json")
        self.assertEqual(json.loads(target.read_text(encoding="utf-8")),
                         {"consenso": "vero"})
        # La copia legacy resta come backup ma con nome inerte.
        self.assertFalse(legacy.exists())
        self.assertTrue((self.data / ("clodia-tools-gate.json"
                                      + state_paths.MIGRATED_SUFFIX)).is_file())

    def test_state_rewritten_on_shared_volume_is_never_read_back(self) -> None:
        """Il vettore dell'issue: riscrivere il file sulla datadir condivisa."""
        (self.data / "clodia-tools-gate.json").write_text("{}", encoding="utf-8")
        target = state_paths.state_path("clodia-tools-gate.json")
        target.write_text(json.dumps({"legittimo": True}), encoding="utf-8")

        # Un processo dell'agent-server ricrea il file legacy con stato ostile.
        (self.data / "clodia-tools-gate.json").write_text(
            json.dumps({"auto-concesso": True}), encoding="utf-8")

        again = state_paths.state_path("clodia-tools-gate.json")
        self.assertEqual(again, target)
        self.assertEqual(json.loads(again.read_text(encoding="utf-8")),
                         {"legittimo": True})

    def test_nested_store_is_migrated_with_parents(self) -> None:
        legacy = self.data / "delegations" / "active.jsonl"
        legacy.parent.mkdir(parents=True)
        legacy.write_text("{\"token\": \"x\"}\n", encoding="utf-8")

        target = state_paths.state_path("delegations/active.jsonl")

        self.assertTrue(target.is_file())
        self.assertEqual(target.read_text(encoding="utf-8"), "{\"token\": \"x\"}\n")

    def test_missing_legacy_creates_nothing(self) -> None:
        target = state_paths.state_path("clodia-tools-gate-requests.json")
        self.assertFalse(target.exists())


class BackupPerimeterTests(unittest.TestCase):
    """Isolare lo stato non deve farlo uscire dal backup restic."""

    def test_state_dir_is_a_backup_target_when_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as data, tempfile.TemporaryDirectory() as state:
            with patch.dict("os.environ", {"CLODIA_DATA": data,
                                           "CLODIA_TOOLS_STATE_DIR": state}):
                from . import backup
                self.assertIn(state, backup.backup_targets())

    def test_single_target_when_not_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as data:
            with patch.dict("os.environ", {"CLODIA_DATA": data}, clear=False):
                import os
                os.environ.pop("CLODIA_TOOLS_STATE_DIR", None)
                from . import backup
                self.assertEqual(len(backup.backup_targets()), 1)


class ModuleWiringTests(unittest.TestCase):
    """I moduli che tengono lo stato devono passare da `state_paths`."""

    def test_gate_and_delegation_paths_are_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as data, tempfile.TemporaryDirectory() as state:
            with patch.dict("os.environ", {"CLODIA_DATA": data,
                                           "CLODIA_TOOLS_STATE_DIR": state}):
                from . import delegation, gate
                for path in (gate._store_path(), gate._revoked_path(),
                             gate._req_path(), delegation._store()):
                    self.assertTrue(str(path).startswith(state), path)
                    self.assertNotIn(data, str(path))

    def test_whitelist_config_path_is_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as data, tempfile.TemporaryDirectory() as state:
            with patch.dict("os.environ", {"CLODIA_DATA": data,
                                           "CLODIA_TOOLS_STATE_DIR": state}):
                from . import whitelist
                reloaded = importlib.reload(whitelist)
                try:
                    self.assertEqual(reloaded.CONFIG_PATH,
                                     Path(state) / reloaded.CONFIG_FILENAME)
                    # Il seed dal default baked continua a funzionare.
                    self.assertTrue(reloaded.CONFIG_PATH.is_file())
                    self.assertIn("agents", reloaded.CONFIG)
                finally:
                    importlib.reload(reloaded)


if __name__ == "__main__":
    unittest.main()

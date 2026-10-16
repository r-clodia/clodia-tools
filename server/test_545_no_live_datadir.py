"""clodia-platform#545 §6 — a test run must not be able to reach the live data.

On 2026-10-14 a suite run inside an agent's scratch migrated three of the
gateway's own state files out of the colony's `/datadir` and renamed the
originals `*.migrated-to-state-dir` (clodia-platform#541). Nothing was wrong
with the migration: `state_paths.state_path` did exactly what #80 asks of it.
What was wrong is that a *test* could ask it — `CLODIA_TOOLS_STATE_DIR` pointed
at a temp dir while `CLODIA_DATA` was still the real one, because that variable
is exported in every agent's environment.

Two walls, because they fail in different places:

* the harness (`make test`) points every live-by-default path at a throw-away
  directory, UNCONDITIONALLY — `?=` would inherit exactly the value that caused
  the incident;
* `state_paths` refuses the migration when the process is a test runner: the
  damaging half happens at IMPORT time (`whitelist.CONFIG_PATH`), i.e. before
  any test, any `setUp` or any guard assertion can run.
"""
from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import state_paths

_REPO = Path(__file__).resolve().parent.parent

#: Env → percorso che il codice userebbe se nessuno la imposta. Sono tutti
#: dentro la datadir VERA della colonia: se esistono su questa macchina, la
#: suite non deve poterli toccare.
LIVE_DEFAULTS = {
    "CLODIA_DATA": "/datadir",
    "CLODIA_TOPICS_ROOT": "/datadir/clodia-vault/topics-store",
    "CLODIA_SPAWNS_ROOT": "/datadir/spawns",
    "CLODIA_PKI_CERTS": "/datadir/pki/certs",
    "CLODIA_PKI_REVOKED": "/datadir/pki/revoked.json",
    "CLODIA_SECRETS_DIR": "/datadir/secrets",
}


def _c_e(path: str) -> bool:
    """`Path.exists()` che non esplode su una directory non leggibile.

    Proprio il caso che conta: dentro lo scratch di un agente
    `/datadir/clodia-vault/topics-store` c'è ma non è attraversabile, e
    `exists()` alza `PermissionError`. Un permesso negato dice che quel
    percorso ESISTE e non è nostro — la risposta prudente è «vivo».
    """
    try:
        return Path(path).exists()
    except OSError:
        return True


class HarnessIsolationTests(unittest.TestCase):
    """`make test` è l'unico modo in cui questa suite va eseguita (decision
    record 34): è lì che l'isolamento deve essere scritto."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.makefile = (_REPO / "Makefile").read_text(encoding="utf-8")

    def _export(self, var: str) -> str:
        m = re.search(rf"^export\s+{var}\s*(\?=|:=|=)\s*(.+)$",
                      self.makefile, re.M)
        self.assertIsNotNone(m, f"{var} non è esportata da make test")
        assert m is not None
        self.assertNotEqual(
            "?=", m.group(1),
            f"{var} usa `?=`: in uno scratch di agente quella variabile È già "
            f"impostata sulla datadir vera, e `?=` la eredita (clodia-platform"
            f"#541). Serve `:=`.")
        return m.group(2).strip()

    def test_every_live_default_is_overridden_by_make_test(self) -> None:
        for var in list(LIVE_DEFAULTS) + ["CLODIA_TOOLS_STATE_DIR",
                                          "CLODIA_AUDIT_DIR",
                                          "CLODIA_AUDIT_KEY_DIR",
                                          "CLODIA_VAULT_DIR"]:
            with self.subTest(var=var):
                valore = self._export(var)
                self.assertNotIn("/datadir", valore)
                self.assertTrue(
                    valore.startswith("$(TEST_"),
                    f"{var}={valore}: deve stare sotto la dir usa e getta")

    def test_the_list_of_live_defaults_is_the_one_the_code_has(self) -> None:
        """L'elenco qui sopra non è una memoria: è ricavato dal sorgente.

        «Audit every test» (clodia-platform#545 §6) scritto una volta sola: la
        variabile che QUALCUNO aggiungerà domani con un default sotto
        `/datadir` arriva qui rossa, invece di arrivare in produzione come un
        secondo #541. Il rimedio che il rosso chiede è una riga di Makefile.
        """
        pattern = re.compile(
            r'environ\.get\(\s*"(CLODIA_[A-Z_]+)"\s*(?:,|\)\s*or)\s*"(/datadir[^"]*)"')
        trovate: dict[str, str] = {}
        for sorgente in sorted((_REPO / "server").rglob("*.py")):
            if sorgente.name.startswith("test_"):
                continue
            for var, default in pattern.findall(
                    sorgente.read_text(encoding="utf-8")):
                trovate.setdefault(var, default)
        self.assertTrue(trovate, "lo scan non ha trovato nulla: regex rotta")
        self.assertEqual(
            sorted(trovate), sorted(LIVE_DEFAULTS),
            "LIVE_DEFAULTS non coincide con i default sotto /datadir che il "
            "codice ha davvero: aggiungi la variabile qui E in `make test`")
        for var, default in trovate.items():
            with self.subTest(var=var):
                self.assertEqual(LIVE_DEFAULTS[var], default)


class LiveDatadirTests(unittest.TestCase):
    def test_the_suite_is_not_running_against_a_live_datadir(self) -> None:
        """Rosso SOLO dove il pericolo esiste: su un runner `/datadir` non c'è.

        Se questo test fallisce non è il codice: è l'ambiente. `make test`, o
        le stesse variabili a mano su una directory usa e getta.
        """
        for var, default in LIVE_DEFAULTS.items():
            with self.subTest(var=var):
                corrente = os.environ.get(var) or default
                self.assertFalse(
                    _c_e(default) and Path(corrente).resolve() == Path(default).resolve(),
                    f"{var} punta a {corrente}, che su questa macchina è la "
                    f"datadir VERA della colonia: usa `make test`")


class MigrationNeedsAnOwningProcessTests(unittest.TestCase):
    """La migrazione #80 sposta stato VIVO: la fa il gateway, non un test."""

    def setUp(self) -> None:
        self._data = tempfile.TemporaryDirectory()
        self._state = tempfile.TemporaryDirectory()
        self.addCleanup(self._data.cleanup)
        self.addCleanup(self._state.cleanup)
        self.data = Path(self._data.name)
        self.state = Path(self._state.name)
        env = patch.dict(os.environ, {"CLODIA_DATA": str(self.data),
                                      "CLODIA_TOOLS_STATE_DIR": str(self.state)})
        env.start()
        self.addCleanup(env.stop)
        self.legacy = self.data / "clodia-tools-gate.json"
        self.legacy.write_text(json.dumps({"consenso": "vero"}), encoding="utf-8")

    def test_a_test_run_does_not_touch_the_legacy_state(self) -> None:
        self.assertIn("unittest", sys.modules)  # è esattamente questo processo
        target = state_paths.state_path("clodia-tools-gate.json")
        self.assertFalse(target.exists(), "copiato lo stato legacy da un test")
        self.assertTrue(self.legacy.is_file(), "stato legacy rinominato da un test")
        self.assertFalse((self.data / ("clodia-tools-gate.json"
                                       + state_paths.MIGRATED_SUFFIX)).exists())

    def test_the_owning_process_says_so_and_migrates(self) -> None:
        with patch.dict(os.environ, {state_paths.MIGRATE_ENV: "1"}):
            target = state_paths.state_path("clodia-tools-gate.json")
        self.assertEqual(json.loads(target.read_text(encoding="utf-8")),
                         {"consenso": "vero"})
        self.assertFalse(self.legacy.exists())

    def test_the_path_is_the_same_either_way(self) -> None:
        """Il percorso non dipende dalla migrazione: solo lo spostamento."""
        self.assertEqual(state_paths.state_path("clodia-tools-gate.json"),
                         self.state / "clodia-tools-gate.json")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

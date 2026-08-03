"""Tests for observe mode (`CLODIA_DANGEROUSLY_SKIP_GATES`).

Two things must hold, and the second is the one that would quietly ruin the
experiment: the switch must be hard to turn on by accident, and observing must
not CHANGE anything — in particular it must not populate the whitelist, or the
return to enforcement would find everything already allowed.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import observe, telemetry


class SwitchTests(unittest.TestCase):
    def test_it_is_off_by_default(self):
        with patch.dict("os.environ", {}, clear=True):
            self.assertFalse(observe.skipping())

    def test_only_explicit_truthy_values_turn_it_on(self):
        for v in ("1", "true", "TRUE", "yes", "on"):
            with self.subTest(v=v), patch.dict("os.environ", {observe._ENV: v}):
                self.assertTrue(observe.skipping())
        for v in ("0", "false", "no", "off", "", "maybe", "report"):
            with self.subTest(v=v), patch.dict("os.environ", {observe._ENV: v}):
                self.assertFalse(observe.skipping())

    def test_turning_it_on_warns_once(self):
        """Uno stato che disattiva la supervisione umana non deve poter essere in
        vigore senza lasciare traccia nei log."""
        observe._warned = False
        with patch.dict("os.environ", {observe._ENV: "1"}), \
             self.assertLogs("clodia-tools.observe", level="WARNING") as cm:
            observe.skipping()
        self.assertIn("NON bloccano", cm.output[0])
        observe._warned = False


class RecordTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.f = Path(self.tmp.name) / "verbs.jsonl"
        p = patch.object(telemetry, "_path", side_effect=lambda: self.f)
        p.start()
        self.addCleanup(p.stop)

    def _rows(self):
        return [json.loads(l) for l in self.f.read_text().splitlines() if l.strip()]

    def test_a_gate_is_recorded_as_would_gate(self):
        with patch("server.whitelist.current_chat", return_value="chan:SEAL-1:x:clodia"):
            observe.note("gate", "email.send", "clodia", detail="canale contaminato")
        r = self._rows()[0]
        self.assertEqual(r["outcome"], "would_gate")
        self.assertEqual(r["verb"], "email.send")
        self.assertTrue(r["gated"])

    def test_a_deny_is_recorded_as_would_deny(self):
        with patch("server.whitelist.current_chat", return_value=None):
            observe.note("deny", "mcp.add", "clodia", detail="denied_tools")
        self.assertEqual(self._rows()[0]["outcome"], "would_deny")

    def test_stats_answer_which_controls_would_have_fired(self):
        with patch("server.whitelist.current_chat", return_value=None):
            observe.note("deny", "email.send", "clodia", detail="egress:email")
            observe.note("deny", "email.send", "clodia", detail="egress:email")
            observe.note("gate", "egress-context:SEAL-1/x:ab", "messaggero",
                         detail="contaminato")
        st = telemetry.stats()
        w = st["would_have_fired"]
        self.assertEqual(w["total"], 3)
        self.assertEqual(w["by_agent"], {"clodia": 2, "messaggero": 1})
        self.assertEqual(w["by_verb"]["email.send"], 2)

    def test_recording_never_raises(self):
        with patch.object(telemetry, "record", side_effect=RuntimeError("boom")):
            observe.note("gate", "email.send", "clodia")   # non deve sollevare


if __name__ == "__main__":
    unittest.main()


class EgressCoherenceTests(unittest.TestCase):
    """La whitelist di destinazione deve decidere `report` quando l'osservazione
    è attiva: due punti che decidono la stessa cosa divergono al primo refactor."""

    def test_gate_and_on_both_degrade_to_report(self):
        from . import egress
        for declared in ("gate", "on"):
            with self.subTest(declared=declared), \
                 patch.dict("os.environ", {"CLODIA_EGRESS_ENFORCE": declared,
                                           observe._ENV: "1"}):
                v = egress.check("clodia", {}, "email.send", {"to": "x@y.it"})
                self.assertEqual(v["action"], "allow")
                self.assertTrue(v["would_deny"])
                self.assertEqual(v["applied_mode"], "report")
                self.assertEqual(v["mode"], declared)   # il dichiarato resta leggibile

    def test_without_the_switch_it_still_gates(self):
        from . import egress
        with patch.dict("os.environ", {"CLODIA_EGRESS_ENFORCE": "gate"},
                        clear=False), patch.dict("os.environ", {observe._ENV: "0"}):
            self.assertEqual(
                egress.check("clodia", {}, "email.send", {"to": "x@y.it"})["action"],
                "gate")

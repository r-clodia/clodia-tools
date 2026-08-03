"""Tests for the verb register (clodia-platform#110).

Two invariants, and they are the reason the file exists rather than nice-to-haves:
it must never contain arguments, and it must never break the turn it measures.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import telemetry


class TelemetryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.f = Path(self.tmp.name) / "verbs.jsonl"
        p = patch.object(telemetry, "_path", side_effect=lambda: self.f)
        p.start()
        self.addCleanup(p.stop)

    def _rows(self):
        return [json.loads(l) for l in self.f.read_text().splitlines() if l.strip()]

    def test_a_row_carries_metadata_and_nothing_else(self):
        telemetry.record("email.send", "messaggero", "ok",
                         channel="chan:SEAL-1:x:messaggero", egress_type="email")
        r = self._rows()[0]
        self.assertEqual({"at", "verb", "agent", "outcome", "channel", "egress"},
                         set(r))

    def test_absent_flags_are_omitted_not_written_as_false(self):
        """Il file si legge a occhio: righe piene di `false` nascondono quelle che
        contano."""
        telemetry.record("topic.open", "clodia", "ok")
        self.assertEqual({"at", "verb", "agent", "outcome"}, set(self._rows()[0]))

    def test_the_reason_is_truncated_and_is_a_class_not_a_message(self):
        telemetry.record("email.send", "clodia", "denied", detail="x" * 200)
        self.assertLessEqual(len(self._rows()[0]["why"]), 40)

    def test_it_never_raises_even_if_the_file_is_unwritable(self):
        """Una misura che rompe il turno che sta misurando è peggio della misura
        mancante."""
        with patch.object(telemetry, "_path",
                          side_effect=lambda: Path("/proc/non/scrivibile/x.jsonl")):
            telemetry.record("email.send", "clodia", "ok")   # non deve sollevare

    def test_off_writes_nothing(self):
        with patch.dict("os.environ", {"CLODIA_VERB_LOG": "off"}):
            telemetry.record("email.send", "clodia", "ok")
        self.assertFalse(self.f.exists())

    def test_it_is_on_by_default(self):
        """Un registro opt-in non esiste il giorno che serve."""
        with patch.dict("os.environ", {}, clear=True):
            self.assertTrue(telemetry.enabled())

    def test_stats_answer_what_an_agent_actually_uses(self):
        for _ in range(3):
            telemetry.record("web.fetch", "clodia", "ok", tainted=True)
        telemetry.record("email.send", "clodia", "denied", detail="egress")
        telemetry.record("topic.open", "messaggero", "denied", detail="unattended",
                         unattended=True)
        st = telemetry.stats()
        self.assertEqual(st["rows"], 5)
        self.assertEqual(st["by_verb"]["web.fetch"], 3)
        self.assertEqual(st["by_agent"]["clodia"], 4)
        self.assertEqual(st["by_outcome"], {"ok": 3, "denied": 2})
        self.assertEqual(st["denied_by_reason"], {"egress": 1, "unattended": 1})
        self.assertEqual(st["in_tainted_channel"], 3)
        self.assertEqual(st["unattended"], 1)

    def test_stats_on_an_empty_register_do_not_explode(self):
        st = telemetry.stats()
        self.assertEqual(st["rows"], 0)
        self.assertIsNone(st["first_at"])

    def test_a_corrupt_line_is_skipped_not_fatal(self):
        telemetry.record("web.fetch", "clodia", "ok")
        with open(self.f, "a") as f:
            f.write("questa non e' json\n")
        telemetry.record("email.send", "clodia", "ok")
        self.assertEqual(telemetry.stats()["rows"], 2)


if __name__ == "__main__":
    unittest.main()

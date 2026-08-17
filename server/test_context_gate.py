"""Tests for the context gate decision (clodia-platform#104 §6, step 8).

The unit under test is `_context_gate_needed`: WHEN the gate must fire. Getting
this wrong in either direction defeats the whole model — firing always produces
consent fatigue, and skipping when nobody is watching is the "zero controls"
counter-example of #77 condition 2.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import main, taint


class ContextGateTests(unittest.TestCase):
    CHAT = "chan:SEAL-1:contract:clodia#2"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        for pt in (patch.object(taint, "_path",
                                side_effect=lambda: Path(self.tmp.name) / "t.json"),
                   patch("server.whitelist.current_chat", return_value=self.CHAT),
                   patch.object(main, "_channel_participants",
                                return_value=["clodia", "davide"])):
            pt.start()
            self.addCleanup(pt.stop)

    def _need(self, verb, verdict=None):
        return main._context_gate_needed(verb, "clodia", verdict or {"action": "allow"})

    def test_a_non_egress_verb_never_gates(self):
        taint.mark(self.CHAT, "verb", "web.fetch")
        key, _ = self._need("topic.open")
        self.assertIsNone(key)

    def test_a_clean_channel_does_not_gate(self):
        """#77 condition 1: the taint is what makes the gate usable instead of
        omnipresent. On capability alone it would fire on 150 channels of 156,
        and a gate approved by reflex is worse than no gate."""
        key, _ = self._need("email.send")
        self.assertIsNone(key)

    def test_a_tainted_channel_gates_an_egress_verb(self):
        taint.mark(self.CHAT, "verb", "web.fetch", "clodia")
        key, reason = self._need("email.send")
        self.assertTrue(key.startswith("egress-context:SEAL-1/contract:"))
        # the dialog must name the source, or the human declassifies blind
        self.assertIn("web.fetch", reason)
        self.assertIn("CONTAMINATO", reason)
        self.assertIn("declassificato", reason)

    def test_it_does_not_double_gate_when_the_destination_already_asks(self):
        """The destination gate already puts this very call in front of a human.
        A second dialog on the same send is consent fatigue, not more control."""
        taint.mark(self.CHAT, "verb", "web.fetch")
        key, _ = self._need("email.send", {"action": "gate"})
        self.assertIsNone(key)

    def test_a_whitelisted_destination_is_perimeter_and_does_not_gate(self):
        """The owner's rule, 17 Aug 2026:

            «se la destinazione è censita in whitelist allora va considerata come
             parte del perimetro e non deve essere un segnale che fa scattare il
             gate o incrementare il trifecta»

        This test asserted the OPPOSITE until today, on the reading that a
        whitelisted destination means nobody is watching. Measured consequence on
        `fullstack-dev`: whitelisting `github.com/r-clodia/*` did not silence
        anything — it made this gate mandatory. The work cycle re-armed it by
        itself (`github.issue_read` taints, `github.push` exits), so every single
        cycle cost one approval. A gate that fires every round is approved by
        reflex, which is the failure #77 condition 1 exists to avoid.
        """
        taint.mark(self.CHAT, "verb", "email.read")
        key, _ = self._need("email.send",
                            {"action": "allow", "checked": True, "allowed": True})
        self.assertIsNone(key)

    def test_report_mode_still_gates_because_nothing_was_declared(self):
        """`would_deny`: the destination is NOT in the list — it simply was not
        blocked. There is no declaration of perimeter to honour here, and nobody
        is watching: this is the case condition 2 was really written for."""
        taint.mark(self.CHAT, "verb", "email.read")
        key, _ = self._need("email.send",
                            {"action": "allow", "checked": True, "allowed": False,
                             "would_deny": True})
        self.assertIsNotNone(key)

    def test_an_unchecked_type_still_gates(self):
        """`checked: False` — mode `off`, or a type with no rules at all. The
        absence of confinement is not a perimeter: reading it as one would turn
        "we control nothing" into "everything is declared safe"."""
        taint.mark(self.CHAT, "verb", "email.read")
        key, _ = self._need("email.send", {"action": "allow", "checked": False})
        self.assertIsNotNone(key)

    def test_every_egress_type_is_covered_not_just_email(self):
        taint.mark(self.CHAT, "verb", "web.fetch")
        for verb in ("email.send", "telegram.send", "web.post",
                     "gdrive.upload", "gsheets.write_range",
                     "github.create_pull_request"):
            with self.subTest(verb=verb):
                self.assertIsNotNone(self._need(verb)[0])

    def test_the_key_changes_with_the_composition(self):
        """An unlock granted at two participants must not survive a third
        arriving with outbound verbs (#77)."""
        taint.mark(self.CHAT, "verb", "web.fetch")
        k2, _ = self._need("email.send")
        with patch.object(main, "_channel_participants",
                          return_value=["clodia", "davide", "messaggero"]):
            k3, _ = self._need("email.send")
        self.assertNotEqual(k2, k3)


if __name__ == "__main__":
    unittest.main()

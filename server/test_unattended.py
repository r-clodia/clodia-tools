"""Tests for the unattended-session block (clodia-platform#104, jobs).

Decision of 2 Aug 2026: "for async jobs a total block, no access to topic data,
the only possibility is invoking topic hooks to send information."

The reason a job is not defended by gates like a chat is that **nobody can
answer**. A gate in an unattended session is not a protection, it is a stall
until timeout — the lesson of #116, where boot reconciliation attempted gated
verbs with no channel and produced dozens of out-of-context popups.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import egress, main


class UnattendedTopicBlockTests(unittest.TestCase):
    def _deny(self, verb, unattended=True):
        with patch("server.main.is_unattended", return_value=unattended):
            return main._unattended_denial(verb)

    def test_topic_data_verbs_are_denied_in_a_job(self):
        for verb in ("topic.open", "topic.files", "topic.read_file",
                     "topic.read_document", "topic.fetch", "topic.search",
                     "topic.list", "topic.save_summary", "topic.put"):
            with self.subTest(verb=verb):
                msg = self._deny(verb)
                self.assertIsNotNone(msg)
                # the message must point at the one thing that IS allowed
                self.assertIn("topic.invoke_hook", msg)

    def test_invoke_hook_is_the_one_verb_that_passes(self):
        """Sending information to a topic does not read, list or download."""
        self.assertIsNone(self._deny("topic.invoke_hook"))

    def test_nothing_is_denied_in_an_attended_session(self):
        for verb in ("topic.open", "topic.read_file"):
            with self.subTest(verb=verb):
                self.assertIsNone(self._deny(verb, unattended=False))

    def test_non_topic_verbs_are_not_touched_by_this_rule(self):
        """The block is about topic DATA. Other namespaces are governed by the
        whitelist and by egress, and conflating them here would hide which rule
        refused what."""
        for verb in ("email.send", "web.fetch", "fs.list_dir"):
            with self.subTest(verb=verb):
                self.assertIsNone(self._deny(verb))


class UnattendedEgressTests(unittest.TestCase):
    def test_gate_becomes_deny_when_nobody_can_answer(self):
        with patch.dict("os.environ", {"CLODIA_EGRESS_ENFORCE": "gate"}):
            v = egress.check("clodia", {}, "email.send", {"to": "x@y.it"},
                             unattended=True)
        self.assertEqual(v["action"], "deny")
        self.assertEqual(v["mode"], "gate")   # il modo dichiarato resta leggibile

    def test_the_same_call_from_a_chat_asks_instead(self):
        with patch.dict("os.environ", {"CLODIA_EGRESS_ENFORCE": "gate"}):
            v = egress.check("clodia", {}, "email.send", {"to": "x@y.it"},
                             unattended=False)
        self.assertEqual(v["action"], "gate")

    def test_a_whitelisted_destination_still_works_in_a_job(self):
        """Il blocco non rende i job inutili: una destinazione già approvata da
        un umano passa, ed è il modo previsto per farli funzionare."""
        # whitelist GLOBALE in notazione URI (#128): la destinazione è approvata
        # o non lo è, e non dipende da chi spedisce.
        from . import whitelist as wl
        cfg = {"agents": {}, "egress_allow": ["mailto:*@tomato.blue"]}
        with patch.dict("os.environ", {"CLODIA_EGRESS_ENFORCE": "gate"}), \
                patch.object(wl, "CONFIG", cfg):
            v = egress.check("clodia", {}, "email.send",
                             {"to": "chi@tomato.blue"}, unattended=True)
        self.assertEqual(v["action"], "allow")

    def test_report_mode_is_unaffected(self):
        """`report` non blocca per definizione: non c'è nulla da convertire."""
        with patch.dict("os.environ", {"CLODIA_EGRESS_ENFORCE": "report"}):
            v = egress.check("clodia", {}, "email.send", {"to": "x@y.it"},
                             unattended=True)
        self.assertEqual(v["action"], "allow")


if __name__ == "__main__":
    unittest.main()

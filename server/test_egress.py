"""Tests for the destination whitelist (clodia-platform#104 §7, step 5).

The three properties of §7 that can actually be broken by a refactor are the
DENY defaults — an empty rule set, an unmodelled type, an unreadable
destination. Each has its own test, because each one silently becoming "allow"
is the failure that would make the whole whitelist decorative.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import egress


def _cfg(**allow):
    return {"egress_allow": allow} if allow else {}


class ExtractorTests(unittest.TestCase):
    def test_email_reads_to_cc_and_bcc_and_splits_multiple(self):
        v = egress.decide(_cfg(email=["*"]), "email.send",
                          {"to": "A@Tomato.blue, b@x.it", "cc": "c@y.it"})
        self.assertEqual(v["destinations"], ["a@tomato.blue", "b@x.it", "c@y.it"])

    def test_http_destination_is_the_host_not_the_url(self):
        v = egress.decide(_cfg(http=["*"]), "web.post",
                          {"url": "https://Example.COM/a/b?c=1"})
        self.assertEqual(v["destinations"], ["example.com"])

    def test_github_write_verbs_resolve_to_owner_slash_repo(self):
        v = egress.decide(_cfg(github=["*"]), "github.create_pull_request",
                          {"owner": "r-clodia", "repo": "clodia-logic"})
        self.assertEqual(v["destinations"], ["r-clodia/clodia-logic"])

    def test_github_read_verbs_are_not_egress_at_all(self):
        v = egress.decide({}, "github.list_issues", {"owner": "a", "repo": "b"})
        self.assertFalse(v["checked"])
        self.assertTrue(v["allowed"])

    def test_a_verb_outside_the_table_is_not_checked_here(self):
        v = egress.decide({}, "topic.open", {"tier": "SEAL-1", "name": "x"})
        self.assertFalse(v["checked"])


class DenyDefaultTests(unittest.TestCase):
    """The three deny-by-default rules. Each one is the whole point."""

    def test_an_unmodelled_type_is_denied_not_free(self):
        """§7 property 6. Otherwise the arrival of a pack bypasses the whitelist:
        a new connector type has no rules, and 'no rules → pass' means no
        whitelist at all for anything new."""
        v = egress.decide(_cfg(email=["@tomato.blue"]), "telegram.send",
                          {"chat_id": "76632169"})
        self.assertFalse(v["allowed"])
        self.assertIsNone(v["rules"])
        self.assertIn("telegram", v["reason"])

    def test_a_declared_but_empty_type_is_muted(self):
        """§7 property 1: default empty = no egress. Kept distinct from the case
        above so an operator can tell 'never configured' from 'deliberately
        muted' — they call for opposite actions."""
        v = egress.decide(_cfg(email=[]), "email.send", {"to": "x@y.it"})
        self.assertFalse(v["allowed"])
        self.assertIn("vuota", v["reason"])

    def test_an_unreadable_destination_is_denied(self):
        """`email.reply` carries no recipient: it comes from the message being
        replied to, i.e. from untrusted content. 'Attacker mails in, agent
        replies with the data' is the injection path, so a destination that
        cannot be read from the call must not pass."""
        v = egress.decide(_cfg(email=["@tomato.blue"]), "email.reply",
                          {"email_id": "42", "body": "..."})
        self.assertFalse(v["allowed"])
        self.assertEqual(v["destinations"], [egress.UNKNOWN])

    def test_an_explicit_star_opens_a_type_including_unknown_destinations(self):
        """The opt-out must be explicit and visible in the rules, not implied."""
        v = egress.decide(_cfg(email=["*"]), "email.reply", {"email_id": "42"})
        self.assertTrue(v["allowed"])


class MatchingTests(unittest.TestCase):
    def test_domain_rule_covers_every_address_of_that_domain(self):
        cfg = _cfg(email=["@tomato.blue"])
        self.assertTrue(egress.decide(cfg, "email.send", {"to": "chi@tomato.blue"})["allowed"])
        self.assertFalse(egress.decide(cfg, "email.send", {"to": "chi@tomato.blue.evil.it"})["allowed"])

    def test_exact_rule_is_case_insensitive_but_not_a_prefix(self):
        cfg = _cfg(email=["d.carboni@gmail.com"])
        self.assertTrue(egress.decide(cfg, "email.send", {"to": "D.Carboni@Gmail.com"})["allowed"])
        self.assertFalse(egress.decide(cfg, "email.send", {"to": "d.carboni@gmail.com.evil.it"})["allowed"])

    def test_one_refused_recipient_refuses_the_whole_call(self):
        """A partial send is not a thing: the message goes to every recipient at
        once, so one destination outside the whitelist denies the call."""
        v = egress.decide(_cfg(email=["@tomato.blue"]), "email.send",
                          {"to": "ok@tomato.blue", "cc": "fuori@altrove.it"})
        self.assertFalse(v["allowed"])
        self.assertEqual(v["refused"], ["fuori@altrove.it"])


class ModeTests(unittest.TestCase):
    def _enforce(self, mode, cfg, verb, args):
        with patch.dict("os.environ", {"CLODIA_EGRESS_ENFORCE": mode}):
            return egress.enforce("messaggero", cfg, verb, args)

    def test_report_allows_and_marks_would_deny(self):
        """The default mode. It must NOT block: switching a live instance
        straight to `on` would mute every agent at once, and the real
        destination set is learned from real traffic."""
        v = self._enforce("report", {}, "email.send", {"to": "x@y.it"})
        self.assertTrue(v["allowed"])
        self.assertTrue(v["would_deny"])

    def test_on_raises_for_a_denied_destination(self):
        with self.assertRaises(PermissionError) as cm:
            self._enforce("on", _cfg(email=["@tomato.blue"]), "email.send",
                          {"to": "fuori@altrove.it"})
        # the message must say WHERE to fix it, not just that it failed
        self.assertIn("egress_allow.email", str(cm.exception))

    def test_on_allows_a_whitelisted_destination(self):
        v = self._enforce("on", _cfg(email=["@tomato.blue"]), "email.send",
                          {"to": "chi@tomato.blue"})
        self.assertTrue(v["allowed"])

    def test_off_skips_the_check_entirely(self):
        v = self._enforce("off", {}, "email.send", {"to": "x@y.it"})
        self.assertFalse(v["checked"])

    def test_an_unknown_mode_falls_back_to_report_not_to_off(self):
        """A typo in the env var must not silently disable the whitelist."""
        with patch.dict("os.environ", {"CLODIA_EGRESS_ENFORCE": "enforce"}):
            self.assertEqual(egress.mode(), "report")


if __name__ == "__main__":
    unittest.main()

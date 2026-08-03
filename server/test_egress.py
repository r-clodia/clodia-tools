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


class ReplyRecipientTests(unittest.TestCase):
    """`email.reply` — il destinatario viene dal messaggio, non dalla chiamata."""

    def test_address_is_extracted_from_a_from_header(self):
        for header, want in (
            ("Mario Rossi <mario@x.it>", "mario@x.it"),
            ("  <A@B.IT> ", "a@b.it"),
            ("plain@z.it", "plain@z.it"),
            ('"Chi Sa" <chi@sa.it>', "chi@sa.it"),
        ):
            with self.subTest(header=header):
                self.assertEqual(egress.address_of(header), want)

    def test_a_header_without_an_address_yields_nothing(self):
        """Vuoto → destinazione ignota → nega. Non sapere a chi si risponde non
        è una buona ragione per procedere."""
        for header in ("", "Mario Rossi", "<>", None):
            self.assertEqual(egress.address_of(header), "")

    def test_a_resolved_recipient_is_checked_like_any_other(self):
        """Risolto il destinatario, `email.reply` non è più un caso speciale."""
        cfg = _cfg(email=["@tomato.blue"])
        v = egress.decide(cfg, "email.reply", {"email_id": "1", "to": "chi@tomato.blue"})
        self.assertTrue(v["allowed"])
        v = egress.decide(cfg, "email.reply", {"email_id": "1", "to": "chi@altrove.it"})
        self.assertFalse(v["allowed"])
        self.assertEqual(v["refused"], ["chi@altrove.it"])


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
    def _check(self, mode, cfg, verb, args):
        with patch.dict("os.environ", {"CLODIA_EGRESS_ENFORCE": mode}):
            return egress.check("messaggero", cfg, verb, args)

    def test_gate_is_the_default_and_asks_instead_of_refusing(self):
        """The decision of 3 Aug 2026: start with an empty whitelist and populate
        it through use. An unvetted address is neither refused nor allowed
        silently — it is ASKED."""
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(egress.mode(), "gate")
        v = self._check("gate", {}, "email.send", {"to": "terzo@esterno.it"})
        self.assertEqual(v["action"], "gate")
        self.assertEqual(v["gate_key"], "egress:email:terzo@esterno.it")
        self.assertEqual(v["remember"], ["terzo@esterno.it"])

    def test_the_gate_dialog_says_the_destination_will_be_remembered(self):
        """§7 property 2: adding a destination is more privileged than the single
        send, because it makes it silent forever. If approval populates the
        whitelist, the human must learn it FROM the dialog — otherwise they grant
        a permanent permission believing they authorised one message."""
        v = self._check("gate", {}, "email.send", {"to": "terzo@esterno.it"})
        r = v["gate_reason"]
        self.assertIn("terzo@esterno.it", r)
        self.assertIn("whitelist", r)
        self.assertIn("non chiederanno più", r)

    def test_gate_refuses_when_the_destination_cannot_be_read(self):
        """There is nothing to show in a dialog and nothing to remember: an
        `email.reply` whose recipient comes from the incoming message cannot be
        approved by address. The explicit `*` on the type stays the way out."""
        v = self._check("gate", {}, "email.reply", {"email_id": "42"})
        self.assertEqual(v["action"], "deny")

    def test_a_whitelisted_destination_does_not_gate(self):
        v = self._check("gate", _cfg(email=["@tomato.blue"]), "email.send",
                        {"to": "chi@tomato.blue"})
        self.assertEqual(v["action"], "allow")

    def test_report_allows_and_marks_would_deny(self):
        v = self._check("report", {}, "email.send", {"to": "x@y.it"})
        self.assertEqual(v["action"], "allow")
        self.assertTrue(v["would_deny"])

    def test_on_denies_without_asking(self):
        """The right mode where nobody can answer: an unattended job that hits a
        gate stalls until the request times out (#116)."""
        v = self._check("on", _cfg(email=["@tomato.blue"]), "email.send",
                        {"to": "fuori@altrove.it"})
        self.assertEqual(v["action"], "deny")
        # the error must say WHERE to fix it, not just that it failed
        self.assertIn("egress_allow.email", str(egress.denied_error("x", v)))

    def test_off_skips_the_check_entirely(self):
        v = self._check("off", {}, "email.send", {"to": "x@y.it"})
        self.assertFalse(v["checked"])
        self.assertEqual(v["action"], "allow")

    def test_an_unknown_mode_falls_back_to_gate_not_to_off(self):
        """A typo in the env var must not silently disable the whitelist."""
        with patch.dict("os.environ", {"CLODIA_EGRESS_ENFORCE": "enforce"}):
            self.assertEqual(egress.mode(), "gate")


class RememberTests(unittest.TestCase):
    """Approval populates the whitelist — in the GATEWAY's config."""

    def setUp(self):
        # `remember` fa `from . import whitelist`, che risolve l'ATTRIBUTO del
        # package e non `sys.modules`: un fake iniettato in sys.modules verrebbe
        # ignorato, i test userebbero il modulo vero e — scoperto sbagliando —
        # `save_config()` scriverebbe sul config.yaml del repo. Si patchano
        # quindi CONFIG e save_config sul modulo reale.
        from . import whitelist as wl
        self.cfg = {"agents": {"messaggero": {"allowed_tools": ["email.*"]}}}
        self.saves = 0
        for pt in (patch.object(wl, "CONFIG", self.cfg),
                   patch.object(wl, "save_config", self._saved)):
            pt.start()
            self.addCleanup(pt.stop)

    def _saved(self):
        self.saves += 1

    def test_an_approved_destination_is_added_and_persisted(self):
        rules = egress.remember("messaggero", "email", ["terzo@esterno.it"])
        self.assertEqual(rules, ["terzo@esterno.it"])
        self.assertEqual(
            self.cfg["agents"]["messaggero"]["egress_allow"]["email"],
            ["terzo@esterno.it"])
        self.assertEqual(self.saves, 1)

    def test_remembering_twice_does_not_duplicate(self):
        egress.remember("messaggero", "email", ["a@b.it"])
        rules = egress.remember("messaggero", "email", ["a@b.it"])
        self.assertEqual(rules, ["a@b.it"])

    def test_the_unknown_sentinel_is_never_remembered(self):
        """Writing "?" into a whitelist would open every unreadable destination
        for good — the opposite of what the deny was for."""
        self.assertEqual(egress.remember("messaggero", "email", [egress.UNKNOWN]), [])
        self.assertNotIn("egress_allow", self.cfg["agents"]["messaggero"])


if __name__ == "__main__":
    unittest.main()

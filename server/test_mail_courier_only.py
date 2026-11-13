"""Reading mail is the courier's alone (owner, 14 Nov 2026).

«nessun agente deve poter usare verbi per leggere l'email, questa resta una
funzione a disposizione del solo corriere … possono chiedere un reload di posta
e messaggi al corriere che fa un check immediato».
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from server import authz as A
from server import authz_runtime as R
from server import authz_shadow as S


class PlatformDenyTests(unittest.TestCase):
    def _decide(self, verb, g_extra=(), t=None):
        g = S.platform_tuples() + list(g_extra)
        return A.decide(g, t, agent="clodia", verb=verb, resource="mail:default",
                        targets=[], kind=A.READ, tainted=False).effect

    def test_every_email_verb_is_denied_to_every_agent(self):
        for verb in ("email.read", "email.list", "email.search", "email.send",
                     "email.save_attachment"):
            self.assertEqual(self._decide(verb), A.DENY, verb)

    def test_an_admin_allow_does_not_lift_it(self):
        allow, _ = A.parse_tuples([{"id": "g-allow", "agent": "*", "verb": "email.*",
                                    "resource": "*", "rule": [{"effect": "allow", "match": "*"}]}])
        self.assertEqual(self._decide("email.read", allow), A.DENY)

    def test_a_room_that_enables_email_does_not_lift_it(self):
        room, _ = A.parse_tuples([{"id": "toolbox:email.*", "agent": "*", "verb": "email.*",
                                   "resource": "*", "rule": [{"effect": A.DEFAULT}]}],
                                 level=A.TOPIC, internal=True)
        self.assertEqual(self._decide("email.read", t=room), A.DENY)

    def test_other_verbs_are_untouched(self):
        """A rule allowing `channel.deliver` (how a room replies by mail) still
        allows it next to the platform rule."""
        allow, _ = A.parse_tuples([{"id": "g-deliver", "agent": "*", "verb": "channel.deliver",
                                    "resource": "*", "rule": [{"effect": "allow", "match": "*"}]}])
        self.assertEqual(self._decide("channel.deliver", allow), A.ALLOW)

    def test_the_rule_is_in_force_where_decisions_are_taken(self):
        R.invalidate()
        with patch.object(S, "global_tuples", lambda: ([], [])):
            g, _t = R.tuples_for("clodia", None)
        self.assertIn("platform-email-courier-only", [x.id for x in g])
        R.invalidate()

    def test_it_does_not_count_as_an_applied_plan(self):
        with patch.object(S, "_global_path",
                          lambda: __import__("pathlib").Path("/nonexistent/authz.json")):
            self.assertEqual(S.global_tuples(), ([], []))


class MailCheckVerbTests(unittest.TestCase):
    """`topic.mail_check`: a member asks the courier to check the room now."""

    def _run(self, member=True):
        from server import main
        calls = []
        def membership(svc, tier, name, mutating=False):
            if not member:
                raise PermissionError("non sei partecipante")
        with patch.object(main, "_topics", lambda: object()), \
                patch.object(main, "_require_topic_member", membership), \
                patch.object(main.transfer_channel, "_post",
                             lambda path, body: calls.append((path, body)) or {"delivered": 3}):
            out = main._dispatch_topic("topic.mail_check", {"tier": "SEAL-1", "name": "acme"})
        return out, calls

    def test_it_asks_the_courier_for_the_room(self):
        out, calls = self._run()
        self.assertEqual(out, {"delivered": 3})
        self.assertEqual(calls, [("/internal/courier/check", {"tier": "SEAL-1", "name": "acme"})])

    def test_only_a_member_may_ask(self):
        with self.assertRaises(PermissionError):
            self._run(member=False)

    def test_it_is_a_room_verb_that_changes_nothing(self):
        from server import main
        self.assertIn("mail_check", main._TOPIC_SCOPED_VERBS)
        self.assertNotIn("mail_check", main._TOPIC_MUTATING_VERBS)


if __name__ == "__main__":
    unittest.main()

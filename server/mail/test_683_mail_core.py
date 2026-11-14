"""#683: mail is the gateway's own code again.

1. the vocabulary is the builtin `mail` manifest: `email` is a gateway
   namespace, an old comms-pack (≤ 2.8: `mail` and `telegram`) is not held,
   google-pack's Gmail still extends it;
2. no gateway component may serve `email.*` or reach `mailbox_`;
3. every service the gateway asks for (`mail_switch`) is the native code;
4. an agent naming an `email.*` verb is refused, with the way mail works now.
"""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from .. import main as M
from .. import whitelist
from ..connectors import builtin, resolved
from ..connectors import first_party_fixture as FP
from ..connectors.manifest import core_namespaces


class VocabularyTests(unittest.TestCase):
    def setUp(self) -> None:
        resolved.invalidate()
        self.addCleanup(resolved.invalidate)

    def _with(self, packs: dict):
        p = patch.object(resolved, "manifests", lambda: packs)
        p.start()
        self.addCleanup(p.stop)
        resolved.invalidate()
        return resolved.registry()

    def test_email_is_a_gateway_namespace(self) -> None:
        self.assertIn("email", builtin.namespaces())
        self.assertIn("email", core_namespaces())
        self.assertNotIn("mail", builtin.RELEASED_TO)
        self.assertNotIn("mailbox_", builtin.CORE_CREDENTIALS_FOLLOW)

    def test_an_old_comms_pack_has_both_its_connectors_refused(self) -> None:
        """comms-pack ≤ 2.8 declares `mail` and `telegram`. `mail` is the
        gateway's (#683 phase 1) and `telegram` is released to nobody since
        Telegram's removal (#683 phase 2): neither is held, and the gateway's
        own mail vocabulary stays the one that answers."""
        reg = self._with({**FP.manifests(), "comms-pack": FP.comms_pack()})
        self.assertEqual(reg.by_id("mail").pack, "gateway-mail")
        self.assertIsNone(reg.by_id("telegram"))
        self.assertFalse(resolved.held_by_pack("telegram"))
        self.assertTrue(any("comms-pack" in r for r in resolved.problems()),
                        resolved.problems())

    def test_gmail_still_extends_the_vocabulary(self) -> None:
        reg = self._with(FP.manifests())
        self.assertEqual(reg.by_id("mail-gmail").extends, "mail")
        self.assertIn("gmail", {p.id for p in reg.providers_of("mail")})

    def test_send_is_mapped_without_any_pack(self) -> None:
        self._with({})
        from .. import egress
        spec = egress.spec_for("email.send")
        self.assertEqual(spec[0], "email")
        self.assertEqual(spec[1]({"to": "a@b.it", "cc": "c@d.it"}),
                         ["mailto:a@b.it", "mailto:c@d.it"])


class ServicesTests(unittest.TestCase):
    def test_every_service_is_the_native_code(self) -> None:
        from ..mail import mail, mailboxes
        from ..tools import mail_switch
        self.assertIs(mail_switch.service("diagnostics"), mail.credential_diagnostics)
        self.assertIs(mail_switch.service("mailbox_add"), mailboxes.mailbox_add)
        for name in ("courier_envelopes", "courier_box_index", "courier_attachment",
                     "courier_eml", "system_mailboxes", "test_mailboxes"):
            self.assertTrue(callable(mail_switch.service(name)), name)
        with self.assertRaises(mail_switch.ComponentUnavailable):
            mail_switch.service("pdp_arguments")

    def test_no_agent_read_verb_is_left(self) -> None:
        from ..mail import mail, verbs
        for name in ("folders", "list_messages", "read_message", "search", "reply",
                     "get_attachment"):
            self.assertFalse(hasattr(mail, name), name)
        for name in ("handler_for", "pdp_arguments"):
            self.assertFalse(hasattr(verbs, name), name)

    def test_the_mailbox_vault_is_mailbox_only(self) -> None:
        from ..mail._host import vault
        for name in ("google_studio", "github_pat", "telegram_bot_token"):
            with self.assertRaises(PermissionError):
                vault.deposit(name, {}, cred_type="opaque")
            with self.assertRaises(PermissionError):
                vault.remove(name)


class AgentsAreRefusedTests(unittest.TestCase):
    def test_an_email_verb_says_how_mail_works_now(self) -> None:
        tok = whitelist.set_current_agent("clodia")
        self.addCleanup(whitelist.reset_current_agent, tok)
        for verb in ("email.list", "email.read", "email.reply"):
            with self.subTest(verb=verb), self.assertRaises(M._PackVerbRefused) as e:
                M._check_component(verb)
            self.assertIn("topic.mail_check", str(e.exception))

    def test_send_only_inside_a_delivery(self) -> None:
        with self.assertRaises(M._PackVerbRefused):
            M._check_component("email.send")
        self.assertFalse(M._verb_implemented("email.send"))

        async def inside():
            tok = M._DELIVER_VIA.set(frozenset({"email.send"}))
            try:
                M._check_component("email.send")
                return M._verb_implemented("email.send")
            finally:
                M._DELIVER_VIA.reset(tok)
        self.assertTrue(asyncio.run(inside()))


if __name__ == "__main__":
    unittest.main()

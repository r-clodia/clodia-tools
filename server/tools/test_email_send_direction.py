"""`email.send` e `email.reply` arrivano fino al CLI, sulla whitelist GIUSTA
(clodia-platform#428).

Dal refactor whitelist-mailbox (18 set 2026) `_run_cli` esige `direction`, e
`send` non la passava: ogni invio falliva con `TypeError` prima di partire, per
quattro giorni, perché nessun test percorreva `send` fino al subprocess. Questi
lo percorrono davvero — solo `subprocess.run` e le credenziali sono finti.
"""
from __future__ import annotations

import contextlib
import unittest
from unittest.mock import patch

from . import email


class _Done:
    returncode = 0
    stdout = '{"ok": true}'
    stderr = ""


class DirectionTests(unittest.TestCase):
    def _chiama(self, fn):
        viste = []

        @contextlib.contextmanager
        def _env(account, direction):
            viste.append(direction)
            yield {}

        with patch.object(email, "tool_allowed", lambda v: None), \
                patch.object(email, "known_accounts", return_value={"studio"}), \
                patch.object(email, "_secrets_env", _env), \
                patch.object(email, "_assert_readable", side_effect=AssertionError("non è una lettura")), \
                patch.object(email.subprocess, "run", return_value=_Done()) as run:
            out = fn()
        return out, viste, run

    def test_send_reaches_the_cli_on_the_outbox_whitelist(self):
        out, viste, run = self._chiama(lambda: email.send(
            "m.angrisano@radixgroup.it", "Earnext – sintesi", "testo", account="studio",
            cc="m.sira@radixgroup.it"))
        self.assertTrue(out["ok"])
        self.assertEqual(viste, ["outbox"])
        cmd = run.call_args[0][0]
        self.assertIn("send", cmd)
        self.assertIn("m.sira@radixgroup.it", cmd)

    def test_reply_is_checked_on_the_outbox_whitelist_too(self):
        _out, viste, _run = self._chiama(lambda: email.reply("42", "grazie", account="studio"))
        self.assertEqual(viste, ["outbox"])


if __name__ == "__main__":
    unittest.main()

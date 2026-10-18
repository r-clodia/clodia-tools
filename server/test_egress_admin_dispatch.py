"""The egress/ingress admin verbs reach their dispatcher (review of #405: a
removal of the native Google code once took `_dispatch_egress_admin` with it,
and no test called these verbs)."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import main


class EgressAdminDispatchTests(unittest.TestCase):
    def test_every_admin_verb_has_its_dispatcher(self):
        names = {t.name for t in main._all_native_tools()}
        for verb in ("egress.allow", "egress.revoke", "egress.list",
                     "ingress.allow", "ingress.revoke", "ingress.list"):
            with self.subTest(verb=verb):
                self.assertIn(verb, names)
        self.assertTrue(callable(main._dispatch_egress_admin))

    def test_list_answers(self):
        with patch.object(main._egress if hasattr(main, "_egress") else __import__(
                "server.egress", fromlist=["x"]), "effective_uris",
                lambda *a, **k: ["https://x.it/"]):
            out = main._dispatch_egress_admin("egress.list", {})
        self.assertIsNotNone(out)


if __name__ == "__main__":
    unittest.main()

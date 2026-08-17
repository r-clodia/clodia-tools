"""`github.push` porta una directory, non un repository.

Il 17 ago 2026 il verbo è entrato nel perimetro egress (PR #210) e da quel
momento il PDP ne giudicava la destinazione — che però negli argomenti non c'è:
`push` riceve `dir`. Verdetto: destinazione ignota → nego. Il verbo è stato reso
governato e insieme impossibile, e l'agente ha riportato
`DENIED ... egress_allow.github` su un repository che stava nel perimetro.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import main


class PushDestinationTests(unittest.TestCase):
    def test_the_repo_is_resolved_from_the_working_tree(self):
        with patch("server.tools.github_repo.remote_url",
                   lambda _d: "https://github.com/r-clodia/clodia-logic"):
            out = main._push_destination({"dir": "/scratch/x", "branch": "b"})
        self.assertEqual(out["repo"], "https://github.com/r-clodia/clodia-logic")
        self.assertEqual(out["dir"], "/scratch/x", "gli altri argomenti restano")

    def test_an_explicit_repo_wins_and_costs_no_read(self):
        def boom(_d):
            raise AssertionError("non si legge il remote se il repo è già noto")

        with patch("server.tools.github_repo.remote_url", boom):
            out = main._push_destination({"repo": "https://github.com/a/b"})
        self.assertEqual(out["repo"], "https://github.com/a/b")

    def test_an_unresolvable_remote_leaves_the_arguments_alone(self):
        """Nessuna destinazione inventata: il PDP deve poter dire «non lo so» e
        negare, che per un'uscita è la direzione giusta."""
        with patch("server.tools.github_repo.remote_url", lambda _d: ""):
            out = main._push_destination({"dir": "/scratch/x"})
        self.assertNotIn("repo", out)

    def test_the_perimeter_sees_the_resolved_destination(self):
        from server import egress
        with patch("server.tools.github_repo.remote_url",
                   lambda _d: "https://github.com/r-clodia/clodia-logic"), \
             patch.object(egress, "effective_uris",
                          lambda *_a, **_k: ["https://github.com/r-clodia/"]):
            args = main._push_destination({"dir": "/scratch/x"})
            self.assertTrue(egress.destinations_already_allowed("github.push", args))


if __name__ == "__main__":
    unittest.main()

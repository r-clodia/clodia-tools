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
    def setUp(self):
        p = patch.object(main, "_safe_scratch_path", lambda d: d)
        p.start()
        self.addCleanup(p.stop)

    def test_the_repo_is_resolved_from_the_working_tree(self):
        with patch("server.tools.github_repo.remote_url",
                   lambda _d: "https://github.com/r-clodia/clodia-logic"):
            out = main._push_destination({"dir": "/scratch/x", "branch": "b"})
        self.assertEqual(out["repo"], "https://github.com/r-clodia/clodia-logic")
        self.assertEqual(out["dir"], "/scratch/x", "gli altri argomenti restano")

    def test_a_caller_repo_never_decides(self):
        """`github.push` has no `repo` argument: a forged one is replaced by
        the origin, for the PDP and for the gate's perimeter skip alike
        (review of clodia-tools#400)."""
        with patch("server.tools.github_repo.remote_url",
                   lambda _d: "https://github.com/r-clodia/real"):
            out = main._push_destination({"dir": "/scratch/x",
                                          "repo": "https://github.com/r-clodia/approved"})
        self.assertEqual(out["repo"], "https://github.com/r-clodia/real")

    def test_an_unresolvable_remote_is_an_unknown_destination(self):
        """Nessuna destinazione inventata: il PDP deve poter dire «non lo so» e
        negare, che per un'uscita è la direzione giusta."""
        with patch("server.tools.github_repo.remote_url", lambda _d: ""):
            out = main._push_destination({"dir": "/scratch/x"})
        self.assertEqual(out["repo"], "")

    def test_a_dir_outside_the_scratch_is_an_unknown_destination(self):
        def fuori(_d):
            raise ValueError("fuori dallo scratch")
        with patch.object(main, "_safe_scratch_path", fuori), \
                patch("server.tools.github_repo.remote_url",
                      lambda _d: self.fail("read outside the scratch")):
            self.assertEqual(main._push_destination({"dir": "/datadir"})["repo"], "")

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

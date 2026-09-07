"""Le tre cose che decide il dispatcher, e che l'agente non deve poter dire.

`github.*` è utile solo se il gateway — non il chiamante — stabilisce:

  1. **in quale stanza siamo** (dal claim firmato, non dal body);
  2. **se il repository appartiene al perimetro di quella stanza**;
  3. **con quale credenziale**.

Il terzo è quello che si sbaglia per comodità. Chiedere al chiamante il nome del
mount sembrerebbe innocuo — chi fa `github.push` non sa come l'owner ha
battezzato il mount — ma significherebbe lasciargli scegliere QUALE credenziale
usare: due mount, due owner, e il push finisce col token dell'altro.

Il secondo ha una trappola sua: su `push` il repository non lo dice il
parametro, lo dice l'`origin` che il gateway stesso ha scritto al clone.
Altrimenti si fa approvare un repository e se ne spinge un altro.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import main as M


class OutsideAScopeTests(unittest.TestCase):
    def test_without_a_channel_there_is_no_perimeter(self):
        """Fuori da una stanza non c'è una lista cui appartenere: rifiutare è
        l'unica risposta che non inventa uno scope."""
        with patch.object(M, "_current_topic", lambda: (None, None)):
            with self.assertRaises(ValueError) as ctx:
                M._dispatch_github("github.clone", {"repo": "x", "dest": "y"})
        self.assertIn("canale", str(ctx.exception))


class TheRepositoryOfAPushComesFromTheOriginTests(unittest.TestCase):
    def test_the_caller_cannot_name_a_different_repository(self):
        """Il difetto che questo chiude: farsi approvare `acme/pubblico` e
        spingere dentro `acme/segreto`, che è nella stessa lista solo perché il
        working tree è un altro."""
        visti = {}

        class FintoSvc:
            @staticmethod
            def _require_approved_repo(url, tier, name):
                visti["approvato"] = url

        with patch.object(M, "_current_topic", lambda: ("SEAL-1", "acme")), \
             patch.object(M, "_topics", lambda: FintoSvc()), \
             patch.object(M, "_origin_of", lambda d: "https://github.com/acme/vero"), \
             patch.object(M, "_safe_scratch_path", lambda p: "/datadir/spawns/s/lavoro"), \
             patch.object(M, "_repo_credential", lambda *a: None), \
             patch("server.tools.github_repo.push", lambda *a, **k: {"ok": True}):
            M._dispatch_github("github.push",
                               {"dir": "lavoro", "repo": "https://github.com/acme/finto"})
        self.assertEqual(visti["approvato"], "https://github.com/acme/vero")


class TheCredentialIsScopeLevelTests(unittest.TestCase):
    """Da decision-record #40: il mount git è ritirato (nessuno lo usava in
    produzione), e con lui la ricerca per-mount. Resta solo lo scope, che
    `git_credential` risolve già (mount→scope→piattaforma, qui sempre senza
    mount)."""

    def _svc(self, chiamate):
        class FintoSvc:
            def git_credential(_s, t, n):
                chiamate.append((t, n))
                return ("PAT-scope", "scope")
        return FintoSvc()

    def test_it_asks_the_scope_credential_with_no_mount(self):
        chiamate = []
        tok = M._repo_credential(self._svc(chiamate), "SEAL-1", "acme",
                                 "https://github.com/acme/qualunque")
        self.assertEqual(tok, "PAT-scope")
        self.assertEqual(chiamate, [("SEAL-1", "acme")])


class GateClassTests(unittest.TestCase):
    """Portare fuori e portare dentro non sono lo stesso atto."""

    def test_what_leaves_the_scope_is_gated(self):
        from . import gate
        for v in ("github.push", "github.pull_request"):
            with self.subTest(v):
                self.assertTrue(gate.is_gated(v))
                self.assertEqual(gate.gate_class(v), gate.GATE_OUTWARD)

    def test_what_comes_in_is_not(self):
        """Come `remote_pull`: tirare dentro non sposta il confine — è la lista
        dei repository approvati a dire da dove si può tirare."""
        from . import gate
        for v in ("github.clone", "github.pull"):
            with self.subTest(v):
                self.assertFalse(gate.is_gated(v))


if __name__ == "__main__":
    unittest.main()

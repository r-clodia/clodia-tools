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


class TheCredentialIsFoundByRepositoryTests(unittest.TestCase):
    META = {"mounts": [
        {"name": "pubblico", "type": "git",
         "config": {"url": "https://github.com/acme/pubblico.git"}},
        {"name": "privato", "type": "git",
         "config": {"url": "git@github.com:acme/privato.git"}},
        {"name": "drive", "type": "drive", "config": {"folder": "X"}},
    ]}

    def _svc(self, chiamate):
        class FintoSvc:
            def _read_meta(_s, t, n):
                return (TheCredentialIsFoundByRepositoryTests.META, "v1")

            def git_credential(_s, t, n, mount=None):
                chiamate.append(mount)
                return (f"PAT-{mount or 'scope'}", "mount" if mount else "scope")
        return FintoSvc()

    def test_the_mount_that_carries_this_repository_supplies_it(self):
        chiamate = []
        tok = M._repo_credential(self._svc(chiamate), "SEAL-1", "acme",
                                 "https://github.com/acme/privato")
        self.assertEqual(tok, "PAT-privato")
        self.assertEqual(chiamate, ["privato"])

    def test_the_form_of_the_url_in_the_meta_does_not_matter(self):
        """Nel meta l'URL è come l'owner l'ha scritto: SSH, con `.git`, con lo
        slash. Un confronto testuale userebbe la credenziale sbagliata — o
        nessuna — su un repository perfettamente approvato."""
        chiamate = []
        tok = M._repo_credential(self._svc(chiamate), "SEAL-1", "acme",
                                 "https://github.com/acme/pubblico")
        self.assertEqual(tok, "PAT-pubblico")

    def test_a_repository_with_no_mount_falls_back_visibly(self):
        """Un repo approvato per lista ma non montato resta usabile: la voce 31
        lo prevede. Rifiutare qui romperebbe il caso che la lista serve a
        rendere possibile."""
        chiamate = []
        tok = M._repo_credential(self._svc(chiamate), "SEAL-1", "acme",
                                 "https://github.com/acme/altro")
        self.assertEqual(tok, "PAT-scope")
        self.assertEqual(chiamate, [None])

    def test_a_drive_mount_is_never_asked_for_a_git_credential(self):
        chiamate = []
        M._repo_credential(self._svc(chiamate), "SEAL-1", "acme",
                           "https://github.com/acme/altro")
        self.assertNotIn("drive", chiamate)


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

"""Repository normalisation: the one definition of «the shape of a
repository» the PDP and the host share.

The tests of the git client itself (clone, pull, push, the secret that must not
reach the disk) moved with the client into clodia-packs
(`tests/test_git_core.py`, it-pack's `gateway/git_core.py`, #525).
"""
from __future__ import annotations

import unittest

from . import github_repo as gh


class NormalizeTests(unittest.TestCase):
    """Lo stesso repository si scrive in quattro modi, e un confronto testuale
    con la whitelist direbbe «non approvato» a un repository approvato."""

    def test_the_four_ways_collapse_to_one(self):
        atteso = "https://github.com/acme/tool"
        for forma in ("https://github.com/acme/tool",
                      "https://github.com/acme/tool.git",
                      "https://github.com/acme/tool/",
                      "git@github.com:acme/tool.git",
                      "ssh://github.com/acme/tool"):
            with self.subTest(forma):
                self.assertEqual(gh.normalize_repo(forma), atteso)

    def test_the_short_form_is_the_fifth_way(self):
        """`owner/repo` è come GitHub nomina un repository, ed è la forma che si
        scrive a mano: se non collassa sulla canonica, la whitelist dice «non
        approvato» a un repository approvato — con un messaggio che parla di
        forma dell'URL, quindi manda a cercare il difetto altrove."""
        atteso = "https://github.com/acme/tool"
        for forma in ("acme/tool", "acme/tool.git", "acme/tool/"):
            with self.subTest(forma):
                self.assertEqual(gh.normalize_repo(forma), atteso)

    def test_a_path_is_not_a_short_form(self):
        """La porta della forma breve non deve far entrare un path del
        filesystem: sarebbe un `file://` senza scriverlo."""
        for brutto in ("/datadir/vault", "../etc/passwd", "./tool", "acme",
                       "acme/tool/extra", "acme /tool"):
            with self.subTest(brutto):
                with self.assertRaises(gh.GitHubError):
                    gh.normalize_repo(brutto)

    def test_the_refusal_names_the_forms_that_work(self):
        """Un rifiuto che nomina solo la forma canonica manda a indovinare."""
        with self.assertRaises(gh.GitHubError) as ctx:
            gh.normalize_repo("https://github.com/acme")
        self.assertIn("owner/repo", str(ctx.exception))

    def test_credentials_in_the_url_are_stripped(self):
        """Un URL con le credenziali dentro non deve diventare la voce
        canonica: finirebbe nei log e nei messaggi d'errore."""
        out = gh.normalize_repo("https://x-token:ghp_SEGRETO@github.com/acme/tool.git")
        self.assertEqual(out, "https://github.com/acme/tool")
        self.assertNotIn("ghp_SEGRETO", out)

    def test_a_host_is_not_a_repository(self):
        """Il perimetro è per repository. Se un host passasse per repository,
        approvare `github.com` approverebbe tutto GitHub."""
        for brutto in ("https://github.com", "https://github.com/acme", "", "  "):
            with self.subTest(brutto):
                with self.assertRaises(gh.GitHubError):
                    gh.normalize_repo(brutto)


class LocalRepoIsRefusedTests(unittest.TestCase):
    def test_a_file_url_is_not_a_repository(self):
        """Il git del gateway vede il filesystem del gateway: un
        `file:///datadir/...` sarebbe una lettura del vault con la forma di un
        clone. La lista lo fermerebbe già — questa è la linea che vale quando la
        lista è vuota, cioè quando non c'è confinamento."""
        with self.assertRaises(gh.GitHubError) as ctx:
            gh.normalize_repo("file:///datadir/vault")
        self.assertIn("file://", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

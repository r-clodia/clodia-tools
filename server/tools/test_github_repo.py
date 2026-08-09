"""Le azioni git che escono dallo scope le fa il gateway (§5.2).

La proprietà che questi test difendono è una sola, e si perde senza accorgersene:
**la credenziale non entra nel processo dell'agente**. Un `git clone` con il
token nell'URL funziona benissimo e lascia il segreto in `.git/config` — dentro
la scratch, che l'agente legge con un `cat`. Il disegno sarebbe soddisfatto sulla
carta e falso sul disco.

Per questo il controllo non è «abbiamo usato l'helper» ma «sul disco non c'è il
segreto»: il primo verifica un'intenzione, il secondo un esito. Un meccanismo di
sicurezza che non misura il proprio esito è una convenzione.

I test lavorano su repository git LOCALI (`file://`): niente rete, e restano un
esercizio vero di clone/commit/push invece di una simulazione di sé stessi.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from . import github_repo as gh


def _git(*args, cwd=None):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True,
                          check=True)


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


class Base(unittest.TestCase):
    """Un repository «remoto» vero, ma locale: `file://`, nessuna rete.

    Il seam `ALLOW_LOCAL_REPOS` sposta ciò che è raggiungibile, non la regola:
    la classe qui sopra tiene ferma la regola, questi test esercitano l'idraulica
    contro un repository git vero invece che contro un finto.
    """

    def setUp(self):
        self._seam = unittest.mock.patch.object(gh, "ALLOW_LOCAL_REPOS", True)
        self._seam.start()
        self.addCleanup(self._seam.stop)
        self.root = Path(tempfile.mkdtemp(prefix="gh-"))
        self.origine = self.root / "origine.git"
        semina = self.root / "semina"
        semina.mkdir()
        (semina / "README.md").write_text("uno\n")
        _git("init", "-q", "-b", "main", cwd=semina)
        _git("config", "user.email", "t@example.org", cwd=semina)
        _git("config", "user.name", "T", cwd=semina)
        _git("add", "-A", cwd=semina)
        _git("commit", "-q", "-m", "primo", cwd=semina)
        _git("clone", "--bare", "-q", str(semina), str(self.origine))
        self.url = f"file://{self.origine}"

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _clona(self, dest="lavoro", **kw):
        return gh.clone(self.url, str(self.root / dest), **kw)


class CloneTests(Base):
    def test_a_clone_lands_where_it_was_asked(self):
        out = gh.clone(self.url, str(self.root / "lavoro"))
        self.assertTrue((self.root / "lavoro" / "README.md").exists())
        self.assertEqual(out["branch"], "main")

    def test_a_non_empty_destination_is_refused(self):
        """Clonare sopra il lavoro di qualcuno è una perdita silenziosa: git
        rifiuterebbe comunque, ma con un messaggio che parla di git."""
        d = self.root / "occupata"
        d.mkdir()
        (d / "mio.txt").write_text("lavoro in corso")
        with self.assertRaises(gh.GitHubError):
            gh.clone(self.url, str(d))
        self.assertTrue((d / "mio.txt").exists())

    def test_the_origin_is_the_clean_url(self):
        gh.clone(self.url, str(self.root / "lavoro"))
        cfg = (self.root / "lavoro" / ".git" / "config").read_text()
        self.assertIn(str(self.origine), cfg)
        self.assertNotIn("@", cfg.split("url = ")[1].split("\n")[0])


class TheSecretDoesNotReachTheDiskTests(Base):
    """Il cuore del modulo."""

    def test_the_token_is_not_in_git_config_after_a_clone(self):
        gh.clone(self.url, str(self.root / "lavoro"), token="ghp_SEGRETISSIMO")
        testo = (self.root / "lavoro" / ".git" / "config").read_text()
        self.assertNotIn("ghp_SEGRETISSIMO", testo)

    def test_the_token_is_nowhere_under_the_working_tree(self):
        """Non solo in `.git/config`: ovunque. L'helper è passato con `-c`, che
        non persiste — ma è una proprietà di git, non nostra, e va misurata."""
        gh.clone(self.url, str(self.root / "lavoro"), token="ghp_SEGRETISSIMO")
        trovati = []
        for f in (self.root / "lavoro").rglob("*"):
            if f.is_file():
                try:
                    if "ghp_SEGRETISSIMO" in f.read_text(errors="ignore"):
                        trovati.append(str(f))
                except OSError:
                    pass
        self.assertEqual(trovati, [])

    def test_a_secret_found_on_disk_stops_the_operation(self):
        """Il controllo deve poter fallire: se non fallisse mai, non
        misurerebbe niente."""
        d = self.root / "lavoro"
        gh.clone(self.url, str(d))
        (d / ".git" / "config").write_text(
            (d / ".git" / "config").read_text() + "\n# ghp_SEGRETISSIMO\n")
        with self.assertRaises(gh.GitHubError) as ctx:
            gh._assert_no_secret_on_disk(str(d), "ghp_SEGRETISSIMO")
        self.assertIn("credenziale", str(ctx.exception))

    def test_an_error_message_never_carries_the_token(self):
        """La via meno sorvegliata per far uscire un segreto è il messaggio
        d'errore, che finisce nel log e nella chat."""
        with self.assertRaises(gh.GitHubError) as ctx:
            gh.clone("https://github.com/non/esiste-davvero-xyz",
                     str(self.root / "vuoto"), token="ghp_SEGRETISSIMO")
        self.assertNotIn("ghp_SEGRETISSIMO", str(ctx.exception))


class PushTests(Base):
    def test_push_sends_what_was_committed(self):
        d = self.root / "lavoro"
        gh.clone(self.url, str(d))
        _git("config", "user.email", "t@example.org", cwd=d)
        _git("config", "user.name", "T", cwd=d)
        (d / "nuovo.md").write_text("due\n")
        _git("add", "-A", cwd=d)
        _git("commit", "-q", "-m", "secondo", cwd=d)
        out = gh.push(str(d))
        self.assertTrue(out["ok"])
        log = subprocess.run(["git", "-C", str(self.origine), "log", "--oneline"],
                             capture_output=True, text=True).stdout
        self.assertIn("secondo", log)

    def test_push_does_not_commit(self):
        """Il commit è DENTRO lo scope e lo fa l'agente. Se `push` committasse,
        la separazione dentro/fuori sarebbe scritta nella specifica e non nel
        codice — e uscirebbe roba che nessuno ha deciso di pubblicare."""
        d = self.root / "lavoro"
        gh.clone(self.url, str(d))
        (d / "bozza.md").write_text("non pronto\n")
        out = gh.push(str(d))
        self.assertEqual(out["uncommitted"], 1)
        elenco = subprocess.run(["git", "-C", str(self.origine), "ls-tree", "-r",
                                 "--name-only", "main"],
                                capture_output=True, text=True).stdout
        self.assertNotIn("bozza.md", elenco)

    def test_pushing_something_that_is_not_a_repo_says_so(self):
        vuota = self.root / "niente"
        vuota.mkdir()
        with self.assertRaises(gh.GitHubError) as ctx:
            gh.push(str(vuota))
        self.assertIn("working tree", str(ctx.exception))


class PullTests(Base):
    def test_pull_brings_in_what_changed(self):
        d = self.root / "lavoro"
        gh.clone(self.url, str(d))
        altro = self.root / "altro"
        _git("clone", "-q", self.url, str(altro))
        _git("config", "user.email", "t@example.org", cwd=altro)
        _git("config", "user.name", "T", cwd=altro)
        (altro / "terzo.md").write_text("tre\n")
        _git("add", "-A", cwd=altro)
        _git("commit", "-q", "-m", "terzo", cwd=altro)
        _git("push", "-q", "origin", "main", cwd=altro)
        gh.pull(str(d))
        self.assertTrue((d / "terzo.md").exists())


class PullRequestTests(unittest.TestCase):
    def test_without_a_credential_it_says_who_supplies_it(self):
        """Un rifiuto che non indica la strada insegna solo che il sistema dice
        di no. La credenziale la mette l'owner, al mount."""
        with self.assertRaises(gh.GitHubError) as ctx:
            gh.pull_request("https://github.com/acme/tool", "ramo", "main", "t")
        self.assertIn("owner", str(ctx.exception))

    def test_only_github(self):
        with self.assertRaises(gh.GitHubError):
            gh.pull_request("https://gitlab.com/acme/tool", "ramo", "main", "t",
                            token="x")


if __name__ == "__main__":
    unittest.main()

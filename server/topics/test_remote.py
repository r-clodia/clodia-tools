"""Test GitRemote su repo git reale + bare locale (nessuna dipendenza esterna).
DriveRemote è testato a parte con un fake DriveStorage in-memory.
"""
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from .remote import GitRemote, DriveRemote, RemoteConflict, make_remote, _GH_CRED_HELPER


class GitAuthEnvTest(unittest.TestCase):
    def test_terminal_prompt_disabled_always(self):
        cmd, env = GitRemote("/tmp/x")._build(("pull",))
        self.assertEqual(env.get("GIT_TERMINAL_PROMPT"), "0")   # mai prompt interattivo
        self.assertNotIn("GIT_PAT", env)                        # nessun token senza github
        self.assertNotIn("-c", cmd)

    def test_github_token_injected_scoped(self):
        cmd, env = GitRemote("/tmp/x", github_token="ghp_secret")._build(("pull",))
        self.assertEqual(env.get("GIT_PAT"), "ghp_secret")      # token solo in env
        self.assertEqual(env.get("GIT_TERMINAL_PROMPT"), "0")
        # helper scoped a github.com, e il token NON compare in argv
        self.assertIn("-c", cmd)
        joined = " ".join(cmd)
        self.assertIn("credential.https://github.com.helper=", joined)
        self.assertNotIn("ghp_secret", joined)
        self.assertIn(_GH_CRED_HELPER, joined)


def _has_git() -> bool:
    try:
        subprocess.run(["git", "--version"], capture_output=True, check=True)
        return True
    except Exception:
        return False


@unittest.skipUnless(_has_git(), "git non disponibile")
class GitRemoteTest(unittest.TestCase):
    def test_enable_add_push_pull_disable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bare = root / "origin.git"
            subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True)
            subprocess.run(["git", "-C", str(bare), "symbolic-ref", "HEAD", "refs/heads/main"], check=True)

            a = root / "topicA" / "files"
            a.mkdir(parents=True)
            (a / "doc.txt").write_text("v1", encoding="utf-8")
            ra = make_remote("git", str(a))
            ra.enable({"url": str(bare)})
            self.assertTrue((a / ".git").is_dir())

            # nuovo file → commit + push
            (a / "note.md").write_text("ciao", encoding="utf-8")
            ra.add("note.md")
            ra.commit("add note")
            ra.push()

            # secondo topic clona dal bare e vede i file → pull funziona
            b = root / "topicB" / "files"
            b.mkdir(parents=True)
            subprocess.run(["git", "clone", "-q", str(bare), str(b)], check=True)
            self.assertEqual((b / "note.md").read_text(encoding="utf-8"), "ciao")
            self.assertEqual((b / "doc.txt").read_text(encoding="utf-8"), "v1")

            # disable → .git rimosso, file preservati
            ra.disable()
            self.assertFalse((a / ".git").is_dir())
            self.assertTrue((a / "doc.txt").is_file())
            self.assertTrue((a / "note.md").is_file())

    def test_git_commit_filters_by_remoteignore(self):
        """Su git il filtro agisce sullo staging del commit: i path esclusi non
        entrano nel commit (e quindi non vengono pushati)."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a = root / "topic" / "files"; a.mkdir(parents=True)
            (a / ".remoteignore").write_text("*.pdf\n", encoding="utf-8")
            (a / "keep.md").write_text("ok", encoding="utf-8")
            (a / "drop.pdf").write_text("PDF", encoding="utf-8")
            (a / "secret.key").write_text("KEY", encoding="utf-8")
            r = make_remote("git", str(a))
            r.enable({})   # git locale senza origin
            r.commit("first")
            tracked = subprocess.run(["git", "-C", str(a), "ls-files"],
                                     capture_output=True, text=True).stdout.split()
            self.assertIn("keep.md", tracked)
            self.assertNotIn("drop.pdf", tracked)      # filtrato da .remoteignore
            self.assertNotIn("secret.key", tracked)    # hard deny
            self.assertNotIn(".remoteignore", tracked)  # control-plane

    def test_pull_conflict_escala(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bare = root / "o.git"
            subprocess.run(["git", "init", "--bare", "-q", str(bare)], check=True)
            subprocess.run(["git", "-C", str(bare), "symbolic-ref", "HEAD", "refs/heads/main"], check=True)
            a = root / "A" / "files"; a.mkdir(parents=True)
            (a / "f.txt").write_text("base", encoding="utf-8")
            ra = GitRemote(str(a)); ra.enable({"url": str(bare)})
            # clone B, diverge, push
            b = root / "B" / "files"; b.mkdir(parents=True)
            subprocess.run(["git", "clone", "-q", str(bare), str(b)], check=True)
            subprocess.run(["git", "-C", str(b), "config", "user.email", "b@x"], check=True)
            subprocess.run(["git", "-C", str(b), "config", "user.name", "b"], check=True)
            (b / "f.txt").write_text("da-B", encoding="utf-8")
            subprocess.run(["git", "-C", str(b), "commit", "-aqm", "B"], check=True)
            subprocess.run(["git", "-C", str(b), "push", "-q"], check=True)
            # A diverge in modo incompatibile e prova pull → conflitto → escala
            (a / "f.txt").write_text("da-A", encoding="utf-8")
            ra.commit("A")
            with self.assertRaises(RemoteConflict):
                ra.pull()


class _FakeDrive:
    """DriveStorage in-memory: {path -> (bytes, mtime, mime, url)}."""
    def __init__(self):
        self.files = {}
        self.reads = 0   # quante volte è stato SCARICATO un contenuto (per il test incrementale)
    def write(self, path, data, if_version=None):
        self.files[path] = (data, 1000.0, None, None); return "v"
    def add_native(self, path, url, mime="application/vnd.google-apps.document"):
        """Simula un Doc nativo Google (non scaricabile via get_media)."""
        self.files[path] = (b"", 1000.0, mime, url)
    def read(self, path):
        from .storage import ReadResult
        self.reads += 1
        _d, _m, mime, _u = self.files[path]
        if mime and mime.startswith("application/vnd.google-apps."):
            raise RuntimeError("HTTP 403: native doc non scaricabile via get_media")
        return ReadResult(self.files[path][0], "v")
    def stat(self, path):
        from .storage import Stat
        if path not in self.files:
            return None
        import hashlib
        d, m, _mime, _u = self.files[path]
        return Stat(version="v", size=len(d), mtime=m, kind="file", md5=hashlib.md5(d).hexdigest())
    def list(self, path):
        from .storage import Entry
        import hashlib
        out = []
        for p in self.files:
            if "/" not in p and path == "":
                _d, _m, mime, url = self.files[p]
                # version = md5 dei metadati (come Drive md5Checksum): il pull lo usa
                # per saltare i file identici senza scaricarli.
                ver = None if (mime and mime.startswith("application/vnd.google-apps.")) \
                    else hashlib.md5(_d).hexdigest()
                out.append(Entry(name=p, kind="file", size=len(_d), mime=mime, url=url, version=ver))
        return out


class DriveRemoteTest(unittest.TestCase):
    def test_two_lists_and_push_pull(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = root / "files"; files.mkdir()
            (files / "a.txt").write_text("AAA", encoding="utf-8")
            fake = _FakeDrive()
            r = DriveRemote(str(files), str(root / "state.json"),
                            drive_factory=lambda acct, folder: fake)
            r.enable({"folder": "F", "account": "acct"})
            # add → sync+push; commit no-op; push → carica e svuota push-list
            r.add("a.txt")
            self.assertEqual(r.status()["pending"], 1)
            r.commit("x")
            self.assertEqual(r.push()["pushed"], 1)
            self.assertEqual(r.status()["pending"], 0)          # push-list svuotata
            self.assertEqual(r.status()["synced"], 1)
            self.assertIn("a.txt", fake.files)                   # arrivato su Drive
            # pull di un file NUOVO dal remote → entra in sync ma NON in push
            fake.write("b.txt", b"BBB")
            res = r.pull()
            self.assertEqual(res["pulled"], 1)
            self.assertTrue((files / "b.txt").is_file())
            self.assertEqual(r.status()["synced"], 2)
            self.assertEqual(r.status()["pending"], 0)           # i pull NON vanno in push-list
            # disable → stato rimosso, file preservati
            r.disable()
            self.assertFalse((root / "state.json").is_file())
            self.assertTrue((files / "a.txt").is_file())
            self.assertTrue((files / "b.txt").is_file())

    def test_pull_incremental_skips_unchanged(self):
        """Il pull NON ri-scarica i file locali già identici (md5 dai metadati):
        un pull ripetuto senza modifiche fa ZERO download."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = root / "files"; files.mkdir()
            fake = _FakeDrive()
            fake.write("doc.txt", b"HELLO")
            r = DriveRemote(str(files), str(root / "state.json"),
                            drive_factory=lambda acct, folder: fake)
            r.enable({"folder": "F", "account": "acct"})
            # 1° pull: file nuovo → 1 download
            self.assertEqual(r.pull()["pulled"], 1)
            self.assertEqual(fake.reads, 1)
            self.assertEqual((files / "doc.txt").read_bytes(), b"HELLO")
            # 2° pull SENZA modifiche → skip via md5: NESSUN download
            self.assertEqual(r.pull()["pulled"], 0)
            self.assertEqual(fake.reads, 1)   # <-- niente ri-download
            # modifica remota → il pull ri-scarica SOLO quel file
            fake.write("doc.txt", b"HELLO WORLD")
            r.pull()
            self.assertEqual(fake.reads, 2)   # scaricato perché l'md5 è cambiato

    def test_pull_native_doc_becomes_stub(self):
        """Doc nativo Google → NON crasha (403); si materializza uno stub
        proxy .gdrive.json col link, e lo stub NON finisce nella push-list."""
        import json as _json
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = root / "files"; files.mkdir()
            fake = _FakeDrive()
            fake.write("bin.txt", b"DATA")
            fake.add_native("piano.doc", "https://docs.google.com/document/d/XYZ/edit")
            r = DriveRemote(str(files), str(root / "state.json"),
                            drive_factory=lambda acct, folder: fake)
            r.enable({"folder": "F", "account": "acct"})
            res = r.pull()
            # binario scaricato + stub scritto = 2 file materializzati
            self.assertEqual(res["pulled"], 2)
            self.assertEqual(res["skipped"], [])
            self.assertTrue((files / "bin.txt").is_file())
            stub = files / "piano.doc.gdrive.json"
            self.assertTrue(stub.is_file())
            payload = _json.loads(stub.read_text(encoding="utf-8"))
            self.assertEqual(payload["gdrive_url"], "https://docs.google.com/document/d/XYZ/edit")
            self.assertTrue(payload["mimeType"].startswith("application/vnd.google-apps."))
            # lo stub è in sync-list ma NON in push-list (non si ri-carica su Drive)
            self.assertEqual(r.status()["pending"], 0)
            self.assertIn("piano.doc.gdrive.json", r._load()["sync"])
            # pull idempotente: seconda volta nessun nuovo file
            self.assertEqual(r.pull()["pulled"], 0)

    def test_pull_respects_remoteinclude_ignore(self):
        """Il filtro .remoteinclude/.remoteignore blocca il pull dei path esclusi;
        il report riporta gli stati per-file."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = root / "files"; files.mkdir()
            (files / ".remoteinclude").write_text("*.csv\n*.md\n", encoding="utf-8")
            (files / ".remoteignore").write_text("*.tmp\n", encoding="utf-8")
            fake = _FakeDrive()
            fake.write("dati.csv", b"a,b")          # incluso
            fake.write("nota.md", b"# nota")         # incluso
            fake.write("preventivo.pdf", b"%PDF")    # fuori allowlist
            fake.write("scratch.tmp", b"tmp")        # ignorato (ma anche fuori allowlist)
            r = DriveRemote(str(files), str(root / "state.json"),
                            drive_factory=lambda acct, folder: fake)
            r.enable({"folder": "F", "account": "acct"})
            res = r.pull()
            self.assertEqual(res["pulled"], 2)
            self.assertTrue((files / "dati.csv").is_file())
            self.assertTrue((files / "nota.md").is_file())
            self.assertFalse((files / "preventivo.pdf").exists())
            self.assertFalse((files / "scratch.tmp").exists())
            rep = res["report"]
            self.assertEqual(rep["counts"]["synced"], 2)
            self.assertIn("preventivo.pdf", rep["skipped_by_include"])
            # .remoteinclude/.remoteignore sono control-plane: non compaiono nello status
            self.assertNotIn(".remoteinclude", r.status()["files"])

    def test_push_skips_hard_deny_and_filtered(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = root / "files"; files.mkdir()
            (files / ".remoteignore").write_text("*.pdf\n", encoding="utf-8")
            (files / "ok.csv").write_text("x", encoding="utf-8")
            (files / "big.pdf").write_text("PDF", encoding="utf-8")
            (files / "secret.key").write_text("KEY", encoding="utf-8")
            fake = _FakeDrive()
            r = DriveRemote(str(files), str(root / "state.json"),
                            drive_factory=lambda acct, folder: fake)
            r.enable({"folder": "F", "account": "acct"})
            r.add("ok.csv"); r.add("big.pdf"); r.add("secret.key")
            res = r.push()
            self.assertEqual(res["pushed"], 1)          # solo ok.csv
            self.assertIn("ok.csv", fake.files)
            self.assertNotIn("big.pdf", fake.files)     # filtrato da .remoteignore
            self.assertNotIn("secret.key", fake.files)  # hard deny
            rep = res["report"]
            self.assertIn("big.pdf", rep["skipped_by_ignore"])
            self.assertIn("secret.key", rep["skipped_by_hard_deny"])
            self.assertEqual(r.status()["pending"], 0)  # push-list svuotata


if __name__ == "__main__":
    unittest.main()

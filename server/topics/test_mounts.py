"""Una vista sola, due mount: `local/` e `remote/<nome>/`.

Prima di questo i due piani erano in XOR. `DRIVE_REMOTE.md`: «Drive è la source
of truth […] i file locali spariscono dalla vista». Misurato su
`SEAL-1/proof-of-flex-2` il 7 ago 2026: 26 file mostrati (di Drive) e **65
invisibili** su disco — la Guide for Applicants, i deliverable, le slide del
pilota portoghese. Nascosti consapevolmente, con la conferma del 4 ago, quando
erano 18.

Il montaggio fissa cosa significa un path: `local/x` e `remote/drive/x` sono file
DIVERSI che possono avere lo stesso nome. È per questo che la domanda «quale dei
due risponde a una lettura?» non si pone — non è esprimibile.

Il test che conta di più è quello sulla forma LEGACY. `files/x` deve continuare a
risolvere dove risolveva prima — Drive su un topic Drive — perché mapparlo su
`local/` cambierebbe in silenzio il bersaglio di ogni riferimento già scritto nei
messaggi, nelle etichette di provenienza e nella memoria degli agenti.
"""
from __future__ import annotations

import unittest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch

from .local_fs import LocalFsStorage
from .service import TopicService, TopicError


class FakeRemote:
    """Uno storage finto che sta per il remote montato."""

    def __init__(self):
        self.data = {"relazione.pdf": b"dal remote"}

    def list(self, path):
        from .storage import Entry
        if path.strip("/"):
            return []
        return [Entry(name=n, kind="file", size=len(v), mime=None, url=None,
                      version="v1") for n, v in self.data.items()]

    def read(self, path):
        from .storage import ReadResult, NotFound
        n = path.strip("/")
        if n not in self.data:
            raise NotFound(n)
        return ReadResult(data=self.data[n], version="v1")

    def write(self, path, data, if_version=None):
        self.data[path.strip("/")] = data
        return "v2"

    def stat(self, path):
        return None

    def exists(self, path):
        return path.strip("/") in self.data

    def delete(self, path):
        self.data.pop(path.strip("/"), None)


class Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="mounts-"))
        self.svc = TopicService(LocalFsStorage(str(self.root)))
        self.svc.new("SEAL-1", "acme", {"title": "Acme", "owner": "davide"})
        self.svc.put_file("SEAL-1", "acme", "nota-locale.md", b"dal locale")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _with_remote(self):
        """Aggancia un remote finto, senza toccare Drive."""
        meta, ver = self.svc._read_meta("SEAL-1", "acme")
        meta["remote"] = {"type": "drive", "config": {"folder": "FID", "name": "50-execution"}}
        self.svc._write_meta("SEAL-1", "acme", meta, base_version=ver)
        fake = FakeRemote()
        return (patch.object(self.svc, "_drive_remote_config", lambda m: {"folder": "FID"}),
                patch.object(self.svc, "_drive_backend_for", lambda t, n, c: fake)), fake

    def run_with(self, ctx, fn):
        for c in ctx:
            c.start()
        try:
            return fn()
        finally:
            [c.stop() for c in ctx]


class RootTests(Base):
    def test_the_root_shows_local_when_there_is_no_remote(self):
        nomi = [e["name"] for e in self.svc.list_files("SEAL-1", "acme")]
        self.assertIn("local", nomi)
        self.assertNotIn("remote", nomi)

    def test_files_is_no_longer_a_folder(self):
        """`files/` sparisce dalla vista: il contenuto non si è spostato, si
        raggiunge da `local/`. Lasciarlo accanto ai mount mostrerebbe le stesse
        cose due volte con due nomi."""
        nomi = [e["name"] for e in self.svc.list_files("SEAL-1", "acme")]
        self.assertNotIn("files", nomi)

    def test_the_control_plane_stays_visible_but_is_not_a_mount(self):
        """Vedere meta.json e summary.md è utile; renderli scrivibili per path
        sarebbe disfare A1. Restano voci della radice, non mount."""
        voci = {e["name"]: e for e in self.svc.list_files("SEAL-1", "acme")}
        self.assertIn("summary.md", voci)
        self.assertEqual(voci["summary.md"]["kind"], "file")

    def test_the_root_shows_both_mounts_with_a_remote(self):
        ctx, _ = self._with_remote()

        def go():
            nomi = [e["name"] for e in self.svc.list_files("SEAL-1", "acme")]
            self.assertIn("local", nomi)
            self.assertIn("remote", nomi)
        self.run_with(ctx, go)


class BothPlanesVisibleTests(Base):
    def test_local_files_no_longer_disappear_when_a_remote_is_linked(self):
        """Il difetto che questa modifica esiste per chiudere: 65 file su disco e
        zero visibili."""
        ctx, _ = self._with_remote()

        def go():
            locali = [e["name"] for e in self.svc.list_files("SEAL-1", "acme", "local")]
            self.assertIn("nota-locale.md", locali)
        self.run_with(ctx, go)

    def test_the_remote_is_listed_under_its_own_name(self):
        ctx, _ = self._with_remote()

        def go():
            mounts = [e["name"] for e in self.svc.list_files("SEAL-1", "acme", "remote")]
            self.assertEqual(mounts, ["drive"])
            voci = [e["name"] for e in self.svc.list_files("SEAL-1", "acme", "remote/drive")]
            self.assertIn("relazione.pdf", voci)
        self.run_with(ctx, go)

    def test_the_two_planes_can_hold_the_same_name(self):
        """La ragione per cui la domanda sulla collisione non si pone: sono due
        file diversi con due path diversi."""
        ctx, fake = self._with_remote()

        def go():
            fake.data["omonimo.md"] = b"versione remota"
            self.svc.put_file("SEAL-1", "acme", "local/omonimo.md", b"versione locale")
            self.assertEqual(self.svc.read_file("SEAL-1", "acme", "local/omonimo.md"),
                             b"versione locale")
            self.assertEqual(self.svc.read_file("SEAL-1", "acme", "remote/drive/omonimo.md"),
                             b"versione remota")
        self.run_with(ctx, go)


class LegacyPathTests(Base):
    """La forma `files/x` non deve cambiare bersaglio: mapparla su `local/`
    farebbe puntare a file locali invisibili ogni riferimento già scritto."""

    def test_legacy_resolves_to_the_remote_on_a_remote_topic(self):
        ctx, _ = self._with_remote()

        def go():
            self.assertEqual(self.svc.read_file("SEAL-1", "acme", "files/relazione.pdf"),
                             b"dal remote")
        self.run_with(ctx, go)

    def test_legacy_resolves_to_local_without_a_remote(self):
        self.assertEqual(self.svc.read_file("SEAL-1", "acme", "files/nota-locale.md"),
                         b"dal locale")

    def test_a_bare_name_still_writes_where_it_used_to(self):
        r = self.svc.put_file("SEAL-1", "acme", "nuovo.md", b"x")
        self.assertEqual(r["path"], "local/nuovo.md")


class ExplicitMountTests(Base):
    def test_writing_to_an_unmounted_remote_is_refused(self):
        with self.assertRaises(TopicError) as cm:
            self.svc.put_file("SEAL-1", "acme", "remote/drive/x.md", b"x")
        self.assertIn("non ha un remote", str(cm.exception))

    def test_a_wrong_remote_name_is_refused_with_the_right_one(self):
        ctx, _ = self._with_remote()

        def go():
            with self.assertRaises(TopicError) as cm:
                self.svc.read_file("SEAL-1", "acme", "remote/sbagliato/x")
            self.assertIn("drive", str(cm.exception))
        self.run_with(ctx, go)

    def test_a_mount_itself_cannot_be_deleted(self):
        with self.assertRaises(TopicError):
            self.svc.delete_file("SEAL-1", "acme", "local")

    def test_the_control_plane_cannot_be_deleted_through_the_tree(self):
        with self.assertRaises(TopicError) as cm:
            self.svc.delete_file("SEAL-1", "acme", "AGENTS.md")
        self.assertIn("control-plane", str(cm.exception))

    def test_traversal_is_refused(self):
        for cattivo in ("local/../../etc/passwd", "remote/drive/../.."):
            with self.subTest(path=cattivo):
                with self.assertRaises(TopicError):
                    self.svc.read_file("SEAL-1", "acme", cattivo)

    def test_an_encoded_traversal_never_returns_data(self):
        """`..%2f` NON è un traversal: nessuno lo decodifica, quindi è un nome di
        file letterale. Qui non si asserisce la classe d'errore — sarebbe
        specificare troppo — ma la proprietà che conta: non consegna mai byte.

        La difesa vera è più sotto: `LocalFsStorage._abs` risolve il path e
        rifiuta ciò che esce dalla root, quindi anche un traversal davvero
        decodificato non uscirebbe."""
        with self.assertRaises(Exception):
            self.svc.read_file("SEAL-1", "acme", "local/..%2f")

    def test_the_storage_layer_refuses_a_path_outside_the_root(self):
        """La guardia su cui poggia il test qui sopra, verificata invece che
        presunta."""
        from .storage import StorageError
        with self.assertRaises(StorageError):
            self.svc.s.read("SEAL-1/acme/../../../../etc/passwd")


class ProvenanceTests(Base):
    def test_provenance_is_labelled_on_the_local_mount(self):
        r = self.svc.put_file("SEAL-1", "acme", "local/doc.pdf", b"x",
                              provenance="trusted")
        self.assertEqual(r["provenance"], "trusted")
        self.assertEqual(r["path"], "local/doc.pdf")

    def test_no_provenance_is_invented_for_the_remote(self):
        """Sul remote il file non ce l'ha messo il nostro upload: attribuirgli
        una provenienza sarebbe una classificazione inventata."""
        ctx, _ = self._with_remote()

        def go():
            self.svc.put_file("SEAL-1", "acme", "remote/drive/x.md", b"x")
            mappa = self.svc.provenance_map("SEAL-1", "acme")
            self.assertNotIn("x.md", mappa)
        self.run_with(ctx, go)


if __name__ == "__main__":
    unittest.main()

"""L'albero dei dati, solo locale (decision-record #40).

Prima esisteva anche `remote/<nome>/`, un secondo mount per una cartella Drive
collegata — proxy live, mai sincronizzato, causa misurata della lentezza
riportata da Davide (`_open`, 22 ago 2026: 4-7s per topic su 98). Drive non è
più un filesystem del topic: si raggiunge coi verbi `gdrive.*` nello scratch di
un agente. Qui restano solo i comportamenti del piano locale.
"""
from __future__ import annotations

import unittest
import tempfile
import shutil
from pathlib import Path

from .local_fs import LocalFsStorage
from .service import TopicService, TopicError


class Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="mounts-"))
        self.svc = TopicService(LocalFsStorage(str(self.root)))
        self.svc.new("SEAL-1", "acme", {"title": "Acme", "owner": "davide"})
        self.svc.put_file("SEAL-1", "acme", "nota-locale.md", b"dal locale")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)


class RootTests(Base):
    def test_the_root_shows_only_local(self):
        nomi = [e["name"] for e in self.svc.list_files("SEAL-1", "acme")]
        self.assertEqual(nomi, ["local"])

    def test_files_is_no_longer_a_folder(self):
        """`files/` sparisce dalla vista: il contenuto non si è spostato, si
        raggiunge da `local/`. Lasciarlo accanto ai mount mostrerebbe le stesse
        cose due volte con due nomi."""
        nomi = [e["name"] for e in self.svc.list_files("SEAL-1", "acme")]
        self.assertNotIn("files", nomi)

    def test_the_control_plane_is_not_in_the_data_tree(self):
        """La radice è quella dei DATI. Prima mostrava anche meta.json,
        summary.md e i `meta.json.bak-*` di vecchie migrazioni: rumore in un
        browser di file, e — peggio — insegnava che quei file sono raggiungibili
        per path come gli altri, cioè il contrario di ciò che A1 ha stabilito.

        Si leggono coi loro verbi: stato e deadline nella sezione Meta della
        sidebar, il TLDR nell'intestazione, AGENTS.md nel suo pannello."""
        nomi = [e["name"] for e in self.svc.list_files("SEAL-1", "acme")]
        for cp in ("meta.json", "summary.md", "AGENTS.md"):
            self.assertNotIn(cp, nomi)
        self.assertEqual(sorted(nomi), ["local"])

    def test_migration_backups_no_longer_leak_into_the_view(self):
        """Il caso concreto visto su proof-of-flex-2: due `meta.json.bak-*`
        mostrati a un utente che non li aveva chiesti."""
        d = self.root / "SEAL-1" / "acme"
        (d / "meta.json.bak-20260728").write_text("{}", encoding="utf-8")
        nomi = [e["name"] for e in self.svc.list_files("SEAL-1", "acme")]
        self.assertFalse([n for n in nomi if ".bak" in n])

    def test_the_control_plane_is_still_readable_by_path(self):
        """Non più navigabile non vuol dire sparito: chi sa cosa cerca lo legge."""
        self.assertTrue(self.svc.read_file("SEAL-1", "acme", "meta.json"))


class LegacyPathTests(Base):
    """La forma `files/x` non deve cambiare bersaglio: risolve sempre in
    locale, come faceva un topic senza remote prima di questa modifica."""

    def test_legacy_resolves_to_local(self):
        self.assertEqual(self.svc.read_file("SEAL-1", "acme", "files/nota-locale.md"),
                         b"dal locale")

    def test_a_bare_name_still_writes_where_it_used_to(self):
        r = self.svc.put_file("SEAL-1", "acme", "nuovo.md", b"x")
        self.assertEqual(r["path"], "local/nuovo.md")


class ExplicitMountTests(Base):
    def test_a_mount_itself_cannot_be_deleted(self):
        with self.assertRaises(TopicError):
            self.svc.delete_file("SEAL-1", "acme", "local")

    def test_the_control_plane_cannot_be_deleted_through_the_tree(self):
        with self.assertRaises(TopicError) as cm:
            self.svc.delete_file("SEAL-1", "acme", "AGENTS.md")
        self.assertIn("control-plane", str(cm.exception))

    def test_traversal_is_refused(self):
        for cattivo in ("local/../../etc/passwd",):
            with self.subTest(path=cattivo):
                with self.assertRaises(TopicError):
                    self.svc.read_file("SEAL-1", "acme", cattivo)

    def test_an_encoded_traversal_never_returns_data(self):
        """`..%2f` NON è un traversal: nessuno lo decodifica, quindi è un nome di
        file letterale. Qui non si asserisce la classe d'errore — sarebbe
        specificare troppo — ma la proprietà che conta: non consegna mai byte."""
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


if __name__ == "__main__":
    unittest.main()

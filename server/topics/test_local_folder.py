"""Cartella condivisa Mac↔container: BIND reale, non uno specchio come Drive.

Discussione con Davide (19-20 set 2026): scartato un condiviso di sistema
(SMB) per la privacy — tutto visibile a tutti — scelta una radice unica
(`LOCAL_SHARED_ROOT`) bind-montata una volta sola nel gateway, con un
sottopercorso per-topic anziché un path assoluto scelto a runtime.

Il meccanismo è un symlink dentro `files/` del topic verso
`LOCAL_SHARED_ROOT/<nome>`: `LocalFsStorage._abs()` risolve i symlink e
rifiuta qualunque path che, risolto, esca dalla root — quindi un symlink
VERSO `LOCAL_SHARED_ROOT` (che sta dentro la stessa root) passa il
confinamento, mentre uno che punti fuori (un path assoluto del Mac non
imbustato nella root) verrebbe rifiutato. Questi test coprono sia il verbo di
alto livello sia le due primitive di storage da cui dipende
(`symlink`/`unlink_symlink`), perché il footgun più pericoloso — cancellare
il CONTENUTO REALE della cartella condivisa invece del solo collegamento — si
annida in `unlink_symlink`, non nel verbo.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from .local_fs import LocalFsStorage
from .service import TopicService, TopicError, LOCAL_SHARED_ROOT
from .storage import StorageError


class Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="local-folder-"))
        self.storage = LocalFsStorage(str(self.root))
        self.svc = TopicService(self.storage)
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def crea_topic(self, tier="SEAL-1", name="acme"):
        self.svc.new(tier, name, {"title": "Acme"})
        return tier, name

    def monta_radice_condivisa(self):
        (self.root / LOCAL_SHARED_ROOT).mkdir(parents=True, exist_ok=True)


class LocalFolderAddTests(Base):
    def test_without_the_shared_root_mounted_it_refuses_with_the_remedy(self):
        """Senza il bind mount Docker non esiste `_shared-local`: il rifiuto
        deve dire cosa manca, non sollevare un errore di filesystem generico."""
        tier, name = self.crea_topic()
        with self.assertRaises(TopicError) as cm:
            self.svc.local_folder_add(tier, name, "tomato-amministrazione")
        msg = str(cm.exception)
        self.assertIn(LOCAL_SHARED_ROOT, msg)
        self.assertIn("docker-compose", msg)

    def test_a_successful_add_creates_a_real_symlink(self):
        tier, name = self.crea_topic()
        self.monta_radice_condivisa()
        out = self.svc.local_folder_add(tier, name, "tomato-amministrazione")
        self.assertEqual(out["local_folder"]["name"], "tomato-amministrazione")
        link = self.root / tier / name / "files" / "tomato-amministrazione"
        self.assertTrue(link.is_symlink())
        self.assertEqual(link.resolve(),
                         (self.root / LOCAL_SHARED_ROOT / "tomato-amministrazione").resolve())

    def test_the_shared_subfolder_is_group_writable(self):
        """Trovato da Davide il 23 set 2026: la cartella esisteva ma il suo
        stesso account Mac (utente diverso da chi monta il volume) non
        poteva scriverci — solo il proprietario poteva. Un bind fra utenti
        macOS diversi è inutile se solo un lato può scrivere."""
        tier, name = self.crea_topic()
        self.monta_radice_condivisa()
        self.svc.local_folder_add(tier, name, "condivisa")
        mode = (self.root / LOCAL_SHARED_ROOT / "condivisa").stat().st_mode
        self.assertTrue(mode & 0o020, "il gruppo deve poter scrivere (0o775)")

    def test_a_file_dropped_on_the_mac_side_is_visible_from_the_topic(self):
        """Il punto della feature: è un bind, non una sincronizzazione."""
        tier, name = self.crea_topic()
        self.monta_radice_condivisa()
        self.svc.local_folder_add(tier, name, "condivisa")
        (self.root / LOCAL_SHARED_ROOT / "condivisa" / "nota.txt").write_text("ciao")
        entries = self.storage.list(f"{tier}/{name}/files/condivisa")
        self.assertEqual([e.name for e in entries], ["nota.txt"])

    def test_a_write_from_the_topic_is_visible_on_the_mac_side(self):
        tier, name = self.crea_topic()
        self.monta_radice_condivisa()
        self.svc.local_folder_add(tier, name, "condivisa")
        self.storage.write(f"{tier}/{name}/files/condivisa/report.md", b"# report")
        self.assertEqual(
            (self.root / LOCAL_SHARED_ROOT / "condivisa" / "report.md").read_bytes(),
            b"# report")

    def test_the_mount_name_becomes_the_subfolder_name(self):
        """Un solo nome, non due mappe che possono divergere (vedi docstring
        di `local_folder_add`)."""
        tier, name = self.crea_topic()
        self.monta_radice_condivisa()
        self.svc.local_folder_add(tier, name, "verbale-2026")
        self.assertTrue((self.root / LOCAL_SHARED_ROOT / "verbale-2026").is_dir())

    def test_two_different_topics_never_share_the_same_real_subfolder(self):
        """Trovato da Davide il 23 set 2026 su un topic con dati finanziari
        riservati: senza il controllo globale, un secondo topic che sceglie
        lo stesso mount_name di un primo finirebbe silenziosamente per
        condividere la STESSA cartella reale — la segregazione promessa
        romperebbe esattamente nel meccanismo che dovrebbe garantirla."""
        self.monta_radice_condivisa()
        self.crea_topic("SEAL-1", "acme")
        self.crea_topic("SEAL-1", "beta")
        out_a = self.svc.local_folder_add("SEAL-1", "acme", "documenti")
        out_b = self.svc.local_folder_add("SEAL-1", "beta", "documenti")
        self.assertNotEqual(out_a["local_folder"]["name"], out_b["local_folder"]["name"])
        link_a = (self.root / "SEAL-1" / "acme" / "files" / out_a["local_folder"]["name"]).resolve()
        link_b = (self.root / "SEAL-1" / "beta" / "files" / out_b["local_folder"]["name"]).resolve()
        self.assertNotEqual(link_a, link_b)

    def test_a_colliding_name_gets_disambiguated_not_overwritten(self):
        tier, name = self.crea_topic()
        self.monta_radice_condivisa()
        self.svc.local_folder_add(tier, name, "condivisa")
        out = self.svc.local_folder_add(tier, name, "condivisa")
        self.assertEqual(out["local_folder"]["name"], "condivisa-2")

    def test_it_never_overwrites_an_existing_uploaded_file(self):
        """Un file caricato a mano con lo stesso nome non deve sparire sotto
        un symlink silenzioso."""
        tier, name = self.crea_topic()
        self.monta_radice_condivisa()
        self.storage.write(f"{tier}/{name}/files/report/gia-qui.txt", b"x")
        # "report" esiste già come cartella reale (non dichiarata in
        # local_folders): _unique_name non lo vede, ma Storage.symlink deve
        # comunque rifiutarsi di sovrascriverlo.
        with self.assertRaises(TopicError):
            self.svc.local_folder_add(tier, name, "report")


class LocalFolderRemoveTests(Base):
    def test_removing_the_link_never_touches_the_real_content(self):
        """Il footgun che il metodo esiste per evitare: sganciare un topic
        non deve MAI cancellare il contenuto reale sulla cartella condivisa."""
        tier, name = self.crea_topic()
        self.monta_radice_condivisa()
        self.svc.local_folder_add(tier, name, "condivisa")
        (self.root / LOCAL_SHARED_ROOT / "condivisa" / "prezioso.txt").write_text("non toccarmi")
        self.svc.local_folder_remove(tier, name, "condivisa")
        link = self.root / tier / name / "files" / "condivisa"
        self.assertFalse(link.exists())
        self.assertFalse(link.is_symlink())
        self.assertEqual(
            (self.root / LOCAL_SHARED_ROOT / "condivisa" / "prezioso.txt").read_text(),
            "non toccarmi")

    def test_removing_an_unknown_mount_says_what_exists_instead(self):
        tier, name = self.crea_topic()
        self.monta_radice_condivisa()
        self.svc.local_folder_add(tier, name, "condivisa")
        with self.assertRaises(TopicError) as cm:
            self.svc.local_folder_remove(tier, name, "altra")
        self.assertIn("condivisa", str(cm.exception))

    def test_removing_twice_is_not_an_error(self):
        """Il symlink può essere già sparito (pulizia manuale, doppio click):
        pulire il meta deve restare possibile."""
        tier, name = self.crea_topic()
        self.monta_radice_condivisa()
        self.svc.local_folder_add(tier, name, "condivisa")
        link = self.root / tier / name / "files" / "condivisa"
        link.unlink()
        self.svc.local_folder_remove(tier, name, "condivisa")  # non solleva


class StoragePrimitiveTests(Base):
    """Le tre primitive nuove, isolate da `TopicService`."""

    def test_chmod_shared_adds_group_write(self):
        d = self.root / LOCAL_SHARED_ROOT / "x"
        d.mkdir(parents=True, mode=0o755)
        self.storage.chmod_shared(f"{LOCAL_SHARED_ROOT}/x")
        self.assertTrue(d.stat().st_mode & 0o020)

    def test_symlink_refuses_a_missing_target(self):
        with self.assertRaises(StorageError):
            self.storage.symlink("SEAL-1/acme/files/x", "_shared-local/non-esiste")

    def test_symlink_refuses_to_overwrite(self):
        (self.root / LOCAL_SHARED_ROOT / "a").mkdir(parents=True)
        self.storage.mkdir("SEAL-1/acme/files")
        (self.root / "SEAL-1" / "acme" / "files" / "x").mkdir(parents=True)
        with self.assertRaises(StorageError):
            self.storage.symlink("SEAL-1/acme/files/x", f"{LOCAL_SHARED_ROOT}/a")

    def test_unlink_symlink_refuses_a_real_directory(self):
        """La difesa diretta contro il footgun: se per qualche errore a monte
        `path` non è un symlink, `unlink_symlink` deve rifiutarsi — mai
        degradare a un `rmtree` implicito."""
        real = self.root / LOCAL_SHARED_ROOT / "vera"
        real.mkdir(parents=True)
        with self.assertRaises(StorageError):
            self.storage.unlink_symlink(f"{LOCAL_SHARED_ROOT}/vera")
        self.assertTrue(real.is_dir())

    def test_unlink_symlink_refuses_a_real_file(self):
        (self.root / LOCAL_SHARED_ROOT).mkdir(parents=True)
        f = self.root / LOCAL_SHARED_ROOT / "vero.txt"
        f.write_text("dati")
        with self.assertRaises(StorageError):
            self.storage.unlink_symlink(f"{LOCAL_SHARED_ROOT}/vero.txt")
        self.assertTrue(f.is_file())

    def test_unlink_symlink_removes_only_the_link(self):
        target = self.root / LOCAL_SHARED_ROOT / "target"
        target.mkdir(parents=True)
        (target / "dentro.txt").write_text("resta")
        link = self.root / "SEAL-1" / "acme" / "files" / "x"
        link.parent.mkdir(parents=True)
        link.symlink_to(target, target_is_directory=True)
        self.storage.unlink_symlink("SEAL-1/acme/files/x")
        self.assertFalse(link.exists())
        self.assertTrue((target / "dentro.txt").is_file())


if __name__ == "__main__":
    unittest.main()

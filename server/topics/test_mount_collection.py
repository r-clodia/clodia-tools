"""Drive e Telegram hanno un campo proprio, non più un array condiviso.

Decision-record #40 (7 set 2026): il vecchio `meta["mounts"]` — drive, git e
telegram nella stessa lista, per riuso di schema — sparisce. Drive diventa
`meta["drive_folders"]` (whitelist + confinamento per `gdrive.*`, mai un
filesystem); Telegram diventa `meta["telegram_binds"]`; git non ha nulla da
preservare (nessun topic in produzione ne aveva uno, misurato il 7 set 2026).

I topic scritti prima di questa modifica hanno ancora il vecchio `mounts`: la
migrazione one-shot (`_migrate_mounts_field`, dentro `_open`) li converte senza
perdere l'associazione nome↔folder-id — è la restrizione di perimetro che
`gdrive_root.roots_for_call` legge, e cancellarla silenziosamente lascerebbe
un topic con un perimetro più largo di quello che l'owner aveva scelto.
"""
from __future__ import annotations

import unittest
import tempfile
import shutil
from pathlib import Path

from .local_fs import LocalFsStorage
from .service import TopicService, drive_folders, telegram_binds, _unique_name


class AccessorTests(unittest.TestCase):
    def test_drive_folders_is_always_a_list(self):
        self.assertEqual(drive_folders({}), [])
        self.assertEqual(drive_folders({"drive_folders": None}), [])

    def test_telegram_binds_is_always_a_list(self):
        self.assertEqual(telegram_binds({}), [])
        self.assertEqual(telegram_binds({"telegram_binds": None}), [])

    def test_malformed_entries_are_dropped(self):
        self.assertEqual(drive_folders({"drive_folders": ["x", {"name": "a"}]}), [])
        self.assertEqual(drive_folders({"drive_folders": [{"name": "a", "folder": "F"}]}),
                         [{"name": "a", "folder": "F"}])


class UniqueNameTests(unittest.TestCase):
    def test_the_default_is_the_type(self):
        self.assertEqual(_unique_name("drive", set()), "drive")

    def test_a_collision_does_not_overwrite(self):
        self.assertEqual(_unique_name("drive", {"drive"}), "drive-2")
        self.assertEqual(_unique_name("drive", {"drive", "drive-2"}), "drive-3")

    def test_a_human_name_becomes_a_safe_segment(self):
        for grezzo in ("50 - Execution / Final", "../etc", "Contratti 2026"):
            with self.subTest(grezzo):
                nome = _unique_name(grezzo, set())
                self.assertNotIn("/", nome)
                self.assertNotIn("..", nome)
                self.assertTrue(nome)


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="mountmig-"))
        self.svc = TopicService(LocalFsStorage(str(self.root)))
        self.svc.new("SEAL-1", "acme", {"title": "Acme", "owner": "davide"})

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _seed_legacy_mounts(self, mounts):
        meta, ver = self.svc._read_meta("SEAL-1", "acme")
        meta["mounts"] = mounts
        self.svc._write_meta("SEAL-1", "acme", meta, base_version=ver)

    def test_a_drive_mount_becomes_a_drive_folder(self):
        """L'associazione nome↔folder-id è quella che `gdrive_root` legge per
        restringere il perimetro: sparire silenziosamente la allargherebbe."""
        self._seed_legacy_mounts([
            {"name": "contratti", "type": "drive",
             "config": {"folder": "1XyZ", "account": "a@b.it"}}])
        self.svc._migrate_mounts_field("SEAL-1", "acme")
        meta, _ = self.svc._read_meta("SEAL-1", "acme")
        self.assertEqual(drive_folders(meta),
                         [{"name": "contratti", "folder": "1XyZ", "account": "a@b.it"}])
        self.assertNotIn("mounts", meta)

    def test_a_telegram_mount_becomes_a_telegram_bind(self):
        voce = {"name": "gruppo", "type": "telegram",
                "config": {"chat_id": "-100999", "mode": "excerpt", "people": {}}}
        self._seed_legacy_mounts([voce])
        self.svc._migrate_mounts_field("SEAL-1", "acme")
        meta, _ = self.svc._read_meta("SEAL-1", "acme")
        self.assertEqual(telegram_binds(meta), [voce])

    def test_a_git_mount_is_dropped_without_a_trace(self):
        """Nessun topic in produzione ne aveva uno (misurato il 7 set 2026):
        non c'è nulla da preservare."""
        self._seed_legacy_mounts([
            {"name": "codice", "type": "git", "config": {"url": "https://github.com/x/y"}}])
        self.svc._migrate_mounts_field("SEAL-1", "acme")
        meta, _ = self.svc._read_meta("SEAL-1", "acme")
        self.assertEqual(drive_folders(meta), [])
        self.assertNotIn("mounts", meta)

    def test_mixed_mounts_split_correctly(self):
        self._seed_legacy_mounts([
            {"name": "drive", "type": "drive", "config": {"folder": "F1"}},
            {"name": "codice", "type": "git", "config": {"url": "https://x/y"}},
            {"name": "gruppo", "type": "telegram",
             "config": {"chat_id": "-1", "mode": "notify", "people": {}}},
        ])
        self.svc._migrate_mounts_field("SEAL-1", "acme")
        meta, _ = self.svc._read_meta("SEAL-1", "acme")
        self.assertEqual([f["name"] for f in drive_folders(meta)], ["drive"])
        self.assertEqual([b["name"] for b in telegram_binds(meta)], ["gruppo"])

    def test_a_topic_with_no_legacy_mounts_is_untouched(self):
        self.svc._migrate_mounts_field("SEAL-1", "acme")  # non deve sollevare
        meta, _ = self.svc._read_meta("SEAL-1", "acme")
        self.assertEqual(drive_folders(meta), [])

    def test_migration_is_idempotent(self):
        self._seed_legacy_mounts([
            {"name": "drive", "type": "drive", "config": {"folder": "F1"}}])
        self.svc._migrate_mounts_field("SEAL-1", "acme")
        self.svc._migrate_mounts_field("SEAL-1", "acme")
        meta, _ = self.svc._read_meta("SEAL-1", "acme")
        self.assertEqual(len(drive_folders(meta)), 1)


if __name__ == "__main__":
    unittest.main()

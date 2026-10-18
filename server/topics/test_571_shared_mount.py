"""The Mac-shared folder is the topic's `shared/` mount (clodia-platform#571).

On the Mac the folder is `ClodiaShared/<codename>/` — the codename tells which
topic it belongs to. Inside the topic that name is redundant, so the folder is
a mount of its own, `shared/`, next to `local/`. Until #571 it was a symlink
`files/<codename>` and showed up as `local/<codename>/`: those paths are in
messages already sent, so they keep resolving, and provenance labels set under
them keep applying.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from .local_fs import LocalFsStorage
from .service import TopicService, TopicError, LOCAL_SHARED_ROOT


class Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="shared-mount-"))
        self.storage = LocalFsStorage(str(self.root))
        self.svc = TopicService(self.storage)
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        (self.root / LOCAL_SHARED_ROOT).mkdir(parents=True)

    def topic(self, name="acme", tier="SEAL-1", attach=True):
        self.svc.new(tier, name, {"title": name})
        if attach:
            self.svc.local_folder_add(tier, name)
        return tier, name

    def mac(self, slug: str) -> Path:
        return self.root / LOCAL_SHARED_ROOT / slug

    def legacy_topic(self, name="acme", tier="SEAL-1"):
        """A topic attached BEFORE #571: meta entry plus `files/<slug>` symlink."""
        self.svc.new(tier, name, {"title": name})
        self.mac(name).mkdir()
        meta, ver = self.svc._read_meta(tier, name)
        meta["local_folders"] = [{"name": name}]
        self.svc._write_meta(tier, name, meta, base_version=ver)
        self.storage.symlink(f"{tier}/{name}/files/{name}", f"{LOCAL_SHARED_ROOT}/{name}")
        return tier, name


class MountTests(Base):
    def test_the_root_shows_shared_next_to_local(self):
        tier, name = self.topic()
        root = {e["name"]: e for e in self.svc.list_files(tier, name, "")}
        self.assertEqual(root["shared"]["mount"], "shared")
        self.assertEqual(root["shared"]["folder"], "acme")
        self.assertIn("local", root)

    def test_no_shared_mount_without_a_shared_folder(self):
        tier, name = self.topic(attach=False)
        names = [e["name"] for e in self.svc.list_files(tier, name, "")]
        self.assertEqual(names, ["local"])
        with self.assertRaises(TopicError) as cm:
            self.svc.put_file(tier, name, "shared/x.txt", b"x")
        self.assertIn("local_folder_add", str(cm.exception))

    def test_the_mac_folder_is_named_after_the_codename_the_topic_sees_shared(self):
        tier, name = self.topic()
        (self.mac("acme") / "sub").mkdir()
        (self.mac("acme") / "sub" / "nota.txt").write_text("ciao")
        self.assertEqual([e["path"] for e in self.svc.list_files(tier, name, "shared")],
                         ["shared/sub"])
        self.assertEqual([e["path"] for e in self.svc.list_files(tier, name, "shared/sub")],
                         ["shared/sub/nota.txt"])
        self.assertEqual(self.svc.read_file(tier, name, "shared/sub/nota.txt"), b"ciao")

    def test_local_does_not_show_the_shared_folder(self):
        tier, name = self.topic()
        self.svc.put_file(tier, name, "local/mio.txt", b"m")
        self.assertEqual([e["path"] for e in self.svc.list_files(tier, name, "local")],
                         ["local/mio.txt"])

    def test_a_write_lands_on_the_mac_side(self):
        tier, name = self.topic()
        out = self.svc.put_file(tier, name, "shared/report.md", b"# r")
        self.assertEqual(out["path"], "shared/report.md")
        self.assertEqual((self.mac("acme") / "report.md").read_bytes(), b"# r")

    def test_delete_goes_to_the_topic_trash(self):
        tier, name = self.topic()
        self.svc.put_file(tier, name, "shared/via.txt", b"v")
        out = self.svc.delete_file(tier, name, "shared/via.txt")
        self.assertTrue(out["recoverable"])
        self.assertFalse((self.mac("acme") / "via.txt").exists())

    def test_shared_is_a_reserved_name_for_links(self):
        tier, name = self.topic()
        meta, _ = self.svc._read_meta(tier, name)
        self.assertIn("shared", self.svc._link_mount_names(tier, name, meta))


class ProvenanceTests(Base):
    def test_a_file_written_into_shared_keeps_its_label(self):
        tier, name = self.topic()
        self.svc.put_file(tier, name, "shared/ok.pdf", b"x", provenance="trusted")
        self.assertEqual(self.svc.provenance_of(tier, name, "shared/ok.pdf"), "trusted")
        row = self.svc.list_files(tier, name, "shared")[0]
        self.assertEqual(row["provenance"], "trusted")

    def test_a_label_set_before_571_still_applies(self):
        """Keys stay `<slug>/…`: the label set through the old symlink path is
        the one read through `shared/`."""
        tier, name = self.legacy_topic()
        (self.mac("acme") / "vecchio.pdf").write_bytes(b"x")
        self.svc.set_provenance(tier, name, "acme/vecchio.pdf", "trusted")
        self.assertEqual(self.svc.provenance_of(tier, name, "shared/vecchio.pdf"), "trusted")
        row = self.svc.list_files(tier, name, "shared")[0]
        self.assertEqual(row["provenance"], "trusted")

    def test_a_move_between_local_and_shared_carries_the_label(self):
        tier, name = self.topic()
        self.svc.put_file(tier, name, "local/a.pdf", b"x", provenance="untrusted")
        self.svc.move_file(tier, name, "local/a.pdf", "shared/a.pdf")
        self.assertEqual(self.svc.provenance_of(tier, name, "shared/a.pdf"), "untrusted")
        self.assertTrue((self.mac("acme") / "a.pdf").is_file())
        self.svc.move_file(tier, name, "shared/a.pdf", "local/b.pdf")
        self.assertEqual(self.svc.provenance_of(tier, name, "local/b.pdf"), "untrusted")


class MigrationTests(Base):
    def test_the_old_symlink_goes_away_and_the_content_stays(self):
        tier, name = self.legacy_topic()
        (self.mac("acme") / "dato.txt").write_text("resta")
        link = self.root / tier / name / "files" / "acme"
        self.assertTrue(link.is_symlink())
        self.svc.list_files(tier, name, "")
        self.assertFalse(link.exists() or link.is_symlink())
        self.assertEqual((self.mac("acme") / "dato.txt").read_text(), "resta")
        self.assertEqual([e["path"] for e in self.svc.list_files(tier, name, "shared")],
                         ["shared/dato.txt"])

    def test_open_migrates_too(self):
        tier, name = self.legacy_topic()
        self.svc.open(tier, name)
        self.assertFalse((self.root / tier / name / "files" / "acme").is_symlink())

    def test_old_paths_keep_resolving_before_and_after_the_migration(self):
        tier, name = self.legacy_topic()
        (self.mac("acme") / "x.txt").write_text("x")
        for when in ("before", "after"):
            with self.subTest(when=when):
                if when == "after":
                    self.svc.list_files(tier, name, "")
                self.assertEqual(self.svc.read_file(tier, name, "local/acme/x.txt"), b"x")
                self.assertEqual(self.svc.read_file(tier, name, "files/acme/x.txt"), b"x")
                self.assertEqual(
                    [e["path"] for e in self.svc.list_files(tier, name, "local/acme")],
                    ["shared/x.txt"])

    def test_a_write_by_the_old_path_lands_in_the_shared_folder(self):
        tier, name = self.legacy_topic()
        self.svc.list_files(tier, name, "")
        out = self.svc.put_file(tier, name, "local/acme/nuovo.txt", b"n")
        self.assertEqual(out["path"], "shared/nuovo.txt")
        self.assertEqual((self.mac("acme") / "nuovo.txt").read_bytes(), b"n")
        self.assertFalse((self.root / tier / name / "files" / "acme").exists())

    def test_the_alias_never_reaches_another_topics_folder(self):
        """`local/<slug>/` resolves only to THIS topic's shared folder: the
        segregation of #498 must not leak through the compatibility path."""
        self.topic("acme")
        (self.mac("acme") / "riservato.txt").write_text("solo acme")
        tier, beta = self.topic("beta")
        with self.assertRaises(Exception):
            self.svc.read_file(tier, beta, "local/acme/riservato.txt")


if __name__ == "__main__":
    unittest.main()


class ConfinementTests(Base):
    """A meta can never point `shared/` outside its own folder of the shared
    root (review of clodia-tools#399, B1)."""

    def test_topic_new_drops_local_folders(self):
        self.mac("victim").mkdir()
        self.svc.new("SEAL-1", "evil", {"title": "evil",
                                        "local_folders": [{"name": "victim"}]})
        meta, _ = self.svc._read_meta("SEAL-1", "evil")
        self.assertNotIn("local_folders", meta)
        with self.assertRaises(TopicError):
            self.svc.read_file("SEAL-1", "evil", "shared/x.txt")

    def test_a_traversal_slug_is_not_a_shared_folder(self):
        tier, name = self.topic(attach=False)
        self.svc.new("SEAL-3", "victim", {"title": "victim"})
        self.svc.put_file("SEAL-3", "victim", "local/segreto.txt", b"s")
        meta, ver = self.svc._read_meta(tier, name)
        meta["local_folders"] = [{"name": "../SEAL-3/victim/files"}]
        self.svc._write_meta(tier, name, meta, base_version=ver)
        with self.assertRaises(TopicError):
            self.svc.read_file(tier, name, "shared/segreto.txt")
        self.assertNotIn("shared", [e["name"] for e in self.svc.list_files(tier, name, "")])

    def test_a_symlink_in_the_shared_folder_cannot_leave_it(self):
        tier, name = self.topic()
        self.svc.new("SEAL-3", "victim", {"title": "victim"})
        self.svc.put_file("SEAL-3", "victim", "local/segreto.txt", b"s")
        (self.mac("acme") / "esca").symlink_to(self.root / "SEAL-3" / "victim" / "files")
        with self.assertRaises(TopicError):
            self.svc.read_file(tier, name, "shared/esca/segreto.txt")
        with self.assertRaises(TopicError):
            self.svc.put_file(tier, name, "shared/esca/nuovo.txt", b"x")
        self.assertFalse((self.root / "SEAL-3" / "victim" / "files" / "nuovo.txt").exists())

    def test_a_shared_folder_that_is_a_symlink_out_is_refused(self):
        tier, name = self.topic(attach=False)
        self.svc.new("SEAL-3", "victim", {"title": "victim"})
        self.mac("trap").symlink_to(self.root / "SEAL-3" / "victim" / "files")
        meta, ver = self.svc._read_meta(tier, name)
        meta["local_folders"] = [{"name": "trap"}]
        self.svc._write_meta(tier, name, meta, base_version=ver)
        with self.assertRaises(TopicError):
            self.svc.list_files(tier, name, "shared")


    def test_a_symlink_to_another_topics_shared_folder_is_refused(self):
        tier, name = self.topic()
        self.topic("beta")
        (self.mac("beta") / "suo.txt").write_text("b")
        (self.mac("acme") / "ponte").symlink_to(self.mac("beta"))
        with self.assertRaises(TopicError):
            self.svc.read_file(tier, name, "shared/ponte/suo.txt")

    def test_an_imported_meta_drops_local_folders(self):
        import json
        from .. import topics_api
        raw = json.dumps({"title": "x", "local_folders": [{"name": "victim"}]})
        meta = json.loads(topics_api._snapshot_meta_bytes(raw.encode(), "SEAL-1"))
        self.assertNotIn("local_folders", meta)

    def test_a_long_name_still_gives_a_usable_shared_folder(self):
        self.svc.new("SEAL-1", "acme", {"title": "acme"})
        self.svc.local_folder_add("SEAL-1", "acme", "x" * 300)
        self.assertIn("shared", [e["name"] for e in self.svc.list_files("SEAL-1", "acme", "")])


class EagerMigrationTests(Base):
    def test_boot_migrates_every_legacy_topic_without_opening_them(self):
        self.legacy_topic("acme")
        self.legacy_topic("beta", tier="SEAL-2")
        self.topic("nuovo")
        self.topic("senza", attach=False)
        res = self.svc.migrate_shared_symlinks()
        self.assertEqual(res, {"with_shared": 3, "migrated": 2})
        for tier, name in (("SEAL-1", "acme"), ("SEAL-2", "beta")):
            link = self.root / tier / name / "files" / name
            self.assertFalse(link.is_symlink() or link.exists())
            self.assertTrue(self.mac(name).is_dir())

    def test_the_pass_is_idempotent(self):
        self.legacy_topic("acme")
        self.svc.migrate_shared_symlinks()
        self.assertEqual(self.svc.migrate_shared_symlinks(),
                         {"with_shared": 1, "migrated": 0})

    def test_a_real_directory_with_the_slug_name_is_left_alone(self):
        tier, name = self.topic()
        (self.root / tier / name / "files" / "acme").mkdir(parents=True)
        (self.root / tier / name / "files" / "acme" / "mio.txt").write_text("m")
        self.assertEqual(self.svc.migrate_shared_symlinks()["migrated"], 0)
        self.assertTrue((self.root / tier / name / "files" / "acme" / "mio.txt").exists())

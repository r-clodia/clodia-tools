from __future__ import annotations

import json
import sys
import tempfile
import types
import unittest
from unittest import mock

from .drive_fs import DriveStorage
from .local_fs import LocalFsStorage
from .service import TopicService


class DriveBackedTopicTests(unittest.TestCase):
    """Modello corretto (#45): collegare un topic a una cartella Drive rende
    Drive la source of truth. Nessun upload dei file locali, nessuna
    'migrazione', nessun marker: i verbi file proxano direttamente al remoto."""

    def setUp(self) -> None:
        self.local = LocalFsStorage(tempfile.mkdtemp())
        self.drive = LocalFsStorage(tempfile.mkdtemp())
        self.svc = TopicService(self.local)
        with mock.patch(
            "server.instance_profile.topic_default_participants",
            return_value=[],
        ):
            self.svc.new("SEAL-1", "live", {"owner": "davide"})
        # Drive è la FONTE: pre-popolato col contenuto autoritativo.
        self.drive.write("remote.txt", b"REMOTE")
        # Collega il remote drive scrivendo il meta direttamente (qui il backend
        # Drive è mockato, quindi non passiamo dal provisioning della cartella).
        meta_path = self.svc._meta_p("SEAL-1", "live")
        current = self.local.read(meta_path)
        meta = json.loads(current.data)
        meta["remote"] = {
            "type": "drive",
            "config": {"folder": "folder-id", "account": "davide"},
        }
        self.local.write(
            meta_path,
            json.dumps(meta).encode(),
            if_version=current.version,
        )
        self.backend = mock.patch.object(
            self.svc, "_drive_backend_for", return_value=self.drive)
        self.backend.start()

    def tearDown(self) -> None:
        self.backend.stop()

    def test_reads_and_writes_go_straight_to_drive(self):
        files = self.svc.list_files("SEAL-1", "live", "files")
        self.assertEqual([item["name"] for item in files], ["remote.txt"])

        self.svc.put_file("SEAL-1", "live", "now.txt", b"NOW")
        self.assertEqual(self.drive.read("now.txt").data, b"NOW")
        self.assertFalse(self.local.exists("SEAL-1/live/files/now.txt"))
        self.assertEqual(
            self.svc.read_file("SEAL-1", "live", "files/remote.txt"),
            b"REMOTE",
        )

    def test_local_files_are_hidden_never_uploaded(self):
        # Un file solo-locale, con topic drive-backed, "sparisce dalla vista":
        # non viene mostrato né caricato su Drive, ma resta intatto in locale.
        self.local.write("SEAL-1/live/files/solo-locale.txt", b"LOCAL")
        names = [i["name"] for i in self.svc.list_files("SEAL-1", "live", "files")]
        self.assertNotIn("solo-locale.txt", names)       # nascosto dalla vista
        self.assertFalse(self.drive.exists("solo-locale.txt"))  # mai caricato
        self.assertEqual(
            self.local.read("SEAL-1/live/files/solo-locale.txt").data, b"LOCAL")

    def test_delete_uses_drive_trash_backend(self):
        result = self.svc.delete_file("SEAL-1", "live", "files/remote.txt")
        self.assertEqual(result["trash_path"], "Drive/Cestino")
        self.assertFalse(self.drive.exists("remote.txt"))

    def test_disabling_drive_materializes_remote_files_locally(self):
        class Remote:
            def disable(self):
                return None

        with mock.patch.object(self.svc, "_remote_for", return_value=Remote()):
            self.svc.remote_disable("SEAL-1", "live")

        self.assertEqual(
            self.local.read("SEAL-1/live/files/remote.txt").data, b"REMOTE")
        meta = json.loads(self.local.read("SEAL-1/live/meta.json").data)
        self.assertNotIn("remote", meta)

    def test_disable_keeps_drive_intact_when_pull_fails(self):
        # Se il pull fallisce, Drive (fonte) resta intatto → nessuna perdita.
        class Remote:
            def disable(self):
                return None

        with mock.patch.object(self.svc, "_remote_for", return_value=Remote()), \
             mock.patch.object(self.svc, "_drive_pull_tree",
                               side_effect=RuntimeError("rete giù")):
            with self.assertRaises(Exception):
                self.svc.remote_disable("SEAL-1", "live")
        self.assertEqual(self.drive.read("remote.txt").data, b"REMOTE")


class RemoteEnableGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.local = LocalFsStorage(tempfile.mkdtemp())
        self.svc = TopicService(self.local)
        with mock.patch(
            "server.instance_profile.topic_default_participants",
            return_value=[],
        ):
            self.svc.new("SEAL-1", "withlocal", {"owner": "davide"})
        self.svc.put_file("SEAL-1", "withlocal", "doc.txt", b"X")

    def test_refuses_to_link_drive_when_local_files_present(self):
        # Guardia anti-nascondimento: Drive diventa la fonte e i locali NON sono
        # caricati → collegarlo con file solo-locali li renderebbe invisibili.
        with self.assertRaises(Exception) as ctx:
            self.svc.remote_enable("SEAL-1", "withlocal", "drive",
                                   {"folder": "f", "account": "a"})
        self.assertIn("nasconderebbe", str(ctx.exception))
        self.assertEqual(
            self.local.read("SEAL-1/withlocal/files/doc.txt").data, b"X")

    def test_rejects_confidential_tier_on_drive(self):
        # Guard SEAL (anti-declassamento): topic SEAL-3/4 non possono usare Drive.
        for tier in ("SEAL-3", "SEAL-4"):
            with self.assertRaises(Exception) as ctx:
                self.svc.remote_enable(tier, "riservato", "drive",
                                       {"folder": "f", "account": "a"})
            self.assertIn("cap SEAL", str(ctx.exception))


class DriveStorageCacheTests(unittest.TestCase):
    def test_list_uses_short_lived_cache(self):
        api = mock.Mock()
        api.files.return_value.list.return_value.execute.return_value = {
            "files": [{
                "id": "file-1",
                "name": "report.txt",
                "mimeType": "text/plain",
                "size": "4",
                "md5Checksum": "abcd",
            }]
        }
        storage = DriveStorage(api, "root", cache_ttl=60)

        first = storage.list("")
        second = storage.list("")

        self.assertEqual(first, second)
        self.assertEqual(api.files.return_value.list.call_count, 1)

    def test_read_uses_short_lived_cache(self):
        api = mock.Mock()
        storage = DriveStorage(api, "root", cache_ttl=60)
        node = {
            "id": "file-1",
            "mimeType": "text/plain",
            "md5Checksum": "abcd",
        }

        class Download:
            def __init__(self, buf, request):
                self.buf = buf

            def next_chunk(self):
                self.buf.write(b"DATA")
                return None, True

        googleapiclient = types.ModuleType("googleapiclient")
        googleapiclient.__path__ = []
        http = types.ModuleType("googleapiclient.http")
        http.MediaIoBaseDownload = Download
        googleapiclient.http = http
        with mock.patch.dict(
            sys.modules,
            {"googleapiclient": googleapiclient, "googleapiclient.http": http},
        ), mock.patch.object(storage, "_resolve", return_value=node) as resolve:
            first = storage.read("report.txt")
            second = storage.read("report.txt")

        self.assertEqual(first.data, b"DATA")
        self.assertEqual(second.data, b"DATA")
        self.assertEqual(resolve.call_count, 1)
        self.assertEqual(api.files.return_value.get_media.call_count, 1)


if __name__ == "__main__":
    unittest.main()

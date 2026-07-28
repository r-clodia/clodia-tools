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


class DriveLiveTopicTests(unittest.TestCase):
    def setUp(self) -> None:
        self.local = LocalFsStorage(tempfile.mkdtemp())
        self.drive = LocalFsStorage(tempfile.mkdtemp())
        self.svc = TopicService(self.local)
        with mock.patch(
            "server.instance_profile.topic_default_participants",
            return_value=[],
        ):
            self.svc.new("SEAL-1", "live", {"owner": "davide"})
        self.svc.put_file("SEAL-1", "live", "legacy.txt", b"LOCAL")
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
        self.drive.write("remote.txt", b"REMOTE")
        self.backend = mock.patch.object(
            self.svc, "_drive_backend_for", return_value=self.drive)
        self.backend.start()

    def tearDown(self) -> None:
        self.backend.stop()

    def test_files_are_live_and_local_replica_is_removed(self):
        files = self.svc.list_files("SEAL-1", "live", "files")

        self.assertEqual(
            [item["name"] for item in files],
            ["legacy.txt", "remote.txt"],
        )
        self.assertEqual(self.drive.read("legacy.txt").data, b"LOCAL")
        self.assertEqual(
            self.local.list("SEAL-1/live/files"),
            [],
        )
        self.assertTrue(self.local.exists("SEAL-1/live/.drive-live-v1"))

        self.svc.put_file("SEAL-1", "live", "now.txt", b"NOW")
        self.assertEqual(self.drive.read("now.txt").data, b"NOW")
        self.assertFalse(self.local.exists("SEAL-1/live/files/now.txt"))
        self.assertEqual(
            self.svc.read_file("SEAL-1", "live", "files/remote.txt"),
            b"REMOTE",
        )

    def test_delete_uses_drive_trash_backend(self):
        self.svc.list_files("SEAL-1", "live", "files")
        result = self.svc.delete_file(
            "SEAL-1", "live", "files/remote.txt")

        self.assertEqual(result["trash_path"], "Drive/Cestino")
        self.assertFalse(self.drive.exists("remote.txt"))

    def test_disabling_drive_materializes_remote_files_locally(self):
        class Remote:
            def disable(self):
                return None

        self.svc.list_files("SEAL-1", "live", "files")
        with mock.patch.object(self.svc, "_remote_for", return_value=Remote()):
            self.svc.remote_disable("SEAL-1", "live")

        self.assertEqual(
            self.local.read("SEAL-1/live/files/remote.txt").data,
            b"REMOTE",
        )
        meta = json.loads(self.local.read("SEAL-1/live/meta.json").data)
        self.assertNotIn("remote", meta)
        self.assertFalse(self.local.exists("SEAL-1/live/.drive-live-v1"))


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

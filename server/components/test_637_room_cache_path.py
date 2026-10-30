"""#637 — `host.room_cache_path`: a component's private cache, per room.

The repository copy `github.clone` starts from must be written by the gateway
only. The room's shared folder is not that place: agents write into it with
`topic.put` (review of #637). The cache lives on the gateway's state volume,
per component and per room; the room is the signed claim's, never an
argument, and a name or a symlink cannot lead out of it.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from server import main
from server.components import store
from server.components.host import Host, HostError


class RoomCachePathTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="room-cache-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.room = ("SEAL-1", "blog")
        from server import state_paths
        ps = [patch.object(main, "_current_topic", lambda: self.room),
              patch.object(store, "root", lambda: self.root),
              patch.object(state_paths, "is_isolated", lambda: True)]
        for p in ps:
            p.start()
            self.addCleanup(p.stop)
        self.host = SimpleNamespace(_c=SimpleNamespace(pack="it-pack", id="it"))

    def path(self, name, host=None):
        return Host.room_cache_path(host or self.host, name)

    def test_per_component_and_per_room(self):
        p = Path(self.path("site.git"))
        self.assertEqual(p, self.root / "room-cache" / "it-pack" / "it" / "SEAL-1" / "blog" / "site.git")
        self.assertEqual(oct(p.parent.stat().st_mode & 0o777), "0o700")
        self.room = ("SEAL-1", "other")
        self.assertNotEqual(Path(self.path("site.git")).parent, p.parent)
        other = SimpleNamespace(_c=SimpleNamespace(pack="x-pack", id="x"))
        self.assertIn("x-pack", self.path("site.git", other))

    def test_not_under_the_topic_store(self):
        """Not where `topic.put` writes, nor the Mac-shared root."""
        self.assertNotIn("topics-store", self.path("site.git"))
        self.assertNotIn("_shared-local", self.path("site.git"))

    def test_outside_a_room_refused(self):
        self.room = (None, None)
        with self.assertRaises(HostError):
            self.path("x.git")

    def test_names_that_leave_the_cache_are_refused(self):
        for bad in ("", "..", "../other", "a/b", "/abs", ".hidden", "a..b", "x" * 200):
            with self.subTest(bad=bad), self.assertRaises(HostError):
                self.path(bad)
        self.room = ("SEAL-1", "../evil")
        with self.assertRaises(HostError):
            self.path("x.git")

    def test_no_cache_when_the_state_is_on_the_shared_datadir(self):
        from server import state_paths
        with patch.object(state_paths, "is_isolated", lambda: False):
            with self.assertRaises(HostError):
                self.path("x.git")

    def test_a_symlink_in_the_cache_is_refused(self):
        p = Path(self.path("x.git"))
        os.symlink(self.root, p)
        with self.assertRaises(HostError):
            self.path("x.git")


if __name__ == "__main__":
    unittest.main()

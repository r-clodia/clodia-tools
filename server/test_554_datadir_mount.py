"""The gateway says so when the datadir sits on a permissionless filesystem (#554).

The isolation probe of #544 guards only the gateway's own directories. The rest
of the datadir — transcripts, spawns, audit, topics, pack-service state — was
readable by every spawn uid on terra's virtiofs bind. The check reads the mount
table at boot and logs an ERROR naming #554; it never blocks the start.

Pairs that cannot pass by accident:

1. virtiofs / 9p / fuse.* / fakeowner AT the datadir → ERROR; ext4 / overlay
   (a named volume) → silence;
2. only the mount AT the datadir counts, and the last one on that point wins;
3. it runs from `check_at_boot` in every mode, `off` included.
"""
from __future__ import annotations

import logging
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import isolation


def _line(mid: int, mountpoint: str, fstype: str, source: str = "none") -> str:
    return (f"{mid} 1 0:{mid} / {mountpoint} rw,relatime master:1 - "
            f"{fstype} {source} rw\n")


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.datadir = self.root / "datadir"
        self.datadir.mkdir()
        env = patch.dict(os.environ, {"CLODIA_DATA": str(self.datadir)})
        env.start()
        self.addCleanup(env.stop)
        self.dd = str(self.datadir.resolve())

    def mountinfo(self, *lines: str) -> str:
        p = self.root / "mountinfo"
        p.write_text("".join(lines), encoding="utf-8")
        return str(p)


class VerdictTests(_Base):
    def test_virtiofs_at_the_datadir_is_a_problem_naming_554(self):
        mi = self.mountinfo(_line(1, "/", "overlay"),
                            _line(2, self.dd, "virtiofs", "mac"))
        problem = isolation.datadir_mount_problem(mountinfo=mi)
        self.assertIn("virtiofs", problem)
        self.assertIn("clodia-platform#554", problem)

    def test_every_permissionless_family_is_caught(self):
        for fstype in ("9p", "fakeowner", "fuse", "fuse.grpcfuse", "fuse.sshfs"):
            with self.subTest(fstype=fstype):
                mi = self.mountinfo(_line(2, self.dd, fstype))
                self.assertTrue(isolation.datadir_mount_problem(mountinfo=mi))

    def test_a_named_volume_is_silent(self):
        for fstype in ("ext4", "btrfs", "xfs", "overlay"):
            with self.subTest(fstype=fstype):
                mi = self.mountinfo(_line(2, self.dd, fstype, "/dev/vda1"))
                self.assertEqual(isolation.datadir_mount_problem(mountinfo=mi), "")

    def test_only_the_mount_at_the_datadir_counts(self):
        """A virtiofs mount elsewhere (or BELOW the datadir) says nothing about
        the datadir root; one ABOVE it is not the datadir's own mount either."""
        mi = self.mountinfo(_line(1, "/", "virtiofs"),
                            _line(2, self.dd + "/agents", "virtiofs"),
                            _line(3, self.dd + "x", "virtiofs"))
        self.assertEqual(isolation.datadir_mount_problem(mountinfo=mi), "")

    def test_the_last_mount_on_the_point_wins(self):
        covered = self.mountinfo(_line(2, self.dd, "virtiofs"),
                                 _line(3, self.dd, "ext4"))
        self.assertEqual(isolation.datadir_mount_problem(mountinfo=covered), "")
        exposed = self.mountinfo(_line(2, self.dd, "ext4"),
                                 _line(3, self.dd, "virtiofs"))
        self.assertTrue(isolation.datadir_mount_problem(mountinfo=exposed))

    def test_escaped_mountpoints_are_matched(self):
        spaced = self.root / "data dir"
        spaced.mkdir()
        escaped = str(spaced.resolve()).replace(" ", "\\040")
        mi = self.mountinfo(_line(2, escaped, "virtiofs"))
        with patch.dict(os.environ, {"CLODIA_DATA": str(spaced)}):
            self.assertTrue(isolation.datadir_mount_problem(mountinfo=mi))

    def test_no_mountinfo_is_silence_not_a_crash(self):
        missing = str(self.root / "nope")
        self.assertEqual(isolation.datadir_mount_problem(mountinfo=missing), "")

    def test_optional_fields_do_not_shift_the_fstype(self):
        line = (f"7 1 0:7 / {self.dd} rw shared:3 master:1 propagate_from:2 - "
                f"virtiofs mac rw\n")
        self.assertTrue(isolation.datadir_mount_problem(
            mountinfo=self.mountinfo(line)))


class BootTests(_Base):
    def test_check_logs_an_error_and_returns_the_reason(self):
        mi = self.mountinfo(_line(2, self.dd, "virtiofs"))
        with self.assertLogs("clodia-tools.refmon", logging.ERROR) as log:
            problem = isolation.check_datadir_mount(mountinfo=mi)
        self.assertTrue(problem)
        self.assertTrue(any(r.levelno == logging.ERROR and "#554" in r.getMessage()
                            for r in log.records))

    def test_check_at_boot_runs_it_even_when_the_probe_is_off(self):
        with patch.dict(os.environ, {"CLODIA_ISOLATION_SELFCHECK": "off"}), \
                patch.object(isolation, "check_datadir_mount") as spy, \
                self.assertLogs("clodia-tools.refmon", logging.WARNING):
            isolation.check_at_boot()
        spy.assert_called_once()

    def test_the_check_never_blocks_the_start(self):
        """A crashing diagnostic is a warning, not a SystemExit."""
        with patch.object(isolation, "datadir_mount_problem",
                          side_effect=RuntimeError("boom")), \
                self.assertLogs("clodia-tools.refmon", logging.WARNING):
            self.assertEqual(isolation.check_datadir_mount(), "")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

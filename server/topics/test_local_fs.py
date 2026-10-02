"""Self-test adapter local-fs (Topic System v2, P1).

    python3 -m server.topics.test_local_fs
"""
from __future__ import annotations

import tempfile
import unittest
import warnings


def main() -> int:
    warnings.filterwarnings("ignore")
    from .local_fs import LocalFsStorage
    from .storage import NotFound, StorageError, VersionConflict

    tmp = tempfile.mkdtemp(prefix="clodia-topics-fs-")
    s = LocalFsStorage(tmp)
    ok = 0
    fail = 0

    def check(name, cond):
        nonlocal ok, fail
        print(f"  {'✓' if cond else '✗'} {name}")
        ok += cond
        fail += (not cond)

    # write + read round-trip + version
    v1 = s.write("personal/demo/summary.md", b"riga uno\n")
    r = s.read("personal/demo/summary.md")
    check("read round-trip", r.data == b"riga uno\n")
    check("version coerente", r.version == v1 and v1.startswith("sha256:"))

    # conditional write con versione giusta
    v2 = s.write("personal/demo/summary.md", b"riga due\n", if_version=v1)
    check("conditional write ok", s.read("personal/demo/summary.md").data == b"riga due\n" and v2 != v1)

    # conditional write con versione STALE → conflitto
    try:
        s.write("personal/demo/summary.md", b"clobber\n", if_version=v1)
        check("conflitto su versione stale", False)
    except VersionConflict:
        check("conflitto su versione stale", True)
    check("contenuto non sovrascritto dopo conflitto", s.read("personal/demo/summary.md").data == b"riga due\n")

    # append-only minutes (file nuovi, niente if_version)
    s.write("personal/demo/minutes/20260620-1200-x.md", b"minuta 1\n")
    s.write("personal/demo/minutes/20260620-1300-y.md", b"minuta 2\n")
    mins = [e.name for e in s.list("personal/demo/minutes")]
    check("minutes elencate", mins == ["20260620-1200-x.md", "20260620-1300-y.md"])

    # list della cartella topic
    names = {e.name: e.kind for e in s.list("personal/demo")}
    check("list topic (summary file + minutes dir)", names.get("summary.md") == "file" and names.get("minutes") == "dir")

    # stat
    st = s.stat("personal/demo/summary.md")
    check("stat file", st and st.kind == "file" and st.size > 0)
    check("stat assente → None", s.stat("personal/nope") is None)

    # move (archive-like rename)
    s.write("personal/old/meta.json", b"{}")
    s.move("personal/old", "personal/renamed")
    check("move dir", s.exists("personal/renamed/meta.json") and not s.exists("personal/old"))

    # path traversal bloccato
    try:
        s.read("../../etc/passwd")
        check("traversal bloccato", False)
    except StorageError:
        check("traversal bloccato", True)

    # not found
    try:
        s.read("personal/demo/missing.md")
        check("read inesistente → NotFound", False)
    except NotFound:
        check("read inesistente → NotFound", True)

    import shutil
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{ok} ok, {fail} fail")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())


class SharedFolderModesTests(unittest.TestCase):
    """clodia-platform#498: what lands in the shared folder must be readable
    from the Mac by the human owner (another Unix account)."""

    def setUp(self) -> None:
        import tempfile
        from .local_fs import LocalFsStorage
        from .storage import LOCAL_SHARED_ROOT
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.fs = LocalFsStorage(self._tmp.name)
        self.sh = LOCAL_SHARED_ROOT

    def mode(self, rel: str) -> int:
        import os, stat
        return stat.S_IMODE(os.lstat(self.fs._abs(rel)).st_mode)

    def test_a_private_file_moved_into_the_shared_folder_becomes_0664(self) -> None:
        self.fs.write("data/rendiconto/report.md", b"x")
        self.assertEqual(self.mode("data/rendiconto/report.md"), 0o600)
        self.fs.move("data/rendiconto", f"{self.sh}/hedge/rendiconto")
        self.assertEqual(self.mode(f"{self.sh}/hedge/rendiconto/report.md"), 0o664)
        self.assertEqual(self.mode(f"{self.sh}/hedge/rendiconto"), 0o775)
        self.assertEqual(self.mode(f"{self.sh}/hedge"), 0o775)

    def test_a_whole_tree_moved_in_gets_shared_modes_at_every_level(self) -> None:
        self.fs.write("data/a/b/c.pdf", b"x")
        self.fs.write("data/a/d.md", b"y")
        self.fs.move("data/a", f"{self.sh}/t/a")
        for rel, m in ((f"{self.sh}/t/a", 0o775), (f"{self.sh}/t/a/b", 0o775),
                       (f"{self.sh}/t/a/b/c.pdf", 0o664), (f"{self.sh}/t/a/d.md", 0o664)):
            with self.subTest(rel=rel):
                self.assertEqual(self.mode(rel), m)

    def test_moving_out_of_the_shared_folder_makes_it_private_again(self) -> None:
        self.fs.write(f"{self.sh}/t/x.md", b"x")
        self.assertEqual(self.mode(f"{self.sh}/t/x.md"), 0o664)
        self.fs.move(f"{self.sh}/t/x.md", "data/x.md")
        self.assertEqual(self.mode("data/x.md"), 0o600)

    def test_directories_created_in_the_shared_folder_are_0775(self) -> None:
        self.fs.mkdir(f"{self.sh}/t/new/deep")
        self.assertEqual(self.mode(f"{self.sh}/t/new"), 0o775)
        self.assertEqual(self.mode(f"{self.sh}/t/new/deep"), 0o775)
        self.fs.write(f"{self.sh}/u/v/w.md", b"x")          # parents created by write
        self.assertEqual(self.mode(f"{self.sh}/u/v"), 0o775)

    def test_a_symlink_in_a_moved_tree_is_not_followed(self) -> None:
        import os
        outside = os.path.join(self._tmp.name, "..", "outside-" + os.path.basename(self._tmp.name))
        os.makedirs(outside, exist_ok=True)
        self.addCleanup(lambda: os.rmdir(outside))
        os.chmod(outside, 0o700)
        self.fs.write("data/tree/f.md", b"x")
        os.symlink(outside, self.fs._abs("data/tree") / "link")
        self.fs.move("data/tree", f"{self.sh}/t/tree")
        import stat
        self.assertEqual(stat.S_IMODE(os.stat(outside).st_mode), 0o700)

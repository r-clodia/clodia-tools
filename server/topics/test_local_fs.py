"""Self-test adapter local-fs (Topic System v2, P1).

    python3 -m server.topics.test_local_fs
"""
from __future__ import annotations

import tempfile
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

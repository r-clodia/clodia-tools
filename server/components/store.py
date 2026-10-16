"""Fetch and pin gateway components (clodia-platform#558).

The gateway fetches a component ITSELF, from its upstream, and keeps it in its
own state directory:

    <state_dir>/components/<pack>/<id>/<commit>/    the extracted source.path
    <state_dir>/components/pins.json                {pack: {id: pin record}}

It never reads component code from `/datadir/plugins` or `/datadir/packs`:
those are written by the agent-server, and the code below runs inside the
reference monitor.

A pin records `{repo, path, ref, entry, commit, tree_sha256, fetched_at,
previous}`. `tree_sha256` is recomputed before every import (`verify`): a tree
that changed on disk is not loaded.

Rules applied at fetch time, all needing the upstream:

* the ref is resolved to a commit, and that commit must be reachable from the
  repository's DEFAULT branch (`compare(commit...default)` is `ahead` or
  `identical`): merged code, not a branch somebody pushed;
* against an existing pin, the new commit must be a descendant of it
  (`compare(pinned...new)` is `ahead` or `identical`). `behind` or `diverged`
  is a DOWNGRADE and is refused unless the owner path passes
  `allow_downgrade=True`; so is a change of repository;
* only regular files and directories under `source.path` are extracted, with
  size and count caps; a link or a path escaping the tree refuses the fetch.

No token is needed for a public repository. For a private first-party one the
fetcher retries with the vault's `github_pat` (read by the gateway, never by
the component), and the token never follows a redirect off api.github.com.
"""
from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import shutil
import stat
import tarfile
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

from .grammar import GatewayComponent

LOG = logging.getLogger("clodia-tools.components")

MAX_TARBALL_BYTES = 64 * 1024 * 1024
MAX_FILES = 2000
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
#: Files a component may not ship: they would run without the source the
#: import guard reads.
COMPILED_SUFFIXES = (".pyc", ".pyo", ".so", ".pyd", ".dylib", ".dll")

_LOCK = threading.RLock()


class FetchError(RuntimeError):
    """The upstream could not be reached or answered something unusable."""


class FetchRefused(PermissionError):
    """The fetch is possible but not allowed (downgrade, unmerged, bad tree)."""


class Fetcher(Protocol):
    def resolve(self, repo: str, ref: str) -> str: ...
    def default_branch(self, repo: str) -> str: ...
    def compare(self, repo: str, base: str, head: str) -> str: ...
    def tarball(self, repo: str, commit: str) -> bytes: ...


# --------------------------------------------------------------------------
# the GitHub fetcher
# --------------------------------------------------------------------------

API = "https://api.github.com"
#: Hosts a tarball redirect may point to. The token is never sent there.
REDIRECT_HOSTS = frozenset({"codeload.github.com"})


def _vault_token() -> str:
    """The `github_pat` the gateway holds, or "". Read by the gateway only."""
    try:
        from .. import vault
        if not vault.has_credential("github_pat"):
            return ""
        bundle = vault.read_internal("github_pat")
        return str(bundle.get("value") or bundle.get("token") or "")
    except Exception:  # noqa: BLE001 — no token: public repositories only
        return ""


class GitHubFetcher:
    """`Fetcher` over the GitHub REST API (stdlib-free: httpx, already a dep)."""

    def __init__(self, token_source=_vault_token, timeout: float = 30.0) -> None:
        self._token_source = token_source
        self._timeout = timeout

    def _get(self, url: str, *, accept: str = "application/vnd.github+json"):
        import httpx
        headers = {"Accept": accept, "User-Agent": "clodia-tools-components"}
        with httpx.Client(timeout=self._timeout, follow_redirects=False) as c:
            r = c.get(url, headers=headers)
            if r.status_code in (401, 403, 404):
                token = self._token_source()
                if token:
                    r = c.get(url, headers={**headers,
                                            "Authorization": f"Bearer {token}"})
            if r.status_code in (301, 302, 303, 307, 308):
                loc = r.headers.get("location", "")
                host = httpx.URL(loc).host if loc else ""
                if host not in REDIRECT_HOSTS:
                    raise FetchError(f"redirect to unexpected host '{host}'")
                # A fresh request WITHOUT the Authorization header: the
                # redirect URL carries its own short-lived token.
                r = c.get(loc, headers={"User-Agent": "clodia-tools-components"})
            if r.status_code != 200:
                raise FetchError(f"GET {url}: HTTP {r.status_code}")
            return r

    def resolve(self, repo: str, ref: str) -> str:
        r = self._get(f"{API}/repos/{repo}/commits/{ref}",
                      accept="application/vnd.github.sha")
        sha = r.text.strip()
        if len(sha) != 40 or any(ch not in "0123456789abcdef" for ch in sha):
            raise FetchError(f"{repo}@{ref}: not a commit sha ({sha[:20]!r})")
        return sha

    def default_branch(self, repo: str) -> str:
        branch = str(self._get(f"{API}/repos/{repo}").json().get("default_branch") or "")
        if not branch:
            raise FetchError(f"{repo}: no default branch")
        return branch

    def compare(self, repo: str, base: str, head: str) -> str:
        data = self._get(f"{API}/repos/{repo}/compare/{base}...{head}").json()
        return str(data.get("status") or "")

    def tarball(self, repo: str, commit: str) -> bytes:
        r = self._get(f"{API}/repos/{repo}/tarball/{commit}")
        data = r.content
        if len(data) > MAX_TARBALL_BYTES:
            raise FetchError(f"{repo}@{commit}: tarball larger than "
                             f"{MAX_TARBALL_BYTES} bytes")
        return data


# --------------------------------------------------------------------------
# paths and pins
# --------------------------------------------------------------------------

def root() -> Path:
    """`<state_dir>/components` — computed per call, never cached at import."""
    from .. import state_paths
    return state_paths.state_dir() / "components"


def _pins_path() -> Path:
    return root() / "pins.json"


@dataclass(frozen=True)
class Pin:
    pack: str
    id: str
    repo: str
    path: str
    ref: str
    entry: str
    commit: str
    tree_sha256: str
    fetched_at: float
    previous: str = ""

    def source(self) -> tuple[str, str, str, str]:
        return (self.repo, self.path, self.ref, self.entry)

    @property
    def dir(self) -> Path:
        return root() / self.pack / self.id / self.commit


def _load_pins() -> dict:
    try:
        data = json.loads(_pins_path().read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_pins(data: dict) -> None:
    p = _pins_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)


def pin_of(pack: str, cid: str) -> Pin | None:
    rec = (_load_pins().get(pack) or {}).get(cid)
    if not isinstance(rec, dict):
        return None
    try:
        return Pin(**{k: rec[k] for k in Pin.__dataclass_fields__ if k in rec})
    except TypeError:
        return None


def _record(pin: Pin) -> None:
    data = _load_pins()
    data.setdefault(pin.pack, {})[pin.id] = asdict(pin)
    _save_pins(data)


def forget(pack: str, cid: str) -> None:
    """Drop a pin and its trees (the component is no longer declared)."""
    with _LOCK:
        data = _load_pins()
        if cid in (data.get(pack) or {}):
            data[pack].pop(cid, None)
            if not data[pack]:
                data.pop(pack, None)
            _save_pins(data)
        shutil.rmtree(root() / pack / cid, ignore_errors=True)


# --------------------------------------------------------------------------
# integrity
# --------------------------------------------------------------------------

def tree_sha256(directory: Path) -> str:
    """Hash of a tree: every regular file's relative path and content hash,
    sorted. A link, a device or a FIFO anywhere makes the tree invalid."""
    h = hashlib.sha256()
    entries = []
    for dirpath, dirnames, filenames in os.walk(directory, followlinks=False):
        for d in dirnames:
            if os.path.islink(os.path.join(dirpath, d)):
                raise FetchRefused(f"link in component tree: {d}")
        for f in filenames:
            full = os.path.join(dirpath, f)
            st = os.lstat(full)
            if not stat.S_ISREG(st.st_mode):
                raise FetchRefused(f"not a regular file in component tree: {f}")
            rel = os.path.relpath(full, directory).replace(os.sep, "/")
            with open(full, "rb") as fh:
                entries.append((rel, hashlib.sha256(fh.read()).hexdigest()))
    for rel, digest in sorted(entries):
        h.update(f"{rel}\0{digest}\n".encode())
    return "sha256:" + h.hexdigest()


def verify(pin: Pin) -> str:
    """"" when the pinned tree is intact, else why not."""
    d = pin.dir
    try:
        resolved = d.resolve(strict=True)
    except OSError:
        return f"pinned tree {d} is missing"
    if not str(resolved).startswith(str(root().resolve()) + os.sep):
        return f"pinned tree {d} resolves outside the gateway component store"
    try:
        actual = tree_sha256(resolved)
    except (OSError, FetchRefused) as e:
        return f"pinned tree unreadable: {e}"
    if actual != pin.tree_sha256:
        return (f"pinned tree of {pin.pack}/{pin.id}@{pin.commit[:12]} changed on "
                f"disk (recorded {pin.tree_sha256[:19]}…, found {actual[:19]}…)")
    return ""


# --------------------------------------------------------------------------
# extraction
# --------------------------------------------------------------------------

def _extract(data: bytes, source_path: str, dest: Path) -> int:
    """Extract `source_path` of a GitHub tarball into `dest`. Returns files."""
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except tarfile.TarError as e:
        raise FetchError(f"tarball unreadable: {e}") from e
    count = total = 0
    with tf:
        members = tf.getmembers()
        tops = {m.name.split("/", 1)[0] for m in members if m.name}
        if len(tops) != 1:
            raise FetchRefused("tarball does not have exactly one top directory")
        prefix = f"{tops.pop()}/{source_path.strip('/')}/"
        for m in members:
            if not m.name.startswith(prefix):
                continue
            rel = m.name[len(prefix):].rstrip("/")
            if not rel:
                continue
            parts = rel.split("/")
            if any(p in ("", ".", "..") for p in parts) or rel.startswith("/"):
                raise FetchRefused(f"unsafe path in component tree: {rel}")
            if "__pycache__" in parts or rel.lower().endswith(COMPILED_SUFFIXES):
                # Bytecode or a native extension would run without the source
                # the import guard reads (an unchecked-hash .pyc is loaded
                # blindly): a component ships source only.
                raise FetchRefused(f"compiled code in component tree: {rel}")
            target = dest.joinpath(*parts)
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not m.isfile():
                raise FetchRefused(f"component tree contains a link or special "
                                   f"file: {rel}")
            count += 1
            total += m.size
            if count > MAX_FILES or total > MAX_TOTAL_BYTES or m.size > MAX_FILE_BYTES:
                raise FetchRefused("component tree exceeds the size/count caps")
            fh = tf.extractfile(m)
            if fh is None:
                raise FetchRefused(f"unreadable member {rel}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "wb") as out:
                out.write(fh.read())
            os.chmod(target, 0o644)
    if count == 0:
        raise FetchRefused(f"source.path '{source_path}' has no files at that commit")
    return count


# --------------------------------------------------------------------------
# ensure
# --------------------------------------------------------------------------

def _is_merged(fetcher: Fetcher, repo: str, commit: str) -> bool:
    default = fetcher.default_branch(repo)
    return fetcher.compare(repo, commit, default) in ("ahead", "identical")


def ensure(component: GatewayComponent, fetcher: Fetcher, *,
           refresh: bool = False, allow_downgrade: bool = False) -> Pin:
    """The pin of `component`, fetching it when needed.

    Without `refresh`, an existing pin whose declared source (repo, path, ref,
    entry) matches the manifest is returned as is: a branch ref is pinned to the
    commit fetched first, and only a refresh (pack Update) moves it.
    """
    with _LOCK:
        old = pin_of(component.pack, component.id)
        if old is not None and not refresh and old.source() == component.source() \
                and not verify(old):
            return old
        commit = fetcher.resolve(component.repo, component.ref)
        if not _is_merged(fetcher, component.repo, commit):
            raise FetchRefused(
                f"{component.repo}@{commit[:12]} ({component.ref}) is not reachable "
                "from the repository's default branch: only merged code runs in "
                "the gateway")
        if old is not None and old.repo != component.repo and not allow_downgrade:
            raise FetchRefused(
                f"{component.key}: source repository changed from '{old.repo}' "
                f"to '{component.repo}'; only the owner can approve that "
                "(allow_downgrade)")
        if old is not None and old.commit != commit and not allow_downgrade:
            status = fetcher.compare(component.repo, old.commit, commit)
            if status not in ("ahead", "identical"):
                raise FetchRefused(
                    f"{component.key}: {commit[:12]} is not newer than the pinned "
                    f"{old.commit[:12]} (upstream says '{status}'): downgrade "
                    "refused; only the owner can allow it")
        if old is not None and old.commit == commit and old.source() == component.source() \
                and not verify(old):
            return old
        data = fetcher.tarball(component.repo, commit)
        base = root() / component.pack / component.id
        base.mkdir(parents=True, exist_ok=True)
        tmp = Path(tempfile.mkdtemp(prefix=".fetch-", dir=base))
        try:
            _extract(data, component.path, tmp)
            digest = tree_sha256(tmp)
            final = base / commit
            if final.exists():
                shutil.rmtree(final)
            os.replace(tmp, final)
        except BaseException:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
        pin = Pin(pack=component.pack, id=component.id, repo=component.repo,
                  path=component.path, ref=component.ref, entry=component.entry,
                  commit=commit, tree_sha256=digest, fetched_at=time.time(),
                  previous=(old.commit if old is not None and old.commit != commit
                            else (old.previous if old is not None else "")))
        _record(pin)
        _prune(base, keep={commit, pin.previous})
        LOG.warning("components: %s pinned at %s@%s (%s)", component.key,
                    component.repo, commit[:12], digest[:19])
        return pin


def _prune(base: Path, keep: set[str]) -> None:
    for d in base.iterdir():
        if d.is_dir() and d.name not in keep and not d.name.startswith(".fetch-"):
            shutil.rmtree(d, ignore_errors=True)

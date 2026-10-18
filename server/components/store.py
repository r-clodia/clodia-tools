"""Fetch and pin gateway components (clodia-platform#558).

The gateway fetches a component ITSELF, from the pack's known upstream
(`connectors.builtin.FIRST_PARTY_SOURCES`), and keeps it in its own state
directory:

    <state_dir>/components/<pack>/<id>/<commit>/            extracted source.path
    <state_dir>/components/<pack>/<id>/<commit>.pack.yaml   the pack's manifest
    <state_dir>/components/pins.json                        {pack: {id: pin}}
    <state_dir>/components/floors.json                      {pack: {id: floor}}

It never reads component code from `/datadir/plugins` or `/datadir/packs`:
those are written by the agent-server, and the code below runs inside the
reference monitor.

**The manifest comes from the pin too.** From the moment a pack has a pinned
gateway component, its manifest — connectors, mappings, taint, components,
credentials — is `<prefix>pack.yaml` read from the SAME tarball at the SAME
commit, hashed into the pin, and `connectors.resolved.manifests()` substitutes
it for the datadir copy (`pinned_manifest`). A rewritten datadir manifest can no
longer drop the mapping that makes the PDP check a component's verb, nor change
which code, entry module or vault prefixes the component gets.

Rules applied at fetch time, all needing the upstream:

* `source.ref` must BE the repository's default branch, and the commit is its
  head: no tag, branch or sha chosen by a manifest;
* the new commit must descend from the FLOOR — the highest commit ever pinned
  for that (pack, id), kept in `floors.json` and never removed, not even when
  the pack is uninstalled — `compare(floor...new)` is `ahead` or `identical`.
  Anything else (a rewound upstream, a re-install) is a DOWNGRADE, refused
  unless the owner refreshes with `allow_downgrade=True`; so is a change of
  repository;
* only regular files and directories under `source.path` are extracted, with
  size and count caps; no links, no bytecode or native code, no path escaping
  the tree; a `.gitattributes` with `export-ignore`/`export-subst` at the repo
  root or on the way to the pack refuses the fetch (the archive would differ
  from the reviewed tree);
* the tarball is streamed and cut at `MAX_TARBALL_BYTES`.

`tree_sha256` and `manifest_sha256` are recomputed before every import
(`verify`): a tree or manifest that changed on disk is not loaded.

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
from typing import Any, Protocol

from .grammar import GatewayComponent, parse_components

LOG = logging.getLogger("clodia-tools.components")

MAX_TARBALL_BYTES = 64 * 1024 * 1024
MAX_FILES = 2000
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
#: Files a component may not ship: they would run without the source the
#: import guard reads.
COMPILED_SUFFIXES = (".pyc", ".pyo", ".so", ".pyd", ".dylib", ".dll")
#: `.gitattributes` attributes that make `git archive` differ from the tree.
ARCHIVE_ATTRIBUTES = ("export-ignore", "export-subst")

_LOCK = threading.RLock()


class FetchError(RuntimeError):
    """The upstream could not be reached or answered something unusable."""


class FetchRefused(PermissionError):
    """The fetch is possible but not allowed (downgrade, provenance, bad tree)."""


class ComponentGone(FetchRefused):
    """The pack's UPSTREAM no longer declares this component (removed or
    renamed, e.g. comms-pack 2.1.1 `mail` → `comms`). Authoritative only on a
    refresh, which reads the first-party head."""


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
_UA = {"User-Agent": "clodia-tools-components"}


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
    """`Fetcher` over the GitHub REST API (httpx, already a dependency)."""

    def __init__(self, token_source=_vault_token, timeout: float = 30.0) -> None:
        self._token_source = token_source
        self._timeout = timeout

    def _client(self):
        import httpx
        return httpx.Client(timeout=self._timeout, follow_redirects=False)

    def _open(self, c, url: str, accept: str):
        """A STREAMED 200 response for `url`; the caller closes it."""
        import httpx
        headers = {"Accept": accept, **_UA}
        r = c.send(c.build_request("GET", url, headers=headers), stream=True)
        if r.status_code in (401, 403, 404):
            token = self._token_source()
            if token:
                r.close()
                r = c.send(c.build_request(
                    "GET", url, headers={**headers, "Authorization": f"Bearer {token}"}),
                    stream=True)
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("location", "")
            r.close()
            host = httpx.URL(loc).host if loc else ""
            if host not in REDIRECT_HOSTS:
                raise FetchError(f"redirect to unexpected host '{host}'")
            # A fresh request WITHOUT the Authorization header: the redirect
            # URL carries its own short-lived token.
            r = c.send(c.build_request("GET", loc, headers=dict(_UA)), stream=True)
        if r.status_code != 200:
            r.close()
            raise FetchError(f"GET {url}: HTTP {r.status_code}")
        return r

    def _get(self, url: str, *, accept: str = "application/vnd.github+json",
             cap: int = 4 * 1024 * 1024) -> bytes:
        with self._client() as c:
            r = self._open(c, url, accept)
            try:
                return _read_capped(r, cap, url)
            finally:
                r.close()

    def resolve(self, repo: str, ref: str) -> str:
        sha = self._get(f"{API}/repos/{repo}/commits/{ref}",
                        accept="application/vnd.github.sha").decode().strip()
        if len(sha) != 40 or any(ch not in "0123456789abcdef" for ch in sha):
            raise FetchError(f"{repo}@{ref}: not a commit sha ({sha[:20]!r})")
        return sha

    def default_branch(self, repo: str) -> str:
        branch = str(json.loads(self._get(f"{API}/repos/{repo}"))
                     .get("default_branch") or "")
        if not branch:
            raise FetchError(f"{repo}: no default branch")
        return branch

    def compare(self, repo: str, base: str, head: str) -> str:
        data = json.loads(self._get(f"{API}/repos/{repo}/compare/{base}...{head}",
                                    cap=32 * 1024 * 1024))
        return str(data.get("status") or "")

    def tarball(self, repo: str, commit: str) -> bytes:
        return self._get(f"{API}/repos/{repo}/tarball/{commit}",
                         cap=MAX_TARBALL_BYTES)


def _read_capped(r, cap: int, what: str) -> bytes:
    """Read a streamed response, refusing it past `cap` bytes."""
    declared = r.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > cap:
        raise FetchError(f"{what}: larger than {cap} bytes")
    buf = bytearray()
    for chunk in r.iter_bytes():
        buf += chunk
        if len(buf) > cap:
            raise FetchError(f"{what}: larger than {cap} bytes")
    return bytes(buf)


# --------------------------------------------------------------------------
# paths, pins, floors
# --------------------------------------------------------------------------

def root() -> Path:
    """`<state_dir>/components` — computed per call, never cached at import."""
    from .. import state_paths
    return state_paths.state_dir() / "components"


def _pins_path() -> Path:
    return root() / "pins.json"


def _floors_path() -> Path:
    return root() / "floors.json"


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
    manifest_sha256: str = ""
    previous: str = ""

    def source(self) -> tuple[str, str, str, str]:
        return (self.repo, self.path, self.ref, self.entry)

    @property
    def dir(self) -> Path:
        return root() / self.pack / self.id / self.commit

    @property
    def manifest_path(self) -> Path:
        return root() / self.pack / self.id / f"{self.commit}.pack.yaml"


def _load_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _pin_from(rec: Any) -> Pin | None:
    if not isinstance(rec, dict):
        return None
    try:
        return Pin(**{k: rec[k] for k in Pin.__dataclass_fields__ if k in rec})
    except TypeError:
        return None


def pin_of(pack: str, cid: str) -> Pin | None:
    return _pin_from((_load_json(_pins_path()).get(pack) or {}).get(cid))


def pins_signature() -> tuple:
    """`stat` of the pin file, for the registry's rebuild signature."""
    try:
        st = _pins_path().stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return ()


def floor_of(pack: str, cid: str) -> dict | None:
    rec = (_load_json(_floors_path()).get(pack) or {}).get(cid)
    return rec if isinstance(rec, dict) and rec.get("commit") else None


def _set_floor(pin: Pin) -> None:
    data = _load_json(_floors_path())
    data.setdefault(pin.pack, {})[pin.id] = {"repo": pin.repo, "commit": pin.commit,
                                             "at": pin.fetched_at}
    _save_json(_floors_path(), data)


def _record(pin: Pin) -> None:
    data = _load_json(_pins_path())
    data.setdefault(pin.pack, {})[pin.id] = asdict(pin)
    _save_json(_pins_path(), data)
    _invalidate_registry()


def _invalidate_registry() -> None:
    try:
        from ..connectors import resolved
        resolved.invalidate()
    except Exception:  # noqa: BLE001
        pass


def forget(pack: str, cid: str) -> None:
    """Drop a pin and its trees (the component is no longer declared).

    The FLOOR stays: re-installing the pack later cannot pin anything older
    than what this gateway has already run."""
    with _LOCK:
        data = _load_json(_pins_path())
        if cid in (data.get(pack) or {}):
            data[pack].pop(cid, None)
            if not data[pack]:
                data.pop(pack, None)
            _save_json(_pins_path(), data)
            _invalidate_registry()
        shutil.rmtree(root() / pack / cid, ignore_errors=True)


# --------------------------------------------------------------------------
# integrity
# --------------------------------------------------------------------------

def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


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


def _inside_store(p: Path) -> bool:
    return str(p).startswith(str(root().resolve()) + os.sep)


def verify(pin: Pin) -> str:
    """"" when the pinned tree AND manifest are intact, else why not."""
    d = pin.dir
    try:
        resolved = d.resolve(strict=True)
    except OSError:
        return f"pinned tree {d} is missing"
    if not _inside_store(resolved):
        return f"pinned tree {d} resolves outside the gateway component store"
    try:
        actual = tree_sha256(resolved)
    except (OSError, FetchRefused) as e:
        return f"pinned tree unreadable: {e}"
    if actual != pin.tree_sha256:
        return (f"pinned tree of {pin.pack}/{pin.id}@{pin.commit[:12]} changed on "
                f"disk (recorded {pin.tree_sha256[:19]}…, found {actual[:19]}…)")
    _, problem = _read_manifest(pin)
    return problem


def _read_manifest(pin: Pin) -> tuple[dict | None, str]:
    """`(pinned manifest, "")` or `(None, why not)`."""
    import yaml
    if not pin.manifest_sha256:
        return None, f"pin of {pin.pack}/{pin.id} carries no manifest"
    p = pin.manifest_path
    try:
        if os.path.islink(p) or not _inside_store(p.resolve(strict=True)):
            return None, f"pinned manifest {p} is not a file of the store"
        data = p.read_bytes()
    except OSError:
        return None, f"pinned manifest {p} is missing"
    if _sha256(data) != pin.manifest_sha256:
        return None, (f"pinned manifest of {pin.pack}/{pin.id}@{pin.commit[:12]} "
                      "changed on disk")
    try:
        doc = yaml.safe_load(data.decode("utf-8")) or {}
    except Exception as e:  # noqa: BLE001
        return None, f"pinned manifest unreadable: {type(e).__name__}"
    if not isinstance(doc, dict):
        return None, "pinned manifest is not a mapping"
    return {**doc, "name": pin.pack}, ""


def pinned_manifest(pack: str) -> dict | None:
    """The manifest of `pack` from its pinned upstream copy, verified, or None.

    What `connectors.resolved.manifests()` serves for that pack instead of the
    datadir copy. None when the pack has no pin or the pinned copy fails its
    hash (the caller then keeps the datadir copy, and the component itself is
    refused by `verify`)."""
    for rec in (_load_json(_pins_path()).get(pack) or {}).values():
        pin = _pin_from(rec)
        if pin is None:
            continue
        doc, problem = _read_manifest(pin)
        if doc is not None:
            return doc
        LOG.error("components: %s", problem)
    return None


def pinned_component(pin: Pin) -> GatewayComponent:
    """The component as the PINNED manifest declares it."""
    doc, problem = _read_manifest(pin)
    if doc is None:
        raise FetchRefused(problem)
    comps, problems = parse_components(doc, pack=pin.pack)
    for c in comps:
        if c.id == pin.id:
            return c
    raise FetchRefused(f"pinned manifest of {pin.pack} declares no gateway component "
                       f"'{pin.id}'" + (f" ({'; '.join(problems)})" if problems else ""))


# --------------------------------------------------------------------------
# extraction
# --------------------------------------------------------------------------

def _gitattributes_problem(members, top: str, pack_prefix: str) -> str:
    """A `.gitattributes` at the repo root or on the way to the pack that uses
    archive attributes: `git archive` would differ from the reviewed tree."""
    ancestors = {""}
    parts = pack_prefix.strip("/").split("/")
    for i in range(1, len(parts) + 1):
        ancestors.add("/".join(parts[:i]))
    for m, data in members:
        rel = m.name[len(top) + 1:]
        if not rel.endswith(".gitattributes"):
            continue
        d = rel.rsplit("/", 1)[0] if "/" in rel else ""
        if d in ancestors or d.startswith(pack_prefix.strip("/") + "/"):
            text = data.decode("utf-8", "replace")
            if any(a in text for a in ARCHIVE_ATTRIBUTES):
                return (f"'{rel}' sets {list(ARCHIVE_ATTRIBUTES)}: the archive "
                        "would differ from the reviewed tree")
    return ""


def _open_tar(data: bytes):
    try:
        return tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
    except tarfile.TarError as e:
        raise FetchError(f"tarball unreadable: {e}") from e


def _top(members) -> str:
    tops = {m.name.split("/", 1)[0] for m in members if m.name}
    if len(tops) != 1:
        raise FetchRefused("tarball does not have exactly one top directory")
    return tops.pop()


def _extract_manifest(data: bytes, pack_prefix: str) -> bytes:
    """`<pack_prefix>pack.yaml` of the tarball, after the attributes check."""
    with _open_tar(data) as tf:
        members = tf.getmembers()
        top = _top(members)
        attrs = []
        for m in members:
            if m.isfile() and m.name.endswith("/.gitattributes") and m.size < 1 << 20:
                fh = tf.extractfile(m)
                attrs.append((m, fh.read() if fh else b""))
        problem = _gitattributes_problem(attrs, top, pack_prefix)
        if problem:
            raise FetchRefused(problem)
        want = f"{top}/{pack_prefix.strip('/')}/pack.yaml"
        for m in members:
            if m.name == want:
                if not m.isfile() or m.size > MAX_MANIFEST_BYTES:
                    raise FetchRefused(f"{pack_prefix}pack.yaml is not a regular "
                                       "file of acceptable size")
                fh = tf.extractfile(m)
                return fh.read() if fh else b""
    raise FetchRefused(f"no {pack_prefix}pack.yaml at that commit")


def _extract(data: bytes, source_path: str, dest: Path) -> int:
    """Extract `source_path` of a GitHub tarball into `dest`. Returns files."""
    count = total = 0
    with _open_tar(data) as tf:
        members = tf.getmembers()
        prefix = f"{_top(members)}/{source_path.strip('/')}/"
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

def ensure(component: GatewayComponent, fetcher: Fetcher, *,
           refresh: bool = False, allow_downgrade: bool = False) -> Pin:
    """The pin of `component`, fetching it when needed.

    `component` is only the TRIGGER (parsed from whatever manifest is served):
    what gets pinned is the component declared by `<prefix>pack.yaml` at the
    head of the default branch of the pack's known upstream. Without `refresh`,
    an intact pin whose source matches is returned as is.
    """
    from . import trust

    with _LOCK:
        known = trust.first_party_source(component.pack)
        if known is None:
            raise FetchRefused(f"'{component.pack}' has no known first-party upstream")
        repo, prefix = known
        problem = trust.source_problem(component)
        if problem:
            raise FetchRefused(problem)
        old = pin_of(component.pack, component.id)
        if old is not None and not refresh and old.source() == component.source() \
                and not verify(old):
            return old
        default = fetcher.default_branch(repo)
        if component.ref != default:
            raise FetchRefused(
                f"{component.key}: source.ref '{component.ref}' is not the default "
                f"branch '{default}' of {repo}: only the default branch is fetched")
        commit = fetcher.resolve(repo, default)
        floor = floor_of(component.pack, component.id)
        base = floor or ({"repo": old.repo, "commit": old.commit} if old else None)
        if base is not None and not allow_downgrade:
            if str(base.get("repo") or "").lower() != repo.lower():
                raise FetchRefused(
                    f"{component.key}: source repository changed from "
                    f"'{base.get('repo')}' to '{repo}'; only the owner can approve "
                    "that (allow_downgrade)")
            if base["commit"] != commit:
                status = fetcher.compare(repo, base["commit"], commit)
                if status not in ("ahead", "identical"):
                    raise FetchRefused(
                        f"{component.key}: {commit[:12]} does not descend from "
                        f"{base['commit'][:12]}, the highest commit this gateway "
                        f"has pinned (upstream says '{status}'): downgrade refused; "
                        "only the owner can allow it")
        if old is not None and old.commit == commit and old.source() == component.source() \
                and not verify(old):
            return old
        data = fetcher.tarball(repo, commit)
        if len(data) > MAX_TARBALL_BYTES:
            raise FetchError(f"{repo}@{commit}: tarball larger than {MAX_TARBALL_BYTES}")
        manifest_bytes = _extract_manifest(data, prefix)
        import yaml
        try:
            doc = yaml.safe_load(manifest_bytes.decode("utf-8")) or {}
        except Exception as e:  # noqa: BLE001
            raise FetchRefused(f"{prefix}pack.yaml unreadable: {type(e).__name__}") from e
        if not isinstance(doc, dict):
            raise FetchRefused(f"{prefix}pack.yaml is not a mapping")
        doc = {**doc, "name": component.pack}
        comps, probs = parse_components(doc, pack=component.pack)
        pinned = next((c for c in comps if c.id == component.id), None)
        if pinned is None:
            raise ComponentGone(
                f"upstream {prefix}pack.yaml at {commit[:12]} declares no gateway "
                f"component '{component.id}'" + (f" ({'; '.join(probs)})" if probs else ""))
        why = trust.refusal(pinned, doc)
        if why:
            raise FetchRefused(f"upstream manifest at {commit[:12]}: {why}")
        if pinned.ref != default:
            raise FetchRefused(f"upstream manifest at {commit[:12]}: source.ref "
                               f"'{pinned.ref}' is not the default branch")
        base_dir = root() / component.pack / component.id
        base_dir.mkdir(parents=True, exist_ok=True)
        tmp = Path(tempfile.mkdtemp(prefix=".fetch-", dir=base_dir))
        try:
            _extract(data, pinned.path, tmp)
            digest = tree_sha256(tmp)
            final = base_dir / commit
            if final.exists():
                shutil.rmtree(final)
            os.replace(tmp, final)
        except BaseException:
            shutil.rmtree(tmp, ignore_errors=True)
            raise
        mpath = base_dir / f"{commit}.pack.yaml"
        mtmp = mpath.with_suffix(".tmp")
        mtmp.write_bytes(manifest_bytes)
        os.chmod(mtmp, 0o644)
        os.replace(mtmp, mpath)
        pin = Pin(pack=component.pack, id=component.id, repo=pinned.repo,
                  path=pinned.path, ref=pinned.ref, entry=pinned.entry,
                  commit=commit, tree_sha256=digest, fetched_at=time.time(),
                  manifest_sha256=_sha256(manifest_bytes),
                  previous=(old.commit if old is not None and old.commit != commit
                            else (old.previous if old is not None else "")))
        _record(pin)
        _set_floor(pin)
        _prune(base_dir, keep={commit, pin.previous})
        LOG.warning("components: %s pinned at %s@%s (tree %s, manifest %s)",
                    component.key, repo, commit[:12], digest[:19],
                    pin.manifest_sha256[:19])
        return pin


def _prune(base: Path, keep: set[str]) -> None:
    for d in base.iterdir():
        name = d.name[:-len(".pack.yaml")] if d.name.endswith(".pack.yaml") else d.name
        if name not in keep and not d.name.startswith(".fetch-"):
            if d.is_dir():
                shutil.rmtree(d, ignore_errors=True)
            else:
                d.unlink(missing_ok=True)

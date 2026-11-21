"""Stdio MCP backends run as an unprivileged uid (clodia-platform#577).

Since #540 a pack's stdio MCP server gets an environment built from an
allowlist, but it still ran with the gateway's own uid — root. Root reads
`/proc/<gateway pid>/environ` (the gateway's secrets) and the vault files
under the datadir directly: the environment filter was defence in depth, not
the boundary. The boundary is a different uid, the same answer the pack
SERVICES gave in #515 (`services/launch.py`).

What a sandboxed backend process gets:

- **its own uid**, stable per backend (`uid_for`), from a pool of its own
  (`CLODIA_MCP_UID_BASE`, default 61000) — not the services' pool (60000) nor
  the agent spawns' (`CLODIA_AGENT_SANDBOX_UID`, 60000 on the agent-server);
- **a primary gid per plugin** — the plugin that declares the server — which
  owns the plugin's legacy datastore files (`path:` declarations, e.g. the
  `leads` CRM) and lets the process create its journal next to them;
- **one supplementary gid per datastore INSTANCE bound to the call** (#686):
  the instance file is `root:<instance gid> 0660`, its structure directory
  `root:<plugin gid> 1770`. The process opens the instance of the caller's
  scope and no other — not the next scope's instance of the same structure,
  whose file carries a different gid;
- **a private HOME** `<datadir>/mcp-sandbox/<backend>/` (0700, its own) with a
  `tmp/` used as `TMPDIR`, and that directory as working directory;
- no supplementary group of the gateway, `no_new_privs`, the services'
  resource limits (`launch.rlimits()`), umask 007.

What it can read is what any unprivileged uid of the container can read:
the image, the pack runtime (`<datadir>/runtime`, world-readable), the plugin
directories. What it can NOT read is what is root-only: the vault, the
secrets, `/gateway-state`, other uids' process environments, the gateway's
temp files, the other plugins' datastore files (hardened here at each spawn:
no bit for "others").

The privilege drop happens in a separate stub (`_DROPPER`), never in a
`preexec_fn`: Python code between `fork` and `exec` in a gateway with other
threads is a recipe for a deadlock (same reasoning as `launch._LIMITER`). The
stub is a fresh `python -I` that drops and `exec`s the real command, so the
pid the MCP client holds stays the server's.

Switch: `CLODIA_MCP_SANDBOX` = `auto` (default: on when the gateway is root,
i.e. in the container; off in local development, where it cannot drop a uid
anyway), `on` (required: a gateway that is not root refuses to start stdio
backends instead of running them as itself), `off` (as before #577). With
`CLODIA_SERVICE_ISOLATION=off` and no explicit value, `auto` is off too: the
instance said it does not isolate pack code.
"""
from __future__ import annotations

import fcntl
import json
import logging
import os
import re
import stat
import sys
import threading
import zlib
from dataclasses import dataclass, field
from pathlib import Path

LOG = logging.getLogger("clodia-tools.mcp_sandbox")

MODES = ("auto", "on", "off")

#: First uid of the backends' pool, and its size.
DEFAULT_UID_BASE = 61000
DEFAULT_UID_SPAN = 1000
#: First gid of the plugin/instance groups, and its size. Allocated and
#: remembered, never derived alone: two instances sharing a gid would read
#: each other, which is exactly what the gid is for.
DEFAULT_GID_BASE = 62000
DEFAULT_GID_SPAN = 20000

#: Under `<datadir>`: homes, and the uid/gid maps.
SANDBOX_DIR = "mcp-sandbox"
UID_MAP = "uids.json"
GID_MAP = "gids.json"

#: `PATH` tail when the backend's env has none: never inherited, never empty
#: (an empty element means "the current directory").
BASE_PATH = "/usr/local/bin:/usr/bin:/bin"

#: The stub that drops privileges and `exec`s the real command.
#: argv: [spec json, command, *args]. Exit 71 = could not drop: the server
#: never runs with the gateway's identity by accident.
_DROPPER = (
    "import ctypes, json, os, resource, sys\n"
    "spec = json.loads(sys.argv[1])\n"
    "for name, value in spec['rlimits'].items():\n"
    "    key = getattr(resource, name, None)\n"
    "    if key is None:\n"
    "        continue\n"
    "    try:\n"
    "        _, hard = resource.getrlimit(key)\n"
    "        if hard != resource.RLIM_INFINITY:\n"
    "            value = min(value, hard)\n"
    "        resource.setrlimit(key, (value, value))\n"
    "    except (OSError, ValueError) as exc:\n"
    "        sys.stderr.write('mcp-sandbox: rlimit %s: %s\\n' % (name, exc))\n"
    "        os._exit(71)\n"
    "try:\n"
    "    os.setgroups(spec['groups'])\n"
    "    os.setresgid(spec['gid'], spec['gid'], spec['gid'])\n"
    "    os.setresuid(spec['uid'], spec['uid'], spec['uid'])\n"
    "except OSError as exc:\n"
    "    sys.stderr.write('mcp-sandbox: cannot drop privileges: %s\\n' % exc)\n"
    "    os._exit(71)\n"
    "if 0 in os.getresuid() or 0 in os.getresgid():\n"
    "    sys.stderr.write('mcp-sandbox: still root after the drop\\n')\n"
    "    os._exit(71)\n"
    "try:\n"
    "    libc = ctypes.CDLL(None, use_errno=True)\n"
    "    if libc.prctl(38, 1, 0, 0, 0) != 0:\n"  # PR_SET_NO_NEW_PRIVS
    "        raise OSError(ctypes.get_errno(), 'prctl')\n"
    "except (OSError, AttributeError) as exc:\n"
    "    sys.stderr.write('mcp-sandbox: no_new_privs: %s\\n' % exc)\n"
    "    os._exit(71)\n"
    "os.umask(spec['umask'])\n"
    "os.execvp(sys.argv[2], sys.argv[2:])\n"
)

UMASK = 0o007


class SandboxUnavailable(PermissionError):
    """The sandbox is required (`CLODIA_MCP_SANDBOX=on`) but cannot apply."""


@dataclass(frozen=True)
class Identity:
    backend: str
    uid: int
    gid: int
    home: Path
    plugins: tuple[str, ...] = ()
    groups: tuple[int, ...] = field(default=())


_LOCK = threading.Lock()
_WARNED = {"done": False}


def data_dir() -> Path:
    """Read at every call: tests (and a restart on another volume) change it."""
    return Path(os.environ.get("CLODIA_DATA") or "/datadir")


def mode() -> str:
    raw = (os.environ.get("CLODIA_MCP_SANDBOX") or "").strip().lower()
    if not raw:
        if (os.environ.get("CLODIA_SERVICE_ISOLATION") or "").strip().lower() == "off":
            return "off"
        return "auto"
    if raw in MODES:
        return raw
    # A typo must not switch a security control off silently.
    LOG.warning("CLODIA_MCP_SANDBOX=%r is not one of %s: treated as 'on'",
                raw, "/".join(MODES))
    return "on"


def enabled() -> bool:
    """Whether stdio backends are started under the sandbox. Raises
    `SandboxUnavailable` when it is required and the gateway is not root."""
    m = mode()
    if m == "off":
        return False
    if os.geteuid() != 0:
        if m == "on":
            raise SandboxUnavailable(
                "CLODIA_MCP_SANDBOX=on but the gateway is not root: it cannot start "
                "an MCP server under another uid. Refused instead of running it as "
                "the gateway (set CLODIA_MCP_SANDBOX=off for local development)")
        if not _WARNED["done"]:
            _WARNED["done"] = True
            LOG.info("mcp sandbox: gateway not root, stdio MCP backends run as "
                     "the gateway's user (CLODIA_MCP_SANDBOX=auto)")
        return False
    return True


def _env_int(name: str, default: int) -> int:
    raw = (os.environ.get(name) or "").strip()
    return int(raw) if raw.isdigit() and int(raw) > 0 else default


def _pool(kind: str) -> tuple[int, int]:
    if kind == "uid":
        return (_env_int("CLODIA_MCP_UID_BASE", DEFAULT_UID_BASE),
                _env_int("CLODIA_MCP_UID_SPAN", DEFAULT_UID_SPAN))
    return (_env_int("CLODIA_MCP_GID_BASE", DEFAULT_GID_BASE),
            _env_int("CLODIA_MCP_GID_SPAN", DEFAULT_GID_SPAN))


def _root() -> Path:
    d = data_dir() / SANDBOX_DIR
    d.mkdir(parents=True, exist_ok=True)
    # Traversable, not listable: a backend reaches its own home by name.
    os.chmod(d, 0o711)
    return d


def _allocate(kind: str, key: str) -> int:
    """The id remembered for `key`, or a new one never given to another key.

    Derived from the key (stable when the map is lost), but the map wins and
    an id taken by another key is never handed out again — the lesson of
    clodia-platform#545 §5 for the services' uids."""
    base, span = _pool(kind)
    path = _root() / (UID_MAP if kind == "uid" else GID_MAP)
    with _LOCK:
        fd = os.open(str(path) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                known = {str(k): int(v) for k, v in raw.items()
                         if isinstance(v, int) and not isinstance(v, bool)
                         and base <= v < base + span} if isinstance(raw, dict) else {}
            except (OSError, ValueError):
                known = {}
            if key in known:
                return known[key]
            taken = set(known.values())
            start = zlib.crc32(key.encode()) % span
            for step in range(span):
                candidate = base + (start + step) % span
                if candidate not in taken:
                    known[key] = candidate
                    tmp = path.with_name(path.name + ".tmp")
                    tmp.write_text(json.dumps(known, sort_keys=True), encoding="utf-8")
                    os.chmod(tmp, 0o600)
                    os.replace(tmp, path)
                    return candidate
            raise SandboxUnavailable(
                f"no free {kind} left in the MCP sandbox pool ({base}..{base + span - 1})")
        finally:
            os.close(fd)


def _slug(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_.-]", "_", str(name or "")).strip("._") or "backend"
    return s[:64]


def owning_plugins(backend: str) -> tuple[str, ...]:
    """The installed plugins (dir names under `plugins/`) whose manifest
    declares the MCP server `backend` — the same lookup as
    `proxy.bound_structures`."""
    from . import datastores
    from .connectors.resolved import norm_name
    want = norm_name(backend)
    out = []
    for plugin, _root_dir, meta in datastores._manifests():
        servers = meta.get("mcp_servers")
        if isinstance(servers, dict) and any(norm_name(str(n)) == want for n in servers):
            out.append(plugin)
    return tuple(sorted(set(out)))


def plugin_gid(plugin: str) -> int:
    return _allocate("gid", f"plugin:{plugin}")


def instance_gid(instance_id: str) -> int:
    return _allocate("gid", f"instance:{instance_id}")


def identity(b: dict) -> Identity | None:
    """The sandbox identity of the stdio backend `b`, or None when the sandbox
    is off. Creates its private home (0700, owned by it)."""
    if not enabled():
        return None
    backend = str(b.get("name") or "")
    if not backend:
        backend = "anon-" + format(zlib.crc32(json.dumps(
            [b.get("command"), b.get("args")], default=str).encode()), "08x")
    plugins = owning_plugins(backend)
    uid = _allocate("uid", f"backend:{backend}")
    # A server declared by one plugin shares that plugin's group; otherwise
    # (admin mount, or a name two plugins claim) a group of its own.
    gid = plugin_gid(plugins[0]) if len(plugins) == 1 else _allocate("gid", f"backend:{backend}")
    home = _root() / _slug(backend)
    for d in (home, home / "tmp"):
        d.mkdir(parents=True, exist_ok=True)
        os.chown(d, uid, gid)
        os.chmod(d, 0o700)
    return Identity(backend=backend, uid=uid, gid=gid, home=home, plugins=plugins)


def scratch(ident: Identity | None) -> str:
    """A fresh directory for files the gateway builds for the process (the
    throwaway databases of a tool listing): inside its home when sandboxed,
    so that it can reach them; a plain temp dir otherwise."""
    import tempfile
    if ident is None:
        return tempfile.mkdtemp(prefix="clodia-mcp-probe-")
    d = tempfile.mkdtemp(prefix="probe-", dir=str(ident.home))
    os.chown(d, ident.uid, ident.gid)
    return d


def hand_over(ident: Identity | None, path: str | Path) -> None:
    """Give `path` (a file the gateway just built for the process) to it."""
    if ident is not None:
        os.chown(path, ident.uid, ident.gid)
        os.chmod(path, 0o600)


def _no_others(p: Path) -> None:
    """Drop every permission bit for "others" on `p` (no-op if absent)."""
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        return
    if stat.S_ISREG(st.st_mode) and st.st_mode & 0o007:
        os.chmod(p, stat.S_IMODE(st.st_mode) & ~0o007)


def _harden_legacy(ident: Identity) -> None:
    """Legacy datastores (`path:` declarations, e.g. `leads`): no bit for
    others on ANY plugin's file — they were 0644, readable by every uid — and
    the files of this backend's own plugin shared with its group, with the
    parent directory writable by it (SQLite creates its journal there, and a
    server that bootstraps its database creates the file)."""
    from . import datastores
    for ds in datastores._legacy_entries():
        p = Path(ds["abs_path"])
        plugin_root = (Path(datastores.DATADIR) / "plugins" / ds["pack"]).resolve()
        try:
            # `abs_path` is resolved: a `path:` with `..` or a symlink that
            # leads out of the plugin is never touched — the gateway must not
            # chmod a file a manifest merely names.
            p.parent.relative_to(plugin_root)
        except ValueError:
            LOG.warning("mcp sandbox: datastore %s/%s outside its plugin dir, ignored",
                        ds["pack"], ds["name"])
            continue
        if ds["pack"] not in ident.plugins or len(ident.plugins) != 1:
            _no_others(p)
            continue
        parent = p.parent
        parent.mkdir(parents=True, exist_ok=True)
        if parent != plugin_root:
            os.chown(parent, 0, ident.gid)
            os.chmod(parent, 0o2770)
        if p.is_file() and not p.is_symlink():
            os.chown(p, os.lstat(p).st_uid, ident.gid)
            os.chmod(p, 0o660)


def _grant_instance(ident: Identity, instance_id: str, path: str) -> int:
    """`root:<instance gid> 0660` on the instance file, its structure dir
    `root:<plugin gid> 1770` (journal creation, no deleting the others'
    files). Returns the gid the process needs."""
    from . import datastores
    p = Path(path)
    try:
        p.relative_to(datastores.platform_dir().resolve())
    except ValueError:
        raise PermissionError(f"istanza '{instance_id}': file fuori da datastores/") from None
    if p.is_symlink() or not p.is_file():
        raise PermissionError(f"istanza '{instance_id}': file assente o non regolare")
    gid = instance_gid(instance_id)
    struct_dir = p.parent
    os.chown(struct_dir, 0, ident.gid)
    os.chmod(struct_dir, 0o1770)
    os.chown(p, 0, gid)
    os.chmod(p, 0o660)
    return gid


def prepare(ident: Identity, instances: tuple[tuple[str, str], ...] = ()) -> Identity:
    """The identity with the supplementary groups of this call's instances
    (`(instance id, file)` pairs, from `proxy.bind_instances`), after the
    files are set up for it."""
    _harden_legacy(ident)
    groups = sorted({_grant_instance(ident, iid, path) for iid, path in instances})
    return Identity(backend=ident.backend, uid=ident.uid, gid=ident.gid,
                    home=ident.home, plugins=ident.plugins, groups=tuple(groups))


def wrap(ident: Identity, command: str, args: list[str],
         env: dict[str, str]) -> tuple[str, list[str], dict[str, str]]:
    """`(command, args, env)` that start `command args` under `ident`."""
    from .services import launch
    spec = {"uid": ident.uid, "gid": ident.gid, "groups": list(ident.groups),
            "umask": UMASK, "rlimits": launch.rlimits()}
    env = dict(env)
    env["HOME"] = str(ident.home)
    env["TMPDIR"] = str(ident.home / "tmp")
    env.setdefault("PATH", BASE_PATH)
    return (sys.executable,
            ["-I", "-c", _DROPPER, json.dumps(spec), str(command), *[str(a) for a in args]],
            env)

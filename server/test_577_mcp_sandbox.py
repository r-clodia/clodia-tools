"""#577 — stdio MCP backends run as an unprivileged uid, not as the gateway.

Two layers:

- unit tests (everywhere): the switch, the id allocation, what `session()`
  hands the MCP client when the sandbox is on and when it is off;
- `SandboxedProcessTests` (Linux, root): a REAL stdio MCP started through
  `proxy.call_proxied` / `list_proxied_tools` under the sandbox. It cannot read
  a root-only file (a stand-in vault), the gateway's `/proc/<pid>/environ`, nor
  the instance of another scope; it can read and write its own instance and
  its plugin's legacy datastore, and its tools still list (the smoke test).
  Off root they skip; `RootSuiteViaSudo` re-runs them under `sudo -n` when the
  machine allows it (the CI runner does), so CI exercises the real drop.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

from . import mcp_sandbox, proxy, whitelist
from .test_684_datastore_instances import _Base

_LINUX = sys.platform.startswith("linux")
_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0


class ModeTests(unittest.TestCase):
    def _mode(self, **env):
        with patch.dict(os.environ, env, clear=False):
            for k in ("CLODIA_MCP_SANDBOX", "CLODIA_SERVICE_ISOLATION"):
                if k not in env:
                    os.environ.pop(k, None)
            return mcp_sandbox.mode()

    def test_default_is_auto(self):
        self.assertEqual("auto", self._mode())

    def test_service_isolation_off_switches_auto_off(self):
        self.assertEqual("off", self._mode(CLODIA_SERVICE_ISOLATION="off"))
        # an explicit value wins
        self.assertEqual("on", self._mode(CLODIA_SERVICE_ISOLATION="off",
                                          CLODIA_MCP_SANDBOX="on"))

    def test_a_typo_is_on_never_off(self):
        self.assertEqual("on", self._mode(CLODIA_MCP_SANDBOX="of"))

    def test_not_root_auto_runs_as_today_on_refuses(self):
        with patch.object(mcp_sandbox.os, "geteuid", return_value=1000):
            with patch.dict(os.environ, {"CLODIA_MCP_SANDBOX": "auto"}):
                self.assertFalse(mcp_sandbox.enabled())
            with patch.dict(os.environ, {"CLODIA_MCP_SANDBOX": "on"}):
                with self.assertRaises(mcp_sandbox.SandboxUnavailable):
                    mcp_sandbox.enabled()
        with patch.object(mcp_sandbox.os, "geteuid", return_value=0), \
                patch.dict(os.environ, {"CLODIA_MCP_SANDBOX": "off"}):
            self.assertFalse(mcp_sandbox.enabled())


class AllocationTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="sbx577-")
        self.addCleanup(shutil.rmtree, self.d, True)
        p = patch.dict(os.environ, {"CLODIA_DATA": self.d})
        p.start()
        self.addCleanup(p.stop)

    def test_ids_are_stable_distinct_and_in_their_pool(self):
        a = mcp_sandbox._allocate("uid", "backend:a")
        b = mcp_sandbox._allocate("uid", "backend:b")
        self.assertNotEqual(a, b)
        self.assertEqual(a, mcp_sandbox._allocate("uid", "backend:a"))
        self.assertTrue(61000 <= a < 62000)
        g = mcp_sandbox.instance_gid("p/s:x")
        self.assertTrue(62000 <= g < 82000)
        self.assertNotEqual(g, mcp_sandbox.instance_gid("p/s:y"))
        self.assertNotEqual(g, mcp_sandbox.plugin_gid("p"))

    def test_a_collision_never_shares_an_id(self):
        with patch.dict(os.environ, {"CLODIA_MCP_GID_SPAN": "3"}):
            got = {mcp_sandbox._allocate("gid", f"instance:{i}") for i in range(3)}
            self.assertEqual(3, len(got))
            with self.assertRaises(mcp_sandbox.SandboxUnavailable):
                mcp_sandbox._allocate("gid", "instance:4")

    def test_the_map_is_root_only(self):
        mcp_sandbox._allocate("uid", "backend:a")
        mode = os.stat(Path(self.d) / "mcp-sandbox" / "uids.json").st_mode & 0o777
        self.assertEqual(0o600, mode)


class SessionWiringTests(unittest.TestCase):
    B = {"name": "demo", "transport": "stdio", "command": "python3",
         "args": ["srv.py", "--x"], "env": {"DEMO": "1"}}

    def _params(self, **kw):
        seen = {}

        @asynccontextmanager
        async def fake_stdio(params):
            seen["params"] = params
            raise RuntimeError("stop here")
            yield  # pragma: no cover

        async def go():
            async with proxy.session(dict(self.B), **kw):
                pass
        with patch.object(proxy, "_resolve_secrets", lambda b: b), \
                patch.object(proxy, "stdio_client", fake_stdio):
            with self.assertRaises(RuntimeError):
                asyncio.run(go())
        return seen["params"]

    def test_sandbox_off_is_todays_spawn(self):
        with patch.dict(os.environ, {"CLODIA_MCP_SANDBOX": "off"}):
            p = self._params()
        self.assertEqual("python3", p.command)
        self.assertEqual(["srv.py", "--x"], p.args)
        self.assertIsNone(p.cwd)
        self.assertEqual("1", p.env["DEMO"])

    def test_sandbox_on_wraps_the_command_in_the_dropper(self):
        ident = mcp_sandbox.Identity(backend="demo", uid=61005, gid=62001,
                                     home=Path("/datadir/mcp-sandbox/demo"),
                                     plugins=("demo-plugin",))
        seen = {}

        def prepare(i, instances=()):
            seen["instances"] = instances
            return mcp_sandbox.Identity(backend=i.backend, uid=i.uid, gid=i.gid,
                                        home=i.home, plugins=i.plugins, groups=(62007,))
        with patch.object(mcp_sandbox, "identity", lambda b: ident), \
                patch.object(mcp_sandbox, "prepare", prepare):
            p = self._params(instances=(("p/s:x", "/datadir/datastores/p/s/x.db"),))
        self.assertEqual((("p/s:x", "/datadir/datastores/p/s/x.db"),), seen["instances"])
        self.assertEqual(sys.executable, p.command)
        self.assertEqual(["-I", "-c", mcp_sandbox._DROPPER], p.args[:3])
        spec = json.loads(p.args[3])
        self.assertEqual((61005, 62001, [62007], 0o007),
                         (spec["uid"], spec["gid"], spec["groups"], spec["umask"]))
        self.assertIn("RLIMIT_NPROC", spec["rlimits"])
        self.assertEqual(["python3", "srv.py", "--x"], p.args[4:])
        self.assertEqual("/datadir/mcp-sandbox/demo", p.cwd)
        self.assertEqual("/datadir/mcp-sandbox/demo", p.env["HOME"])
        self.assertEqual("/datadir/mcp-sandbox/demo/tmp", p.env["TMPDIR"])
        self.assertEqual("1", p.env["DEMO"])

    def test_required_but_unavailable_refuses_to_spawn(self):
        with patch.dict(os.environ, {"CLODIA_MCP_SANDBOX": "on"}), \
                patch.object(mcp_sandbox.os, "geteuid", return_value=1000):
            with self.assertRaises(mcp_sandbox.SandboxUnavailable):
                self._params()

    def test_grants_never_come_from_the_mount_entry(self):
        """A pack writes its mount's `env`: naming a file there must not make
        the gateway open that file up. Only `_bind_instances` grants."""
        b = {"name": "normattiva", "command": "x",
             "env": {"CLODIA_DATASTORE_X": "/datadir/clodia-vault/creds.json"}}
        self.assertEqual((b, {}, ()), proxy._bind_instances("normattiva", b, {}))


class LegacyHardeningTests(unittest.TestCase):
    """Another plugin's legacy datastore loses its bits for "others"; a file a
    manifest names OUTSIDE its plugin is never touched."""

    def test_others_lose_read_and_outside_paths_are_ignored(self):
        from . import datastores
        root = Path(tempfile.mkdtemp(prefix="sbx577-legacy-"))
        self.addCleanup(shutil.rmtree, root, True)
        plugin = root / "plugins" / "crm"
        (plugin / "data").mkdir(parents=True)
        (plugin / "plugin.yaml").write_text(
            "name: crm\ndatastores:\n- {name: crm, path: data/crm.db}\n"
            "- {name: esc, path: ../../outside.db}\n")
        inside, outside = plugin / "data" / "crm.db", root / "outside.db"
        for f in (inside, outside):
            f.write_bytes(b"")
            os.chmod(f, 0o644)
        ident = mcp_sandbox.Identity(backend="other", uid=61001, gid=62001,
                                     home=root / "h", plugins=("someone-else",))
        with patch.object(datastores, "DATADIR", str(root)):
            mcp_sandbox._harden_legacy(ident)
        self.assertEqual(0o640, os.stat(inside).st_mode & 0o777)
        self.assertEqual(0o644, os.stat(outside).st_mode & 0o777)


# ── The real thing (Linux, root) ─────────────────────────────────────────────

_PROBE_MCP = textwrap.dedent('''
    import json, os, sqlite3
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("contabilita")

    @mcp.tool()
    def read(path: str) -> str:
        try:
            with open(path, "rb") as fh:
                fh.read(1)
            return "READ"
        except PermissionError:
            return "DENIED"
        except Exception as exc:
            return "ERR " + type(exc).__name__

    @mcp.tool()
    def write(path: str = "") -> str:
        path = path or os.environ["CLODIA_DATASTORE_CONTABILITA"]
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE IF NOT EXISTS movimenti (id INTEGER PRIMARY KEY, importo REAL)")
        conn.execute("INSERT INTO movimenti (importo) VALUES (1)")
        conn.commit()
        n = conn.execute("SELECT count(*) FROM movimenti").fetchone()[0]
        conn.close()
        return str(n)

    @mcp.tool()
    def me() -> str:
        home = os.environ["HOME"]
        with open(os.path.join(os.environ["TMPDIR"], "t"), "w") as fh:
            fh.write("x")
        return json.dumps({"uid": os.getuid(), "euid": os.geteuid(), "gid": os.getgid(),
                           "groups": os.getgroups(), "home": home, "cwd": os.getcwd(),
                           "db": os.environ.get("CLODIA_DATASTORE_CONTABILITA")})

    mcp.run()
''')


@unittest.skipUnless(_LINUX and _ROOT, "needs root on Linux to drop a uid "
                     "(runs in CI through RootSuiteViaSudo)")
class SandboxedProcessTests(_Base):
    def setUp(self):
        super().setUp()
        # /datadir is 0755 in the container: the sandbox uid traverses it.
        os.chmod(self.root, 0o755)
        for k, v in {"CLODIA_DATA": str(self.root), "CLODIA_MCP_SANDBOX": "on"}.items():
            p = patch.dict(os.environ, {k: v})
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(shutil.rmtree, self.root, True)
        # A stand-in vault: what the gateway keeps for itself.
        vault = self.root / "clodia-vault"
        vault.mkdir(mode=0o700)
        self.secret = vault / "creds.json"
        self.secret.write_text('{"token": "s3cret"}')
        os.chmod(self.secret, 0o600)
        # Another plugin's legacy datastore, created 0644 like SQLite does.
        other = self.root / "plugins" / "other" / "data"
        other.mkdir(parents=True)
        (self.root / "plugins" / "other" / "plugin.yaml").write_text(
            "name: other\ndatastores:\n- {name: crm, path: data/crm.db}\n")
        self.other_db = other / "crm.db"
        sqlite3.connect(self.other_db).close()
        os.chmod(self.other_db, 0o644)

        script = self.plugin / "mcp" / "probe.py"
        script.write_text(_PROBE_MCP, encoding="utf-8")
        backend = {"name": "contabilita", "transport": "stdio", "command": sys.executable,
                   "args": [str(script)], "pack": "studio-commercialista"}
        self.write_manifest(
            decl=[{"name": "contabilita", "schema": "mcp/schema.sql"},
                  {"name": "leads", "path": "data/leads.db"}],
            mcp={"contabilita": {"command": sys.executable, "args": [str(script)]}})
        p = patch.object(proxy, "CONFIG", {"mcp_backends": [backend]})
        p.start()
        self.addCleanup(p.stop)
        proxy.clear_cache()
        self.addCleanup(proxy.clear_cache)
        self.create("tomato")
        self.create("uncommon")
        self.imp("tomato", "assetti-contabili/contabilita:tomato")
        self.imp("uncommon", "assetti-contabili/contabilita:uncommon")
        self.inst = self.root / "datastores/assetti-contabili/contabilita"

    def call(self, tool, args=None, scope="SEAL-2/tomato"):
        with patch.object(whitelist, "current_channel", lambda: scope), \
                patch.object(whitelist, "agent_name", lambda: "commercialista"), \
                patch.object(whitelist, "current_clearance", lambda: "SEAL-2"), \
                patch.object(proxy, "is_disabled", lambda n: False):
            return asyncio.run(proxy.call_proxied(f"contabilita.{tool}", args or {}))

    def test_it_runs_as_its_own_uid_with_a_private_home(self):
        me = json.loads(self.call("me"))
        self.assertNotEqual(0, me["uid"])
        self.assertEqual(me["uid"], me["euid"])
        self.assertTrue(61000 <= me["uid"] < 62000, me)
        self.assertNotIn(0, me["groups"])
        self.assertEqual(str(self.root / "mcp-sandbox" / "contabilita"), me["home"])
        self.assertEqual(me["home"], me["cwd"])
        self.assertTrue(me["db"].endswith("contabilita/tomato.db"))

    def test_it_cannot_read_the_vault_nor_the_gateways_environment(self):
        self.assertEqual("DENIED", self.call("read", {"path": str(self.secret)}))
        self.assertEqual("DENIED", self.call(
            "read", {"path": f"/proc/{os.getpid()}/environ"}))
        self.assertEqual("DENIED", self.call("read", {"path": "/proc/1/environ"}))

    def test_it_reads_and_writes_its_instance_and_no_other(self):
        self.assertEqual("1", self.call("write"))
        self.assertEqual("2", self.call("write"))
        # the gateway (root) sees what the process wrote
        conn = sqlite3.connect(self.inst / "tomato.db")
        self.assertEqual(2, conn.execute("SELECT count(*) FROM movimenti").fetchone()[0])
        conn.close()
        # the other scope's instance of the SAME structure stays out of reach
        self.assertEqual("DENIED", self.call("read", {"path": str(self.inst / "uncommon.db")}))
        # ... and is reachable from its own scope
        self.assertEqual("1", self.call("write", scope="SEAL-2/uncommon"))
        self.assertEqual("DENIED", self.call("read", {"path": str(self.inst / "tomato.db")},
                                             scope="SEAL-2/uncommon"))

    def test_its_plugins_legacy_datastore_yes_another_plugins_no(self):
        leads = self.plugin / "data" / "leads.db"
        self.assertEqual("1", self.call("write", {"path": str(leads)}))
        self.assertTrue(leads.is_file())
        self.assertEqual("DENIED", self.call("read", {"path": str(self.other_db)}))
        self.assertEqual(0, os.stat(self.other_db).st_mode & 0o007)

    def test_tools_still_list_the_smoke_test(self):
        with patch("server.whitelist.disabled_backend_tools", lambda b: set()), \
                patch.object(proxy, "_is_transport", lambda b: False):
            tools = asyncio.run(proxy.list_proxied_tools())
            res = asyncio.run(proxy.test_backend("contabilita"))
        self.assertIn("contabilita.me", {t.name for t in tools})
        self.assertTrue(res["ok"], res)


@unittest.skipUnless(_LINUX and not _ROOT and shutil.which("sudo"),
                     "only where the suite is not root but may become it (the CI runner)")
class RootSuiteViaSudo(unittest.TestCase):
    def test_the_real_sandbox_under_root(self):
        if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
            self.skipTest("sudo needs a password here")
        repo = Path(__file__).resolve().parent.parent
        # Its own state, never the outer suite's: files root writes into the
        # outer audit/state dirs would be unwritable for the tests after this.
        tmp = tempfile.mkdtemp(prefix="sbx577-sudo-")
        self.addCleanup(subprocess.run, ["sudo", "-n", "rm", "-rf", tmp])
        env = {k: os.environ[k] for k in ("PATH", "LANG", "AGENT_SERVER_URL",
                                          "CLODIA_TOOLS_MCP_URL") if k in os.environ}
        for k, sub in {"CLODIA_AUDIT_DIR": "audit/store", "CLODIA_AUDIT_KEY_DIR": "audit/key",
                       "CLODIA_DATA": "data", "CLODIA_TOOLS_STATE_DIR": "state",
                       "CLODIA_TOPICS_ROOT": "topics", "CLODIA_SPAWNS_ROOT": "spawns",
                       "CLODIA_SECRETS_DIR": "secrets", "CLODIA_PKI_CERTS": "pki/certs",
                       "CLODIA_PKI_REVOKED": "pki/revoked.json",
                       "CLODIA_VAULT_DIR": "vault"}.items():
            env[k] = os.path.join(tmp, sub)
        env["HOME"] = tmp
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        done = subprocess.run(
            ["sudo", "-n", "env", *[f"{k}={v}" for k, v in env.items()],
             sys.executable, "-B", "-m", "unittest", "-v",
             "server.test_577_mcp_sandbox.SandboxedProcessTests"],
            cwd=repo, capture_output=True, text=True, timeout=600)
        out = done.stdout + done.stderr
        self.assertEqual(0, done.returncode, out[-4000:])
        self.assertNotIn("skipped", out, out[-4000:])
        self.assertIn("Ran 5 tests", out, out[-4000:])


if __name__ == "__main__":
    unittest.main()

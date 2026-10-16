"""clodia-platform#558 — pack code mounted in the gateway, run under the usual checks.

Everything here builds a fake instance in a temp dir: state dir, datadir,
vault, audit, and the connectors' first-seen stamps (`make test` shares
`CLODIA_TOOLS_STATE_DIR` across the suite). The upstream is a fake fetcher
over in-memory tarballs with a linear `main` history.
"""
from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import sys
import tarfile
import tempfile
import textwrap
import unittest
import yaml
from pathlib import Path
from unittest.mock import AsyncMock, patch

from mcp.types import Tool

from .. import main, proxy
from ..claims import ClaimsContext
from ..connectors import builtin, resolved
from . import guard, loader, store, trust
from .grammar import ComponentError, GatewayComponent, parse_components, parse_gateway
from .host import Host, HostError

TOKEN = {"agent": "clodia", "execution_id": "clodia-558", "principal": "davide",
         "chat": "chan:SEAL-2:titulon-tech:clodia"}

REPO = "r-clodia/clodia-logic"
FIXTURE_PREFIX = "catalogs/packs/fixture-pack/"
BROKEN_PREFIX = "catalogs/packs/broken-pack/"
GW_PATH = FIXTURE_PREFIX + "gateway"


def _connector(cid: str, ns: str, verbs=()) -> dict:
    return {"id": cid, "manifest_version": 1, "namespace": ns, "label": cid,
            **({"verbs": list(verbs)} if verbs else {"taint": [f"{ns}."]})}


def fixture_manifest(*, ref: str = "main", first_party=True, repo: str = REPO,
                     extra_components=()) -> dict:
    m = {
        "name": "fixture-pack",
        "version": "1.0.0",
        "connectors": [_connector("fixture", "fixture", [
            {"verb": "fixture.send", "direction": "egress", "scheme": "mailto",
             "arg": "to", "template": "mailto:{value}", "multi": True,
             "dtype": "email"},
            {"verb": "fixture.read", "direction": "source", "scheme": "mailfrom",
             "arg": "sender", "template": "mailfrom:{value}"},
        ])],
        "components": [
            {"id": "gw", "target": "gateway",
             "source": {"repo": repo, "path": GW_PATH, "ref": ref},
             "entry": "fixture_component", "connectors": ["fixture"],
             "credentials": ["fixture_"]},
            {"id": "skills", "target": "agent-server", "anything": "goes"},
            {"id": "card", "target": "webui"},
            *extra_components,
        ],
    }
    if first_party is not None:
        m["first_party"] = first_party
    return m


def broken_manifest() -> dict:
    return {
        "name": "broken-pack", "first_party": True,
        "connectors": [_connector("broken", "broken")],
        "components": [{"id": "gw", "target": "gateway",
                        "source": {"repo": REPO, "path": BROKEN_PREFIX + "gw",
                                   "ref": "main"},
                        "entry": "broken_component", "connectors": ["broken"]}],
    }


FIXTURE_COMPONENT = textwrap.dedent('''
    from mcp.types import Tool
    from . import helper

    CALLS = []
    HOST = []

    def register(host):
        HOST.append(host)

        def send(arguments):
            CALLS.append(("send", dict(arguments)))
            return {"sent_to": arguments.get("to"), "helper": helper.VALUE,
                    "agent": host.agent()}

        def read(arguments):
            CALLS.append(("read", dict(arguments)))
            return {"from": arguments.get("sender"), "body": "hello"}

        async def connect(request):
            body = await request.json()
            host.set_config("folder", body.get("folder"))
            return {"ok": True, "folder": host.config("folder")}

        host.register_verb(Tool(name="fixture.send", description="Send.",
                                inputSchema={"type": "object", "properties": {
                                    "to": {"type": "string"}}}), send)
        host.register_verb(Tool(name="fixture.read", description="Read.",
                                inputSchema={"type": "object"}), read)
        host.register_route("connect", ["POST"], connect, auth="owner")
''')

BROKEN_COMPONENT = textwrap.dedent('''
    def register(host):
        raise RuntimeError("boom at register")
''')


def _sha(n: int) -> str:
    return hashlib.sha1(f"commit-{n}".encode()).hexdigest()


def tarball(files: dict[str, str], *, top: str = "r-clodia-clodia-logic-abc1234") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for rel, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(f"{top}/{rel}")
            info.size = len(data)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def fixture_tree(value: str = "v1", *, component: str = FIXTURE_COMPONENT,
                 manifest: dict | None = None, broken: dict | None = None
                 ) -> dict[str, str]:
    """The upstream repository: both packs' code AND their `pack.yaml`."""
    return {f"{GW_PATH}/fixture_component.py": component,
            f"{GW_PATH}/helper.py": f"VALUE = {value!r}\n",
            f"{GW_PATH}/evil.py": "import builtins\nbuiltins.CLODIA_558_EVIL_RAN = True\n",
            f"{FIXTURE_PREFIX}pack.yaml": yaml.safe_dump(manifest or fixture_manifest()),
            "catalogs/packs/other/x.py": "import server.vault\n",   # outside path
            f"{BROKEN_PREFIX}pack.yaml": yaml.safe_dump(broken or broken_manifest()),
            f"{BROKEN_PREFIX}gw/broken_component.py": BROKEN_COMPONENT}


class FakeFetcher:
    """A linear `main`: commits[0] … commits[-1] (the head)."""

    def __init__(self) -> None:
        self.commits: list[str] = []
        self.trees: dict[str, bytes] = {}
        self.refs: dict[str, str] = {}
        self.tarball_calls = 0
        self.push(fixture_tree("v1"))

    def push(self, files: dict[str, str], *, branch: str = "main") -> str:
        sha = _sha(len(self.trees) + 1)
        self.trees[sha] = tarball(files)
        if branch == "main":
            self.commits.append(sha)
        self.refs[branch] = sha
        return sha

    def rewind(self, sha: str) -> None:
        """Upstream `main` force-pushed back to `sha`."""
        self.refs["main"] = sha

    def resolve(self, repo: str, ref: str) -> str:
        if ref in self.refs:
            return self.refs[ref]
        if ref in self.trees:
            return ref
        raise store.FetchError(f"no ref {ref}")

    def default_branch(self, repo: str) -> str:
        return "main"

    def compare(self, repo: str, base: str, head: str) -> str:
        base, head = self.resolve(repo, base), self.resolve(repo, head)
        if base not in self.commits or head not in self.commits:
            return "diverged"
        i, j = self.commits.index(base), self.commits.index(head)
        return "identical" if i == j else ("ahead" if j > i else "behind")

    def tarball(self, repo: str, commit: str) -> bytes:
        self.tarball_calls += 1
        return self.trees[commit]


def _cfg(*uris, tools=("*",), sources=()):
    return {"egress_allow": list(uris), "source_allow": list(sources),
            "agents": {"clodia": {"allowed_tools": list(tools)}}}


def _with(cfg):
    from .. import whitelist as wl
    return patch.object(wl, "CONFIG", cfg)


class _Instance(unittest.TestCase):
    """A fake instance: temp state/data/vault/audit, packs, fetcher."""

    PACKS = ("fixture",)

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        env = patch.dict(os.environ, {
            "CLODIA_TOOLS_STATE_DIR": str(self.base / "state"),
            "CLODIA_DATA": str(self.base / "data"),
            "CLODIA_VAULT_DIR": str(self.base / "vault"),
            "CLODIA_AUDIT_DIR": str(self.base / "audit"),
            "CLODIA_AUDIT_KEY_DIR": str(self.base / "auditkey"),
            "CLODIA_EGRESS_ENFORCE": "on",
        })
        env.start()
        self.addCleanup(env.stop)
        for p in (patch.object(resolved, "_first_seen_path",
                               lambda: self.base / "state" / "first-seen.json"),
                  patch.object(resolved, "_DATA", self.base / "data"),
                  patch.object(builtin, "FIRST_PARTY_PACKS",
                               frozenset({"fixture-pack", "broken-pack",
                                          *builtin.FIRST_PARTY_PACKS})),
                  patch.object(builtin, "FIRST_PARTY_SOURCES",
                               {**builtin.FIRST_PARTY_SOURCES,
                                "fixture-pack": (REPO, FIXTURE_PREFIX),
                                "broken-pack": (REPO, BROKEN_PREFIX)})):
            p.start()
            self.addCleanup(p.stop)
        self.manifests: dict[str, dict] = {}
        if "fixture" in self.PACKS:
            self.manifests["fixture-pack"] = fixture_manifest()
        if "broken" in self.PACKS:
            self.manifests["broken-pack"] = broken_manifest()
        # The DATADIR copies (what the agent-server writes). `resolved.
        # manifests()` substitutes the pinned upstream copy on top of them.
        m = patch.object(resolved, "_installed_manifests", lambda: dict(self.manifests))
        m.start()
        self.addCleanup(m.stop)
        self.fetcher = FakeFetcher()
        f = patch.object(loader, "fetcher_factory", lambda: self.fetcher)
        f.start()
        self.addCleanup(f.stop)
        loader.reset()
        resolved.invalidate()
        self.addCleanup(resolved.invalidate)
        self.addCleanup(loader.reset)

    def reconcile(self, **kw) -> dict[str, dict]:
        resolved.invalidate()
        rows = loader.reconcile(force=True, **kw)
        return {f"{r['pack']}/{r['id']}": r for r in rows}

    def component_module(self):
        return sys.modules["clodia_components.fixture_pack.gw.fixture_component"]


# --------------------------------------------------------------------------
# 1. grammar
# --------------------------------------------------------------------------

class GrammarTests(unittest.TestCase):
    def test_gateway_entry_is_parsed_others_are_ignored(self) -> None:
        comps, problems = parse_components(fixture_manifest(), pack="fixture-pack")
        self.assertEqual(problems, [])
        (c,) = comps
        self.assertEqual((c.pack, c.id, c.repo, c.path, c.ref, c.entry),
                         ("fixture-pack", "gw", REPO, GW_PATH, "main",
                          "fixture_component"))
        self.assertEqual(c.connectors, ("fixture",))
        self.assertEqual(c.credentials, ("fixture_",))
        self.assertEqual(dict(c.namespaces), {"fixture": "fixture"})
        self.assertEqual(c.org, "r-clodia")

    def test_no_components_block(self) -> None:
        self.assertEqual(parse_components({"name": "x"}, pack="x"), ([], []))

    def _refused(self, **changes) -> str:
        entry = dict(fixture_manifest()["components"][0])
        src = dict(entry["source"])
        for k, v in changes.items():
            if k in ("repo", "path", "ref"):
                src[k] = v
            elif v is None:
                entry.pop(k, None)
            else:
                entry[k] = v
        entry["source"] = src
        with self.assertRaises(ComponentError) as cm:
            parse_gateway(entry, pack="fixture-pack", manifest=fixture_manifest())
        return str(cm.exception)

    def test_refusals(self) -> None:
        self.assertIn("relative", self._refused(path="/datadir/plugins/x"))
        self.assertIn("invalid segment", self._refused(path="a/../../datadir"))
        self.assertIn("'<owner>/<repository>'",
                      self._refused(repo="https://github.com/r-clodia/x"))
        self.assertIn("not a valid ref", self._refused(ref="main..x"))
        self.assertIn("dotted Python", self._refused(entry="../x"))
        self.assertIn("not declared", self._refused(connectors=["nope"]))
        self.assertIn("non-empty list", self._refused(connectors=[]))
        self.assertIn("must match", self._refused(credentials=["Google-"]))

    def test_a_local_path_key_is_refused(self) -> None:
        """No way to point the gateway at code on a shared volume."""
        for key in ("local", "dir", "plugin_dir"):
            with self.subTest(key=key):
                self.assertIn("unknown key", self._refused(**{key: "/datadir/packs/x"}))
        entry = dict(fixture_manifest()["components"][0])
        entry["source"] = {**entry["source"], "file": "/datadir/plugins/x.py"}
        with self.assertRaises(ComponentError):
            parse_gateway(entry, pack="fixture-pack", manifest=fixture_manifest())

    def test_one_bad_entry_does_not_drop_the_others(self) -> None:
        m = fixture_manifest(extra_components=[
            {"id": "bad", "target": "gateway", "source": {"repo": REPO}},
            {"id": "x", "target": "mars"},
            {"id": "gw", "target": "webui"}])
        comps, problems = parse_components(m, pack="fixture-pack")
        self.assertEqual([c.id for c in comps], ["gw"])
        self.assertEqual(len(problems), 3, problems)

    def test_schema_md_example_parses(self) -> None:
        from ..connectors.test_manifest import _examples
        (m,) = [m for m in _examples().values() if m.get("components")]
        comps, problems = parse_components(m, pack=m["name"])
        self.assertEqual(problems, [])
        self.assertEqual(len(comps), 1)


# --------------------------------------------------------------------------
# 2. trust
# --------------------------------------------------------------------------

class TrustTests(_Instance):
    def _comp(self, manifest=None) -> tuple[GatewayComponent, dict]:
        m = manifest or self.manifests["fixture-pack"]
        (c,), _ = parse_components(m, pack=m["name"])
        return c, m

    def test_first_party_in_allowed_org_is_trusted(self) -> None:
        self.assertEqual(trust.refusal(*self._comp()), "")

    def test_manifest_flag_is_required(self) -> None:
        for flag in (None, False, "yes"):
            with self.subTest(flag=flag):
                c, m = self._comp(fixture_manifest(first_party=flag))
                self.assertIn("first_party: true", trust.refusal(c, m))

    def test_the_flag_alone_is_not_enough(self) -> None:
        m = fixture_manifest()
        m["name"] = "someone-pack"
        c, _ = self._comp(m)
        self.assertIn("not a pack this gateway knows as first-party",
                      trust.refusal(c, m))

    def test_org_outside_the_allow_list(self) -> None:
        c, m = self._comp(fixture_manifest(repo="evil-org/clodia-logic"))
        self.assertIn("outside the allowed organisations", trust.refusal(c, m))

    def test_allowed_orgs_from_gateway_config_then_env(self) -> None:
        with _with({"components": {"allowed_orgs": ["Acme"]}}):
            self.assertEqual(trust.allowed_orgs(), {"acme"})
        with _with({}), patch.dict(os.environ, {trust.ORGS_ENV: "a, b"}):
            self.assertEqual(trust.allowed_orgs(), {"a", "b"})
        with _with({}), patch.dict(os.environ, {trust.ORGS_ENV: ""}):
            self.assertEqual(trust.allowed_orgs(), {"r-clodia"})

    def test_shared_state_dir_refuses_everything(self) -> None:
        with patch.dict(os.environ, {"CLODIA_TOOLS_STATE_DIR": str(self.base / "data")}):
            self.assertIn("not isolated", trust.refusal(*self._comp()))

    def test_owner_approval_hook_is_default_deny(self) -> None:
        c, m = self._comp(fixture_manifest(repo="evil-org/x"))
        self.assertFalse(trust.owner_approved(c))
        with patch.object(trust, "owner_approved", lambda comp: True):
            self.assertEqual(trust.refusal(c, m), "")

    def test_refused_component_is_never_fetched_and_its_verbs_are_denied(self) -> None:
        self.manifests["fixture-pack"] = fixture_manifest(repo="evil-org/clodia-logic")
        rows = self.reconcile()
        self.assertEqual(rows["fixture-pack/gw"]["status"], "refused")
        self.assertEqual(self.fetcher.tarball_calls, 0)
        self.assertIn("outside the allowed organisations",
                      loader.refusal("fixture.send"))


# --------------------------------------------------------------------------
# 3. fetch, pin, integrity, downgrade
# --------------------------------------------------------------------------

class PinTests(_Instance):
    def test_pinned_in_the_gateway_state_dir_never_the_datadir(self) -> None:
        rows = self.reconcile()
        row = rows["fixture-pack/gw"]
        self.assertEqual(row["status"], "loaded", row)
        pin = store.pin_of("fixture-pack", "gw")
        self.assertEqual(pin.commit, self.fetcher.commits[-1])
        state = (self.base / "state").resolve()
        self.assertTrue(str(pin.dir.resolve()).startswith(str(state / "components")))
        self.assertFalse(str(pin.dir.resolve()).startswith(str((self.base / "data").resolve())))
        # Only source.path is extracted, and importing it wrote no bytecode.
        self.assertEqual(sorted(p.name for p in pin.dir.iterdir()),
                         ["evil.py", "fixture_component.py", "helper.py"])
        self.assertTrue(pin.manifest_path.is_file())
        self.assertEqual(store.verify(pin), "")
        rec = json.loads((state / "components" / "pins.json").read_text())
        self.assertEqual(set(rec["fixture-pack"]["gw"]),
                         {"pack", "id", "repo", "path", "ref", "entry", "commit",
                          "tree_sha256", "fetched_at", "manifest_sha256", "previous"})
        self.assertTrue(rec["fixture-pack"]["gw"]["tree_sha256"].startswith("sha256:"))

    def test_a_branch_ref_stays_pinned_until_a_refresh(self) -> None:
        self.reconcile()
        first = store.pin_of("fixture-pack", "gw").commit
        self.fetcher.push(fixture_tree("v2"))
        self.reconcile()
        self.assertEqual(store.pin_of("fixture-pack", "gw").commit, first)
        self.assertEqual(self.fetcher.tarball_calls, 1)
        rows = self.reconcile(refresh_pack="fixture-pack")
        self.assertEqual(rows["fixture-pack/gw"]["commit"], self.fetcher.commits[-1])
        self.assertEqual(self.component_module().helper.VALUE, "v2")
        self.assertEqual(store.pin_of("fixture-pack", "gw").previous, first)

    def test_unmerged_commit_is_refused(self) -> None:
        self.fetcher.push(fixture_tree("evil"), branch="feature")
        self.manifests["fixture-pack"] = fixture_manifest(ref="feature")
        rows = self.reconcile()
        self.assertEqual(rows["fixture-pack/gw"]["status"], "failed")
        self.assertIn("default branch", rows["fixture-pack/gw"]["reason"])
        self.assertIn("disabled", loader.refusal("fixture.send"))

    def test_downgrade_refused_unless_the_owner_allows_it(self) -> None:
        old = self.fetcher.commits[-1]
        self.fetcher.push(fixture_tree("v2"))
        self.reconcile()
        self.assertEqual(store.pin_of("fixture-pack", "gw").commit, self.fetcher.commits[-1])
        self.fetcher.rewind(old)                 # upstream force-pushed back
        rows = self.reconcile(refresh_pack="fixture-pack")
        self.assertIn("downgrade refused", rows["fixture-pack/gw"]["reason"])
        self.assertNotEqual(rows["fixture-pack/gw"]["commit"], old)
        # `allow_downgrade` without a refresh is ignored…
        rows = self.reconcile(allow_downgrade=True)
        self.assertNotEqual(rows["fixture-pack/gw"]["commit"], old)
        # …and honoured on the owner's refresh, which lowers the floor.
        rows = self.reconcile(refresh_pack="fixture-pack", allow_downgrade=True)
        self.assertEqual(rows["fixture-pack/gw"]["status"], "loaded")
        self.assertEqual(rows["fixture-pack/gw"]["commit"], old)
        self.assertEqual(store.floor_of("fixture-pack", "gw")["commit"], old)

    def test_a_repository_change_is_a_downgrade(self) -> None:
        """The known upstream itself moves (a code change of the table): the
        floor names the old repository, so only the owner can accept it."""
        self.reconcile()
        with patch.object(builtin, "FIRST_PARTY_SOURCES",
                          {**builtin.FIRST_PARTY_SOURCES,
                           "fixture-pack": ("r-clodia/clodia-packs", FIXTURE_PREFIX)}):
            self.manifests["fixture-pack"] = fixture_manifest(repo="r-clodia/clodia-packs")
            with patch.object(store, "pinned_manifest", lambda p: None):
                resolved.invalidate()
                rows = self.reconcile(refresh_pack="fixture-pack")
        self.assertIn("source repository changed", rows["fixture-pack/gw"]["reason"])

    def test_a_tampered_tree_is_not_loaded(self) -> None:
        self.reconcile()
        pin = store.pin_of("fixture-pack", "gw")
        (pin.dir / "helper.py").write_text("VALUE = 'tampered'\n")
        self.assertIn("changed on disk", store.verify(pin))
        (c,), _ = parse_components(self.manifests["fixture-pack"], pack="fixture-pack")
        st = loader.load(c, pin)
        self.assertEqual(st.status, "failed")
        self.assertIn("changed on disk", st.reason)

    def test_unsafe_tarballs_are_refused(self) -> None:
        for name, files in (
                ("link", None),
                ("empty path", {"elsewhere/x.py": "x"}),
                ("bytecode", {f"{GW_PATH}/__pycache__/m.cpython-312.pyc": "x"}),
                ("native", {f"{GW_PATH}/fast.so": "x"})):
            with self.subTest(name=name):
                if files is None:
                    buf = io.BytesIO()
                    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
                        info = tarfile.TarInfo(f"top/{GW_PATH}/evil")
                        info.type = tarfile.SYMTYPE
                        info.linkname = "/datadir/clodia-vault"
                        tf.addfile(info)
                    data = buf.getvalue()
                else:
                    data = tarball(files)
                with tempfile.TemporaryDirectory() as d, \
                        self.assertRaises(store.FetchRefused):
                    store._extract(data, GW_PATH, Path(d))

    def test_a_component_no_longer_declared_is_unloaded_and_forgotten(self) -> None:
        self.reconcile()
        self.assertTrue(loader.has_verb("fixture.send"))
        self.manifests.pop("fixture-pack")
        self.reconcile()
        self.assertFalse(loader.has_verb("fixture.send"))
        self.assertIsNone(store.pin_of("fixture-pack", "gw"))
        self.assertNotIn("clodia_components.fixture_pack.gw", sys.modules)

    def test_fetch_error_keeps_the_running_pin(self) -> None:
        self.reconcile()
        commit = store.pin_of("fixture-pack", "gw").commit

        def down(*a, **k):
            raise store.FetchError("upstream down")
        with patch.object(self.fetcher, "resolve", down):
            rows = self.reconcile(refresh_pack="fixture-pack")
        self.assertEqual(rows["fixture-pack/gw"]["status"], "loaded")
        self.assertEqual(rows["fixture-pack/gw"]["commit"], commit)


class GitHubFetcherTests(unittest.TestCase):
    """The token is optional, and never follows a redirect."""

    def test_token_only_on_retry_and_never_on_redirect(self) -> None:
        import httpx
        seen = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append((str(request.url), request.headers.get("authorization")))
            if request.url.host == "api.github.com":
                if not request.headers.get("authorization"):
                    return httpx.Response(404)
                return httpx.Response(302, headers={
                    "location": "https://codeload.github.com/r-clodia/x/legacy.tar.gz/abc?token=t"})
            return httpx.Response(200, content=b"tar")

        real = httpx.Client
        with patch.object(httpx, "Client",
                          lambda **kw: real(transport=httpx.MockTransport(handler), **kw)):
            f = store.GitHubFetcher(token_source=lambda: "PAT")
            self.assertEqual(f.tarball("r-clodia/x", "a" * 40), b"tar")
        self.assertEqual([a for _, a in seen], [None, "Bearer PAT", None])

    def test_redirect_to_an_unexpected_host_is_refused(self) -> None:
        import httpx

        def handler(request):
            return httpx.Response(302, headers={"location": "https://evil.example/x"})
        real = httpx.Client
        with patch.object(httpx, "Client",
                          lambda **kw: real(transport=httpx.MockTransport(handler), **kw)):
            with self.assertRaises(store.FetchError):
                store.GitHubFetcher(token_source=lambda: "").tarball("r-clodia/x", "a" * 40)


# --------------------------------------------------------------------------
# 4. import guard
# --------------------------------------------------------------------------

class GuardTests(_Instance):
    def test_forbidden_imports(self) -> None:
        bad = ["import server.vault", "from server.vault import get_secret",
               "from server import vault", "from server import main as m",
               "import server", "from server.whitelist import CONFIG",
               "import server.state_paths as sp", "from server.gate import x",
               "from server.egress import check",
               "import importlib\nimportlib.import_module('server.vault')",
               "__import__('server.main')",
               "import importlib\nimportlib.import_module(name)"]
        for src in bad:
            with self.subTest(src=src):
                self.assertTrue(guard.scan_source(src), src)

    def test_allowed_imports(self) -> None:
        ok = ["from . import helper", "from .sub import x", "import json",
              "from mcp.types import Tool", "import httpx",
              "import importlib\nimportlib.import_module('json')"]
        for src in ok:
            with self.subTest(src=src):
                self.assertEqual(guard.scan_source(src), [])

    def test_a_component_importing_the_vault_is_refused_at_load(self) -> None:
        evil = FIXTURE_COMPONENT.replace("from . import helper",
                                         "from . import helper\nfrom server import vault")
        self.fetcher.push(fixture_tree(component=evil))
        rows = self.reconcile()
        self.assertEqual(rows["fixture-pack/gw"]["status"], "refused")
        self.assertIn("import guard", rows["fixture-pack/gw"]["reason"])
        self.assertFalse(loader.has_verb("fixture.send"))

    def test_the_guard_reads_every_file_of_the_tree(self) -> None:
        tree = fixture_tree()
        tree[f"{GW_PATH}/deep/inner.py"] = "import server.main\n"
        self.fetcher.push(tree)
        rows = self.reconcile()
        self.assertEqual(rows["fixture-pack/gw"]["status"], "refused")
        self.assertIn("deep/inner.py", rows["fixture-pack/gw"]["reason"])


# --------------------------------------------------------------------------
# 5. load and register
# --------------------------------------------------------------------------

class LoadTests(_Instance):
    def test_loaded_in_its_own_namespace_with_its_verbs(self) -> None:
        rows = self.reconcile()
        row = rows["fixture-pack/gw"]
        self.assertEqual(row["status"], "loaded", row)
        self.assertEqual(row["verbs"], ["fixture.read", "fixture.send"])
        self.assertEqual(row["routes"], ["connect"])
        mod = self.component_module()
        self.assertEqual(mod.__name__, "clodia_components.fixture_pack.gw.fixture_component")
        self.assertEqual(mod.helper.__name__, "clodia_components.fixture_pack.gw.helper")
        self.assertNotIn("fixture_component", sys.modules)
        self.assertIn("fixture.send", {t.name for t in loader.tools()})

    def test_listed_with_native_verbs_but_not_in_the_native_catalogue(self) -> None:
        self.reconcile()

        async def go():
            with ClaimsContext(TOKEN, "t"), _with(_cfg()), \
                    patch.object(proxy, "list_proxied_tools", AsyncMock(return_value=[])):
                return await main.list_tools()
        names = {t.name for t in asyncio.run(go())}
        self.assertIn("fixture.send", names)
        self.assertIn("topic.open", names)
        self.assertNotIn("fixture.send", main.all_native_verb_names())
        self.assertTrue(main._verb_implemented("fixture.send"))

    def test_registration_closes_after_register(self) -> None:
        self.reconcile()
        host = self.component_module().HOST[0]
        with self.assertRaises(HostError):
            host.register_verb(Tool(name="fixture.late", inputSchema={"type": "object"}),
                               lambda a: None)
        with self.assertRaises(HostError):
            host.register_route("late", ["GET"], lambda r: None)

    def _host(self) -> Host:
        (c,), _ = parse_components(self.manifests["fixture-pack"], pack="fixture-pack")
        return Host(c, native_names=main.all_native_verb_names,
                    reserved_namespaces=loader._reserved_namespaces,
                    taken=lambda n: "other-pack/x" if n == "fixture.taken" else None)

    def test_verb_registration_rules(self) -> None:
        host = self._host()
        schema = {"type": "object"}
        for name in ("email.send", "topic.open", "other.verb", "fixture",
                     "fixture.taken"):
            with self.subTest(name=name):
                with self.assertRaises(HostError):
                    host.register_verb(Tool(name=name, inputSchema=schema), lambda a: 1)
        host.register_verb(Tool(name="fixture.ok", inputSchema=schema), lambda a: 1)
        with self.assertRaises(HostError):
            host.register_verb(Tool(name="fixture.ok", inputSchema=schema), lambda a: 1)

    def test_route_registration_requires_owner_or_admin(self) -> None:
        host = self._host()
        for auth in ("public", "", "agent", None):
            with self.subTest(auth=auth), self.assertRaises(HostError):
                host.register_route("connect", ["POST"], lambda r: {}, auth=auth)
        for path in ("test", "../x", "/", "A"):
            with self.subTest(path=path), self.assertRaises(HostError):
                host.register_route(path, ["POST"], lambda r: {})
        with self.assertRaises(HostError):
            host.register_route("x", ["TRACE"], lambda r: {})
        host.register_route("connect", ["POST"], lambda r: {}, auth="admin")
        host.register_route("auth", ["GET"], lambda r: {})
        self.assertEqual(host.routes["auth"].auth, "owner")


class FailureIsolationTests(_Instance):
    PACKS = ("fixture", "broken")

    def test_a_failing_component_is_disabled_alone(self) -> None:
        rows = self.reconcile()
        self.assertEqual(rows["fixture-pack/gw"]["status"], "loaded")
        self.assertEqual(rows["broken-pack/gw"]["status"], "failed")
        self.assertIn("boom at register", rows["broken-pack/gw"]["reason"])
        self.assertIn("boom at register", loader.refusal("broken.anything"))
        self.assertEqual(loader.refusal("fixture.send"), "")

        async def go(name):
            with ClaimsContext(TOKEN, "t"), _with(_cfg()):
                return await main.call_tool(name, {})
        out = asyncio.run(go("broken.anything"))
        self.assertTrue(out[0].text.startswith("DENIED"), out[0].text)
        self.assertIn("broken-pack/gw", out[0].text)

    def test_a_disabled_component_never_denies_a_native_verb(self) -> None:
        """Its namespaces come from a manifest the agent-server writes."""
        m = broken_manifest()
        m["connectors"] = [_connector("broken", "topic")]
        m["components"][0]["connectors"] = ["broken"]
        self.manifests["broken-pack"] = m
        rows = self.reconcile()
        self.assertNotEqual(rows["broken-pack/gw"]["status"], "loaded")
        self.assertEqual(loader.refusal("topic.open"), "")

    def test_an_import_error_or_exit_is_contained(self) -> None:
        for src in ("raise ImportError('x')\n", "import sys\nsys.exit(3)\n",
                    "def register(host):\n    host.register_verb(1, 2)\n",
                    "x = 1\n"):
            with self.subTest(src=src):
                tree = fixture_tree()
                tree["catalogs/packs/broken-pack/gw/broken_component.py"] = src
                self.fetcher.push(tree)
                rows = self.reconcile(refresh_pack="broken-pack")
                self.assertEqual(rows["broken-pack/gw"]["status"], "failed")
                self.assertEqual(rows["fixture-pack/gw"]["status"], "loaded")


# --------------------------------------------------------------------------
# 6. a component verb runs through call_tool like a native one
# --------------------------------------------------------------------------

class CallPathTests(_Instance):
    def setUp(self) -> None:
        super().setUp()
        self.reconcile()
        self.gate = AsyncMock(return_value={})

    def events(self, type_: str) -> list[dict]:
        out = []
        for seg in sorted((self.base / "audit").glob("events-*.jsonl")):
            out += [json.loads(x) for x in seg.read_text().splitlines() if x.strip()]
        return [e for e in out if e["event"]["type"] == type_]

    def run_call(self, name, args, cfg=None, extra=()):
        async def go():
            with ClaimsContext(TOKEN, "t"), \
                    patch.object(main, "_require_gate_consent", self.gate), \
                    _with(cfg or _cfg("mailto:collega@casa.it")):
                for p in extra:
                    p.start()
                try:
                    return await main.call_tool(name, args)
                finally:
                    for p in extra:
                        p.stop()
        return asyncio.run(go())

    def calls(self):
        return self.component_module().CALLS

    def test_allowed_send_runs_the_handler_and_is_audited(self) -> None:
        out = self.run_call("fixture.send", {"to": "collega@casa.it"})
        text = out[0].text
        self.assertFalse(text.startswith(("DENIED", "ERROR")), text)
        self.assertEqual(json.loads(text), {"sent_to": "collega@casa.it",
                                            "helper": "v1", "agent": "clodia"})
        self.assertEqual(self.calls(), [("send", {"to": "collega@casa.it"})])
        (call,) = [e for e in self.events("tool.call")
                   if e["event"]["resource"] == "fixture.send"]
        self.assertTrue(call["tool"]["parameters_hash"].startswith("sha256:"))
        (res,) = [e for e in self.events("tool.result")
                  if e["event"]["resource"] == "fixture.send"]
        self.assertEqual(res["result"]["status"], "ok")
        (ev,) = self.events("flow.egress")
        self.assertEqual(ev["tool"]["name"], "fixture.send")
        self.assertEqual(ev["tool"]["destination"], ["mailto:collega@casa.it"])
        self.assertEqual(ev["decision"]["rule"][0]["rule"], "mailto:collega@casa.it")

    def test_egress_denied_never_reaches_the_handler(self) -> None:
        out = self.run_call("fixture.send", {"to": "estraneo@fuori.it"})
        self.assertTrue(out[0].text.startswith("DENIED"), out[0].text)
        self.assertEqual(self.calls(), [])
        self.assertEqual(self.events("flow.egress"), [])
        (d,) = [e for e in self.events("policy.decision")
                if e["event"]["resource"] == "fixture.send"
                and e["decision"]["policy"] == "egress"]
        self.assertEqual(d["decision"]["result"], "deny")
        self.assertEqual(d["decision"]["reason_class"], "not_listed")

    def test_whitelist_applies(self) -> None:
        out = self.run_call("fixture.send", {"to": "collega@casa.it"},
                            cfg=_cfg("mailto:collega@casa.it", tools=["topic.open"]))
        self.assertTrue(out[0].text.startswith("DENIED"), out[0].text)
        self.assertIn("whitelist", out[0].text)
        self.assertEqual(self.calls(), [])

    def test_wildcard_whitelist_of_the_namespace(self) -> None:
        out = self.run_call("fixture.send", {"to": "collega@casa.it"},
                            cfg=_cfg("mailto:collega@casa.it", tools=["fixture.*"]))
        self.assertFalse(out[0].text.startswith(("DENIED", "ERROR")), out[0].text)

    def test_deny_applies(self) -> None:
        out = self.run_call("fixture.send", {"to": "collega@casa.it"},
                            extra=[patch.object(main, "agent_denies",
                                                lambda n, a: n == "fixture.send")])
        self.assertTrue(out[0].text.startswith("DENIED"), out[0].text)
        self.assertEqual(self.calls(), [])

    def test_unattended_block_applies(self) -> None:
        out = self.run_call("fixture.send", {"to": "collega@casa.it"},
                            extra=[patch.object(main, "_unattended_denial",
                                                lambda n: "unattended session")])
        self.assertTrue(out[0].text.startswith("DENIED"), out[0].text)
        self.assertEqual(self.calls(), [])

    def test_a_gated_component_verb_asks_the_gate(self) -> None:
        from .. import gate
        out = self.run_call("fixture.send", {"to": "collega@casa.it"},
                            extra=[patch.object(gate, "is_gated",
                                                lambda n: n == "fixture.send"),
                                   patch.object(gate, "perimeter_answers", lambda n: False)])
        self.assertFalse(out[0].text.startswith(("DENIED", "ERROR")), out[0].text)
        self.assertEqual(self.gate.await_args_list[0].args[:2], ("clodia", "fixture.send"))

    def test_a_refused_gate_stops_the_call(self) -> None:
        from .. import gate
        self.gate.side_effect = PermissionError("gate refused by the owner")
        out = self.run_call("fixture.send", {"to": "collega@casa.it"},
                            extra=[patch.object(gate, "is_gated",
                                                lambda n: n == "fixture.send"),
                                   patch.object(gate, "perimeter_answers", lambda n: False)])
        self.assertTrue(out[0].text.startswith("DENIED"), out[0].text)
        self.assertEqual(self.calls(), [])

    def test_a_read_taints_and_records_ingress(self) -> None:
        from .. import taint
        with patch.object(taint, "note_verb") as noted:
            out = self.run_call("fixture.read", {"sender": "ignoto@fuori.it"})
        self.assertFalse(out[0].text.startswith(("DENIED", "ERROR")), out[0].text)
        noted.assert_called_once()
        self.assertEqual(noted.call_args.kwargs.get("vetted"), False)
        (ev,) = self.events("flow.ingress")
        self.assertEqual(ev["tool"]["source"], "mailfrom:ignoto@fuori.it")
        self.assertEqual(ev["tool"]["vetted"], "not_vetted")

    def test_without_its_connector_in_the_registry_the_verb_is_denied(self) -> None:
        """No mapping, no call: an unmapped verb would be an unchecked one."""
        m = self.manifests["fixture-pack"]
        stripped = {**m, "connectors": []}
        with patch.object(resolved, "manifests", lambda: {"fixture-pack": stripped}):
            resolved.invalidate()
            out = self.run_call("fixture.send", {"to": "collega@casa.it"})
        resolved.invalidate()
        self.assertTrue(out[0].text.startswith("DENIED"), out[0].text)
        self.assertIn("not active", out[0].text)
        self.assertEqual(self.calls(), [])

    def test_a_handler_error_is_an_error_not_a_crash(self) -> None:
        mod = self.component_module()
        spec = loader.verb("fixture.send")
        from .. import components
        with patch.object(components, "verb", lambda n: spec.__class__(
                **{**spec.__dict__, "handler": lambda a: 1 / 0}) if n == "fixture.send"
                else None):
            out = self.run_call("fixture.send", {"to": "collega@casa.it"})
        self.assertTrue(out[0].text.startswith("ERROR: ZeroDivisionError"), out[0].text)
        self.assertEqual(mod.CALLS, [])


# --------------------------------------------------------------------------
# 7. host capabilities
# --------------------------------------------------------------------------

class CredentialsTests(_Instance):
    def comp(self, pack="fixture-pack", creds=("fixture_",), ns=None) -> GatewayComponent:
        return GatewayComponent(pack=pack, id="gw", repo=REPO, path=GW_PATH, ref="main",
                                entry="x", connectors=("c",), credentials=tuple(creds),
                                namespaces=ns or {"c": "fixture"})

    def host(self, comp) -> Host:
        return Host(comp, native_names=list, reserved_namespaces=frozenset,
                    taken=lambda n: None)

    def test_scoped_to_the_declared_prefix(self) -> None:
        creds = self.host(self.comp()).credentials("fixture_")
        creds.deposit("fixture_main", {"token": "t"})
        self.assertEqual(creds.list(), ["fixture_main"])
        self.assertEqual(creds.read_internal("fixture_main"), {"token": "t"})
        self.assertTrue(creds.has("fixture_main"))
        for other in ("google_x", "fixture", "fixturex", "github_pat", "app_google_oauth"):
            with self.subTest(other=other), self.assertRaises(HostError):
                creds.read_internal(other)
            with self.subTest(other=other), self.assertRaises(HostError):
                creds.deposit(other, {})
            with self.subTest(other=other), self.assertRaises(HostError):
                creds.remove(other)
        self.assertTrue(creds.remove("fixture_main"))

    def test_read_for_an_agent_honours_the_grant(self) -> None:
        from .. import vault
        creds = self.host(self.comp()).credentials("fixture_")
        creds.deposit("fixture_main", {"token": "t"}, grant_agents=["clodia"])
        cfg = {"agents": {"clodia": {"allowed_tools": ["*"]},
                          "messaggero": {"allowed_tools": []}}}
        with _with(cfg), ClaimsContext(TOKEN, "t"):
            self.assertEqual(creds.read("fixture_main"), {"token": "t"})
        with _with(cfg), ClaimsContext({**TOKEN, "agent": "messaggero"}, "t"), \
                self.assertRaises(vault.VaultDenied):
            creds.read("fixture_main")

    def test_undeclared_prefix_refused(self) -> None:
        with self.assertRaises(HostError):
            self.host(self.comp()).credentials("other_")

    def test_prefix_outside_its_namespaces_refused(self) -> None:
        with self.assertRaises(HostError):
            self.host(self.comp(creds=("weather_",))).credentials("weather_")

    def test_core_prefix_only_after_the_switch_to_this_pack(self) -> None:
        comp = self.comp(pack="google-pack", creds=("google_", "app_google_oauth"),
                         ns={"google": "gdrive"})
        host = self.host(comp)
        with patch.object(builtin, "_packaged", lambda: frozenset()):
            builtin._RELEASED.clear()
            for p in ("google_", "app_google_oauth"):
                with self.subTest(p=p), self.assertRaises(HostError):
                    host.credentials(p)
        everything = frozenset({"google", "google-sheets", "google-docs",
                                "google-calendar", "mail-gmail"})
        with patch.object(builtin, "_packaged", lambda: everything):
            builtin._RELEASED.clear()
            host.credentials("google_")
            host.credentials("app_google_oauth")
            # …but never for another pack, even a first-party one.
            other = self.host(self.comp(pack="comms-pack",
                                        creds=("google_", "app_google_oauth")))
            for p in ("google_", "app_google_oauth"):
                with self.subTest(p=p), self.assertRaises(HostError):
                    other.credentials(p)
        builtin._RELEASED.clear()

    def test_switch_flipped_back_revokes_an_accessor_already_handed_out(self) -> None:
        comp = self.comp(pack="google-pack", creds=("google_",), ns={"google": "gdrive"})
        everything = frozenset({"google", "google-sheets", "google-docs",
                                "google-calendar", "mail-gmail"})
        with patch.object(builtin, "_packaged", lambda: everything):
            builtin._RELEASED.clear()
            creds = self.host(comp).credentials("google_")
        builtin._RELEASED.clear()
        with patch.object(builtin, "_packaged", lambda: frozenset()), \
                self.assertRaises(HostError):
            creds.list()
        builtin._RELEASED.clear()


class RouteTests(_Instance):
    def setUp(self) -> None:
        super().setUp()
        self.reconcile()
        from starlette.applications import Starlette
        from starlette.routing import Route
        from starlette.testclient import TestClient
        from .. import components_api

        async def core(request):
            return components_api.JSONResponse({"core": True})
        app = Starlette(routes=[Route("/tools/fixture-pack/core", core, methods=["GET"]),
                                *components_api.internal_routes,
                                *components_api.catch_all_routes])
        self.client = TestClient(app)
        from .. import tools_api
        self.tools_api = tools_api

    def _as(self, owner: bool, admin: bool):
        return [patch.object(self.tools_api, "_authorized_owner", lambda r: owner),
                patch.object(self.tools_api, "_authorized", lambda r: admin)]

    def post(self, url, body, *, owner, admin):
        ps = self._as(owner, admin)
        for p in ps:
            p.start()
        try:
            return self.client.post(url, json=body)
        finally:
            for p in ps:
                p.stop()

    def test_owner_route_requires_the_owner(self) -> None:
        r = self.post("/tools/fixture-pack/connect", {"folder": "f1"}, owner=False, admin=True)
        self.assertEqual(r.status_code, 401)
        r = self.post("/tools/fixture-pack/connect", {"folder": "f1"}, owner=True, admin=True)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json(), {"ok": True, "folder": "f1"})

    def test_admin_routes_need_a_human_admin_and_are_audited(self) -> None:
        loaded = loader._STATES["fixture-pack/gw"]
        from .host import RouteSpec
        loaded.routes["status"] = RouteSpec(component="fixture-pack/gw",
                                            pack="fixture-pack", path="status",
                                            methods=frozenset({"POST"}),
                                            handler=lambda r: {"ok": 1}, auth="admin")
        r = self.post("/tools/fixture-pack/status", {}, owner=False, admin=True)
        self.assertEqual(r.status_code, 401)
        r = self.post("/tools/fixture-pack/status", {}, owner=True, admin=True)
        self.assertEqual(r.status_code, 200)
        out = []
        for seg in sorted((self.base / "audit").glob("events-*.jsonl")):
            out += [json.loads(x) for x in seg.read_text().splitlines() if x.strip()]
        rec = [e for e in out if e["event"]["type"] == "control.component"]
        self.assertEqual([(e["event"]["resource"], e["result"]["status"]) for e in rec],
                         [("/tools/fixture-pack/status", 401),
                          ("/tools/fixture-pack/status", 200)])

    def test_config_is_written_from_an_owner_route_only(self) -> None:
        host = self.component_module().HOST[0]
        with self.assertRaises(HostError):
            host.set_config("folder", "x")
        self.post("/tools/fixture-pack/connect", {"folder": "f2"}, owner=True, admin=True)
        self.assertEqual(host.config("folder"), "f2")

    def test_unknown_paths_and_methods(self) -> None:
        r = self.post("/tools/fixture-pack/nope", {}, owner=True, admin=True)
        self.assertEqual(r.status_code, 404)
        ps = self._as(True, True)
        for p in ps:
            p.start()
        try:
            self.assertEqual(self.client.get("/tools/fixture-pack/connect").status_code, 405)
            # a core route keeps winning, and a wrong method on it stays 405
            self.assertEqual(self.client.get("/tools/fixture-pack/core").json(), {"core": True})
            self.assertEqual(self.client.post("/tools/fixture-pack/core").status_code, 405)
        finally:
            for p in ps:
                p.stop()

    def test_status_and_refresh(self) -> None:
        r = self.post("/internal/components/fixture-pack/refresh", {}, owner=False, admin=False)
        self.assertEqual(r.status_code, 401)
        # A super-agent or the agent-server's service role passes `_authorized`
        # but is not a human admin: refused.
        r = self.post("/internal/components/fixture-pack/refresh", {}, owner=False, admin=True)
        self.assertEqual(r.status_code, 401)
        self.fetcher.push(fixture_tree("v3"))
        r = self.post("/internal/components/fixture-pack/refresh", {}, owner=True, admin=True)
        self.assertEqual(r.status_code, 200, r.text)
        (row,) = r.json()["components"]
        self.assertEqual(row["commit"], self.fetcher.commits[-1])
        ps = self._as(False, True)
        for p in ps:
            p.start()
        try:
            st = self.client.get("/internal/components").json()
        finally:
            for p in ps:
                p.stop()
        self.assertEqual([c["status"] for c in st["components"]], ["loaded"])


class TopicsTests(_Instance):
    def test_topic_io_goes_through_membership_and_crossing(self) -> None:
        self.reconcile()
        host = self.component_module().HOST[0]

        class Svc:
            def __init__(self):
                self.put = []

            def read_file(self, tier, name, path):
                return b"bytes"

            def put_file(self, tier, name, path, data, provenance, by=""):
                self.put.append((tier, name, path, provenance, by))
                return {"path": path}
        svc = Svc()
        checks = []
        noted = []
        with ClaimsContext(TOKEN, "t"), \
                patch.object(main, "_topics", lambda: svc), \
                patch.object(main, "_require_topic_member",
                             lambda s, t, n, mutating=False: checks.append((t, n, mutating))), \
                patch.object(main, "_note_crossing",
                             lambda *a, **k: noted.append(k)), \
                patch("server.taint.mark") as marked:
            self.assertEqual(host.topics.read_file("SEAL-1", "t", "files/a"), b"bytes")
            host.topics.put_file("SEAL-1", "t", "files/b", b"x")
            with self.assertRaises(HostError):
                host.topics.put_file("SEAL-1", "t", "files/c", b"x", provenance="trusted")
        self.assertEqual(checks, [("SEAL-1", "t", False), ("SEAL-1", "t", True)])
        self.assertEqual(noted, [{"data": b"bytes", "kind": "file"}])
        self.assertEqual(svc.put, [("SEAL-1", "t", "files/b", "untrusted", "clodia")])
        marked.assert_called_once()

    def test_membership_refusal_propagates(self) -> None:
        self.reconcile()
        host = self.component_module().HOST[0]

        def refuse(*a, **k):
            raise PermissionError("not a participant")
        with ClaimsContext(TOKEN, "t"), \
                patch.object(main, "_topics", lambda: object()), \
                patch.object(main, "_require_topic_member", refuse):
            with self.assertRaises(PermissionError):
                host.topics.read_file("SEAL-1", "t", "files/a")


# --------------------------------------------------------------------------
# review of #382 — the three blockers, as the reviewer reproduced them
# --------------------------------------------------------------------------

class ProvenanceTests(_Instance):
    """Blocker 1: a tampered datadir pack.yaml cannot choose the code."""

    def _tamper(self, **source) -> dict:
        m = fixture_manifest()
        m["components"][0]["source"] = {**m["components"][0]["source"], **source}
        self.manifests["fixture-pack"] = m
        return self.reconcile()

    def test_another_merged_repository_of_the_org_is_refused(self) -> None:
        rows = self._tamper(repo="r-clodia/clodia-tools")
        self.assertEqual(rows["fixture-pack/gw"]["status"], "refused")
        self.assertIn("is not the upstream of 'fixture-pack'",
                      rows["fixture-pack/gw"]["reason"])
        self.assertEqual(self.fetcher.tarball_calls, 0)

    def test_a_path_outside_the_pack_directory_is_refused(self) -> None:
        rows = self._tamper(path="catalogs/packs/other")
        self.assertEqual(rows["fixture-pack/gw"]["status"], "refused")
        self.assertIn("outside the directory", rows["fixture-pack/gw"]["reason"])
        self.assertEqual(self.fetcher.tarball_calls, 0)

    def test_a_ref_other_than_the_default_branch_is_refused(self) -> None:
        sha = self.fetcher.push(fixture_tree("v1"), branch="feature")
        for ref in ("feature", sha, "v1.0.0"):
            with self.subTest(ref=ref):
                rows = self._tamper(ref=ref)
                self.assertEqual(rows["fixture-pack/gw"]["status"], "failed")
                self.assertIn("not the default branch", rows["fixture-pack/gw"]["reason"])
        self.assertEqual(self.fetcher.tarball_calls, 0)

    def test_the_entry_module_comes_from_the_pinned_manifest(self) -> None:
        """Same repo and prefix, different module: the datadir names `evil`,
        upstream names `fixture_component` — upstream wins."""
        import builtins
        self.manifests["fixture-pack"] = m = fixture_manifest()
        m["components"][0]["entry"] = "evil"
        rows = self.reconcile()
        self.assertEqual(rows["fixture-pack/gw"]["status"], "loaded", rows)
        self.assertFalse(getattr(builtins, "CLODIA_558_EVIL_RAN", False))
        self.assertNotIn("clodia_components.fixture_pack.gw.evil", sys.modules)
        self.assertEqual(store.pin_of("fixture-pack", "gw").entry, "fixture_component")

    def test_the_org_list_only_narrows_the_table(self) -> None:
        with _with({"components": {"allowed_orgs": ["someone-else"]}}):
            rows = self.reconcile()
        self.assertEqual(rows["fixture-pack/gw"]["status"], "refused")


class ManifestAuthorityTests(_Instance):
    """Blocker 2: the pinned upstream manifest governs, not the datadir copy."""

    def setUp(self) -> None:
        super().setUp()
        self.reconcile()
        self.gate = AsyncMock(return_value={})

    def send(self, to: str):
        async def go():
            with ClaimsContext(TOKEN, "t"), \
                    patch.object(main, "_require_gate_consent", self.gate), \
                    _with(_cfg("mailto:collega@casa.it")):
                return await main.call_tool("fixture.send", {"to": to})
        return asyncio.run(go())

    def calls(self):
        return sys.modules["clodia_components.fixture_pack.gw.fixture_component"].CALLS

    def _datadir(self, connector: dict) -> None:
        m = fixture_manifest()
        m["connectors"] = [connector]
        self.manifests["fixture-pack"] = m
        self.reconcile()

    def test_dropping_the_mapping_in_the_datadir_does_not_bypass_the_pdp(self) -> None:
        self._datadir(_connector("fixture", "fixture", [
            {"verb": "fixture.read", "direction": "source", "scheme": "mailfrom",
             "arg": "sender", "template": "mailfrom:{value}"}]))
        out = self.send("estraneo@fuori.it")
        self.assertTrue(out[0].text.startswith("DENIED"), out[0].text)
        self.assertEqual(self.calls(), [])

    def test_a_taint_only_datadir_connector_does_not_bypass_the_pdp(self) -> None:
        self._datadir(_connector("fixture", "fixture"))       # taint only
        out = self.send("estraneo@fuori.it")
        self.assertTrue(out[0].text.startswith("DENIED"), out[0].text)
        self.assertEqual(self.calls(), [])

    def test_the_served_manifest_is_the_pinned_one(self) -> None:
        self.manifests["fixture-pack"] = {"name": "fixture-pack", "connectors": []}
        served = resolved.manifests()["fixture-pack"]
        self.assertEqual(served["connectors"], fixture_manifest()["connectors"])

    def test_an_unclassified_component_verb_is_denied(self) -> None:
        """Defence in depth: even the pinned manifest must classify the verb."""
        upstream = fixture_manifest()
        upstream["connectors"] = [_connector("fixture", "fixture", [
            {"verb": "fixture.read", "direction": "source", "scheme": "mailfrom",
             "arg": "sender", "template": "mailfrom:{value}"}])]
        self.fetcher.push(fixture_tree(manifest=upstream))
        rows = self.reconcile(refresh_pack="fixture-pack")
        self.assertEqual(rows["fixture-pack/gw"]["status"], "loaded")
        out = self.send("collega@casa.it")
        self.assertTrue(out[0].text.startswith("DENIED"), out[0].text)
        self.assertIn("no egress, source or taint classification", out[0].text)
        self.assertEqual(self.calls(), [])

    def test_a_tampered_pinned_manifest_disables_the_component(self) -> None:
        pin = store.pin_of("fixture-pack", "gw")
        pin.manifest_path.write_text("name: fixture-pack\nconnectors: []\n")
        self.assertIn("changed on disk", store.verify(pin))
        self.assertIsNone(store.pinned_manifest("fixture-pack"))


class DowngradeFloorTests(_Instance):
    """Blocker 3: uninstalling for one round does not reset the floor."""

    def test_reinstall_after_a_rewind_cannot_pin_an_older_commit(self) -> None:
        old = self.fetcher.commits[-1]
        self.fetcher.push(fixture_tree("v2"))
        self.reconcile()
        high = store.pin_of("fixture-pack", "gw").commit
        self.assertNotEqual(high, old)
        self.manifests.pop("fixture-pack")             # one round without it
        self.reconcile()
        self.assertIsNone(store.pin_of("fixture-pack", "gw"))
        self.assertEqual(store.floor_of("fixture-pack", "gw")["commit"], high)
        self.fetcher.rewind(old)
        self.manifests["fixture-pack"] = fixture_manifest()
        rows = self.reconcile()
        self.assertEqual(rows["fixture-pack/gw"]["status"], "failed")
        self.assertIn("does not descend", rows["fixture-pack/gw"]["reason"])
        self.assertIsNone(store.pin_of("fixture-pack", "gw"))

    def test_reinstall_with_an_old_ref_is_refused(self) -> None:
        old = self.fetcher.commits[-1]
        self.fetcher.push(fixture_tree("v2"))
        self.reconcile()
        self.manifests.pop("fixture-pack")
        self.reconcile()
        self.manifests["fixture-pack"] = fixture_manifest(ref=old)
        rows = self.reconcile()
        self.assertEqual(rows["fixture-pack/gw"]["status"], "failed")
        self.assertIsNone(store.pin_of("fixture-pack", "gw"))

    def test_the_owner_can_still_go_back(self) -> None:
        old = self.fetcher.commits[-1]
        self.fetcher.push(fixture_tree("v2"))
        self.reconcile()
        self.fetcher.rewind(old)
        rows = self.reconcile(refresh_pack="fixture-pack", allow_downgrade=True)
        self.assertEqual(rows["fixture-pack/gw"]["commit"], old)


class ReviewNonBlockingTests(_Instance):
    def test_dot_repository_names_are_refused(self) -> None:
        for repo in ("r-clodia/..", "r-clodia/.", "../x", "r-clodia/..."):
            with self.subTest(repo=repo):
                m = fixture_manifest(repo=repo)
                comps, problems = parse_components(m, pack="fixture-pack")
                self.assertEqual(comps, [])
                self.assertTrue(problems)

    def test_one_gateway_component_per_pack(self) -> None:
        extra = dict(fixture_manifest()["components"][0], id="gw2")
        comps, problems = parse_components(fixture_manifest(extra_components=[extra]),
                                           pack="fixture-pack")
        self.assertEqual([c.id for c in comps], ["gw"])
        self.assertIn("at most one", problems[0])

    def test_gitattributes_with_archive_attributes_refuse_the_fetch(self) -> None:
        for where in ("", "catalogs/", FIXTURE_PREFIX, GW_PATH + "/"):
            for attr in ("export-ignore", "export-subst"):
                with self.subTest(where=where, attr=attr):
                    tree = fixture_tree()
                    tree[f"{where}.gitattributes"] = f"helper.py {attr}\n"
                    self.fetcher.push(tree)
                    rows = self.reconcile(refresh_pack="fixture-pack")
                    self.assertIn(".gitattributes", rows["fixture-pack/gw"]["reason"])
        tree = fixture_tree()
        tree["elsewhere/.gitattributes"] = "x export-ignore\n"
        tree[".gitattributes"] = "*.png binary\n"
        self.fetcher.push(tree)
        rows = self.reconcile(refresh_pack="fixture-pack")
        self.assertEqual(rows["fixture-pack/gw"]["reason"], "")

    def test_tarball_is_streamed_with_a_cap(self) -> None:
        import httpx
        sent = []

        def handler(request):
            def body():
                for _ in range(100):
                    sent.append(1)
                    yield b"x" * 1024
            return httpx.Response(200, content=body())
        real = httpx.Client
        with patch.object(httpx, "Client",
                          lambda **kw: real(transport=httpx.MockTransport(handler), **kw)), \
                patch.object(store, "MAX_TARBALL_BYTES", 10 * 1024), \
                self.assertRaises(store.FetchError):
            store.GitHubFetcher(token_source=lambda: "").tarball("r-clodia/x", "a" * 40)
        self.assertLess(len(sent), 100)


if __name__ == "__main__":
    unittest.main()

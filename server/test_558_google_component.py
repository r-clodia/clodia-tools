"""google-pack's REAL gateway component, against the gateway (clodia-platform#558).

Needs a clodia-logic checkout: `CLODIA_LOGIC_SRC=<path> make test` (skipped
otherwise, like clodia-logic's tests that need `CLODIA_TOOLS_SRC`). The code
under test is `catalogs/packs/google-pack/` of that checkout, served by a fake
GitHub fetcher as the upstream tarball: the gateway pins it, verifies it, scans
its imports, imports it as `clodia_components.google_pack.google` and calls
`register(host)` — the production path of `server.components`, nothing
short-circuited. The datadir holds the same `pack.yaml`, the profile says
`connectors: {google: pack}`.

Then:

1. **Load**: status `loaded`, the 24 verbs with the native schemas verbatim,
   the routes, the services; on `native` the component is pinned on standby
   and serves nothing.
2. **PDP parity**: every public PDP answer about Google is the same with the
   builtin manifest (`native`) and with google-pack's PINNED manifest (`pack`);
   the pins tables of `test_524_google_pins` hold.
3. **The Google suites, re-run against the component**: the pins of #524
   (unconfined calls, account-root and topic perimeters, labels), `gdrive_root`
   (ancestry, the three traps, fail-closed, config, cost, fast path, write
   destination, refusal messages, calendar, native docs, verb coverage), the
   per-topic perimeter, Sheets, Drive update, labels, the confinement API, and
   the REST/wire suite of `google_io` (wire requests byte-identical to the
   discovery client's). Each suite runs UNCHANGED: its module globals and the
   `server.tools.<module>` attributes it patches by name are pointed at the
   component's modules for the duration of the test.
4. **The call path**: `call_tool` runs a component verb after the whitelist and
   the egress PDP (and `gdrive.update`'s parent lookup is the component's
   service); the gateway's `/tools/google/*` forward to the component's routes;
   the custody of `google_<acct>` is unchanged (same name, shape, type, grant).
"""
from __future__ import annotations

import asyncio
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import AsyncMock, patch

import yaml

LOGIC_SRC = os.environ.get("CLODIA_LOGIC_SRC", "")
PACK_DIR = (Path(LOGIC_SRC) / "catalogs" / "packs" / "google-pack") if LOGIC_SRC else None
HAVE_LOGIC = bool(PACK_DIR and (PACK_DIR / "gateway" / "google_component.py").is_file())
NEEDS_LOGIC = unittest.skipUnless(
    HAVE_LOGIC, "set CLODIA_LOGIC_SRC to a clodia-logic checkout with google-pack 2.x")

PACK = "google-pack"
KEY = "google-pack/google"
PREFIX = "catalogs/packs/google-pack/"
COMMIT = "a" * 40
MODULE_ROOT = "clodia_components.google_pack.google"
#: The component's modules that replace the gateway's, by native name.
MODULES = ("google_io", "gdrive", "gdrive_root", "gdrive_labels", "gsheets",
           "gdocs", "gcalendar")
NAMESPACES = ("gdrive", "gsheets", "gdocs", "gcalendar")


def _upstream_tarball() -> bytes:
    """The clodia-logic repository as GitHub would serve it: google-pack's
    directory at `catalogs/packs/google-pack/`, compiled files left out."""
    buf = io.BytesIO()
    top = "r-clodia-clodia-logic-" + COMMIT[:7]
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path in sorted(PACK_DIR.rglob("*")):
            if not path.is_file() or "__pycache__" in path.parts \
                    or path.suffix in (".pyc", ".pyo"):
                continue
            rel = path.relative_to(PACK_DIR).as_posix()
            data = path.read_bytes()
            info = tarfile.TarInfo(f"{top}/{PREFIX}{rel}")
            info.size = len(data)
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class _Fetcher:
    def __init__(self) -> None:
        self.data = _upstream_tarball()

    def default_branch(self, repo: str) -> str:
        return "main"

    def resolve(self, repo: str, ref: str) -> str:
        return COMMIT

    def compare(self, repo: str, base: str, head: str) -> str:
        return "identical" if base == head else "ahead"

    def tarball(self, repo: str, commit: str) -> bytes:
        return self.data


def real_manifest() -> dict:
    return yaml.safe_load((PACK_DIR / "pack.yaml").read_text(encoding="utf-8"))


class GoogleComponentInstance:
    """Mixin: a fake instance where google-pack's real component is loaded.

    `setUp` builds the instance, loads the component and points the suites'
    module globals (and `server.tools.<module>`) at the component BEFORE the
    suite's own `setUp` runs, so a suite subclassed with this mixin first runs
    unchanged against the component."""

    GOOGLE = "pack"
    #: Suite modules whose globals are re-pointed at the component.
    SUITES: tuple = ()

    def setUp(self) -> None:  # noqa: D401
        from . import instance_profile
        from . import tools as tools_pkg
        from .components import loader
        from .connectors import resolved
        from .tools import (gcalendar, gdocs, gdrive, gdrive_labels, gdrive_root,
                            google_io, gsheets)
        from . import google_oauth
        # Registered FIRST so that it runs LAST, after the environment is
        # restored: the profile and the registry are re-read from the real
        # (test) datadir, not from this instance's `google: pack`.
        self.addCleanup(self._reload)
        tmp = Path(tempfile.mkdtemp(prefix="g558-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        self.base = tmp
        data = tmp / "data"
        (data / "packs" / PACK).mkdir(parents=True)
        (data / "packs" / PACK / "pack.yaml").write_text(
            yaml.safe_dump(real_manifest()), encoding="utf-8")
        env = patch.dict(os.environ, {
            "CLODIA_TOOLS_STATE_DIR": str(tmp / "state"),
            "CLODIA_DATA": str(data),
            "CLODIA_VAULT_DIR": str(tmp / "vault"),
            "CLODIA_AUDIT_DIR": str(tmp / "audit"),
            "CLODIA_AUDIT_KEY_DIR": str(tmp / "auditkey"),
        })
        env.start()
        self.addCleanup(env.stop)
        for p in (patch.object(resolved, "_DATA", data),
                  patch.object(resolved, "_first_seen_path",
                               lambda: tmp / "state" / "first-seen.json"),
                  patch.object(loader, "fetcher_factory", _Fetcher)):
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(loader.reset)
        loader.reset()
        self.position(self.GOOGLE)
        if self.GOOGLE == "pack":
            row = self.state()
            assert row and row["status"] == "loaded", f"component not loaded: {row}"
            comp = {m: sys.modules[f"{MODULE_ROOT}.{m}"] for m in MODULES}
            comp["google_oauth"] = sys.modules[f"{MODULE_ROOT}.google_oauth"]
            self.comp = comp
            native = {google_io: comp["google_io"], gdrive: comp["gdrive"],
                      gdrive_root: comp["gdrive_root"],
                      gdrive_labels: comp["gdrive_labels"], gsheets: comp["gsheets"],
                      gdocs: comp["gdocs"], gcalendar: comp["gcalendar"],
                      google_oauth: comp["google_oauth"]}
            # Attributes of `server.tools` (what `from .tools import gdrive`
            # reads) AND `sys.modules` (what `patch("server.tools.gdrive.x")`
            # resolves): a suite patching by name patches the component.
            swaps = [patch.object(tools_pkg, m, comp[m]) for m in MODULES]
            swaps.append(patch.dict(sys.modules, {f"server.tools.{m}": comp[m]
                                                  for m in MODULES}))
            for mod in self.SUITES:
                for name, value in list(vars(mod).items()):
                    if isinstance(value, ModuleType) and value in native:
                        swaps.append(patch.object(mod, name, native[value]))
            # The suites stub the native verbs' own whitelist re-check; on the
            # component the dispatcher's check is the only one.
            swaps.append(patch.object(comp["gdrive"], "tool_allowed",
                                      lambda *a, **k: None, create=True))
            for p in swaps:
                p.start()
                self.addCleanup(p.stop)
            for m in ("gdrive_root",):
                comp[m].reset_cache()
                comp[m].reset_topic_cache()
            comp["google_io"].forget()
        super().setUp()

    # -- helpers ------------------------------------------------------------

    def _reload(self) -> None:
        from . import instance_profile
        from .connectors import resolved
        instance_profile.load(force=True)
        resolved.invalidate()

    def position(self, google: str) -> None:
        from . import instance_profile
        from .components import loader
        from .connectors import resolved
        (self.base / "data" / "profile.yaml").write_text(
            f"edition: full\nconnectors:\n  google: {google}\n", encoding="utf-8")
        instance_profile.load(force=True)
        resolved.invalidate()
        loader.reconcile(force=True)

    def state(self) -> dict | None:
        from .components import loader
        return loader.state_of(PACK)


# --------------------------------------------------------------------------
# 1. load
# --------------------------------------------------------------------------

@NEEDS_LOGIC
class LoadTests(GoogleComponentInstance, unittest.TestCase):
    def test_loaded_with_the_24_verbs_routes_and_services(self):
        from . import main
        row = self.state()
        self.assertEqual((row["status"], row["commit"]), ("loaded", COMMIT))
        self.assertEqual(sorted(row["verbs"]), sorted(main._GOOGLE_NATIVE_NAMES))
        self.assertEqual(sorted(row["routes"]), ["app", "auth", "connect"])
        self.assertEqual(sorted(row["services"]), sorted([
            "accounts", "credential_changed", "describe_folder", "folder_labels",
            "mail_run", "pdp_arguments", "perimeter_changed", "test_connection",
            # google-pack >= 2.1.0: Gmail for comms-pack's mail component (#558)
            "mail_accounts", "mail_exec"]))

    def test_the_schemas_are_the_native_ones_verbatim(self):
        from . import main
        from . import components
        native = {t.name: t for t in main._GDRIVE_TOOLS + main._GCALENDAR_TOOLS
                  + main._GDOCS_TOOLS + main._GSHEETS_TOOLS}
        mine = {t.name: t for t in components.tools()}
        self.assertEqual(set(mine), set(native))
        for name, tool in native.items():
            with self.subTest(verb=name):
                self.assertEqual(mine[name].description, tool.description)
                self.assertEqual(mine[name].inputSchema, tool.inputSchema)

    def test_the_natives_step_aside(self):
        from . import main
        from .connectors.manifest import core_namespaces
        natives = {t.name for t in main._all_native_tools()}
        for verb in main._GOOGLE_NATIVE_NAMES:
            with self.subTest(verb=verb):
                self.assertNotIn(verb, natives)
                self.assertTrue(main._is_packaged_verb(verb))
                self.assertTrue(main._verb_implemented(verb))
                self.assertIsNotNone(main._component_verb(verb))
        self.assertFalse(set(NAMESPACES) & core_namespaces())

    def test_the_import_guard_finds_nothing(self):
        from .components import guard, store
        pin = store.pin_of(PACK, "google")
        self.assertEqual(guard.scan_tree(pin.dir), [])
        self.assertEqual(store.verify(pin), "")

    def test_native_position_keeps_it_on_standby(self):
        from . import main
        from . import components
        self.position("native")
        row = self.state()
        self.assertEqual(row["status"], "standby")
        self.assertEqual((row["verbs"], row["routes"], row["services"]), ([], [], []))
        self.assertEqual(components.tools(), [])
        for verb in main._GOOGLE_NATIVE_NAMES:
            self.assertIsNone(main._component_verb(verb))
            self.assertEqual(components.refusal(verb), "")
        self.position("pack")
        self.assertEqual(self.state()["status"], "loaded")

    def test_its_credentials_follow_the_switch(self):
        from .components.host import HostError
        host = self.comp["gdrive"]._host.get()
        for prefix in ("google_", "gworkspace_", "gmail_", "app_google_oauth"):
            host.credentials(prefix)                     # no exception
        from . import instance_profile
        (self.base / "data" / "profile.yaml").write_text(
            "edition: full\nconnectors:\n  google: native\n", encoding="utf-8")
        instance_profile.load(force=True)
        with self.assertRaises(HostError):
            host.credentials("google_")


# --------------------------------------------------------------------------
# 2. PDP parity
# --------------------------------------------------------------------------

@NEEDS_LOGIC
class PdpParityTests(GoogleComponentInstance, unittest.TestCase):
    def test_every_answer_is_the_same_in_both_positions(self):
        from .connectors import resolved
        from .connectors.test_558_google_switch import _risposte
        self.assertEqual(resolved.registry().by_id("google").pack, PACK)
        self.assertIsNotNone(__import__("server.components.store", fromlist=["x"])
                             .pinned_manifest(PACK), "the manifest is the pinned one")
        da_pack = _risposte()
        self.position("native")
        self.assertTrue(resolved.registry().by_id("google").builtin)
        nativo = _risposte()
        self.assertEqual(set(nativo), set(da_pack))
        for key in sorted(nativo):
            with self.subTest(question=key):
                self.assertEqual(da_pack[key], nativo[key])

    def test_every_component_verb_is_classified(self):
        from .components import loader
        from . import main
        for verb in main._GOOGLE_NATIVE_NAMES:
            with self.subTest(verb=verb):
                self.assertTrue(loader._classified(verb))
                self.assertEqual(loader.refusal(verb), "")

    def test_the_connectors_are_the_builtin_ones(self):
        """The real pack.yaml's connectors are exactly what the switch test
        derives from the builtin `google.yaml`."""
        from .connectors.test_558_google_switch import _google_pack
        real = {c["id"]: c for c in real_manifest()["connectors"]}
        derived = {c["id"]: c for c in _google_pack()["connectors"]}
        self.assertEqual(set(real), set(derived))
        for cid in real:
            with self.subTest(connector=cid):
                self.assertEqual(real[cid], derived[cid])


# --------------------------------------------------------------------------
# 3. the Google suites, against the component
# --------------------------------------------------------------------------

from .tools import google_io as NATIVE_GOOGLE_IO  # noqa: E402
from . import test_524_google_pins as PINS  # noqa: E402
from . import test_gdrive_confinement_api as CONF  # noqa: E402
from . import test_gdrive_root as GR  # noqa: E402
from . import test_gdrive_root_per_topic as GRT  # noqa: E402
from .tools import test_524_google_io as GIO  # noqa: E402
from .tools import test_gdrive_labels as LAB  # noqa: E402
from .tools import test_gdrive_update as UPD  # noqa: E402
from .tools import test_gsheets as GS  # noqa: E402


class _OnComponent(GoogleComponentInstance):
    SUITES = (PINS, CONF, GR, GRT, GIO, LAB, UPD, GS)

    def setUp(self) -> None:
        super().setUp()
        # Belt and braces: the suite really talks to the component.
        from .tools import gdrive
        assert gdrive is not None
        assert PINS.gdrive is self.comp["gdrive"], "suite not re-pointed"


def _suite(base):
    return NEEDS_LOGIC(type(f"Component{base.__name__}", (_OnComponent, base), {}))


ComponentPinsPdp = _suite(PINS.PdpParityTests)
ComponentPinsLabels = _suite(PINS.FolderLabelShapeTests)
ComponentPinsUnconfined = _suite(PINS.UnconfinedCallsTests)
ComponentPinsAccountRoot = _suite(PINS.AccountRootTests)
ComponentPinsTopicPerimeter = _suite(PINS.TopicPerimeterTests)
ComponentGdriveRootAncestry = _suite(GR.AncestryTests)
ComponentGdriveRootTraps = _suite(GR.TheThreeTraps)
ComponentGdriveRootFailClosed = _suite(GR.FailClosedTests)
ComponentGdriveRootConfig = _suite(GR.ConfigTests)
ComponentGdriveRootCost = _suite(GR.CostTests)
ComponentGdriveRootFastPath = _suite(GR.FastPathTests)
ComponentGdriveRootWriteDestination = _suite(GR.WriteDestinationTests)
ComponentGdriveRootRefusalMessage = _suite(GR.RefusalMessageTests)
ComponentGdriveRootCalendar = _suite(GR.CalendarTests)
ComponentGdriveRootNativeDoc = _suite(GR.NativeDocTests)
ComponentGdriveRootVerbCoverage = _suite(GR.VerbCoverageTests)
ComponentPerTopic = _suite(GRT.PerTopicTests)
ComponentPerTopicCeiling = _suite(GRT.CeilingTests)
ComponentPerTopicSignedClaim = _suite(GRT.SignedClaimTests)
ComponentConfinementWrite = _suite(CONF.WriteTests)
ComponentConfinementDisclosure = _suite(CONF.DisclosureTests)
ComponentSheets = _suite(GS.GSheetsTest)
ComponentDriveUpdate = _suite(UPD.UpdateTests)
ComponentDriveLabels = _suite(LAB.LabelTests)
ComponentWireParity = _suite(GIO.WireParityTests)
ComponentRequest = _suite(GIO.RequestTests)
ComponentRestTransport = _suite(GIO.TransportTests)
ComponentToken = _suite(GIO.TokenTests)
ComponentTokenStaysOnItsHost = _suite(GIO.TokenStaysOnItsHostTests)
ComponentTokenCacheFollowsTheVault = _suite(GIO.TokenCacheFollowsTheVaultTests)


# --------------------------------------------------------------------------
# 4. the call path, the routes, the custody
# --------------------------------------------------------------------------

TOKEN = {"agent": "clodia", "execution_id": "clodia-558g", "principal": "davide",
         "chat": "chan:SEAL-2:acme:clodia"}


@NEEDS_LOGIC
class CallPathTests(_OnComponent, unittest.TestCase):
    """A component verb through `call_tool`: whitelist, egress PDP (enforced),
    the component's `pdp_arguments`, then the handler."""

    def setUp(self) -> None:
        super().setUp()
        e = patch.dict(os.environ, {"CLODIA_EGRESS_ENFORCE": "on"})
        e.start()
        self.addCleanup(e.stop)
        self.fake = PINS.FakeGoogle({"F1": ["ROOT"], "ROOT": [], "DOC1": ["F1"],
                                     "OUT": ["ELSE"], "ELSE": []})
        PINS._install(self, self.fake)
        self.src_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.src_dir, True)

    def run_call(self, name, args, *, egress=(), tools=("*",)):
        from . import main
        from . import whitelist as wl
        from .claims import ClaimsContext
        cfg = {"egress_allow": list(egress), "source_allow": [],
               "agents": {"clodia": {"allowed_tools": list(tools)}}}

        async def go():
            with ClaimsContext(TOKEN, "t"), \
                    patch.object(main, "_require_gate_consent",
                                 AsyncMock(return_value={})), \
                    patch.object(main, "_safe_scratch_path", lambda p: p), \
                    patch.object(wl, "CONFIG", cfg):
                return await main.call_tool(name, args)
        return asyncio.run(go())[0].text

    def test_a_read_runs_on_the_component(self):
        out = self.run_call("gdrive.rename", {"file_id": "F1", "new_name": "x"})
        self.assertFalse(out.startswith(("DENIED", "ERROR")), out)
        self.assertEqual(json.loads(out)["renamed"], True)
        self.assertEqual(self.fake.ops(), ["files.update"])

    def test_a_namespace_wildcard_reaches_the_component_verbs(self):
        out = self.run_call("gdrive.rename", {"file_id": "F1", "new_name": "x"},
                            tools=["gdrive.*"])
        self.assertFalse(out.startswith(("DENIED", "ERROR")), out)

    def test_the_whitelist_applies(self):
        out = self.run_call("gdrive.rename", {"file_id": "F1", "new_name": "x"},
                            tools=["topic.open"])
        self.assertTrue(out.startswith("DENIED"), out)
        self.assertEqual(self.fake.ops(), [])

    def test_an_upload_outside_the_list_is_denied_before_the_handler(self):
        src = os.path.join(self.src_dir, "a.txt")
        Path(src).write_text("x")
        out = self.run_call("gdrive.upload", {"src": src, "folder_id": "OUT"},
                            egress=["gdrive:folder/F1"])
        self.assertTrue(out.startswith("DENIED"), out)
        self.assertNotIn("files.create", self.fake.ops())
        out = self.run_call("gdrive.upload", {"src": src, "folder_id": "F1"},
                            egress=["gdrive:folder/F1"])
        self.assertFalse(out.startswith(("DENIED", "ERROR")), out)
        self.assertIn("files.create", self.fake.ops())

    def test_the_parent_of_an_update_comes_from_the_component(self):
        src = os.path.join(self.src_dir, "a.txt")
        Path(src).write_text("x")
        out = self.run_call("gdrive.update", {"file_id": "DOC1", "src": src},
                            egress=["gdrive:folder/ELSE"])
        self.assertTrue(out.startswith("DENIED"), out)
        self.assertNotIn("files.update", self.fake.ops())
        self.fake.calls.clear()
        out = self.run_call("gdrive.update", {"file_id": "DOC1", "src": src},
                            egress=["gdrive:folder/F1"])
        self.assertFalse(out.startswith(("DENIED", "ERROR")), out)
        self.assertEqual(self.fake.ops()[0], "files.get")      # the parent lookup
        self.assertIn("files.update", self.fake.ops())

    def test_native_google_io_refuses_in_pack_position(self):
        self.assertIsNot(NATIVE_GOOGLE_IO, self.comp["google_io"])
        with self.assertRaises(NATIVE_GOOGLE_IO.NativeDisabled):
            NATIVE_GOOGLE_IO.call("conto", "drive", "v3", "GET files", params={})


class _Req:
    def __init__(self, method="GET", body=None, token="ui"):
        self.method = method
        self.headers = {"authorization": f"Bearer {token}"} if token else {}
        self._body = body or {}
        self.path_params = {}

    async def json(self):
        return self._body


@NEEDS_LOGIC
class RouteAndCustodyTests(_OnComponent, unittest.TestCase):
    APP = {"client_id": "CID", "client_secret": "CSECRET",  # gitleaks:allow
           "redirect_uri": "http://127.0.0.1"}

    def setUp(self) -> None:
        super().setUp()
        from . import tools_api
        for p in (patch.object(tools_api, "_UI_TOKEN", "ui"),
                  patch.object(tools_api, "_connector_guard", lambda _c: None)):
            p.start()
            self.addCleanup(p.stop)
        from . import vault
        vault.deposit("app_google_oauth", dict(self.APP), cred_type="google_app",
                      grant_agents=[])

    def test_auth_is_the_components_and_needs_a_human_admin(self):
        from . import tools_api
        r = asyncio.run(tools_api.google_auth(_Req()))
        self.assertEqual(r.status_code, 200, r.body)
        body = json.loads(r.body)
        self.assertIn("client_id=CID", body["auth_url"])
        self.assertIn(body["state"], sys.modules[f"{MODULE_ROOT}.routes"]._states)
        with patch.object(tools_api, "_authorized", lambda _r: True):
            r = asyncio.run(tools_api.google_auth(_Req(token="agent-token")))
        self.assertEqual(r.status_code, 401)        # the component's auth applies

    def test_connect_deposits_the_same_bundle(self):
        from . import tools_api, vault
        go = self.comp["google_oauth"]
        state = json.loads(asyncio.run(tools_api.google_auth(_Req())).body)["state"]
        with patch.object(go, "exchange_code",  # gitleaks:allow — fake test credential
                          lambda *a: {"refresh_token": "RT", "access_token": "AT"}), \
                patch.object(go, "get_profile_email", lambda _t: "Mario.Rossi@x.it"):
            r = asyncio.run(tools_api.google_connect(
                _Req("POST", {"code": "C", "state": state})))
        self.assertEqual(r.status_code, 200, r.body)
        self.assertEqual(json.loads(r.body), {"connected": True, "account": "Mario_Rossi",
                                              "email": "Mario.Rossi@x.it"})
        self.assertEqual(vault.read_internal("google_Mario_Rossi"), {
            "client_id": "CID", "client_secret": "CSECRET", "refresh_token": "RT",  # gitleaks:allow — fake test credential
            "email": "Mario.Rossi@x.it", "account": "Mario_Rossi",
            "scope": PINS.go.UNIFIED_SCOPE})
        self.assertEqual(vault.credential_type("google_Mario_Rossi"), "oauth2_google")

    def test_app_status_and_config(self):
        from . import tools_api, vault
        r = asyncio.run(tools_api.google_app_status(_Req()))
        self.assertEqual(json.loads(r.body), {"configured": True,
                                              "redirect_uri": "http://127.0.0.1"})
        r = asyncio.run(tools_api.google_app_config(_Req("POST", {
            "client_id": "N", "client_secret": "S"})))  # gitleaks:allow
        self.assertEqual(r.status_code, 200, r.body)
        self.assertEqual(vault.read_internal("app_google_oauth")["client_id"], "N")

    def test_without_the_component_the_routes_fail_closed(self):
        from . import tools_api
        from .components import loader
        loader.reset()
        r = asyncio.run(tools_api.google_auth(_Req()))
        self.assertEqual(r.status_code, 503)
        self.assertIn("google-pack", json.loads(r.body)["detail"])

    def test_the_tools_card_test_is_the_components(self):
        from . import tools_api
        out = tools_api._test_connector("google")
        self.assertEqual(out, {"ok": None, "detail": "nessun account Google connesso"})


@NEEDS_LOGIC
class GmailTests(_OnComponent, unittest.TestCase):
    """`email.*` on a Google account runs the component's Gmail client with
    the per-call XOAUTH2 files the gateway's vault materialises."""

    def test_folders_runs_the_bundled_client_with_this_calls_files(self):
        from .tools import email as EM
        core = sys.modules[f"{MODULE_ROOT}.gmail_core"]
        probe = Path(self.base) / "probe_client.py"
        probe.write_text(
            "import json, os, sys\n"
            "d = os.environ['CLODIA_SECRETS_DIR']\n"
            "print(json.dumps({'argv': sys.argv[1:], 'files': sorted(os.listdir(d)),"
            " 'bytecode': os.environ.get('PYTHONDONTWRITEBYTECODE')}))\n")
        bundle = {"client_id": "CID", "client_secret": "CS",  # gitleaks:allow
                  "refresh_token": "RT", "email": "studio@gmail.com"}  # gitleaks:allow — fake test credential
        with patch.object(core, "CLIENT", probe), \
                patch.object(EM, "known_accounts", return_value={"studio"}), \
                patch.object(EM.vault, "has_credential", lambda c: c == "google_studio"), \
                patch("server.vault.read_internal", lambda c: dict(bundle)), \
                patch.object(EM, "_assert_mailbox_allowed", lambda *a: None), \
                patch.object(EM.subprocess, "run") as native_run:
            out = EM._run_cli("studio", ["folders"], want_json=True, direction="inbox")
        native_run.assert_not_called()
        self.assertEqual(out["argv"], ["--account", "studio", "folders"])
        self.assertEqual(out["files"], ["email_config.json", "email_oauth_tokens.json",
                                        "google_oauth_client.json"])
        self.assertEqual(out["bytecode"], "1")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

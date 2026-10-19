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
   the routes, the services; a profile still saying `native` changes nothing
   (#526).
2. **PDP parity**: every public PDP answer about Google is the same with the
   former builtin declaration (`testdata/former_builtin/google.yaml`) and with
   google-pack's PINNED manifest; the pins tables of `test_524_google_pins`
   hold.
3. (The native Google suites re-run against the component lived here until
   the native client was removed, #524: those cases are in clodia-logic now.)
4. **The call path**: `call_tool` runs a component verb after the whitelist and
   the egress PDP (and `gdrive.update`'s parent lookup is the component's
   service); the component's routes `/tools/google-pack/*` (the gateway's
   `/tools/google/*` aliases were removed with #526);
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

    def setUp(self) -> None:  # noqa: D401
        from . import instance_profile
        from .components import loader
        from .connectors import resolved
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
            swaps = []
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
        """The native schemas went with the native code (#524): the component
        registers exactly the 24 verbs the gateway names."""
        from . import main
        from . import components
        mine = {t.name for t in components.tools()
                if t.name.split(".", 1)[0] in ("gdrive", "gcalendar", "gdocs", "gsheets")}
        self.assertEqual(mine, set(main._GOOGLE_NATIVE_NAMES))

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

    def test_a_profile_saying_native_changes_nothing(self):
        from . import main
        self.position("native")
        self.assertEqual(self.state()["status"], "loaded")
        for verb in main._GOOGLE_NATIVE_NAMES:
            self.assertIsNotNone(main._component_verb(verb))

    def test_its_credentials_are_google_packs(self):
        host = self.comp["gdrive"]._host.get()
        self.position("native")                          # ignored (#526)
        for prefix in ("google_", "gworkspace_", "gmail_", "app_google_oauth"):
            host.credentials(prefix)                     # no exception


# --------------------------------------------------------------------------
# 2. PDP parity
# --------------------------------------------------------------------------

@NEEDS_LOGIC
class PdpParityTests(GoogleComponentInstance, unittest.TestCase):
    def test_every_answer_is_the_former_builtins(self):
        from .connectors import resolved
        from .connectors.test_558_google_switch import _risposte
        self.assertEqual(resolved.registry().by_id("google").pack, PACK)
        self.assertIsNotNone(__import__("server.components.store", fromlist=["x"])
                             .pinned_manifest(PACK), "the manifest is the pinned one")
        da_pack = _risposte()
        nativo = _former_builtin_answers(_risposte)
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

# A fake Google API for the call-path tests, answering at the component's
# `google_io` transport (moved here from the removed `test_524_google_pins`).
ACCT = "conto"


class _Request:
    def __init__(self, fn):
        self._fn = fn

    def execute(self, **_kw):
        return self._fn()


class _Resource:
    """`svc.files()`, `svc.spreadsheets().values()`, … — every method call is
    recorded as `(resource.method, kwargs)` and answered by the owner."""

    _CHILDREN = {"spreadsheets": ("values",)}

    def __init__(self, owner, name):
        self._o, self._n = owner, name

    def __getattr__(self, method):
        if method.startswith("_"):
            raise AttributeError(method)
        if method in self._CHILDREN.get(self._n, ()):
            return lambda: _Resource(self._o, f"{self._n}.{method}")
        op = f"{self._n}.{method}"

        def call(**kw):
            kw = {k: v for k, v in kw.items() if v is not None}
            if "media_body" in kw:
                kw["media_body"] = kw["media_body"].mimetype()
            self._o.calls.append((op, kw))
            return _Request(lambda: self._o.answer(op, kw))
        return call


class FakeGoogle:
    """Drive, Docs, Sheets and Calendar answered from a parents table."""

    def __init__(self, tree, *, shortcuts=(), names=None, mimes=None, rows=None,
                 calendars=None):
        self.tree = {k: list(v) for k, v in tree.items()}
        self.shortcuts = set(shortcuts)
        self.names = dict(names or {})
        self.mimes = dict(mimes or {})
        self.rows = list(rows or [])
        self.calendars = list(calendars if calendars is not None else [
            {"id": "cal@x.it", "summary": "Mine", "primary": True, "accessRole": "owner"},
            {"id": "other@x.it", "summary": "Theirs", "accessRole": "reader"}])
        self.calls: list[tuple[str, dict]] = []

    def __getattr__(self, resource):
        if resource.startswith("_"):
            raise AttributeError(resource)
        return lambda: _Resource(self, resource)

    def ops(self):
        return [op for op, _ in self.calls]

    def _file(self, fid):
        if fid not in self.tree:
            raise RuntimeError(f"404 File not found: {fid}")
        out = {"id": fid, "name": self.names.get(fid, f"name-{fid}"),
               "mimeType": self.mimes.get(fid, "text/plain"),
               "parents": list(self.tree[fid])}
        if fid in self.shortcuts:
            out["shortcutDetails"] = {"targetId": "elsewhere"}
            out["mimeType"] = gr.SHORTCUT_MIME
        return out

    def answer(self, op, kw):  # noqa: C901 — one branch per API method
        if op == "files.get":
            return self._file(kw["fileId"])
        if op == "files.list":
            return {"files": [dict(r) for r in self.rows]}
        if op == "files.create":
            body = kw.get("body") or {}
            return {"id": "NEW", "name": body.get("name"),
                    "mimeType": body.get("mimeType", "text/plain"),
                    "parents": body.get("parents", [])}
        if op == "files.update":
            f = self._file(kw["fileId"])
            if (kw.get("body") or {}).get("name"):
                f["name"] = kw["body"]["name"]
            if kw.get("addParents"):
                f["parents"] = [kw["addParents"]]
            return f
        if op == "permissions.create":
            return {"id": "PERM1"}
        if op == "documents.create":
            return {"documentId": "DOC1", "title": kw["body"]["title"]}
        if op == "documents.get":
            return {"title": "Doc", "body": {"content": [
                {"endIndex": 1, "sectionBreak": {}},
                {"endIndex": 6, "paragraph": {"elements": [
                    {"textRun": {"content": "ciao\n"}}]}}]}}
        if op == "documents.batchUpdate":
            return {"replies": [{"replaceAllText": {"occurrencesChanged": 2}}]}
        if op == "spreadsheets.get":
            return {"properties": {"title": "Budget"}, "sheets": [
                {"properties": {"title": "T1", "sheetId": 1, "index": 0,
                                "gridProperties": {"rowCount": 5, "columnCount": 3}}}]}
        if op == "spreadsheets.batchUpdate":
            p = kw["body"]["requests"][0]["addSheet"]["properties"]
            return {"replies": [{"addSheet": {"properties": {
                "title": p["title"], "sheetId": 9, "index": p.get("index", 1)}}}]}
        if op == "spreadsheets.values.get":
            return {"range": f"{kw['range']}!A1:B2", "values": [["a", "b"], ["1", "2"]]}
        if op == "spreadsheets.values.append":
            return {"updates": {"updatedRange": f"{kw['range']}!A6:B6",
                                "updatedRows": len(kw["body"]["values"])}}
        if op == "spreadsheets.values.update":
            return {"updatedRange": kw["range"], "updatedCells": 2}
        if op == "calendarList.list":
            return {"items": [dict(c) for c in self.calendars]}
        if op == "events.list":
            return {"items": [{"id": "E1", "summary": "Call", "etag": "x",
                               "start": {"dateTime": "2026-10-20T10:00:00+02:00"},
                               "end": {"dateTime": "2026-10-20T11:00:00+02:00"}}]}
        if op == "events.insert":
            return {"id": "E2", **kw["body"]}
        if op == "events.get":
            return {"id": kw["eventId"], "summary": "Old",
                    "start": {"date": "2026-10-20"}, "end": {"date": "2026-10-21"}}
        if op == "events.update":
            return dict(kw["body"])
        if op == "events.delete":
            return ""
        if op == "freebusy.query":
            return {"calendars": {kw["body"]["items"][0]["id"]: {"busy": [
                {"start": "2026-10-20T10:00:00Z", "end": "2026-10-20T11:00:00Z"}]}}}
        raise AssertionError(f"unexpected Google call {op} {kw}")


def _install(test, fake) -> None:
    """Answer every Google call of the COMPONENT from `fake`."""
    from .tools._google_fake import ServiceTransport
    comp = test.comp
    patches = [patch.object(comp["gdrive"], "gworkspace_accounts", lambda: [ACCT]),
               patch.object(comp["google_io"], "_transport", ServiceTransport(fake))]
    for p in patches:
        p.start()
        test.addCleanup(p.stop)


class _OnComponent(GoogleComponentInstance):
    pass


# The native Google suites that ran here against the component went with the
# native Google client (#524); their cases live in clodia-logic now, next to
# the component they test.


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
        self.fake = FakeGoogle({"F1": ["ROOT"], "ROOT": [], "DOC1": ["F1"],
                                     "OUT": ["ELSE"], "ELSE": []})
        _install(self, self.fake)
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

    def test_there_is_no_native_google_client(self):
        """#524: the gateway has no Google client; only the component's."""
        import importlib.util
        self.assertIsNone(importlib.util.find_spec("server.tools.google_io"))


def _former_builtin_answers(risposte):
    """`risposte()` asked of the registry the former builtin declarations
    build (`first_party_fixture`, the parity reference of #522–#525)."""
    from .connectors import first_party_fixture, resolved
    with patch.object(resolved, "manifests", first_party_fixture.manifests):
        resolved.invalidate()
        try:
            return risposte()
        finally:
            resolved.invalidate()


class _Req:
    def __init__(self, method="GET", body=None, token="ui"):
        self.method = method
        self.headers = {"authorization": f"Bearer {token}"} if token else {}
        self._body = body or {}
        self.path_params = {}

    async def json(self):
        return self._body


def _route(path: str, req: "_Req"):
    """`/tools/google-pack/<path>`: the component's route, through the
    gateway's generic component entrance (the `/tools/google/*` aliases
    were removed with #526)."""
    from . import components_api
    req.path_params = {"pack": PACK, "rest": path}
    return asyncio.run(components_api.component_route(req))


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
        r = _route("auth", _Req())
        self.assertEqual(r.status_code, 200, r.body)
        body = json.loads(r.body)
        self.assertIn("client_id=CID", body["auth_url"])
        self.assertIn(body["state"], sys.modules[f"{MODULE_ROOT}.routes"]._states)
        with patch.object(tools_api, "_authorized", lambda _r: True):
            r = _route("auth", _Req(token="agent-token"))
        self.assertEqual(r.status_code, 401)        # the component's auth applies

    def test_connect_deposits_the_same_bundle(self):
        from . import tools_api, vault
        go = self.comp["google_oauth"]
        state = json.loads(_route("auth", _Req()).body)["state"]
        with patch.object(go, "exchange_code",  # gitleaks:allow — fake test credential
                          lambda *a: {"refresh_token": "RT", "access_token": "AT"}), \
                patch.object(go, "get_profile_email", lambda _t: "Mario.Rossi@x.it"):
            r = _route("connect", _Req("POST", {"code": "C", "state": state}))
        self.assertEqual(r.status_code, 200, r.body)
        self.assertEqual(json.loads(r.body), {"connected": True, "account": "Mario_Rossi",
                                              "email": "Mario.Rossi@x.it"})
        self.assertEqual(vault.read_internal("google_Mario_Rossi"), {
            "client_id": "CID", "client_secret": "CSECRET", "refresh_token": "RT",  # gitleaks:allow — fake test credential
            "email": "Mario.Rossi@x.it", "account": "Mario_Rossi",
            "scope": self.comp["google_oauth"].UNIFIED_SCOPE})
        self.assertEqual(vault.credential_type("google_Mario_Rossi"), "oauth2_google")

    def test_app_status_and_config(self):
        from . import tools_api, vault
        r = _route("app", _Req())
        self.assertEqual(json.loads(r.body), {"configured": True,
                                              "redirect_uri": "http://127.0.0.1"})
        r = _route("app", _Req("POST", {
            "client_id": "N", "client_secret": "S"}))  # gitleaks:allow
        self.assertEqual(r.status_code, 200, r.body)
        self.assertEqual(vault.read_internal("app_google_oauth")["client_id"], "N")

    def test_without_the_component_the_routes_fail_closed(self):
        from .components import loader
        loader._STATES[KEY].status = "failed"
        r = _route("auth", _Req())
        self.assertEqual(r.status_code, 503)
        self.assertIn("google-pack", json.loads(r.body)["detail"])

    def test_the_edition_gates_the_routes(self):
        """#526: `integrations.connectors` without Google closes google-pack's
        routes too, not only its card."""
        from . import instance_profile
        with patch.object(instance_profile, "connectors_allowed",
                          lambda: ["mailboxes"]):
            r = _route("auth", _Req())
        self.assertEqual(r.status_code, 403)
        with patch.object(instance_profile, "connectors_allowed", lambda: ["google"]):
            self.assertEqual(_route("auth", _Req()).status_code, 200)

    def test_the_tools_card_test_is_the_components(self):
        from . import tools_api
        out = tools_api._test_connector("google")
        self.assertEqual(out, {"ok": None, "detail": "nessun account Google connesso"})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


def setUpModule() -> None:
    # comms-pack and it-pack as on every instance (#526): google-pack's
    # `gdrive.upload` shares on comms-pack's `mailto:`. google-pack is this
    # module's own (its REAL manifest, pinned).
    from .connectors import first_party_fixture
    first_party_fixture.install(without=("google-pack",))


def tearDownModule() -> None:
    from .connectors import first_party_fixture
    first_party_fixture.uninstall()

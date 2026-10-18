"""comms-pack's REAL gateway component (mail), against the gateway
(clodia-platform#558).

Needs a clodia-logic checkout: `CLODIA_LOGIC_SRC=<path> make test` (skipped
otherwise). The code under test is `catalogs/packs/comms-pack/` (and, for
Gmail, `catalogs/packs/google-pack/`) of that checkout, served by a fake
GitHub fetcher as the upstream tarball: the gateway pins it, verifies it, scans
its imports, imports it as `clodia_components.comms_pack.comms` and calls
`register(host)` — the production path of `server.components`, nothing
short-circuited. The datadir holds the same `pack.yaml`s, the profile says
`connectors: {mail: pack, google: pack}`.

Then:

1. **Load**: status `loaded`, the 8 verbs with the native schemas verbatim,
   the services; the natives step aside; on `native` the component is pinned
   on standby and serves nothing; the `mailbox_` scope follows the switch.
2. **PDP parity**: every public PDP answer about mail is the same with the
   builtin manifest (`native`) and with comms-pack's PINNED manifest (`pack`);
   the PDP tables of #518 hold; every component verb is classified.
3. (The native mail suites re-run against the component lived here until the
   native mail code was removed, #523: those cases are in clodia-logic now.)
4. **The call path**: `call_tool` runs a component verb after the whitelist
   and the egress PDP; `email.reply`'s recipient is the component's
   (`pdp_arguments`) and the caller's `to` is never kept; topic attachments in
   and out; legacy accounts refused; no component → every verb DENIED and the
   native client never runs; Gmail through google-pack's component, whose
   credential never reaches comms-pack; an end-to-end send through the bundled
   client.
"""
from __future__ import annotations

import asyncio
import base64
import importlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import ModuleType
from unittest.mock import AsyncMock, patch

import yaml

LOGIC_SRC = os.environ.get("CLODIA_LOGIC_SRC", "")
PACKS_DIR = (Path(LOGIC_SRC) / "catalogs" / "packs") if LOGIC_SRC else None
HAVE_LOGIC = bool(PACKS_DIR and (PACKS_DIR / "comms-pack" / "gateway"
                                 / "mail_component.py").is_file())
NEEDS_LOGIC = unittest.skipUnless(
    HAVE_LOGIC, "set CLODIA_LOGIC_SRC to a clodia-logic checkout with comms-pack 2.x")

COMMS = "comms-pack"
GOOGLE = "google-pack"
KEY = "comms-pack/mail"
COMMIT = "b" * 40
MAIL_ROOT = "clodia_components.comms_pack.comms"
GOOGLE_ROOT = "clodia_components.google_pack.google"
EMAIL_VERBS = ("email.send", "email.folders", "email.list", "email.read",
               "email.get_attachment", "email.save_attachment", "email.search",
               "email.reply")


def _upstream_tarball() -> bytes:
    """The clodia-logic repository as GitHub would serve it: comms-pack and
    google-pack under `catalogs/packs/`, compiled files left out."""
    buf = io.BytesIO()
    top = "r-clodia-clodia-logic-" + COMMIT[:7]
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for pack in (COMMS, GOOGLE):
            base = PACKS_DIR / pack
            for path in sorted(base.rglob("*")):
                if not path.is_file() or "__pycache__" in path.parts \
                        or path.suffix in (".pyc", ".pyo"):
                    continue
                rel = path.relative_to(base).as_posix()
                data = path.read_bytes()
                info = tarfile.TarInfo(f"{top}/catalogs/packs/{pack}/{rel}")
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


def real_manifest(pack: str = COMMS) -> dict:
    return yaml.safe_load((PACKS_DIR / pack / "pack.yaml").read_text(encoding="utf-8"))


class MailComponentInstance:
    """Mixin: a fake instance where comms-pack's (and google-pack's) real
    components are loaded.

    `setUp` builds the instance, loads the components and points the suites'
    module globals at the component BEFORE the suite's own `setUp` runs, so a
    suite subclassed with this mixin runs unchanged against the component."""

    MAIL = "pack"
    GOOGLE = "pack"

    def setUp(self) -> None:  # noqa: D401
        from . import main
        from .components import loader
        from .connectors import resolved
        # Registered FIRST so that it runs LAST, after the environment is
        # restored: the profile and the registry are re-read from the real
        # (test) datadir, not from this instance's `mail: pack`.
        self.addCleanup(self._reload)
        tmp = Path(tempfile.mkdtemp(prefix="m558-"))
        self.addCleanup(shutil.rmtree, tmp, True)
        self.base = tmp
        data = tmp / "data"
        for pack in (COMMS, GOOGLE):
            (data / "packs" / pack).mkdir(parents=True)
            (data / "packs" / pack / "pack.yaml").write_text(
                yaml.safe_dump(real_manifest(pack)), encoding="utf-8")
        env = patch.dict(os.environ, {
            "CLODIA_TOOLS_STATE_DIR": str(tmp / "state"),
            "CLODIA_DATA": str(data),
            "CLODIA_VAULT_DIR": str(tmp / "vault"),
            "CLODIA_AUDIT_DIR": str(tmp / "audit"),
            "CLODIA_AUDIT_KEY_DIR": str(tmp / "auditkey"),
            # No legacy `email_config.json` of the machine running the tests
            # leaks in (read by `host.legacy_mail_accounts`).
            "CLODIA_SECRETS_DIR": str(tmp / "no-secrets"),
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
        self.position(self.MAIL, self.GOOGLE)
        if self.MAIL == "pack":
            row = self.state()
            assert row and row["status"] == "loaded", f"component not loaded: {row}"
            mail = sys.modules[f"{MAIL_ROOT}.mail"]
            verbs = sys.modules[f"{MAIL_ROOT}.verbs"]
            client = importlib.import_module(f"{MAIL_ROOT}.email_client")
            self.mail, self.verbs, self.comp_client = mail, verbs, client
            swaps = []
            for p in swaps:
                p.start()
                self.addCleanup(p.stop)
        super().setUp()

    # -- helpers ------------------------------------------------------------

    def _reload(self) -> None:
        from . import instance_profile
        from .connectors import resolved
        instance_profile.load(force=True)
        resolved.invalidate()

    def position(self, mail: str, google: str | None = None) -> None:
        from . import instance_profile
        from .components import loader
        from .connectors import resolved
        google = google or self.GOOGLE
        (self.base / "data" / "profile.yaml").write_text(
            f"edition: full\nconnectors:\n  mail: {mail}\n  google: {google}\n",
            encoding="utf-8")
        instance_profile.load(force=True)
        resolved.invalidate()
        loader.reconcile(force=True)

    def state(self, pack: str = COMMS) -> dict | None:
        from .components import loader
        return loader.state_of(pack)


TOKEN = {"agent": "clodia", "execution_id": "clodia-558m", "principal": "davide",
         "chat": "chan:SEAL-2:acme:clodia", "clearance": "SEAL-2"}
STUDIO = {"email": "studio@example.it", "password": "pw",
          "imap_server": "imap.example.it", "imap_port": 993,
          "smtp_server": "smtp.example.it", "smtp_port": 587}


class _Run:
    """`subprocess.run` of the client, played: records argv and the shipped
    credential, answers per command."""

    def __init__(self, answers: dict) -> None:
        self.answers = answers
        self.calls: list[dict] = []

    def __call__(self, cmd, **kw):
        env = kw.get("env") or {}
        cfg = None
        sd = env.get("CLODIA_SECRETS_DIR")
        if sd and (Path(sd) / "email_config.json").exists():
            cfg = json.loads((Path(sd) / "email_config.json").read_text())
        argv = list(cmd[2:])
        op = argv[2] if len(argv) > 2 else ""
        self.calls.append({"argv": argv, "config": cfg, "env": dict(env), "cmd": cmd})
        out = self.answers.get(op, {"ok": True})
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps(out), stderr="")


# --------------------------------------------------------------------------
# 1. load
# --------------------------------------------------------------------------

@NEEDS_LOGIC
class LoadTests(MailComponentInstance, unittest.TestCase):
    def test_loaded_with_the_8_verbs_and_services(self):
        row = self.state()
        self.assertEqual((row["status"], row["commit"]), ("loaded", COMMIT))
        self.assertEqual(sorted(row["verbs"]), sorted(EMAIL_VERBS))
        self.assertEqual(row["routes"], [])
        self.assertEqual(sorted(row["services"]), sorted([
            "pdp_arguments", "diagnostics", "system_mailboxes", "mailbox_address",
            "mailboxes_list", "mailbox_add", "mailbox_remove", "test_mailboxes"]))
        self.assertEqual(self.state(GOOGLE)["status"], "loaded")

    def test_the_schemas_are_the_native_ones_verbatim(self):
        from . import main
        from . import components
        # The native schemas are gone with the native code (#523): what stays
        # is that the component registers exactly the eight verbs the gateway
        # names (and refuses on `native`).
        mine = {t.name for t in components.tools() if t.name.startswith("email.")}
        self.assertEqual(mine, set(main._EMAIL_VERB_NAMES))

    def test_the_natives_step_aside(self):
        from . import main
        from .connectors.manifest import core_namespaces
        natives = {t.name for t in main._all_native_tools()}
        for verb in EMAIL_VERBS:
            with self.subTest(verb=verb):
                self.assertNotIn(verb, natives)
                self.assertTrue(main._is_packaged_verb(verb))
                self.assertTrue(main._verb_implemented(verb))
                self.assertIsNotNone(main._component_verb(verb))
        self.assertNotIn("email", core_namespaces())

    def test_the_import_guard_finds_nothing(self):
        from .components import guard, store
        pin = store.pin_of(COMMS, "comms")
        self.assertEqual(guard.scan_tree(pin.dir), [])
        self.assertEqual(store.verify(pin), "")

    def test_the_component_never_imports_the_gateway(self):
        import ast
        from .components import store
        pin = store.pin_of(COMMS, "comms")
        for path in pin.dir.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                mods = []
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and not node.level:
                    mods = [node.module or ""]
                for m in mods:
                    with self.subTest(file=path.name, module=m):
                        self.assertFalse(m == "server" or m.startswith("server."))

    def test_native_position_keeps_it_on_standby(self):
        from . import main
        from . import components
        self.position("native")
        # comms-pack's one component also carries Telegram (2.1.1): on
        # `mail: native` it may stay loaded for that half, but serves no mail.
        for verb in EMAIL_VERBS:
            self.assertIsNone(main._component_verb(verb))
            self.assertEqual(components.refusal(verb), "")
            # No native implementation any more (#523): not listed natively.
            self.assertNotIn(verb, {t.name for t in main._all_native_tools()})
        self.position("pack")
        self.assertEqual(self.state()["status"], "loaded")

    def test_its_credentials_follow_the_switch(self):
        from .components.host import HostError
        from . import instance_profile
        host = sys.modules[f"{MAIL_ROOT}._host"].get()
        host.credentials("mailbox_")                     # no exception
        with self.assertRaises(HostError):
            host.credentials("google_")
        (self.base / "data" / "profile.yaml").write_text(
            "edition: full\nconnectors:\n  mail: native\n  google: pack\n",
            encoding="utf-8")
        instance_profile.load(force=True)
        with self.assertRaises(HostError):
            host.credentials("mailbox_")

    def test_the_refusal_phrase_is_the_gateways(self):
        from . import main
        self.assertEqual(self.mail.MITTENTE_NON_VAGLIATO, main.MITTENTE_NON_VAGLIATO)


# --------------------------------------------------------------------------
# 2. PDP parity
# --------------------------------------------------------------------------

@NEEDS_LOGIC
class PdpParityTests(MailComponentInstance, unittest.TestCase):
    def test_every_answer_is_the_same_in_both_positions(self):
        from .connectors import resolved
        from .components import store
        from .connectors.test_523_mail_provider import _risposte
        self.assertEqual(resolved.registry().by_id("mail").pack, COMMS)
        self.assertIsNotNone(store.pinned_manifest(COMMS), "the manifest is the pinned one")
        da_pack = _risposte()
        self.position("native")
        self.assertTrue(resolved.registry().by_id("mail").builtin)
        nativo = _risposte()
        self.assertEqual(set(nativo), set(da_pack))
        for key in sorted(nativo):
            with self.subTest(question=key):
                self.assertEqual(da_pack[key], nativo[key])

    def test_every_component_verb_is_classified(self):
        from .components import loader
        for verb in EMAIL_VERBS:
            with self.subTest(verb=verb):
                self.assertTrue(loader._classified(verb))
                self.assertEqual(loader.refusal(verb), "")

    def test_the_connector_is_the_builtin_one(self):
        """The real pack.yaml's `mail` connector is exactly what the switch
        test derives from the builtin `mail.yaml`."""
        from .connectors.test_558_mail_switch import _mail_connector
        real = {c["id"]: c for c in real_manifest()["connectors"]}["mail"]
        self.assertEqual(real, _mail_connector())


from . import test_518_pdp_tables as T518  # noqa: E402


def _pdp(base):
    return NEEDS_LOGIC(type(f"Pack{base.__name__}", (MailComponentInstance, base), {}))


PackPdpSchemeLists = _pdp(T518.SchemeListsTests)
PackPdpSpecs = _pdp(T518.SpecTests)
PackPdpCanonical = _pdp(T518.CanonicalTests)
PackPdpMatch = _pdp(T518.MatchTests)
PackPdpDanger = _pdp(T518.DangerTests)
PackPdpGrantable = _pdp(T518.GrantableTests)
PackPdpTaint = _pdp(T518.TaintTests)


# --------------------------------------------------------------------------
# 3. the mail suites, against the component
# --------------------------------------------------------------------------

class _OnComponent(MailComponentInstance):
    pass


# The native mail suites that ran here against the component went with the
# native mail code (#523); their cases now live in clodia-logic
# (`test_558_mail_component.py`, `test_523_mail_security_moved.py`), next to
# the component they test.


# --------------------------------------------------------------------------
# 4. the call path
# --------------------------------------------------------------------------

class _CallPath(_OnComponent):
    def setUp(self) -> None:
        super().setUp()
        from . import vault
        e = patch.dict(os.environ, {"CLODIA_EGRESS_ENFORCE": "on"})
        e.start()
        self.addCleanup(e.stop)
        vault.deposit("mailbox_studio", dict(STUDIO), cred_type="mailbox",
                      grant_agents=[])
        self.run_fake = _Run({"read": {"id": "7", "from": "Mario <mario@x.it>",
                                       "subject": "s", "body": "b"},
                              "list": [], "folders": ["INBOX"]})
        p = patch.object(subprocess, "run", self.run_fake)
        p.start()
        self.addCleanup(p.stop)

    def cfg(self, *, egress=(), ingress=("inbox:studio@example.it",), tools=("*",)):
        return {"egress_allow": ["outbox:studio@example.it", *egress],
                "scope_egress_allow": {}, "source_allow": list(ingress),
                "scope_source_allow": {}, "agents": {"clodia": {"allowed_tools": list(tools)}}}

    def run_call(self, name, args, **cfg):
        from . import main
        from . import whitelist as wl
        from .claims import ClaimsContext
        config = self.cfg(**cfg)

        async def go():
            with ClaimsContext(TOKEN, "t"), \
                    patch.object(main, "_require_gate_consent",
                                 AsyncMock(return_value={})), \
                    patch.object(wl, "CONFIG", config):
                return await main.call_tool(name, args)
        return asyncio.run(go())[0].text

    def ops(self) -> list[str]:
        return [c["argv"][2] for c in self.run_fake.calls]


@NEEDS_LOGIC
class CallPathTests(_CallPath, unittest.TestCase):
    def test_a_read_runs_on_the_component_with_this_calls_mailbox_only(self):
        out = self.run_call("email.folders", {"account": "studio"})
        self.assertFalse(out.startswith(("DENIED", "ERROR")), out)
        self.assertEqual(json.loads(out)["folders"], ["INBOX"])
        [call] = self.run_fake.calls
        self.assertEqual(call["argv"][:3], ["--account", "studio", "folders"])
        self.assertEqual(call["config"], {"default": "studio",
                                          "accounts": {"studio": STUDIO}})
        # The client's environment is the call's, not the gateway's.
        self.assertEqual(set(call["env"]), {"PATH", "LANG", "HOME",
                                            "CLODIA_SECRETS_DIR",
                                            "PYTHONDONTWRITEBYTECODE"})
        self.assertTrue(call["cmd"][1].endswith("email_client.py"))
        self.assertFalse(Path(call["env"]["CLODIA_SECRETS_DIR"]).exists())

    def test_the_whitelist_applies(self):
        out = self.run_call("email.folders", {"account": "studio"},
                            tools=["topic.open"])
        self.assertTrue(out.startswith("DENIED"), out)
        self.assertEqual(self.run_fake.calls, [])

    def test_a_mailbox_outside_the_inbox_list_is_refused(self):
        out = self.run_call("email.list", {"account": "studio"}, ingress=())
        self.assertTrue(out.startswith("DENIED"), out)
        self.assertIn("inbox:studio@example.it", out)
        self.assertEqual(self.run_fake.calls, [])

    def test_a_send_outside_the_list_is_denied_before_the_handler(self):
        out = self.run_call("email.send", {"account": "studio", "to": "x@y.it",
                                           "subject": "s", "body": "b"})
        self.assertTrue(out.startswith("DENIED"), out)
        self.assertEqual(self.run_fake.calls, [])
        out = self.run_call("email.send", {"account": "studio", "to": "x@y.it",
                                           "subject": "s", "body": "b"},
                            egress=["mailto:x@y.it"])
        self.assertFalse(out.startswith(("DENIED", "ERROR")), out)
        self.assertEqual(self.ops(), ["send"])

    def test_the_reply_recipient_is_the_components_and_the_callers_to_is_dropped(self):
        """`email.reply` has no `to`: the recipient is the SENDER of the
        message answered, read by the component. An agent passing an allowed
        `to` must not have the reply judged by it (#558 pdp_arguments rule)."""
        out = self.run_call("email.reply", {"account": "studio", "email_id": "7",
                                            "body": "ok", "to": "friend@ok.it"},
                            egress=["mailto:friend@ok.it"])
        self.assertTrue(out.startswith("DENIED"), out)
        self.assertEqual(self.ops(), ["read"])             # the lookup, no reply
        self.run_fake.calls.clear()
        out = self.run_call("email.reply", {"account": "studio", "email_id": "7",
                                            "body": "ok"},
                            egress=["mailto:mario@x.it"])
        self.assertFalse(out.startswith(("DENIED", "ERROR")), out)
        self.assertEqual(self.ops(), ["read", "reply"])

    def test_an_unresolvable_recipient_is_denied(self):
        self.run_fake.answers["read"] = {"id": "7", "from": "???"}
        out = self.run_call("email.reply", {"account": "studio", "email_id": "7",
                                            "body": "ok"},
                            egress=["mailto:mario@x.it"])
        self.assertTrue(out.startswith("DENIED"), out)
        self.assertNotIn("reply", self.ops())

    def test_strict_ingress_refusal_is_classified(self):
        from . import main
        msg = f"{self.mail.MITTENTE_NON_VAGLIATO}: questo canale è a INGRESSO STRETTO"
        self.assertEqual(main._denial_class(msg), "sender_not_vetted")


@NEEDS_LOGIC
class TopicAttachmentTests(_CallPath, unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        from . import main
        from .topics.local_fs import LocalFsStorage
        from .topics.service import TopicService
        self.svc = TopicService(LocalFsStorage(str(self.base / "topics")))
        self.svc.new("SEAL-2", "acme", {"title": "acme", "owner": "davide",
                                        "participants": ["davide", "clodia"]})
        self.svc.put_file("SEAL-2", "acme", "contratto.pdf", b"%PDF contratto",
                          "agent", by="clodia")
        self.crossings: list = []
        orig = main._note_crossing

        def note(*a, **k):
            self.crossings.append(k.get("kind"))
            return orig(*a, **k)
        for p in (patch.object(main, "_topics", lambda: self.svc),
                  patch.object(main, "_note_crossing", note)):
            p.start()
            self.addCleanup(p.stop)

    def test_topic_files_leave_as_attachments(self):
        sent = {}

        def run(cmd, **kw):
            i = cmd.index("--attachment")
            sent["bytes"] = Path(cmd[i + 1]).read_bytes()
            sent["name"] = Path(cmd[i + 1]).name
            return subprocess.CompletedProcess(cmd, 0, stdout="ok", stderr="")
        with patch.object(subprocess, "run", run):
            out = self.run_call("email.send", {
                "account": "studio", "to": "x@y.it", "subject": "s", "body": "b",
                "topic_files": ["files/contratto.pdf"]}, egress=["mailto:x@y.it"])
        self.assertFalse(out.startswith(("DENIED", "ERROR")), out)
        self.assertEqual((sent["bytes"], sent["name"]), (b"%PDF contratto", "contratto.pdf"))
        self.assertEqual(self.crossings, ["attachment"])

    def test_save_attachment_lands_untrusted_and_taints(self):
        from . import taint
        self.run_fake.answers["get-attachment"] = {
            "filename": "a/b.pdf", "content_type": "application/pdf",
            "data": base64.b64encode(b"%PDF ostile").decode()}
        out = self.run_call("email.save_attachment", {
            "account": "studio", "email_id": "7", "filename": "Tomato / NDA.pdf"})
        self.assertFalse(out.startswith(("DENIED", "ERROR")), out)
        r = json.loads(out)
        self.assertEqual((r["provenance"], r["tainted"], r["size"]),
                         ("untrusted", True, len(b"%PDF ostile")))
        self.assertEqual(self.svc.read_file("SEAL-2", "acme", r["topic_path"]),
                         b"%PDF ostile")
        # The sender's name is a NAME, not a path (#420).
        self.assertTrue(r["topic_path"].endswith("/Tomato - NDA.pdf"), r["topic_path"])
        self.assertTrue(taint.status("chan:SEAL-2:acme:clodia")["tainted"])

    def test_a_non_member_topic_is_refused(self):
        from . import main
        self.svc.new("SEAL-2", "altro", {"title": "altro", "owner": "davide",
                                         "participants": ["davide"]})
        self.svc.put_file("SEAL-2", "altro", "x.pdf", b"x", "agent", by="davide")
        member = main._topic_is_member
        p = patch.object(main, "_topic_is_member",
                         lambda meta, c: member(meta, c) and meta.get("title") != "altro")
        p.start()
        self.addCleanup(p.stop)
        out = self.run_call("email.send", {
            "account": "studio", "to": "x@y.it", "subject": "s", "body": "b",
            "topic_files": ["files/x.pdf"], "tier": "SEAL-2", "name": "altro"},
            egress=["mailto:x@y.it"])
        self.assertTrue(out.startswith("DENIED"), out)
        self.assertNotIn("send", self.ops())


@NEEDS_LOGIC
class LegacyTests(_CallPath, unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        d = self.base / "legacy-secrets"
        d.mkdir()
        (d / "email_config.json").write_text(json.dumps({"accounts": {"demo": {
            "email": "studio@example.it", "password": "x"}}}), encoding="utf-8")
        p = patch.dict(os.environ, {"CLODIA_SECRETS_DIR": str(d)})
        p.start()
        self.addCleanup(p.stop)

    def test_listed_and_refused_with_the_reason(self):
        out = json.loads(self.run_call("email.folders", {"account": "studio"}))
        self.assertIn("demo", out["available_accounts"])
        out = self.run_call("email.list", {"account": "demo"})
        self.assertTrue(out.startswith("DENIED"), out)
        self.assertIn("legacy", out)
        self.assertIn("vault", out)
        self.assertEqual(self.ops(), ["folders"])


@NEEDS_LOGIC
class FailClosedTests(_CallPath, unittest.TestCase):
    def test_without_the_component_every_verb_is_denied(self):
        from .components import loader
        loader.reset()
        for verb in EMAIL_VERBS:
            with self.subTest(verb=verb):
                out = self.run_call(verb, {"account": "studio", "email_id": "1",
                                           "to": "x@y.it", "subject": "s", "body": "b",
                                           "filename": "f", "query": "ALL"},
                                    egress=["mailto:x@y.it"])
                self.assertTrue(out.startswith("DENIED"), out)
        self.assertEqual(self.run_fake.calls, [])

    def test_the_component_failing_denies_with_the_reason(self):
        from .components import loader
        with patch.object(loader.trust, "refusal", lambda c, m: "refused for the test"):
            loader.reconcile(force=True)
        self.assertEqual(self.state()["status"], "refused")
        out = self.run_call("email.list", {"account": "studio"})
        self.assertTrue(out.startswith("DENIED"), out)
        self.assertIn("refused for the test", out)
        self.assertEqual(self.run_fake.calls, [])


# --------------------------------------------------------------------------
# Gmail: google-pack's component, through comms-pack's
# --------------------------------------------------------------------------

@NEEDS_LOGIC
class GmailTests(_CallPath, unittest.TestCase):
    BUNDLE = {"client_id": "CID", "client_secret": "CSECRET",  # gitleaks:allow
              "refresh_token": "RT-SECRET", "email": "devnull@gmail.com"}  # gitleaks:allow — fake test credential

    def setUp(self) -> None:
        super().setUp()
        from . import vault
        vault.deposit("google_devnull", dict(self.BUNDLE), cred_type="oauth2_google",
                      grant_agents=[])
        core = sys.modules[f"{GOOGLE_ROOT}.gmail_core"]
        probe = self.base / "probe_client.py"
        probe.write_text(
            "import json, os, sys\n"
            "d = os.environ['CLODIA_SECRETS_DIR']\n"
            "print(json.dumps({'argv': sys.argv[1:], 'files': sorted(os.listdir(d)),"
            " 'tokens': json.load(open(os.path.join(d, 'email_oauth_tokens.json')))}))\n")
        p = patch.object(core, "CLIENT", probe)
        p.start()
        self.addCleanup(p.stop)
        self.read_secret: list = []
        adapter = sys.modules[f"{MAIL_ROOT}._host"].vault
        real = adapter.read_internal

        def spy(name):
            out = real(name)
            self.read_secret.append((name, sorted(out)))
            return out
        p = patch.object(adapter, "read_internal", spy)
        p.start()
        self.addCleanup(p.stop)

    def test_a_google_account_runs_on_google_packs_component(self):
        out = self.run_call("email.folders", {"account": "devnull"},
                            ingress=("inbox:devnull@gmail.com",))
        self.assertFalse(out.startswith(("DENIED", "ERROR")), out)
        r = json.loads(out)["folders"]
        self.assertEqual(r["argv"], ["--account", "devnull", "folders"])
        self.assertEqual(r["files"], ["email_config.json", "email_oauth_tokens.json",
                                      "google_oauth_client.json"])
        self.assertEqual(r["tokens"], {"devnull": {"refresh_token": "RT-SECRET",  # gitleaks:allow
                                                   "email": "devnull@gmail.com"}})
        self.assertEqual(self.run_fake.calls, [])        # not the IMAP client
        # comms-pack saw the address of the Google account, never its secret.
        for name, keys in self.read_secret:
            if name.startswith("google_"):
                self.assertEqual(keys, ["email"])

    def test_the_mailbox_whitelist_applies_to_gmail_too(self):
        out = self.run_call("email.list", {"account": "devnull"})
        self.assertTrue(out.startswith("DENIED"), out)
        self.assertIn("inbox:devnull@gmail.com", out)

    def test_without_google_pack_a_google_account_is_not_served(self):
        self.position("pack", "native")                 # google-pack on standby
        out = self.run_call("email.folders", {"account": "devnull"},
                            ingress=("inbox:devnull@gmail.com",))
        self.assertTrue(out.startswith(("DENIED", "ERROR")), out)
        self.assertIn("google-pack", out)
        self.assertEqual(self.run_fake.calls, [])
        # IMAP is unaffected.
        out = self.run_call("email.folders", {"account": "studio"})
        self.assertFalse(out.startswith(("DENIED", "ERROR")), out)

    def test_mail_exec_takes_attachments_only(self):
        core = sys.modules[f"{GOOGLE_ROOT}.gmail_accounts"]
        for files in ({"secrets/email_config.json": "e30="}, {"x": "e30="}):
            with self.subTest(files=list(files)):
                with self.assertRaises(Exception):
                    core.mail_exec({"account": "devnull", "argv": ["folders"],
                                    "files": files})


# --------------------------------------------------------------------------
# the mailbox routes and the Tools card
# --------------------------------------------------------------------------

class _Req:
    def __init__(self, method="GET", body=None, account=None):
        self.method = method
        self.headers = {}
        self._body = body if body is not None else {}
        self.path_params = {"account": account} if account else {}

    async def json(self):
        return self._body


@NEEDS_LOGIC
class RouteTests(_OnComponent, unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        from . import tools_api
        for p in (patch.object(tools_api, "_authorized", lambda _r: True),
                  patch.object(tools_api, "_connector_guard", lambda _c: None)):
            p.start()
            self.addCleanup(p.stop)

    def test_add_list_remove_through_the_component(self):
        from . import tools_api, vault
        from . import whitelist as wl
        r = asyncio.run(tools_api.email_mailbox_add(_Req("POST", {
            "account": "Info", "email": "info@x.it", "password": "p",
            "smtp_server": "smtp.x.it"})))
        self.assertEqual((r.status_code, json.loads(r.body)),
                         (200, {"account": "info", "connected": True}))
        self.assertEqual(vault.read_internal("mailbox_info"), {
            "email": "info@x.it", "password": "p", "smtp_server": "smtp.x.it",
            "smtp_port": 587})
        self.assertEqual(vault.credential_type("mailbox_info"), "mailbox")
        r = asyncio.run(tools_api.email_mailbox_add(_Req("POST", {"account": "x"})))
        self.assertEqual(r.status_code, 400)
        r = asyncio.run(tools_api.email_mailboxes(_Req()))
        self.assertEqual(json.loads(r.body)["mailboxes"], ["info"])
        cfg = {"egress_allow": ["outbox:info@x.it"], "source_allow": ["inbox:info@x.it"],
               "scope_egress_allow": {}, "scope_source_allow": {}, "agents": {}}
        with patch.object(wl, "CONFIG", cfg), patch.object(wl, "save_config", lambda: None):
            r = asyncio.run(tools_api.email_mailbox_remove(_Req("DELETE", account="info")))
            body = json.loads(r.body)
            self.assertEqual((body["removed"], body["email"]), (True, "info@x.it"))
            self.assertEqual((cfg["egress_allow"], cfg["source_allow"]), ([], []))
        self.assertFalse(vault.has_credential("mailbox_info"))

    def test_without_the_component_the_routes_fail_closed(self):
        from . import tools_api
        from .components import loader
        loader.reset()
        for coro in (tools_api.email_mailboxes(_Req()),
                     tools_api.email_mailbox_add(_Req("POST", {"account": "x"})),
                     tools_api.email_mailbox_remove(_Req("DELETE", account="x"))):
            r = asyncio.run(coro)
            self.assertEqual(r.status_code, 503)
            self.assertIn("comms-pack", json.loads(r.body)["detail"])
        self.assertFalse(tools_api._test_connector("mailboxes")["ok"])
        card = [c for c in tools_api.connectors_snapshot() if c["id"] == "mailboxes"][0]
        self.assertFalse(card["operational"])
        self.assertEqual(card["issues"][-1]["error"], "component_unavailable")

    def test_the_tools_card_test_is_the_components(self):
        from . import tools_api
        self.assertEqual(tools_api._test_connector("mailboxes"),
                         {"ok": None, "detail": "nessuna casella configurata"})


# --------------------------------------------------------------------------
# end to end: the bundled client really runs, on the component's credential
# --------------------------------------------------------------------------

class _Provider(BaseHTTPRequestHandler):
    received: list = []

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        type(self).received.append(json.loads(self.rfile.read(n)))
        body = b'{"data": {"failed": 0}}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # silence
        pass


@NEEDS_LOGIC
class EndToEndSendTests(_OnComponent, unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        from . import vault
        from . import whitelist as wl
        _Provider.received = []
        self.http = HTTPServer(("127.0.0.1", 0), _Provider)
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        self.addCleanup(self.http.server_close)
        self.addCleanup(self.http.shutdown)
        vault.deposit("mailbox_studio", {
            "email": "studio@example.it", "smtp_server": "smtp.invalid",
            "smtp_port": 587, "password": "pw", "smtp_backend": "api",
            "api_url": f"http://127.0.0.1:{self.http.server_port}/send",
            "api_key": "k-123"}, cred_type="mailbox", grant_agents=[])
        self.config = {"egress_allow": ["outbox:studio@example.it"],
                       "scope_egress_allow": {}, "source_allow": [],
                       "scope_source_allow": {}, "agents": {}}
        for p in (patch.object(self.mail, "tool_allowed", lambda *a, **k: None),
                  patch.object(wl, "CONFIG", self.config)):
            p.start()
            self.addCleanup(p.stop)
        self.att = Path(tempfile.mkdtemp()) / "offerta.pdf"
        self.addCleanup(shutil.rmtree, self.att.parent, True)
        self.att.write_bytes(b"%PDF-1.4 offerta")

    def test_the_client_runs_on_the_mailbox_and_attachment(self):
        out = self.mail.send("dest@example.org", "Offerta", "in allegato",
                             account="studio", attachments=[str(self.att)])
        self.assertTrue(out["ok"])
        [payload] = _Provider.received
        self.assertEqual(payload["sender"], "studio@example.it")
        self.assertEqual(payload["to"], ["dest@example.org"])
        self.assertEqual(payload["api_key"], "k-123")
        [allegato] = payload["attachments"]
        self.assertEqual(allegato["filename"], "offerta.pdf")
        self.assertEqual(base64.b64decode(allegato["fileblob"]), b"%PDF-1.4 offerta")

    def test_a_mailbox_not_in_the_outbox_list_never_reaches_the_client(self):
        self.config["egress_allow"] = []
        with self.assertRaises(PermissionError):
            self.mail.send("dest@example.org", "s", "b", account="studio")
        self.assertEqual(_Provider.received, [])

    def test_the_clients_failure_comes_back_as_the_verbs(self):
        self.http.shutdown()
        self.http.server_close()
        with self.assertRaises(RuntimeError) as e:
            self.mail.send("dest@example.org", "s", "b", account="studio")
        self.assertIn("email send failed", str(e.exception))

    def test_no_bytecode_lands_next_to_the_pinned_component(self):
        from .components import store
        self.mail.send("dest@example.org", "s", "b", account="studio")
        pin = store.pin_of(COMMS, "comms")
        self.assertEqual(list(pin.dir.rglob("__pycache__")), [])
        self.assertEqual(store.verify(pin), "")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

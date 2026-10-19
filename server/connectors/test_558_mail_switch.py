"""#558: mail is comms-pack's component's (the switch is retired, #526).

With a STAND-IN component in the loader (no clodia-logic needed; the real
component is `server/test_558_mail_component.py`):

1. comms-pack's `mail` connector is the one the PDP reads, whatever the
   profile says; the `mailbox_` vault scope is comms-pack's component's;
2. the eight verbs LEAVE the native catalogue and dispatch (they are no longer
   gateway-retained, #523's design is superseded) and reach the component's
   handlers through `call_tool`;
3. `email.reply`'s recipient: the caller's `to` is never kept, only the
   component's `pdp_arguments`;
4. fail closed: no component → every `email.*` verb DENIED, the native client
   refuses (`NativeDisabled`), the mailbox routes answer 503, the option set
   and the Tools card are empty, a configuration warning says why;
5. a profile still saying `native` changes nothing.
"""
from __future__ import annotations

import asyncio
import copy
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import yaml

from .. import instance_profile, proxy
from ..components import loader, trust
from ..components.grammar import GatewayComponent
from ..components.host import ServiceSpec, VerbSpec
from ..tools import mail_switch
from . import builtin as B
from . import first_party_fixture as _FP
from . import resolved

PACK = "comms-pack"
EMAIL_VERBS = ("email.send", "email.folders", "email.list", "email.read",
               "email.get_attachment", "email.save_attachment", "email.search",
               "email.reply")
#: The eight verbs as comms-pack's component registers them: the properties
#: matter (the PDP keeps a caller argument only if the schema offers it), the
#: descriptions do not. The gateway's own copy went with the native code (#523).
_PROPS = {
    "email.send": ("to", "subject", "body", "account", "cc", "attachments",
                   "topic_files", "tier", "name"),
    "email.folders": ("account",),
    "email.list": ("account", "folder", "limit"),
    "email.read": ("email_id", "account", "folder"),
    "email.get_attachment": ("email_id", "filename", "account", "folder"),
    "email.save_attachment": ("email_id", "filename", "dest", "tier", "name",
                              "account", "folder"),
    "email.search": ("query", "account", "folder", "limit"),
    "email.reply": ("email_id", "body", "account", "folder", "cc", "attachments"),
}


def _tool(name: str):
    from mcp.types import Tool
    return Tool(name=name, description=name, inputSchema={
        "type": "object", "properties": {p: {} for p in _PROPS[name]}})


_EMAIL_TOOLS = [_tool(n) for n in _PROPS]

#: Verbs with no egress/source mapping and no taint row (`unmapped:`).
UNMAPPED = ["email.folders", "email.save_attachment"]


def _mail_connector() -> dict:
    """comms-pack 2.x's `mail` connector: the builtin vocabulary, verbatim,
    plus what a PACK must add — `forms:` on the mailbox schemes (a topic action
    writes into them), the `imap` provider (no transport: the code is the
    component's) and `unmapped:` (a component verb must be classified)."""
    doc = yaml.safe_load((_FP.FORMER_BUILTIN / "mail.yaml").read_text(encoding="utf-8"))
    entry = copy.deepcopy(doc["connectors"][0])
    forma = [{"label": "address", "pattern": r"^[^@\s]+@[A-Za-z0-9.-]+$",
              "example": "studio@example.org"}]
    for s in entry["schemes"]:
        if s["scheme"] in ("inbox", "outbox"):
            s["forms"] = forma
    entry["providers"] = [{"id": "imap", "label": "IMAP/SMTP"}]
    entry["unmapped"] = list(UNMAPPED)
    return entry


def _comms_pack() -> dict:
    return {"name": PACK, "connectors": [_mail_connector()]}


class _FakeComponent:
    """A stand-in for comms-pack's gateway component in the loader: the eight
    verbs (native schemas) and services that record what the gateway asks."""

    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.recipient = "mario@x.it"

    def _fn(self, name, answer):
        def fn(*args):
            self.calls.append((name, *args))
            return answer(*args) if callable(answer) else answer
        return fn

    def state(self) -> loader.State:
        from .. import main
        comp = GatewayComponent(
            pack=PACK, id="mail", repo="r-clodia/clodia-logic",
            path="catalogs/packs/comms-pack/gateway", ref="main",
            entry="mail_component", connectors=("mail",), credentials=("mailbox_",),
            namespaces={"mail": "email"})
        verbs = {t.name: VerbSpec(component=comp.key, pack=PACK, namespace="email",
                                  tool=t, handler=self._fn(t.name, {"from": "component"}),
                                  offload=False)
                 for t in _EMAIL_TOOLS}
        answers = {
            "pdp_arguments": lambda verb, a: (
                {"to": self.recipient, "cc": "ignored@x.it"}
                if verb == "email.reply" else {}),
            "diagnostics": [{"credential": "mailbox_studio", "account": "studio",
                             "kind": "mailbox", "operational": True, "send_only": False,
                             "missing": [], "error": None}],
            "system_mailboxes": [{"account": "studio", "email": "studio@x.it",
                                  "send_only": False}],
            "mailbox_address": lambda a: "studio@x.it",
            "mailboxes_list": {"mailboxes": ["studio"], "statuses": []},
            "mailbox_add": lambda body: {"status": 200,
                                         "body": {"account": body.get("account"),
                                                  "connected": True}},
            "mailbox_remove": lambda a: {"removed": True, "email": "studio@x.it"},
            "test_mailboxes": {"ok": True, "detail": "component"},
        }
        services = {n: ServiceSpec(component=comp.key, pack=PACK, name=n,
                                   handler=self._fn(n, a)) for n, a in answers.items()}
        return loader.State(component=comp, status="loaded", commit="d" * 40,
                            verbs=verbs, services=services)


class _MailIstanza:
    COMPONENT = True
    MAIL = "pack"

    def setUp(self) -> None:  # noqa: D401
        super().setUp()
        self.addCleanup(self._ricarica)
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        d = self.dir / "packs" / PACK
        d.mkdir(parents=True)
        (d / "pack.yaml").write_text(json.dumps(_comms_pack()), encoding="utf-8")
        for p in (patch.dict(os.environ, {"CLODIA_DATA": str(self.dir)}),
                  patch.object(resolved, "_DATA", self.dir),
                  patch.object(resolved, "_first_seen_path",
                               lambda: self.dir / "first-seen.json"),
                  patch.dict(proxy.CONFIG, {"mcp_backends": []})):
            p.start()
            self.addCleanup(p.stop)
        self.component = _FakeComponent()
        self.addCleanup(loader.reset)
        loader.reset()
        if self.COMPONENT:
            loader._STATES[f"{PACK}/mail"] = self.component.state()
        self.posizione(self.MAIL)

    def _ricarica(self) -> None:
        instance_profile.load(force=True)
        resolved.invalidate()

    def posizione(self, mail: str | None) -> None:
        righe = ["edition: full"] + (["connectors:", f"  mail: {mail}"] if mail else [])
        (self.dir / "profile.yaml").write_text("\n".join(righe) + "\n", encoding="utf-8")
        self._ricarica()


class _Istanza(_MailIstanza, unittest.TestCase):
    pass


def _call(name: str, args: dict, *, egress=()) -> str:
    from .. import main
    from .. import whitelist as wl
    from ..claims import ClaimsContext
    token = {"agent": "clodia", "execution_id": "clodia-558ms", "principal": "davide",
             "chat": "chan:SEAL-2:acme:clodia"}
    cfg = {"agents": {"clodia": {"allowed_tools": ["*"]}},
           "egress_allow": list(egress)}

    async def go():
        with ClaimsContext(token, "t"), \
                patch.object(main, "_require_gate_consent", AsyncMock(return_value={})), \
                patch.object(wl, "CONFIG", cfg), \
                patch.dict(os.environ, {"CLODIA_EGRESS_ENFORCE": "on"}):
            return await main.call_tool(name, args)
    return asyncio.run(go())[0].text


# --------------------------------------------------------------------------
# 1. the switch
# --------------------------------------------------------------------------
class SwitchTests(_Istanza):
    def test_the_packs_connector_is_the_one_that_counts(self):
        mail = resolved.registry().by_id("mail")
        self.assertEqual((mail.pack, mail.builtin, mail.namespace), (PACK, False, "email"))
        self.assertNotIn("gateway-mail", B.manifests())
        self.assertTrue(resolved.held_by_pack("email"))
        self.assertEqual(sorted(v for v in resolved.registry().unmapped_verbs()
                                if v.startswith("email.")), UNMAPPED)

    def test_a_profile_saying_native_changes_nothing(self):
        for pos in ("native", None):
            with self.subTest(posizione=pos):
                self.posizione(pos)
                mail = resolved.registry().by_id("mail")
                self.assertEqual((mail.pack, mail.builtin), (PACK, False))

    def test_the_mailbox_scope_is_comms_packs(self):
        comp = self.component.state().component
        self.assertEqual(B.CORE_CREDENTIALS_FOLLOW["mailbox_"], "mail")
        self.posizione("native")                 # ignored
        self.assertEqual(trust.credential_problem(comp, "mailbox_"), "")
        import dataclasses
        other = dataclasses.replace(comp, pack="google-pack")
        self.assertTrue(trust.credential_problem(other, "mailbox_"))

    def test_released_frees_the_namespace_and_no_vault_prefix(self):
        namespaces, prefixes = B.released()
        self.assertIn("email", namespaces)
        self.assertNotIn("mailbox_", prefixes)       # custody stays the gateway's


# --------------------------------------------------------------------------
# 2. the verbs move to the component
# --------------------------------------------------------------------------
class TheVerbsMoveToTheComponentTests(_Istanza):
    def test_they_are_not_in_the_native_catalogue(self):
        from .. import main
        from . import manifest as M
        natives = {t.name for t in main._all_native_tools()}
        for verb in EMAIL_VERBS:
            with self.subTest(verb=verb):
                self.assertNotIn(verb, natives)
                self.assertNotIn(verb, main._GATEWAY_RETAINED_VERBS)
                self.assertTrue(main._is_packaged_verb(verb))
                self.assertIsNotNone(main._component_verb(verb))
                self.assertTrue(main._verb_implemented(verb))
        self.assertNotIn("email", M.core_namespaces())
        self.assertEqual(main._EMAIL_VERB_NAMES, frozenset(EMAIL_VERBS))

    def test_a_profile_saying_native_still_hands_them_to_the_component(self):
        from .. import main
        from . import manifest as M
        self.posizione("native")
        for verb in EMAIL_VERBS:
            with self.subTest(verb=verb):
                self.assertTrue(main._is_packaged_verb(verb))
                self.assertIsNotNone(main._component_verb(verb))
        self.assertNotIn("email", M.core_namespaces())

    def test_a_call_runs_the_components_handler_not_the_native(self):
        out = _call("email.folders", {"account": "studio"})
        self.assertEqual(json.loads(out), {"from": "component"})
        self.assertEqual(self.component.calls[-1][0], "email.folders")

    def test_the_egress_pdp_judges_before_the_handler(self):
        out = _call("email.send", {"to": "x@y.it", "subject": "s", "body": "b"})
        self.assertTrue(out.startswith("DENIED"), out)
        self.assertNotIn("email.send", [c[0] for c in self.component.calls])
        out = _call("email.send", {"to": "x@y.it", "subject": "s", "body": "b"},
                    egress=["mailto:x@y.it"])
        self.assertEqual(json.loads(out), {"from": "component"})


# --------------------------------------------------------------------------
# 3. the reply recipient
# --------------------------------------------------------------------------
class ReplyRecipientTests(_Istanza):
    def test_the_callers_to_is_never_kept(self):
        from .. import main
        spec = main._component_verb("email.reply")
        out = main._component_pdp_arguments(spec, "email.reply", {
            "email_id": "7", "body": "b", "to": "friend@ok.it", "bcc": "x@ok.it",
            "cc": "boss@ok.it"})
        # `to` is the component's; `bcc` is not in the schema → dropped; `cc`
        # IS offered by the schema → the caller's, and the service cannot
        # rewrite it.
        self.assertEqual(out["to"], "mario@x.it")
        self.assertNotIn("bcc", out)
        self.assertEqual(out["cc"], "boss@ok.it")

    def test_through_call_tool(self):
        out = _call("email.reply", {"email_id": "7", "body": "b", "to": "friend@ok.it"},
                    egress=["mailto:friend@ok.it"])
        self.assertTrue(out.startswith("DENIED"), out)
        self.assertNotIn("email.reply", [c[0] for c in self.component.calls])
        out = _call("email.reply", {"email_id": "7", "body": "b"},
                    egress=["mailto:mario@x.it"])
        self.assertEqual(json.loads(out), {"from": "component"})

    def test_an_empty_answer_is_an_unknown_destination(self):
        self.component.recipient = ""
        out = _call("email.reply", {"email_id": "7", "body": "b"},
                    egress=["mailto:mario@x.it"])
        self.assertTrue(out.startswith("DENIED"), out)


# --------------------------------------------------------------------------
# 4. fail closed
# --------------------------------------------------------------------------
class FailClosedTests(_Istanza):
    COMPONENT = False

    def test_every_email_verb_is_denied(self):
        if True:
            for verb in EMAIL_VERBS:
                with self.subTest(verb=verb):
                    out = _call(verb, {"to": "x@y.it", "subject": "s", "body": "b",
                                       "email_id": "1", "filename": "f", "query": "q"},
                                egress=["mailto:x@y.it"])
                    self.assertTrue(out.startswith("DENIED"), out)
                    self.assertIn("gateway component", out)

    def test_the_mailbox_routes_answer_503(self):
        from .. import tools_api

        class _Req:
            method, headers, path_params = "GET", {}, {"account": "studio"}

            async def json(self):
                return {"account": "x"}
        with patch.object(tools_api, "_authorized", lambda _r: True), \
                patch.object(tools_api, "_connector_guard", lambda _c: None):
            for fn in (tools_api.email_mailboxes, tools_api.email_mailbox_add,
                       tools_api.email_mailbox_remove):
                with self.subTest(route=fn.__name__):
                    r = asyncio.run(fn(_Req()))
                    self.assertEqual(r.status_code, 503)
                    self.assertIn("comms-pack", json.loads(r.body)["detail"])

    def test_listings_are_empty_and_say_why(self):
        from .. import main, tools_api
        from . import actions
        # The Google card still reads the gateway's diagnostics (Google's
        # custody follows the `google` switch): a native mailbox row there
        # must not reach the MAILBOX card on `mail: pack`.
        nativa = [{"credential": "mailbox_nativa", "account": "nativa",
                   "kind": "mailbox", "operational": True, "send_only": False,
                   "missing": [], "error": None}]
        with patch("server.tools.credential_diag.credential_diagnostics",
                   return_value=nativa):
            self.assertEqual(mail_switch.system_mailboxes(), [])
            self.assertEqual(mail_switch.credential_diagnostics(), [])
            self.assertEqual(actions._mailbox_options(), [])
            self.assertFalse(tools_api._test_connector("mailboxes")["ok"])
            card = [c for c in tools_api.connectors_snapshot()
                    if c["id"] == "mail"][0]
            self.assertEqual(card["accounts"], [])
            self.assertFalse(card["operational"])
            self.assertEqual(card["issues"][-1]["error"], "component_unavailable")
            warnings = main.runtime_configuration_warnings()
        self.assertFalse(any("mailbox_nativa" in w for w in warnings), warnings)
        self.assertTrue(any("comms-pack" in w for w in warnings), warnings)


# --------------------------------------------------------------------------
# 5. the gateway's own code asks the side in charge
# --------------------------------------------------------------------------
class LookupsAskTheComponentTests(_Istanza):
    def test_the_component_is_asked(self):
        from . import actions
        self.assertEqual(mail_switch.system_mailboxes(),
                         [{"account": "studio", "email": "studio@x.it",
                           "send_only": False}])
        self.assertEqual([o["values"]["address"] for o in actions._mailbox_options()],
                         ["studio@x.it"])
        self.assertEqual(mail_switch.component_test_mailboxes(),
                         {"ok": True, "detail": "component"})

    def test_the_remove_route_withdraws_the_whitelist_entries_itself(self):
        from .. import tools_api
        from .. import whitelist as wl
        cfg = {"egress_allow": ["outbox:studio@x.it"], "source_allow": ["inbox:studio@x.it"],
               "scope_egress_allow": {}, "scope_source_allow": {}, "agents": {}}

        class _Req:
            method, headers, path_params = "DELETE", {}, {"account": "studio"}
        with patch.object(tools_api, "_authorized", lambda _r: True), \
                patch.object(wl, "CONFIG", cfg), patch.object(wl, "save_config", lambda: None), \
                patch.object(tools_api.vault, "remove",
                             side_effect=AssertionError("the component removes")):
            r = asyncio.run(tools_api.email_mailbox_remove(_Req()))
        body = json.loads(r.body)
        self.assertEqual((body["removed"], body["email"]), (True, "studio@x.it"))
        self.assertEqual((cfg["egress_allow"], cfg["source_allow"]), ([], []))
        self.assertIn(("mailbox_remove", "studio"), self.component.calls)

    def test_a_profile_saying_native_still_asks_the_component(self):
        self.posizione("native")
        self.assertEqual(mail_switch.system_mailboxes(),
                         [{"account": "studio", "email": "studio@x.it",
                           "send_only": False}])


# --------------------------------------------------------------------------
# 6. the retired transport stays the gateway's
# --------------------------------------------------------------------------
class RetiredTransportTests(_Istanza):
    """comms-pack 2.0.0 no longer declares `mail-transport`, but an Update does
    not unmount it: the agent-server copies the new plugin over the old one
    (the old `mail_transport_mcp.py` stays) and mounts what is declared. A
    raw mail client nobody declares any more must not become an agent verb."""

    def _mounts(self, *backends):
        p = patch.dict(proxy.CONFIG, {"mcp_backends": list(backends)})
        p.start()
        self.addCleanup(p.stop)
        resolved.invalidate()

    def test_the_packs_own_stale_mount_stays_internal(self):
        from .. import main
        self._mounts({"name": "mail-transport", "transport": "stdio",
                      "command": "/bin/false", "pack": PACK})
        self.assertTrue(resolved.is_transport_backend("mail-transport.run"))
        with patch.object(proxy, "is_proxied", lambda n: True):
            out = _call("mail-transport.run", {"argv": ["send"], "files": {}})
        self.assertTrue(out.startswith("DENIED"), out)
        self.assertIsNotNone(main)

    def test_only_the_pack_that_stamped_it(self):
        for b in ({"name": "mail-transport", "transport": "stdio",
                   "command": "/bin/false"},
                  {"name": "mail-transport", "transport": "stdio",
                   "command": "/bin/false", "pack": "it-pack"}):
            with self.subTest(backend=b):
                self._mounts(b)
                self.assertFalse(resolved.is_transport_backend("mail-transport.run"))

    def test_the_table(self):
        self.assertEqual(B.RETIRED_TRANSPORTS["comms-pack"], frozenset({"mail-transport"}))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


def setUpModule() -> None:
    # google-pack and it-pack as on every instance (#526); comms-pack is this
    # module's own (`_MailIstanza` writes it).
    _FP.install(without=("comms-pack",))


def tearDownModule() -> None:
    _FP.uninstall()

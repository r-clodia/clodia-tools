"""#523: the provider `transport:` grammar, as comms-pack 1.4.0 used it.

clodia-platform#523 moved the mail TRANSPORT into comms-pack (backend
`mail-transport`). #558 superseded that design: since comms-pack 2.0.0 the
mail code is the pack's GATEWAY COMPONENT (`test_558_mail_switch.py`,
`test_558_mail_component.py`) and the backend is gone. What stays pinned here:

1. the grammar (`transport:` parsed, refused in a builtin manifest) — a
   generic mechanism (it-pack's images use it), and comms-pack 1.4.0's
   manifest must stay VALID on a gateway that is updated before the pack;
2. the resolution (`transport_for` only from a held connector of the pack the
   connector belongs to, only on the pack's own backend), and the backend
   being the gateway's (hidden, denied to every caller);
3. the PDP's answers about mail from comms-pack's connector, pinned (the
   parity with the former builtin was the acceptance of #522/#523);
4. fail closed: no held connector → `email.*` DENIED.

The suites of #503/#461/#420/#428 run against the REAL component in
`server/test_558_mail_component.py`. Since #526 the `native|pack` switch is
retired: a profile still saying `native` changes nothing.
"""
from __future__ import annotations

import base64
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from .. import egress, instance_profile, proxy, taint
from . import builtin as B
from . import first_party_fixture as _FP
from . import manifest as M
from . import resolved

BACKEND = "mail-transport"
TOOL = "run"
PACK = "comms-pack"


def _mail_connector() -> dict:
    """comms-pack 1.4.0's `mail` connector: the builtin vocabulary, verbatim,
    plus what a PACK must add — `forms:` on the mailbox schemes — and the
    IMAP/SMTP provider WITH its transport (the #523 design)."""
    doc = yaml.safe_load((_FP.FORMER_BUILTIN / "mail.yaml").read_text(encoding="utf-8"))
    entry = copy.deepcopy(doc["connectors"][0])
    forma = [{"label": "address", "pattern": r"^[^@\s]+@[A-Za-z0-9.-]+$",
              "example": "studio@example.org"}]
    for s in entry["schemes"]:
        if s["scheme"] in ("inbox", "outbox"):
            s["forms"] = forma
    entry["providers"] = [{"id": "imap", "label": "IMAP/SMTP",
                           "transport": {"backend": BACKEND, "tool": TOOL}}]
    return entry


def _comms_pack(**muta) -> dict:
    entry = _mail_connector()
    entry.update(muta)
    return {"name": PACK, "connectors": [entry]}


def _backend(pack: str | None = PACK, name: str = BACKEND) -> dict:
    b = {"name": name, "transport": "stdio", "command": "/bin/false"}
    if pack:
        b["pack"] = pack
    return b


class _MailIstanza:
    """A fake instance with comms-pack installed and its transport mounted.

    Mixin, so that the suites of #503/#461/#420/#428 can be run again in
    `pack` position by subclassing them (`setUp` of the original first). The
    switch is turned by writing `profile.yaml` for real, as in test_522.
    """

    POSIZIONE = "pack"

    def setUp(self) -> None:  # noqa: D401 — unittest hook
        super().setUp()
        # FIRST cleanup registered here = run after our patches are undone:
        # profile and registry re-read on the real environment, or the rest of
        # the suite would run with mail handed to a pack.
        self.addCleanup(self._ricarica)
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.scrivi_pack(_comms_pack())
        for p in (patch.dict(os.environ, {"CLODIA_DATA": str(self.dir)}),
                  patch.object(resolved, "_DATA", self.dir),
                  patch.object(resolved, "_first_seen_path",
                               lambda: self.dir / "first-seen.json"),
                  patch.dict(proxy.CONFIG, {"mcp_backends": [_backend()]})):
            p.start()
            self.addCleanup(p.stop)
        self.transport_calls: list[dict] = []
        fake = patch.object(proxy, "call_backend_tool_sync", self._fake_transport)
        fake.start()
        self.addCleanup(fake.stop)
        self.posizione(self.POSIZIONE)

    def scrivi_pack(self, doc: dict) -> None:
        pack = self.dir / "packs" / PACK
        pack.mkdir(parents=True, exist_ok=True)
        (pack / "pack.yaml").write_text(json.dumps(doc), encoding="utf-8")
        resolved.invalidate()

    def _ricarica(self) -> None:
        instance_profile.load(force=True)
        resolved.invalidate()

    def posizione(self, mail: str | None, **altri: str) -> None:
        righe = ["edition: full"]
        modi = {**({"mail": mail} if mail else {}), **altri}
        if modi:
            righe.append("connectors:")
            righe += [f"  {k}: {v}" for k, v in modi.items()]
        (self.dir / "profile.yaml").write_text("\n".join(righe) + "\n",
                                               encoding="utf-8")
        self._ricarica()

    def _fake_transport(self, backend: str, tool: str, arguments: dict,
                        timeout: float) -> str:
        """The pack's transport, faithfully: files on disk, `{dir}` resolved,
        the same vendored client, the same answer shape."""
        self.transport_calls.append({"backend": backend, "tool": tool,
                                     "arguments": arguments, "timeout": timeout})
        # The mail transport is retired (comms-pack ≥ 2.0.0) and the native
        # client it used to run is gone (#523): nothing may reach it.
        raise AssertionError("the retired mail transport was called")


class _Istanza(_MailIstanza, unittest.TestCase):
    pass


# --------------------------------------------------------------------------
# 1. grammar
# --------------------------------------------------------------------------
class GrammarTests(unittest.TestCase):
    def _parse(self, provider: dict, *, builtin: bool = False) -> M.Connector:
        entry = _mail_connector()
        entry["providers"] = [provider]
        return M.parse_connector(entry, pack="gateway-mail" if builtin else PACK,
                                 reserved=(), builtin=builtin)

    def test_the_transport_is_parsed(self):
        c = self._parse({"id": "imap", "transport": {"backend": BACKEND, "tool": TOOL}})
        self.assertEqual(c.providers[0].transport, M.Transport(BACKEND, TOOL))

    def test_it_is_optional(self):
        self.assertIsNone(self._parse({"id": "imap"}).providers[0].transport)

    def test_a_builtin_manifest_may_not_declare_one(self):
        """The gateway's own manifest describes in-process code: a transport
        there would route a native verb's credentials to whatever is mounted
        under that name."""
        with self.assertRaises(M.ManifestError) as e:
            self._parse({"id": "imap", "transport": {"backend": BACKEND, "tool": TOOL}},
                        builtin=True)
        self.assertIn("transport", str(e.exception))

    def test_no_builtin_manifest_declares_one(self):
        for nome, doc in B._all().items():
            for entry in doc.get("connectors") or []:
                for p in entry.get("providers") or []:
                    with self.subTest(pack=nome, connettore=entry.get("id")):
                        self.assertNotIn("transport", p)

    def test_names_only(self):
        """A backend is NAMED, never described: a command or a URL here would
        be a second, unreviewed way to mount a process."""
        for t in ({"backend": BACKEND},
                  {"tool": TOOL},
                  {"backend": "Mail Transport", "tool": TOOL},
                  {"backend": BACKEND, "tool": "run; rm"},
                  {"backend": BACKEND, "tool": TOOL, "command": "/bin/sh"},
                  "mail-transport.run"):
            with self.subTest(transport=t):
                with self.assertRaises(M.ManifestError):
                    self._parse({"id": "imap", "transport": t})


# --------------------------------------------------------------------------
# 2. resolution
# --------------------------------------------------------------------------
class TransportResolutionTests(_Istanza):
    def test_in_pack_position_the_held_connector_names_it(self):
        self.assertEqual(resolved.transport_for("mail"), (BACKEND, TOOL))

    def test_a_profile_saying_native_changes_nothing(self):
        for pos in ("native", None):
            with self.subTest(posizione=pos):
                self.posizione(pos)
                self.assertEqual(resolved.transport_for("mail"), (BACKEND, TOOL))

    def test_without_the_pack_there_is_none(self):
        (self.dir / "packs" / PACK / "pack.yaml").unlink()
        resolved.invalidate()
        self.assertIsNone(resolved.transport_for("mail"))

    def test_a_refused_connector_has_no_say(self):
        self.scrivi_pack(_comms_pack(context=[{"arg": "agent", "value": "bogus"}]))
        self.assertFalse(resolved.held_by_pack("email"))
        self.assertIsNone(resolved.transport_for("mail"))

    def test_a_backend_the_pack_did_not_mount_is_not_used(self):
        """The gateway hands the transport one mailbox's credential: a manifest
        naming somebody else's backend would have it delivered there."""
        for b in (_backend(pack=None), _backend(pack="it-pack")):
            with self.subTest(backend=b), \
                    patch.dict(proxy.CONFIG, {"mcp_backends": [b]}):
                resolved.invalidate()
                self.assertIsNone(resolved.transport_for("mail"))

    def test_no_provider_with_a_transport_means_none(self):
        self.scrivi_pack(_comms_pack(providers=[{"id": "imap"}]))
        self.assertIsNotNone(resolved.registry().by_id("mail"))
        self.assertIsNone(resolved.transport_for("mail"))

    def test_the_backend_is_a_transport_in_both_positions(self):
        """Hidden whatever the switch says: in `native` the pack's connector is
        refused for collision, but its backend may be mounted and is no less
        raw for that."""
        for pos in ("pack", "native"):
            with self.subTest(posizione=pos):
                self.posizione(pos)
                self.assertEqual(resolved.transport_backends(),
                                 frozenset({resolved.norm_name(BACKEND)}))
                self.assertTrue(resolved.is_transport_backend(f"{BACKEND}.{TOOL}"))
                self.assertFalse(resolved.is_transport_backend("github.get_file"))

    def test_a_pack_cannot_hide_a_neighbours_backend(self):
        with patch.dict(proxy.CONFIG, {"mcp_backends": [_backend(pack="it-pack")]}):
            resolved.invalidate()
            self.assertEqual(resolved.transport_backends(), frozenset())


# --------------------------------------------------------------------------
# 3. served by the gateway in pack position, and parity
# --------------------------------------------------------------------------
EMAIL_VERBS = ("email.send", "email.folders", "email.list", "email.read",
               "email.get_attachment", "email.save_attachment", "email.search",
               "email.reply")


def _risposte() -> dict:
    """The PDP's public answers about mail, as test_522 asks them."""
    def grantable(direzione: str, uri: str) -> bool:
        try:
            egress.check_grantable(direzione, uri)
        except ValueError:
            return False
        return True

    args = {"to": "A@Example.it; b@example.it", "cc": "c@example.it",
            "bcc": "", "subject": "s", "body": "b"}
    out: dict = {
        "forme": {f"{d}:{u}": grantable(d, u) for d, u in (
            ("egress", "mailto:a@example.it"), ("egress", "outbox:studio@example.it"),
            ("ingress", "inbox:studio@example.it"),
            ("ingress", "mailfrom:a@example.it"))},
        "danger": egress.danger_note("mailto:a@example.it"),
        "taint": {v: taint.taints(v) for v in EMAIL_VERBS},
        "fonte": resolved.source_uri("email.read", {}, {"from": "Mario <M@X.it>"}),
        "schemi": (tuple(resolved.registry().scheme_names("egress")),
                   tuple(resolved.registry().scheme_names("source"))),
    }
    for verbo in EMAIL_VERBS:
        spec = egress.spec_for(verbo)
        out[f"spec:{verbo}"] = None if spec is None else (spec[0], tuple(spec[1](args)))
    mail = resolved.registry().by_id("mail")
    if mail is not None:
        a = next(a for a in mail.topic_actions if a.id == "mailbox-link")
        out["azione"] = (a.admin_only, a.binding,
                         tuple(t.format(address="x@y.it") for t in a.adds_ingress),
                         tuple(t.format(address="x@y.it") for t in a.adds_egress))
    return out


class AnswersTests(_Istanza):
    def test_the_answers_are_pinned(self):
        for pos in ("native", "pack"):           # the profile changes nothing
            with self.subTest(posizione=pos):
                self.posizione(pos)
                r = _risposte()
                self.assertEqual(r["spec:email.send"], (
                    "email", ("mailto:a@example.it", "mailto:b@example.it",
                              "mailto:c@example.it")))
                self.assertEqual(r["fonte"], "mailfrom:m@x.it")
                self.assertTrue(r["taint"]["email.list"])
                self.assertTrue(r["forme"]["egress:mailto:a@example.it"])
                self.assertTrue(r["danger"])
                self.assertIn("mailto", r["schemi"][0])
                self.assertEqual(r["azione"][2], ("inbox:x@y.it",))

    def test_the_pins_can_fail(self):
        """A dropped `cc` mapping in the pack shows up as a difference."""
        nativo = _risposte()
        entry = _mail_connector()
        entry["verbs"] = [v for v in entry["verbs"]
                          if not (v["verb"] == "email.send" and v["arg"] == "cc")]
        self.scrivi_pack({"name": PACK, "connectors": [entry]})
        self.assertNotEqual(nativo["spec:email.send"],
                            _risposte()["spec:email.send"])


# --------------------------------------------------------------------------
# 4. fail closed
# --------------------------------------------------------------------------
def _call(name: str, args: dict) -> str:
    import asyncio

    from .. import main
    return asyncio.run(main.call_tool(name, args))[0].text


class FailClosedTests(_Istanza):
    def _rifiuta_il_connettore(self):
        self.scrivi_pack(_comms_pack(context=[{"arg": "agent", "value": "bogus"}]))
        self.assertFalse(resolved.held_by_pack("email"))

    def test_without_the_packs_connector_every_email_verb_is_denied(self):
        """Without it `email.send` would be unmapped — a send nobody checks."""
        self._rifiuta_il_connettore()
        for verbo in EMAIL_VERBS:
            with self.subTest(verbo=verbo):
                self.assertTrue(_call(verbo, {"to": "x@y.it"}).startswith("DENIED:"))

    def test_without_the_pack_installed_too(self):
        (self.dir / "packs" / PACK / "pack.yaml").unlink()
        resolved.invalidate()
        self.assertTrue(_call("email.send", {"to": "x@y.it"}).startswith("DENIED:"))

    def test_without_the_pack_the_others_fail_closed_not_the_registry(self):
        """`gdrive.upload` shares with a person on `mailto:`, which comms-pack
        declares. Without it google-pack cannot be held — its outbound verbs
        fail closed — but the gateway's own registry is not degraded."""
        (self.dir / "packs" / PACK / "pack.yaml").unlink()
        resolved.invalidate()
        self.assertEqual(resolved.degraded(), "")
        self.assertIsNone(egress.spec_for("gdrive.upload"))
        self.assertTrue(resolved.failsafe_denied("gdrive.upload"))
        self.assertFalse(resolved.held_by_pack("email"))
        self.assertIsNone(resolved.transport_for("mail"))
        self.assertTrue(_call("email.send", {"to": "x@y.it"}).startswith("DENIED:"))

    def test_a_profile_saying_native_does_not_lift_the_refusal(self):
        from .. import main
        self.posizione("native")
        self._rifiuta_il_connettore()
        with self.assertRaises(main._PackVerbRefused):
            main._check_pack_connector_held("email.send")

class TelegramBindingVerbsFailClosedTests(unittest.TestCase):
    """The retained Telegram binding verbs follow the same rule now: in `pack`
    position they need the pack's telegram connector held."""

    def test_listen_is_denied_without_the_packs_connector(self):
        from .test_522_pack_switch import _comms_pack as comms
        from .test_522_pack_switch import _Istanza as Telegram

        class _T(Telegram):
            def runTest(self):  # noqa: N802
                pass
        t = _T()
        t.setUp()
        try:
            t.posizione("pack")
            broken = comms()
            broken["connectors"][0]["context"] = [{"arg": "agent", "value": "bogus"}]
            (t.dir / "packs" / "comms-pack" / "pack.yaml").write_text(
                json.dumps(broken), encoding="utf-8")
            resolved.invalidate()
            self.assertTrue(_call("telegram.listen", {"chat_id": "1"})
                            .startswith("DENIED:"))
        finally:
            t.doCleanups()


# --------------------------------------------------------------------------
# 5. the transport backend is the gateway's
# --------------------------------------------------------------------------
class TransportBackendIsInternalTests(_Istanza):
    def setUp(self) -> None:
        super().setUp()
        altro = {"name": "normattiva", "transport": "stdio", "command": "/bin/false"}
        p = patch.dict(proxy.CONFIG, {"mcp_backends": [_backend(), altro]})
        p.start()
        self.addCleanup(p.stop)
        resolved.invalidate()
        from mcp.types import Tool
        cache = patch.dict(proxy._TOOL_CACHE, {
            BACKEND: [Tool(name=f"{BACKEND}.{TOOL}", inputSchema={"type": "object"})],
            "normattiva": [Tool(name="normattiva.cerca",
                                inputSchema={"type": "object"})]})
        cache.start()
        self.addCleanup(cache.stop)

    def test_never_listed(self):
        import asyncio
        for pos in ("pack", "native"):
            with self.subTest(posizione=pos):
                self.posizione(pos)
                nomi = [t.name for t in asyncio.run(proxy.list_proxied_tools())]
                self.assertEqual(nomi, ["normattiva.cerca"])

    def test_an_agent_call_is_denied_in_both_positions(self):
        from .. import main
        for pos in ("pack", "native"):
            with self.subTest(posizione=pos):
                self.posizione(pos)
                self.assertTrue(main.proxy.is_proxied(f"{BACKEND}.{TOOL}"))
                out = _call(f"{BACKEND}.{TOOL}", {"argv": ["--account", "x", "folders"],
                                                  "files": {}})
                self.assertTrue(out.startswith("DENIED:"), out)
        self.assertEqual(self.transport_calls, [])

    def test_the_neighbour_is_not_refused_for_it(self):
        from .. import main
        main._check_not_transport("normattiva.cerca")  # no exception

    def test_a_pack_cannot_hide_an_unclaimed_admin_mount(self):
        """Review of #378: a pack naming `normattiva` (mounted by an admin,
        owned by no pack) as its transport hid it from every agent."""
        from .. import main
        self.scrivi_pack(_comms_pack(providers=[{
            "id": "imap", "transport": {"backend": "normattiva", "tool": "cerca"}}]))
        self.assertNotIn("normattiva", resolved.transport_backends())
        main._check_not_transport("normattiva.cerca")  # still reachable


class SyncCallTests(unittest.TestCase):
    """`call_backend_tool_sync` from a thread that already runs a loop."""

    def test_it_moves_to_a_worker_thread_instead_of_failing(self):
        import asyncio
        seen = {}

        class _S:
            async def call_tool(self, tool, arguments):
                seen["thread"] = threading.current_thread().name
                from mcp.types import CallToolResult, TextContent
                return CallToolResult(content=[TextContent(type="text", text="ok")])

        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def _session(_b):
            yield _S()

        with patch.dict(proxy.CONFIG, {"mcp_backends": [_backend()]}), \
                patch.object(proxy, "_session", _session):
            async def on_loop():
                return proxy.call_backend_tool_sync(BACKEND, TOOL, {}, 5)
            self.assertEqual(asyncio.run(on_loop()), "ok")
            self.assertEqual(proxy.call_backend_tool_sync(BACKEND, TOOL, {}, 5), "ok")

    def test_a_tool_error_raises(self):
        from contextlib import asynccontextmanager

        from mcp.types import CallToolResult, TextContent

        class _S:
            async def call_tool(self, tool, arguments):
                return CallToolResult(content=[TextContent(type="text", text="no")],
                                      isError=True)

        @asynccontextmanager
        async def _session(_b):
            yield _S()

        with patch.dict(proxy.CONFIG, {"mcp_backends": [_backend()]}), \
                patch.object(proxy, "_session", _session):
            with self.assertRaises(proxy.BackendToolError):
                proxy.call_backend_tool_sync(BACKEND, TOOL, {}, 5)

    def test_an_unmounted_backend_raises(self):
        with patch.dict(proxy.CONFIG, {"mcp_backends": []}):
            with self.assertRaises(proxy.BackendToolError):
                proxy.call_backend_tool_sync(BACKEND, TOOL, {}, 5)


if __name__ == "__main__":
    unittest.main()


def setUpModule() -> None:
    # google-pack and it-pack as on every instance (#526); comms-pack is this
    # module's own (`_MailIstanza` writes it).
    _FP.install(without=("comms-pack",))


def tearDownModule() -> None:
    _FP.uninstall()

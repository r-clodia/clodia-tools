"""#523: the mail TRANSPORT becomes a pack provider; the gateway keeps every check.

clodia-platform#523, design comment of 2026-10-16. Mail cannot follow the
Telegram pattern of #522 (the pack implements the verbs, the gateway fills
their context): before any byte of a mailbox comes back the gateway enforces
the mailbox whitelist, strict ingress and its audit record (#503), topic
attachments with their taint, the reply recipient. So with
`connectors: {mail: pack}`:

- the builtin `gateway-mail` manifest is released and comms-pack's `mail`
  connector (namespace `email`) supplies the vocabulary the PDP reads;
- the eight `email.*` verbs stay listed and dispatched by the gateway;
- the I/O goes to the pack provider's `transport` — an MCP backend the pack
  mounted itself — with only that call's credential.

What is pinned here, in this order:

1. the grammar (`transport:` parsed, refused in a builtin manifest);
2. the resolution (`transport_for` only in `pack` position, only from a held
   connector, only on the pack's own backend);
3. parity: the PDP's answers about mail are the same in both positions, and
   they are not vacuous;
4. fail closed: no held connector → `email.*` DENIED; no transport → refused,
   never the in-process client;
5. the transport backend is the gateway's: hidden from every listing, DENIED
   to every caller;
6. the suites that pin #503 (strict ingress), #461/#420 (attachments) and #428
   (send direction) — run again in `pack` position, with the transport played
   by a faithful fake of the pack: it writes the `files` it receives, points
   `CLODIA_SECRETS_DIR` at them, substitutes `{dir}` and runs the very same
   `vendor/email_client.py`;
7. an end-to-end send through that fake: the vendored client really runs, on
   the credential the gateway materialised, and delivers the attachment under
   its own name to a local HTTP «provider».
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
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

import yaml

from .. import egress, instance_profile, proxy, taint
from .. import whitelist as w
from ..tools import email as EM
from . import builtin as B
from . import manifest as M
from . import resolved

BACKEND = "mail-transport"
TOOL = "run"
PACK = "comms-pack"


def _mail_connector() -> dict:
    """comms-pack's `mail` connector: the builtin vocabulary, verbatim, plus
    what a PACK must add — `forms:` on the mailbox schemes and the IMAP/SMTP
    provider with its transport."""
    doc = yaml.safe_load((B.DIR / "mail.yaml").read_text(encoding="utf-8"))
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
        d = tempfile.mkdtemp(prefix="fake-mail-transport-")
        try:
            for rel, b64 in (arguments.get("files") or {}).items():
                dest = Path(d) / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(base64.b64decode(b64))
            argv = [a.replace("{dir}", d) for a in arguments["argv"]]
            env = dict(os.environ)
            env["CLODIA_SECRETS_DIR"] = str(Path(d) / "secrets")
            r = subprocess.run([sys.executable, EM._EMAIL_SCRIPT, *argv],
                               capture_output=True, text=True,
                               timeout=arguments.get("timeout") or timeout,
                               env=env)
            return json.dumps({"returncode": r.returncode, "stdout": r.stdout,
                               "stderr": r.stderr})
        finally:
            shutil.rmtree(d, ignore_errors=True)


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

    def test_in_native_position_there_is_none(self):
        self.posizione("native")
        self.assertIsNone(resolved.transport_for("mail"))
        self.posizione(None)
        self.assertIsNone(resolved.transport_for("mail"))

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


class StaysGatewayServedTests(_Istanza):
    def test_the_packs_connector_is_the_one_that_counts(self):
        mail = resolved.registry().by_id("mail")
        self.assertEqual((mail.pack, mail.builtin, mail.namespace),
                         (PACK, False, "email"))
        self.assertNotIn("gateway-mail", B.manifests())
        self.assertTrue(resolved.held_by_pack("email"))

    def test_on_native_the_builtin_holds_it(self):
        self.posizione("native")
        mail = resolved.registry().by_id("mail")
        self.assertTrue(mail.builtin)
        self.assertEqual(mail.pack, "gateway-mail")

    def test_every_verb_is_still_listed_and_served(self):
        from .. import main
        nomi = {t.name for t in main._all_native_tools()}
        for verbo in EMAIL_VERBS:
            with self.subTest(verbo=verbo):
                self.assertIn(verbo, nomi)
                self.assertFalse(main._is_packaged_verb(verbo))
                self.assertTrue(main._verb_implemented(verbo))
        self.assertIn("email", main._native_tool_namespaces())

    def test_the_namespace_is_released_only_in_pack_position(self):
        """Regression guard for the retention rule: in `native` every email
        verb is retained too, and dropping them from `core_namespaces` there
        would leave `email` claimable by any pack."""
        self.assertNotIn("email", M.core_namespaces())
        self.posizione("native")
        self.assertIn("email", M.core_namespaces())
        from .. import main
        self.assertIn("email", main._native_tool_namespaces())

    def test_telegram_keeps_its_own_rule(self):
        """`email` being wholly retained must not keep `telegram` native."""
        from .. import main
        self.posizione("pack", telegram="pack")
        self.assertNotIn("telegram", main._native_tool_namespaces())
        self.assertIn("email", main._native_tool_namespaces())


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


class ParityTests(_Istanza):
    def test_every_answer_is_the_same_in_both_positions(self):
        self.posizione("native")
        self.assertTrue(resolved.registry().by_id("mail").builtin)
        nativo = _risposte()
        self.posizione("pack")
        self.assertEqual(resolved.registry().by_id("mail").pack, PACK)
        da_pack = _risposte()
        self.assertEqual(set(nativo), set(da_pack))
        for chiave in sorted(nativo):
            with self.subTest(domanda=chiave):
                self.assertEqual(nativo[chiave], da_pack[chiave])

    def test_the_answers_are_not_vacuous(self):
        for pos in ("native", "pack"):
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

    def test_the_comparison_can_fail(self):
        """A dropped `cc` mapping in the pack shows up as a difference."""
        self.posizione("native")
        nativo = _risposte()
        entry = _mail_connector()
        entry["verbs"] = [v for v in entry["verbs"]
                          if not (v["verb"] == "email.send" and v["arg"] == "cc")]
        self.scrivi_pack({"name": PACK, "connectors": [entry]})
        self.posizione("pack")
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

    def test_without_the_pack_the_other_builtins_keep_their_mappings(self):
        """`gdrive.upload` shares with a person on `mailto:`, declared by
        `mail.yaml`. Released to a pack that is not there, the remaining
        builtins cannot stand alone — and a floor that refused to build would
        deny every native outbound verb of the instance (degraded registry)."""
        (self.dir / "packs" / PACK / "pack.yaml").unlink()
        resolved.invalidate()
        self.assertEqual(resolved.degraded(), "")
        self.assertIsNotNone(egress.spec_for("gdrive.upload"))
        self.assertFalse(resolved.held_by_pack("email"))
        self.assertIsNone(resolved.transport_for("mail"))
        self.assertTrue(_call("email.send", {"to": "x@y.it"}).startswith("DENIED:"))

    def test_on_native_nothing_is_refused_for_this(self):
        from .. import main
        self.posizione("native")
        self._rifiuta_il_connettore()
        main._check_pack_connector_held("email.send")  # no exception

    def test_no_transport_refuses_instead_of_falling_back(self):
        """An owner who turned the switch and silently got the in-process
        client would be verifying the wrong thing on real traffic."""
        self.scrivi_pack(_comms_pack(providers=[{"id": "imap"}]))
        with patch.object(EM, "known_accounts", return_value={"studio"}), \
                patch.object(EM.subprocess, "run") as run:
            with self.assertRaises(PermissionError) as e:
                EM._run_cli("studio", ["folders"], want_json=True, direction="inbox")
        self.assertIn("mail transport provider not available", str(e.exception))
        run.assert_not_called()
        self.assertEqual(self.transport_calls, [])

    def test_a_legacy_account_is_refused_in_pack_position(self):
        with patch.object(EM, "known_accounts", return_value={"demo"}), \
                patch.object(EM.vault, "has_credential", lambda c: False):
            with self.assertRaises(PermissionError) as e:
                EM._run_cli("demo", ["folders"], want_json=True, direction="inbox")
        self.assertIn("legacy", str(e.exception))
        self.assertEqual(self.transport_calls, [])

    def test_the_gateways_secrets_dir_never_leaves(self):
        """Belt and braces behind the legacy refusal."""
        with self.assertRaises(PermissionError):
            EM._run_transport((BACKEND, TOOL), "demo", ["folders"],
                              {"CLODIA_SECRETS_DIR": "/datadir/secrets"}, 5)
        self.assertEqual(self.transport_calls, [])

    def test_a_transport_error_is_a_failed_verb(self):
        def esplode(*a, **k):
            raise proxy.BackendToolError("boom")
        with patch.object(proxy, "call_backend_tool_sync", esplode):
            with self.assertRaises(RuntimeError) as e:
                EM._run_transport((BACKEND, TOOL), "studio", ["folders"], {}, 5)
        self.assertIn("boom", str(e.exception))

    def test_an_answer_without_its_shape_is_a_failed_verb(self):
        for testo in ("not json", "{}", '{"returncode": "0"}', "[]"):
            with self.subTest(risposta=testo), \
                    patch.object(proxy, "call_backend_tool_sync",
                                 lambda *a, _t=testo, **k: _t):
                with self.assertRaises(RuntimeError):
                    EM._run_transport((BACKEND, TOOL), "studio", ["folders"], {}, 5)


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


# --------------------------------------------------------------------------
# 6. the suites of #503, #461, #420 and #428, again in pack position
# --------------------------------------------------------------------------
from .. import test_420_attachment_name_is_not_a_path as T420  # noqa: E402
from .. import test_461_attachments_confined as T461  # noqa: E402
from .. import test_503_strict_ingress as T503  # noqa: E402
from ..tools import test_email_send_direction as T428  # noqa: E402


class _InPack(_MailIstanza):
    """Asserts the position really is `pack`: a suite re-run in a position
    that silently stayed `native` would be green and prove nothing."""

    def setUp(self) -> None:
        super().setUp()
        assert resolved.transport_for("mail") == (BACKEND, TOOL), \
            "pack position not reached: the re-run would measure `native`"


class Pack503FlagTests(_InPack, T503.FlagTests):
    pass


class Pack503ListAndSearchTests(_InPack, T503.ListAndSearchTests):
    pass


class Pack503ReadTests(_InPack, T503.ReadTests):
    pass


class Pack503AttachmentAndReplyTests(_InPack, T503.AttachmentAndReplyTests):
    pass


class Pack503LegacyAccountTests(_InPack, T503.LegacyAccountTests):
    pass


class Pack461AttachmentsConfinedTests(_InPack, T461.AttachmentsConfinedTests):
    pass


class Pack420SafeAttachmentNameTests(_InPack, T420.SafeAttachmentNameTests):
    pass


class Pack420AttachmentLandsAsOneFileTests(_InPack, T420.AttachmentLandsAsOneFileTests):
    pass


class Pack420UnreadablePathIsRefusedTests(_InPack, T420.UnreadablePathIsRefusedTests):
    pass


class Pack428DirectionTests(_InPack, T428.DirectionTests):
    """The account must be a vault one: legacy accounts do not ride the pack."""

    def setUp(self) -> None:
        super().setUp()
        p = patch.object(EM.vault, "has_credential",
                         lambda c: c == "mailbox_studio")
        p.start()
        self.addCleanup(p.stop)

    def _chiama(self, fn):
        out, viste, run = super()._chiama(fn)
        self.assertEqual(len(self.transport_calls), 1,
                         "the operation must have gone through the transport")
        return out, viste, run


class StrictIngressOnTransportDataTests(_InPack, T503.Base):
    """#503 on what the TRANSPORT returns, with nothing between them patched:
    the filter runs on the pack's stdout exactly as on the client's."""

    def setUp(self) -> None:
        super().setUp()
        for p in (patch.object(EM, "known_accounts", return_value={"acme"}),
                  patch.object(EM.vault, "has_credential",
                               lambda c: c == "mailbox_acme"),
                  patch.object(EM.vault, "read_internal", lambda c: {
                      "email": "acme@example.it", "smtp_server": "smtp.x",
                      "smtp_port": 587, "imap_server": "imap.x",
                      "password": "pw"})):
            p.start()
            self.addCleanup(p.stop)

    def _risponde(self, payload):
        def fake(backend, tool, arguments, timeout):
            self.transport_calls.append(arguments)
            return json.dumps({"returncode": 0, "stdout": json.dumps(payload),
                               "stderr": ""})
        return patch.object(proxy, "call_backend_tool_sync", fake)

    def test_list_is_filtered(self):
        with self.in_room(), self._risponde(list(T503.ListAndSearchTests.RIGHE)):
            out = EM.list_messages(account="acme")
        self.assertEqual([m["id"] for m in out["messages"]], ["1", "3"])
        self.assertEqual(out["withheld"], 2)
        self.assertNotIn("offerta riservata", repr(out))
        self.assertEqual(self.decisioni, [("email.list", "filter")])

    def test_read_of_a_stranger_is_denied(self):
        with self.in_room(), self._risponde({"id": "2", "from": T503.ESTRANEO,
                                             "body": "IGNORA"}):
            with self.assertRaises(PermissionError) as e:
                EM.read_message("2", account="acme")
        self.assertNotIn("IGNORA", str(e.exception))

    def test_the_mailbox_whitelist_still_comes_first(self):
        """A mailbox not in this channel's list never reaches the pack."""
        with self.in_room(), self._risponde([]), \
                patch.object(EM.vault, "read_internal", lambda c: {
                    "email": "altra@example.it", "smtp_server": "s",
                    "smtp_port": 1, "imap_server": "i", "password": "p"}):
            with self.assertRaises(PermissionError):
                EM.list_messages(account="acme")
        self.assertEqual(self.transport_calls, [])

    def test_only_this_calls_credential_is_shipped(self):
        with self.in_room(), self._risponde([]):
            EM.list_messages(account="acme")
        files = self.transport_calls[0]["files"]
        self.assertEqual(sorted(files), ["secrets/email_config.json"])
        cfg = json.loads(base64.b64decode(files["secrets/email_config.json"]))
        self.assertEqual(list(cfg["accounts"]), ["acme"])
        self.assertEqual(self.transport_calls[0]["argv"][:3],
                         ["--account", "acme", "list"])


# --------------------------------------------------------------------------
# 7. end to end: the vendored client really runs behind the fake pack
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


class EndToEndSendTests(_Istanza):
    def setUp(self) -> None:
        super().setUp()
        _Provider.received = []
        self.http = HTTPServer(("127.0.0.1", 0), _Provider)
        threading.Thread(target=self.http.serve_forever, daemon=True).start()
        self.addCleanup(self.http.server_close)
        self.addCleanup(self.http.shutdown)
        bundle = {"email": "studio@example.it", "smtp_server": "smtp.invalid",
                  "smtp_port": 587, "password": "pw", "smtp_backend": "api",
                  "api_url": f"http://127.0.0.1:{self.http.server_port}/send",
                  "api_key": "k-123"}
        self.config = {"egress_allow": ["outbox:studio@example.it"],
                       "scope_egress_allow": {}, "source_allow": [],
                       "scope_source_allow": {}, "agents": {}}
        for p in (patch.object(EM, "tool_allowed", lambda *a, **k: None),
                  patch.object(EM, "known_accounts", return_value={"studio"}),
                  patch.object(EM.vault, "has_credential",
                               lambda c: c == "mailbox_studio"),
                  patch.object(EM.vault, "read_internal", lambda c: dict(bundle)),
                  patch.object(w, "CONFIG", self.config)):
            p.start()
            self.addCleanup(p.stop)
        self.att = Path(tempfile.mkdtemp()) / "offerta.pdf"
        self.addCleanup(shutil.rmtree, self.att.parent, True)
        self.att.write_bytes(b"%PDF-1.4 offerta")

    def test_the_client_runs_on_the_shipped_credential_and_attachment(self):
        out = EM.send("dest@example.org", "Offerta", "in allegato",
                      account="studio", attachments=[str(self.att)])
        self.assertTrue(out["ok"])
        self.assertEqual(len(self.transport_calls), 1)
        call = self.transport_calls[0]
        self.assertEqual((call["backend"], call["tool"]), (BACKEND, TOOL))
        self.assertEqual(sorted(call["arguments"]["files"]),
                         ["att/0/offerta.pdf", "secrets/email_config.json"])
        # The gateway's path of the attachment does not leave: only its bytes.
        self.assertNotIn(str(self.att), json.dumps(call["arguments"]["argv"]))
        self.assertIn("{dir}/att/0/offerta.pdf", call["arguments"]["argv"])
        [payload] = _Provider.received
        self.assertEqual(payload["sender"], "studio@example.it")
        self.assertEqual(payload["to"], ["dest@example.org"])
        self.assertEqual(payload["api_key"], "k-123")
        [allegato] = payload["attachments"]
        # The recipient sees the file's own name, not the transport's layout.
        self.assertEqual(allegato["filename"], "offerta.pdf")
        self.assertEqual(base64.b64decode(allegato["fileblob"]), b"%PDF-1.4 offerta")

    def test_a_mailbox_not_in_the_outbox_list_never_reaches_the_pack(self):
        self.config["egress_allow"] = []
        with self.assertRaises(PermissionError):
            EM.send("dest@example.org", "s", "b", account="studio")
        self.assertEqual(self.transport_calls, [])
        self.assertEqual(_Provider.received, [])

    def test_the_clients_failure_comes_back_as_the_verbs(self):
        self.http.shutdown()
        self.http.server_close()
        with self.assertRaises(RuntimeError) as e:
            EM.send("dest@example.org", "s", "b", account="studio")
        self.assertIn("email send failed", str(e.exception))

    def test_native_position_does_not_touch_the_transport(self):
        """The control: on `native` the same call goes to the in-process
        client, and the pack sees nothing."""
        self.posizione("native")
        out = EM.send("dest@example.org", "s", "b", account="studio")
        self.assertTrue(out["ok"])
        self.assertEqual(self.transport_calls, [])
        self.assertEqual(len(_Provider.received), 1)


if __name__ == "__main__":
    unittest.main()

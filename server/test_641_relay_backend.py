"""clodia-platform#641 — `relay:`/`pairing:` through a mounted MCP backend.

The transport runs in its own container and is an MCP server the gateway
calls (`proxy.call_backend_tool_sync`). Here the backend is a fake: the call
helper is patched with an in-memory server that keeps a poll queue with
cursors, records sends and answers pairing — what goes through the gateway's
code (ownership, vetting, ack/cursor, error mapping, routes) is real.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import unittest
from unittest.mock import AsyncMock, patch

from starlette.applications import Starlette
from starlette.testclient import TestClient

from . import channels_api, egress, proxy, tools_api, whitelist
from . import main as M
from .connectors import first_party_fixture as _first_party
from .connectors import resolved
from .connectors import validate as _validate
from .connectors.manifest import ManifestError, build_registry, parse_connector
from .test_638_639_pack_relay import _connector, _installed, _pack

_H = {"Authorization": "Bearer ckt1.finto"}
PACK = "sms-demo-pack"
BACKEND = "sms-transport"
GOOD = {"chat_id": "+39333000111", "chat_uri": "sms:+39333000111",
        "sender_uri": "sms:+39333000222", "text": "ciao"}
BAD = {"chat_id": "-1", "chat_uri": "tg:-1", "text": "other scheme"}


def _backend_doc(*, attachments: bool = True, pairing: bool = True) -> dict:
    """The fixture pack in the backend form: no service, no base."""
    c = _connector("http://127.0.0.1:1", with_relay=False, with_pairing=False)
    c.pop("services")
    c["relay"] = {"backend": BACKEND, "label": "SMS", "attachments": attachments}
    if pairing:
        c["pairing"] = {"backend": BACKEND}
    return {"name": PACK, "connectors": [c]}


class _FakeBackend:
    """The transport container, as its MCP tools answer."""

    def __init__(self, rows=()):
        self.queue = list(enumerate(rows, start=1))
        self.calls: list[tuple[str, str, dict, float]] = []
        self.sent: list[dict] = []
        self.pairing = {"state": "pairing", "code": "ABCD-1234"}
        self.error: tuple[str, str] | None = None     # (tool, text) → isError
        self.down = False

    def __call__(self, backend, tool, arguments, timeout, **kw):
        self.calls.append((backend, tool, dict(arguments), timeout))
        self.kwargs = kw
        if self.down:
            raise proxy.BackendUnavailable(f"backend MCP '{backend}' non montato")
        if self.error and self.error[0] == tool:
            err = proxy.BackendToolError(f"{backend}.{tool}: {self.error[1]}")
            err.text = self.error[1]
            raise err
        if tool == "relay_poll":
            ack = arguments.get("ack")
            if ack is not None:
                self.queue = [(n, r) for n, r in self.queue if n > int(ack)]
            out = {"messages": [r for _n, r in self.queue]}
            if self.queue:
                out["cursor"] = str(self.queue[-1][0])
            return json.dumps(out)
        if tool == "relay_send":
            self.sent.append(dict(arguments))
            return json.dumps({"ok": True, "message_id": f"m{len(self.sent)}"})
        if tool == "relay_download":
            return json.dumps({"content_b64": "aGk=", "size": 2, "mime": "text/plain"})
        if tool in ("pairing_status", "pairing_start"):
            return json.dumps(self.pairing)
        raise proxy.BackendToolError(f"unknown tool {tool}")


def _mounted(pack: str | None = PACK, name: str = BACKEND):
    entry = {"name": name, "transport": "http", "url": "http://transport:8080/mcp"}
    if pack:
        entry["pack"] = pack
    return patch.object(proxy, "_backends", lambda: {name: entry})


def setUpModule() -> None:
    _first_party.install()


def tearDownModule() -> None:
    _first_party.uninstall()


class _Case(unittest.TestCase):
    doc = None
    owner: str | None = PACK

    def setUp(self):
        self.fake = _FakeBackend([GOOD, BAD])
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        resolved._TRANSPORTS = None
        self.addCleanup(setattr, resolved, "_TRANSPORTS", None)
        for p in (_installed(self.doc or _backend_doc()), _mounted(self.owner),
                  patch.object(proxy, "call_backend_tool_sync", self.fake),
                  patch.object(channels_api.internal_auth, "authorize",
                               lambda *a, **k: ({"agent": "clodia"}, None)),
                  patch.object(tools_api, "_authorized_owner", lambda r: True)):
            stack.enter_context(p)
        self.client = TestClient(Starlette(routes=channels_api.routes
                                           + tools_api.routes))

    def post(self, path, body=None):
        return self.client.post(path, json=body or {}, headers=_H)


# --------------------------------------------------------------------------
# manifest
# --------------------------------------------------------------------------

class ManifestTests(unittest.TestCase):
    def test_the_backend_form_parses_without_service_or_base(self):
        c = parse_connector(_backend_doc()["connectors"][0], pack=PACK,
                            reserved=frozenset())
        self.assertEqual((c.relay.backend, c.relay.service, c.relay.base),
                         (BACKEND, "", ""))
        self.assertEqual((c.pairing.backend, c.pairing.service), (BACKEND, ""))
        self.assertTrue(c.relay.attachments)

    def _refused(self, raw, fragment=""):
        with self.assertRaises(ManifestError) as cm:
            parse_connector(raw, pack=PACK, reserved=frozenset())
        self.assertIn(fragment, str(cm.exception))

    def test_backend_and_service_are_mutually_exclusive(self):
        for key in ("relay", "pairing"):
            for extra in ({"service": "sms-relay"}, {"base": "http://127.0.0.1:1"}):
                with self.subTest(key=key, extra=extra):
                    raw = _connector("http://127.0.0.1:1")
                    raw[key] = {**raw[key], "backend": BACKEND, **extra}
                    if key == "relay":
                        raw[key].pop("service" if "base" in extra else "base", None)
                    self._refused(raw, "both")

    def test_backend_names_follow_the_slug_rules(self):
        for name in ("SMS", "sms_transport", "-sms", "sms-", "a" * 41, "a.b", ""):
            with self.subTest(name=name):
                doc = _backend_doc()
                doc["connectors"][0]["relay"]["backend"] = name
                self._refused(doc["connectors"][0])

    def test_pairing_backend_takes_no_paths(self):
        doc = _backend_doc()
        doc["connectors"][0]["pairing"]["status"] = "/status"
        self._refused(doc["connectors"][0], "pairing_status")

    def test_the_relay_backend_still_needs_scheme_forms(self):
        doc = _backend_doc()
        doc["connectors"][0]["schemes"][0].pop("forms")
        doc["connectors"][0]["topic_actions"] = []
        self._refused(doc["connectors"][0], "forms")

    def test_the_listing_never_names_the_backend(self):
        reg = build_registry({PACK: _backend_doc()}, reserved=frozenset())
        row = _validate.summary(reg.by_id("sms"))
        self.assertEqual(row["relay"]["label"], "SMS")
        self.assertTrue(row["pairing"])
        self.assertNotIn(BACKEND, json.dumps(row))

    def test_service_form_unchanged(self):
        c = parse_connector(_connector("http://127.0.0.1:8731"), pack=PACK,
                            reserved=frozenset())
        self.assertEqual((c.relay.backend, c.relay.service), ("", "sms-relay"))


# --------------------------------------------------------------------------
# relay routes through the backend
# --------------------------------------------------------------------------

class RelayBackendTests(_Case):
    def test_poll_ack_round_trip(self):
        r = self.post("/internal/channels/sms/poll", {"timeout": 3}).json()
        self.assertEqual((r["messages"], r["cursor"]), ([GOOD], "2"))
        backend, tool, args, timeout = self.fake.calls[-1]
        self.assertEqual((backend, tool, args), (BACKEND, "relay_poll", {"timeout": 3}))
        self.assertEqual(timeout, 3 + channels_api.POLL_MARGIN)
        r2 = self.post("/internal/channels/sms/poll", {"timeout": 3, "ack": "2"}).json()
        self.assertEqual(r2, {"messages": [], "count": 0})
        self.assertEqual(self.fake.calls[-1][2], {"timeout": 3, "ack": "2"})
        self.assertEqual(self.fake.queue, [])

    def test_send(self):
        r = self.post("/internal/channels/sms/send",
                      {"chat_id": "+39333000111", "text": "hi", "thread_id": 2})
        self.assertEqual(r.json(), {"ok": True, "message_id": "m1"})
        self.assertEqual(self.fake.sent, [{"chat_id": "+39333000111", "text": "hi",
                                           "thread_id": 2}])

    def test_download(self):
        r = self.post("/internal/channels/sms/download", {"file_id": "f1"})
        self.assertEqual(r.json(), {"content_b64": "aGk=", "size": 2,
                                    "mime": "text/plain"})
        self.assertEqual(self.fake.calls[-1][1:3], ("relay_download", {"file_id": "f1"}))

    def test_errors_map_to_the_same_classes(self):
        self.fake.error = ("relay_send", "boom")
        self.assertEqual(self.post("/internal/channels/sms/send",
                                   {"chat_id": "+1", "text": "x"}).status_code, 502)
        self.fake.error = None
        self.fake.down = True
        self.assertEqual(self.post("/internal/channels/sms/poll",
                                   {"timeout": 1}).status_code, 503)

    def test_a_non_json_answer_is_502(self):
        with patch.object(proxy, "call_backend_tool_sync", lambda *a, **k: "not json"):
            self.assertEqual(self.post("/internal/channels/sms/poll",
                                       {"timeout": 1}).status_code, 502)


class NotOwnedTests(_Case):
    owner = None        # mounted by an admin without the pack's stamp

    def test_a_backend_the_pack_did_not_mount_is_never_called(self):
        self.assertEqual(self.post("/internal/channels/sms/poll",
                                   {"timeout": 1}).status_code, 503)
        self.assertEqual(self.client.get("/tools/connectors/sms/pairing",
                                         headers=_H).status_code, 503)
        self.assertEqual(self.fake.calls, [])
        # …and, unclaimed, it is not hidden as this pack's transport either.
        self.assertFalse(resolved.is_transport_backend(BACKEND))


class AnotherPacksBackendTests(_Case):
    owner = "other-pack"

    def test_another_packs_backend_is_never_called(self):
        self.assertEqual(self.post("/internal/channels/sms/send",
                                   {"chat_id": "+1", "text": "x"}).status_code, 503)
        self.assertEqual(self.fake.calls, [])


# --------------------------------------------------------------------------
# pairing through the backend
# --------------------------------------------------------------------------

class PairingBackendTests(_Case):
    def test_status_and_start(self):
        from .audit import control
        events = []
        with patch.object(control, "emit", lambda *a, **k: events.append((a, k))), \
                patch.object(tools_api, "_admin_principal", lambda r: "davide"):
            r = self.client.get("/tools/connectors/sms/pairing", headers=_H)
            self.assertEqual(r.json(), {"state": "pairing", "code": "ABCD-1234"})
            self.assertEqual(self.fake.calls[-1][1:3], ("pairing_status", {}))
            self.fake.pairing = {"state": "open", "me": "+39333", "secret": "x"}
            r = self.client.post("/tools/connectors/sms/pairing", headers=_H)
        self.assertEqual(r.json(), {"state": "open", "me": "+39333"})
        self.assertEqual(self.fake.calls[-1][1:3], ("pairing_start", {}))
        self.assertEqual(events, [(("connector", "pairing_start", "sms"),
                                   {"admin": "davide", "pack": PACK})])

    def test_a_tool_refusal_comes_back_filtered(self):
        self.fake.error = ("pairing_start",
                           json.dumps({"state": "open", "error": "already paired",
                                       "token": "x"}))
        with patch.object(tools_api, "_admin_principal", lambda r: "davide"), \
                patch("server.audit.control.emit", lambda *a, **k: None):
            r = self.client.post("/tools/connectors/sms/pairing", headers=_H)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.json(), {"state": "open", "error": "already paired"})

    def test_down_is_503(self):
        self.fake.down = True
        self.assertEqual(self.client.get("/tools/connectors/sms/pairing",
                                         headers=_H).status_code, 503)


# --------------------------------------------------------------------------
# the backend is a transport: hidden from and refused to agents
# --------------------------------------------------------------------------

class TransportHiddenTests(_Case):
    def test_it_is_a_transport_backend(self):
        self.assertTrue(resolved.is_transport_backend(BACKEND))
        self.assertTrue(resolved.is_transport_backend(f"{BACKEND}.relay_send"))

    def test_never_listed(self):
        from mcp.types import Tool
        with patch.dict(proxy._TOOL_CACHE, {BACKEND: [Tool(
                name=f"{BACKEND}.relay_send", description="", inputSchema={})]}):
            tools = asyncio.run(proxy.list_proxied_tools())
        self.assertEqual([t for t in tools if t.name.startswith(BACKEND)], [])

    def test_an_agents_call_is_refused(self):
        tok = whitelist.set_current_agent("clodia")
        self.addCleanup(whitelist.reset_current_agent, tok)
        out = asyncio.run(M.call_tool(f"{BACKEND}.relay_send",
                                      {"chat_id": "+1", "text": "x"}))[0].text
        self.assertTrue(out.startswith("DENIED"), out)
        self.assertEqual(self.fake.calls, [])


# --------------------------------------------------------------------------
# channel.deliver through the backend
# --------------------------------------------------------------------------

ROOM = ("SEAL-2", "preventivi")


class DeliverBackendTests(_Case):
    def setUp(self):
        super().setUp()
        cfg = {"agents": {"segretario": {"allowed_tools": ["channel.deliver"],
                                         "denied_tools": [],
                                         "profile_tools": ["channel.deliver"]}},
               "egress_allow": [],
               "scope_egress_allow": {f"{ROOM[0]}/{ROOM[1]}": ["sms:+39333000111"]}}
        tok = whitelist.set_current_agent("segretario")
        self.addCleanup(whitelist.reset_current_agent, tok)
        self.gate = AsyncMock(return_value={})
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        for p in (patch.object(whitelist, "CONFIG", cfg),
                  patch.object(M, "_current_topic", lambda: ROOM),
                  patch.object(M, "_check_component", lambda n: None),
                  patch.object(M, "_check_pack_connector_held", lambda n: None),
                  patch.object(M, "_unattended_denial", lambda n: None),
                  patch.object(M.origin, "evaluate", return_value={"action": "allow"}),
                  patch.object(M, "_require_gate_consent", self.gate),
                  patch.object(egress, "mode", lambda: "on"),
                  patch.object(egress, "_scope_of_call",
                               lambda: f"{ROOM[0]}/{ROOM[1]}"),
                  patch.object(M._taint, "note_verb", lambda *a, **k: None),
                  patch.object(M._tlm, "record", lambda *a, **k: None)):
            stack.enter_context(p)

    def test_the_reply_goes_out_through_relay_send(self):
        out = asyncio.run(M.call_tool("channel.deliver", {
            "destination": "sms:+39333000111", "text": "risposta"}))[0].text
        self.assertFalse(out.startswith(("DENIED", "ERROR")), out)
        self.assertEqual(self.fake.sent, [{"chat_id": "+39333000111",
                                           "text": "risposta"}])
        self.gate.assert_not_awaited()

    def test_an_undeclared_destination_is_refused(self):
        out = asyncio.run(M.call_tool("channel.deliver", {
            "destination": "sms:+39333000999", "text": "x"}))[0].text
        self.assertTrue(out.startswith("DENIED"), out)
        self.assertEqual(self.fake.sent, [])


# --------------------------------------------------------------------------
# the admin path: mount a pack's server with the pack's stamp
# --------------------------------------------------------------------------

class AdminMountTests(unittest.TestCase):
    """The admin path, through the REAL `register_mcp_core`."""

    def setUp(self):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        self.cfg = {"mcp_backends": []}
        self.owner = True
        self.events = []
        from .audit import control
        for p in (_installed(_backend_doc()),
                  patch.object(whitelist, "CONFIG", self.cfg),
                  patch.object(whitelist, "save_config", lambda: None),
                  patch.object(whitelist, "reload_config", lambda: None),
                  patch.object(proxy, "clear_cache", lambda: None),
                  patch.object(tools_api, "_authorized", lambda r: True),
                  patch.object(tools_api, "_authorized_owner", lambda r: self.owner),
                  patch.object(tools_api, "_admin_principal", lambda r: "davide"),
                  patch.object(control, "emit",
                               lambda *a, **k: self.events.append((a, k)))):
            stack.enter_context(p)
        self.client = TestClient(Starlette(routes=tools_api.routes))

    def _mount(self, name, pack):
        body = {"config": {"mcpServers": {name: {"url": "http://transport:8080/mcp"}}}}
        if pack is not None:
            body["pack"] = pack
        return self.client.post("/tools/mcp", json=body, headers=_H)

    def _stamp(self, name):
        return next((b.get("pack") for b in self.cfg["mcp_backends"]
                     if b["name"] == name), "(not mounted)")

    def test_a_declared_backend_is_mounted_with_the_packs_stamp_and_audited(self):
        r = self._mount(BACKEND, PACK)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self._stamp(BACKEND), PACK)
        self.assertEqual(self.events, [(("mcp", "mount", BACKEND),
                                        {"pack": PACK, "by": "davide"})])

    def test_the_connector_namespace_is_declared_too(self):
        # The pack's agent-facing backend is named after its connector.
        self.assertEqual(self._mount("sms", PACK).status_code, 200)
        self.assertEqual(self._stamp("sms"), PACK)

    def test_an_undeclared_name_or_an_unknown_pack_is_refused(self):
        self.assertEqual(self._mount("other", PACK).status_code, 403)
        self.assertEqual(self._mount(BACKEND, "no-such-pack").status_code, 403)
        self.assertEqual(self.cfg["mcp_backends"], [])

    def test_only_a_human_admin_may_stamp(self):
        self.owner = False
        self.assertEqual(self._mount(BACKEND, PACK).status_code, 403)
        # Without `pack` an unclaimed name mounts as before.
        self.assertEqual(self._mount("anything", None).status_code, 200)
        self.assertIsNone(self._stamp("anything"))

    def test_a_claimed_name_without_the_pack_is_409(self):
        for name in (BACKEND, "SMS Transport", "sms_transport", "sms"):
            with self.subTest(name=name):
                r = self._mount(name, None)
                self.assertEqual(r.status_code, 409)
                self.assertIn(PACK, r.json()["error"])
        self.assertEqual(self.cfg["mcp_backends"], [])


class DeclaredBackendsTests(unittest.TestCase):
    """What a pack declares: servers, plugins' servers, namespaces, backends."""

    def test_sources(self):
        import shutil
        import tempfile
        from pathlib import Path
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "plugins/wa-plugin").mkdir(parents=True)
        (tmp / "plugins/wa-plugin/plugin.yaml").write_text(
            "mcp_servers:\n  WA Agent: {url: http://x}\n")
        (tmp / "plugins/wa-plugin/.mcp.json").write_text(
            json.dumps({"mcpServers": {"wa_extra": {"url": "http://y"}}}))
        doc = _backend_doc()
        doc["plugins"] = ["wa-plugin", "../escape"]
        doc["mcp_servers"] = {"top-level": {}}
        doc["connectors"][0]["namespace"] = "whatsapp"
        with patch.object(resolved, "_DATA", tmp), \
                patch.object(resolved, "_raw_pack_docs", lambda: {PACK: doc}):
            got = resolved.declared_backends(PACK)
            self.assertEqual(resolved.backend_claimant("Whats-App"), None)
            self.assertEqual(resolved.backend_claimant("whatsapp"), PACK)
        self.assertEqual(set(got), {"wa_agent", "wa_extra", "top_level",
                                    "whatsapp", "sms_transport"})
        self.assertEqual(resolved.declared_backends("nobody"), frozenset())


class McpAddGateTextTests(unittest.TestCase):
    def test_the_gate_names_the_pack_being_granted_ownership(self):
        txt = M._gate_effect_reason("mcp.add", {
            "config": {"mcpServers": {BACKEND: {"url": "http://x"}}}, "pack": PACK})
        self.assertIn(PACK, txt)
        self.assertNotIn("COME DEL PACK", M._gate_effect_reason("mcp.add", {
            "config": {"mcpServers": {BACKEND: {"url": "http://x"}}}}))


class ReviewManifestTests(unittest.TestCase):
    def test_the_backend_may_not_be_the_connectors_namespace(self):
        for key in ("relay", "pairing"):
            with self.subTest(key=key):
                doc = _backend_doc()
                doc["connectors"][0][key]["backend"] = "sms"
                with self.assertRaises(ManifestError) as cm:
                    parse_connector(doc["connectors"][0], pack=PACK,
                                    reserved=frozenset())
                self.assertIn("namespace", str(cm.exception))

    def test_two_connectors_may_not_share_a_backend(self):
        doc = _backend_doc()
        second = json.loads(json.dumps(doc["connectors"][0]))
        second.update(id="sms2", namespace="sms2", label="SMS 2")
        second["schemes"][0]["scheme"] = "sms2"
        second["topic_actions"][0]["adds"] = {"ingress": ["sms2:{chat}"],
                                              "egress": ["sms2:{chat}"]}
        second.pop("pairing")
        doc["connectors"].append(second)
        with self.assertRaises(ManifestError) as cm:
            build_registry({PACK: doc}, reserved=frozenset())
        self.assertIn("same relay/pairing backend", str(cm.exception))


class ReviewCallTests(_Case):
    def test_the_checked_entry_is_the_one_called_with_a_small_margin_and_a_cap(self):
        self.post("/internal/channels/sms/poll", {"timeout": 3})
        kw = self.fake.kwargs
        self.assertEqual(kw["entry"]["pack"], PACK)
        self.assertEqual(kw["margin"], channels_api.BACKEND_SESSION_MARGIN)
        self.assertLessEqual(kw["margin"], 5)
        self.assertEqual(kw["max_bytes"], 2 * channels_api.MAX_POLL_BYTES + 64 * 1024)

    def test_unknown_tool_and_vault_refusal_are_explicit_502s(self):
        from mcp.shared.exceptions import McpError
        from mcp.types import ErrorData

        def _unknown(*a, **k):
            raise McpError(ErrorData(code=-32601, message="Unknown tool: relay_poll"))

        def _vault(*a, **k):
            try:
                raise PermissionError("mcp: secret of another pack")
            except PermissionError as inner:
                raise BaseExceptionGroup("tg", [inner])   # as anyio wraps it
        for fake, word in ((_unknown, "does not serve"), (_vault, "vault rules")):
            with self.subTest(word=word), \
                    patch.object(proxy, "call_backend_tool_sync", fake):
                r = self.post("/internal/channels/sms/poll", {"timeout": 1})
                self.assertEqual(r.status_code, 502)
                self.assertIn(word, r.json()["error"])

    def test_an_oversized_answer_is_502(self):
        def _big(*a, **k):
            raise proxy.BackendResponseTooLarge("too big")
        with patch.object(proxy, "call_backend_tool_sync", _big):
            self.assertEqual(self.post("/internal/channels/sms/poll",
                                       {"timeout": 1}).status_code, 502)


class WireBoundTests(unittest.TestCase):
    """A hostile http backend streaming a huge answer is cut on the wire."""

    def test_the_response_is_not_read_past_the_cap(self):
        import threading
        import time
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        sent = {"n": 0}

        class Flood(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                self.rfile.read(int(self.headers.get("content-length") or 0))
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.end_headers()
                chunk = b"x" * 65536
                try:
                    for _ in range(4096):          # up to 256 MB
                        self.wfile.write(chunk)
                        sent["n"] += len(chunk)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def do_GET(self):
                self.send_response(405)
                self.end_headers()

            def do_DELETE(self):
                self.send_response(200)
                self.end_headers()

        srv = ThreadingHTTPServer(("127.0.0.1", 0), Flood)
        threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05},
                         daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        entry = {"name": "flood", "transport": "http",
                 "url": f"http://127.0.0.1:{srv.server_address[1]}/mcp"}
        t0 = time.monotonic()
        with self.assertRaises(proxy.BackendResponseTooLarge):
            proxy.call_backend_tool_sync("flood", "relay_poll", {}, 10,
                                         max_bytes=200_000, margin=1, entry=entry)
        self.assertLess(time.monotonic() - t0, 8)
        # The server is cut off long before it has sent its 256 MB.
        self.assertLess(sent["n"], 64 * 1024 * 1024)


class RoomToolsTransportTests(_Case):
    def test_a_transport_is_neither_enablable_nor_accepted(self):
        from . import room_tools
        with patch.object(room_tools, "_catalogue",
                          lambda: {BACKEND: set(), "sms": set(), "topic": {"topic.open"}}):
            self.assertNotIn(BACKEND, room_tools.enablable())
            self.assertIn("sms", room_tools.enablable())
            with self.assertRaises(room_tools.ToolboxError):
                room_tools.check(f"{BACKEND}.*")
            self.assertNotIn(BACKEND, room_tools.mcp_catalogue())

    def test_a_hyphenated_transport_is_matched_normalised(self):
        from . import room_tools
        with patch.object(room_tools, "_catalogue",
                          lambda: {"sms-transport": set()}), \
                patch.object(resolved, "transport_backends",
                             lambda: frozenset({"sms_transport"})):
            self.assertEqual(room_tools.enablable(), {})
            self.assertEqual(room_tools.mcp_catalogue(), {})


if __name__ == "__main__":
    unittest.main()

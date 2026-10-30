"""clodia-platform#638 and #639 — a pack connector's relay transport and its
device pairing step, on the gateway side.

A fixture pack (`sms-demo-pack`) declares an `sms:` vocabulary, a service on
loopback, a `relay:` and a `pairing:`. The service is a real HTTP server on
127.0.0.1 in a thread, so the forwarding is exercised end to end with the
real client: what is tested is what goes over the socket.
"""
from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import AsyncMock, MagicMock, patch

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.testclient import TestClient

from . import channels_api, connectors_api, egress, tools_api, topics_api, whitelist
from . import main as M
from .connectors import actions as ca
from .connectors import first_party_fixture as _first_party
from .connectors import resolved
from .connectors import validate as _validate
from .connectors.manifest import ManifestError, build_registry, parse_connector

_H = {"Authorization": "Bearer ckt1.finto"}


# --------------------------------------------------------------------------
# the fake transport service
# --------------------------------------------------------------------------

class _Service:
    """A loopback HTTP JSON service that records what it receives."""

    def __init__(self):
        self.calls: list[tuple[str, str, dict]] = []
        self.closed = False
        #: The service's per-start secret, as the supervisor would inject it.
        self.token = "svc-secret-1"
        self.answers: dict[str, tuple[int, object]] = {}
        self.refused = 0
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def _answer(self, method):
                n = int(self.headers.get("content-length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}") if n else {}
                # What a conforming service does: refuse without the header.
                if not hmac.compare_digest(
                        self.headers.get("X-Clodia-Service-Token") or "",
                        outer.token):
                    outer.refused += 1
                    status, payload = 401, {"error": "token"}
                else:
                    outer.calls.append((method, self.path, body))
                    answer = outer.answers.get(
                        f"{method} {self.path}", (404, {"error": "no route"}))
                    status, payload = answer(body) if callable(answer) else answer
                raw = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                self._answer("GET")

            def do_POST(self):
                self._answer("POST")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.server.shutdown()
        self.server.server_close()


def _connector(base: str, *, attachments: bool = False, with_relay: bool = True,
               with_pairing: bool = True, **extra) -> dict:
    c = {
        "id": "sms", "manifest_version": 1, "namespace": "sms", "label": "SMS",
        "schemes": [{"scheme": "sms", "direction": "both",
                     "forms": [{"label": "number", "pattern": r"\+[0-9]{6,15}",
                                "example": "+39333000111"}]}],
        "services": [{"name": "sms-relay", "command": ["python3", "relay.py"],
                      "health": {"kind": "tcp",
                                 "target": base.removeprefix("http://")}}],
        "topic_actions": [{"id": "sms-link", "label": "SMS", "binding": "channel",
                           "fields": [{"name": "chat"}],
                           "adds": {"ingress": ["sms:{chat}"],
                                    "egress": ["sms:{chat}"]}}],
    }
    if with_relay:
        c["relay"] = {"service": "sms-relay", "base": base, "label": "SMS",
                      "attachments": attachments}
    if with_pairing:
        c["pairing"] = {"service": "sms-relay", "base": base}
    c.update(extra)
    return c


def _pack(base: str, **kw) -> dict:
    return {"name": "sms-demo-pack", "connectors": [_connector(base, **kw)]}


@contextlib.contextmanager
def _installed(doc: dict):
    """The first-party packs plus `doc`, as the live registry."""
    own = resolved._installed_manifests

    def installed():
        out = dict(own())
        out[doc["name"]] = doc
        return out
    with patch.object(resolved, "_installed_manifests", installed):
        resolved.invalidate()
        try:
            yield
        finally:
            resolved.invalidate()


def setUpModule() -> None:
    _first_party.install()


def tearDownModule() -> None:
    _first_party.uninstall()


# --------------------------------------------------------------------------
# A) manifest
# --------------------------------------------------------------------------

BASE = "http://127.0.0.1:8731"


def _parse(base=BASE, **kw):
    return parse_connector(_connector(base, **kw), pack="sms-demo-pack",
                           reserved=frozenset())


class ManifestTests(unittest.TestCase):
    def test_relay_and_pairing_parse(self):
        c = _parse(attachments=True)
        self.assertEqual((c.relay.service, c.relay.base, c.relay.label,
                          c.relay.attachments),
                         ("sms-relay", BASE, "SMS", True))
        self.assertEqual((c.pairing.service, c.pairing.base, c.pairing.status,
                          c.pairing.start), ("sms-relay", BASE, "/status", "/pair"))

    def test_attachments_default_false_and_pairing_paths_custom(self):
        c = _parse(with_pairing=False)
        self.assertFalse(c.relay.attachments)
        self.assertIsNone(c.pairing)
        c = parse_connector(_connector(BASE, **{"pairing": {
            "service": "sms-relay", "base": BASE,
            "status": "/link/state", "start": "/link/start"}}),
            pack="p", reserved=frozenset())
        self.assertEqual((c.pairing.status, c.pairing.start),
                         ("/link/state", "/link/start"))

    def test_loopback_hosts_accepted(self):
        for base in ("http://127.0.0.1:1", "http://localhost:8080",
                     "http://[::1]:65535"):
            self.assertEqual(_parse(base, **{"relay": {
                "service": "sms-relay", "base": base, "label": "SMS"}}).relay.base,
                base)

    def _refused(self, fragment: str, **kw):
        with self.assertRaises(ManifestError) as cm:
            _parse(**kw)
        self.assertIn(fragment, str(cm.exception))

    def test_bad_bases_are_refused(self):
        for base in ("https://127.0.0.1:8731", "http://10.0.0.1:8731",
                     "http://127.0.0.1", "http://127.0.0.1:8731/",
                     "http://127.0.0.1:8731/x", "http://127.0.0.1:8731?a=1",
                     "http://u@127.0.0.1:8731", "http://127.0.0.1:8731#f",
                     "http://127.0.0.1.evil.io:80", "http://127.0.0.1:87 31",
                     "ftp://127.0.0.1:21", "http://[::1"):
            for key in ("relay", "pairing"):
                with self.subTest(base=base, key=key):
                    with self.assertRaises(ManifestError):
                        _parse(**{key: {"service": "sms-relay", "base": base,
                                        "label": "SMS"}})

    def test_the_service_must_be_the_connectors_own(self):
        self._refused("not one of this connector's services", **{"relay": {
            "service": "other", "base": BASE, "label": "SMS"}})
        self._refused("not one of this connector's services", **{"pairing": {
            "service": "other", "base": BASE}})

    def test_relay_needs_a_scheme_with_forms(self):
        self._refused("forms", schemes=[{"scheme": "sms", "direction": "both"}],
                      topic_actions=[])

    def test_label_rules_and_unknown_keys(self):
        self._refused("label", **{"relay": {"service": "sms-relay", "base": BASE}})
        self._refused("label", **{"relay": {"service": "sms-relay", "base": BASE,
                                            "label": "x" * 33}})
        self._refused("unknown keys", **{"relay": {"service": "sms-relay",
                                                   "base": BASE, "label": "SMS",
                                                   "path": "/x"}})
        self._refused("expected true or false", **{"relay": {
            "service": "sms-relay", "base": BASE, "label": "SMS",
            "attachments": "yes"}})

    def test_pairing_paths_are_plain(self):
        for path in ("status", "/../x", "//x", "/a b", "/x?y", "http://e/x"):
            with self.subTest(path=path):
                self._refused("plain path", **{"pairing": {
                    "service": "sms-relay", "base": BASE, "status": path}})

    def test_an_extends_connector_may_not_declare_them(self):
        for key in ("relay", "pairing"):
            with self.subTest(key=key):
                raw = {"id": "sms-x", "manifest_version": 1, "namespace": "smsx",
                       "extends": "sms",
                       "providers": [{"id": "x"}],
                       key: {"service": "s", "base": BASE, "label": "SMS"}}
                with self.assertRaises(ManifestError) as cm:
                    parse_connector(raw, pack="p", reserved=frozenset())
                self.assertIn(key, str(cm.exception))

    def test_a_gateway_manifest_may_not_declare_them(self):
        raw = _connector(BASE)
        with self.assertRaises(ManifestError):
            parse_connector(raw, pack="gw", builtin=True)

    def test_registry_finds_the_relay_by_scheme(self):
        reg = build_registry({"sms-demo-pack": _pack(BASE)}, reserved=frozenset())
        self.assertEqual(reg.relay_for_scheme("sms").id, "sms")
        self.assertEqual(reg.relay_for_scheme("SMS").id, "sms")
        self.assertIsNone(reg.relay_for_scheme("tg"))


# --------------------------------------------------------------------------
# B) GET /internal/connectors
# --------------------------------------------------------------------------

class ListingTests(unittest.TestCase):
    def test_the_row_shows_relay_and_pairing_but_never_the_base(self):
        reg = build_registry({"sms-demo-pack": _pack(BASE, attachments=True)},
                             reserved=frozenset())
        row = _validate.summary(reg.by_id("sms"))
        self.assertEqual(row["relay"], {"label": "SMS", "attachments": True,
                                        "seal_cap": "SEAL-1", "schemes": ["sms"]})
        self.assertIs(row["pairing"], True)
        self.assertNotIn("8731", json.dumps(row))
        self.assertNotIn("127.0.0.1", json.dumps(row))

    def test_a_connector_without_them_has_the_same_row_as_before(self):
        reg = build_registry({"sms-demo-pack": _pack(BASE, with_relay=False,
                                                     with_pairing=False)},
                             reserved=frozenset())
        row = _validate.summary(reg.by_id("sms"))
        self.assertNotIn("relay", row)
        self.assertNotIn("pairing", row)

    def test_the_route_carries_it(self):
        with _installed(_pack(BASE)), \
                patch.object(connectors_api, "_authorize", lambda r: ({}, None)):
            r = TestClient(Starlette(routes=connectors_api.routes)).get(
                "/internal/connectors", headers=_H)
        self.assertEqual(r.status_code, 200, r.text)
        row = next(c for c in r.json()["connectors"] if c["id"] == "sms")
        self.assertEqual(row["relay"]["label"], "SMS")
        self.assertTrue(row["pairing"])
        tg = next(c for c in r.json()["connectors"] if c["id"] == "telegram")
        self.assertNotIn("relay", tg)


# --------------------------------------------------------------------------
# C) /internal/channels/{connector}/…
# --------------------------------------------------------------------------

class _RouteCase(unittest.TestCase):
    attachments = False

    def setUp(self):
        self.svc = _Service()
        self.addCleanup(self.svc.close)
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(_installed(_pack(self.svc.base,
                                             attachments=self.attachments)))
        self.running = True
        stack.enter_context(patch.object(
            channels_api, "service_token",
            lambda c, s: self.svc.token if self.running else None))
        self.auth = ({"agent": "clodia"}, None)
        stack.enter_context(patch.object(
            channels_api.internal_auth, "authorize",
            lambda *a, **k: self.auth))
        self.client = TestClient(Starlette(routes=channels_api.routes))

    def post(self, path, body):
        return self.client.post(path, json=body, headers=_H)


class ChannelRouteTests(_RouteCase):
    def test_poll_keeps_only_rows_in_the_connectors_own_forms(self):
        good = {"chat_id": "+39333000111", "chat_uri": "sms:+39333000111",
                "sender_uri": "sms:+39333000222", "text": "ciao"}
        no_sender = {"chat_id": "+39333000111", "chat_uri": "sms:+39333000111",
                     "text": "ok"}
        c = "+39333000111"
        rows = [good, no_sender,
                {"chat_id": "-100123", "chat_uri": "tg:-100123", "text": "other scheme"},
                {"chat_id": "pippo", "chat_uri": "sms:pippo", "text": "bad form"},
                {"chat_id": c, "chat_uri": "sms:" + c, "sender_uri": "mailto:a@b.it"},
                {"chat_id": c, "chat_uri": "sms:" + c, "sender_uri": ""},
                {"text": "no chat"}, "not a row",
                # vetted as one chat, answered into another: dropped (#3)
                {"chat_id": "+39333000999", "chat_uri": "sms:" + c, "text": "x"},
                {"chat_uri": "sms:" + c, "text": "no chat_id"},
                {"chat_id": c, "chat_uri": "SMS:" + c, "text": "case"}]
        self.svc.answers["POST /poll"] = (200, {"messages": rows})
        with self.assertLogs("clodia-tools.channels_api", level="WARNING") as logs:
            r = self.post("/internal/channels/sms/poll", {"timeout": 3})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["messages"], [good, no_sender])
        self.assertEqual(self.svc.calls, [("POST", "/poll", {"timeout": 3})])
        self.assertTrue(any("9 relayed row(s) dropped" in m for m in logs.output))
        self.assertTrue(any("<scheme>:<chat_id>" in m for m in logs.output))
        # The dropped values are not in the log: personal data.
        self.assertFalse(any("pippo" in m or "a@b.it" in m for m in logs.output))

    def test_poll_timeout_is_bounded(self):
        self.svc.answers["POST /poll"] = (200, {"messages": []})
        self.post("/internal/channels/sms/poll", {"timeout": 999})
        self.assertEqual(self.svc.calls[-1][2], {"timeout": 50})

    def test_send_forwards_and_answers_ok_and_message_id(self):
        self.svc.answers["POST /send"] = (200, {"ok": True, "message_id": "m-1",
                                                "extra": "dropped"})
        r = self.post("/internal/channels/sms/send",
                      {"chat_id": "+39333000111", "text": "hi", "thread_id": 4})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json(), {"ok": True, "message_id": "m-1"})
        self.assertEqual(self.svc.calls, [("POST", "/send", {
            "chat_id": "+39333000111", "text": "hi", "thread_id": 4})])

    def test_send_validates_its_body(self):
        for body in ({"text": "x"}, {"chat_id": "+1", "text": 3},
                     {"chat_id": "+1", "text": "x", "thread_id": {"a": 1}}):
            with self.subTest(body=body):
                self.assertEqual(self.post("/internal/channels/sms/send",
                                           body).status_code, 400)
        self.assertEqual(self.svc.calls, [])

    def test_download_is_404_without_attachments(self):
        r = self.post("/internal/channels/sms/download", {"file_id": "f1"})
        self.assertEqual(r.status_code, 404)
        self.assertEqual(self.svc.calls, [])

    def test_unknown_connector_and_connector_without_relay_are_404(self):
        for cid in ("nope", "telegram", "core"):
            with self.subTest(cid=cid):
                self.assertEqual(self.post(f"/internal/channels/{cid}/poll",
                                           {}).status_code, 404)
        self.assertEqual(self.svc.calls, [])

    def test_no_other_path_is_proxied(self):
        r = self.post("/internal/channels/sms/status", {})
        self.assertEqual(r.status_code, 404)
        r = self.post("/internal/channels/sms/poll/../status", {})
        self.assertIn(r.status_code, (404, 405))
        self.assertEqual(self.svc.calls, [])

    def test_service_not_running_is_503(self):
        self.running = False
        r = self.post("/internal/channels/sms/send", {"chat_id": "+1", "text": "x"})
        self.assertEqual(r.status_code, 503)
        self.assertEqual(self.svc.calls, [])

    def test_service_not_answering_is_503(self):
        self.svc.close()
        r = self.post("/internal/channels/sms/poll", {"timeout": 1})
        self.assertEqual(r.status_code, 503, r.text)

    def test_service_errors_are_502(self):
        self.svc.answers["POST /send"] = (500, {"error": "boom"})
        r = self.post("/internal/channels/sms/send", {"chat_id": "+1", "text": "x"})
        self.assertEqual(r.status_code, 502)

    def test_same_authorisation_as_the_telegram_routes(self):
        self.auth = (None, JSONResponse({"error": "forbidden"}, status_code=403))
        for op in ("poll", "send", "download"):
            with self.subTest(op=op):
                self.assertEqual(self.post(f"/internal/channels/sms/{op}",
                                           {"chat_id": "+1", "text": "x"}).status_code,
                                 403)
        self.assertEqual(self.svc.calls, [])

    def test_routes_are_mounted_in_the_app(self):
        from .http_app import build_app
        paths = {getattr(r, "path", "") for r in build_app().routes}
        for op in ("poll", "send", "download"):
            self.assertIn(f"/internal/channels/{{connector}}/{op}", paths)


class ChannelDownloadTests(_RouteCase):
    attachments = True

    def test_download_forwards_and_shapes_the_answer(self):
        self.svc.answers["POST /download"] = (200, {
            "content_b64": "aGk=", "size": 2, "mime": "text/plain", "x": 1})
        r = self.post("/internal/channels/sms/download", {"file_id": "f1"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json(), {"content_b64": "aGk=", "size": 2,
                                    "mime": "text/plain"})
        self.assertEqual(self.svc.calls, [("POST", "/download", {"file_id": "f1"})])


class BaseRecheckTests(unittest.TestCase):
    def test_forward_refuses_a_non_loopback_base_at_call_time(self):
        with self.assertRaises(channels_api.RelayRefused):
            asyncio.run(channels_api.forward("http://10.0.0.1:80", "/send", {},
                                             timeout=1, max_bytes=10, token="t"))


# --------------------------------------------------------------------------
# D) bindings under the action's own connector id
# --------------------------------------------------------------------------

class _Room:
    """A topic of tier `tier` whose meta records the owner's SEAL ack the way
    `TopicService.accept_channel_cap` does, bindings in a temp dir."""

    def __init__(self, test, tier: str, doc: dict):
        import shutil
        import tempfile
        from pathlib import Path
        from .tools import telegram_bindings as tb
        self.tmp = tempfile.mkdtemp()
        test.addCleanup(shutil.rmtree, self.tmp, True)
        self.tier = tier
        self.meta = {"tier": tier}
        self.liste: dict = {}
        self.accepted: list = []
        svc = MagicMock()
        svc.open.side_effect = lambda t, n: {"meta": dict(self.meta)}

        def _accept(t, n, ctype, by="", cap=None):
            self.accepted.append((ctype, cap))
            from .topics import service as S
            self.meta[S.CHANNEL_SEAL_ACK] = {"channel": ctype, "tier": tier}
        svc.accept_channel_cap.side_effect = _accept
        self.revoked: list = []

        def _revoke(t, n, ctype=None):
            self.revoked.append(ctype)
            self.meta.pop(S.CHANNEL_SEAL_ACK, None)
        from .topics import service as S
        svc.revoke_channel_cap_ack.side_effect = _revoke
        stack = contextlib.ExitStack()
        test.addCleanup(stack.close)
        for p in (_installed(doc),
                  patch.object(tb, "_path",
                               lambda: Path(self.tmp) / "telegram-bindings.json"),
                  patch.object(egress, "scope_allow",
                               lambda d, s, u: self.liste.setdefault((d, s), []).append(u)),
                  patch.object(egress, "scope_revoke",
                               lambda d, s, u: self.liste.get((d, s), []).remove(u)),
                  patch.object(egress, "scope_uris",
                               lambda d, s, cfg=None: list(self.liste.get((d, s), []))),
                  patch.object(topics_api, "_service", lambda: svc)):
            stack.enter_context(p)

    def apply(self, **body):
        connector, action = ca.find("sms", "sms-link")
        return ca.apply(connector, action, self.tier, "acme", body=body)


class BindingTests(unittest.TestCase):
    def test_binding_channel_writes_under_its_own_connector(self):
        from .tools import channel_bindings as cb
        room = _Room(self, "SEAL-1", _pack(BASE))
        out = room.apply(action="connect", chat="+39333000111")
        self.assertEqual(out["bound"], "+39333000111")
        # Under `sms`, not `telegram`.
        self.assertEqual(cb.load("sms", base=room.tmp),
                         {"+39333000111": {"instance": "messaggero",
                                           "tier": "SEAL-1", "topic": "acme"}})
        self.assertEqual(cb.load("telegram", base=room.tmp), {})
        self.assertEqual(room.liste[("ingress", "SEAL-1/acme")], ["sms:+39333000111"])
        out = room.apply(action="disconnect")
        self.assertIsNone(out["bound"])
        self.assertEqual(cb.load("sms", base=room.tmp), {})
        self.assertEqual(room.liste[("ingress", "SEAL-1/acme")], [])


class SealCapTests(unittest.TestCase):
    """B1: a pack relay is capped, fail closed, with Telegram's ack flow."""

    def test_default_cap_is_seal_1_and_needs_the_owners_ack_above(self):
        from .tools import channel_bindings as cb
        room = _Room(self, "SEAL-2", _pack(BASE))
        connector, action = ca.find("sms", "sms-link")
        seal = ca.state(connector, action, "SEAL-2", "acme")["seal"]
        self.assertEqual((seal["tier"], seal["cap"], seal["requires_ack"]),
                         ("SEAL-2", "SEAL-1", True))
        with self.assertRaises(ca.ActionError) as cm:
            room.apply(action="connect", chat="+39333000111")
        self.assertIn("SEAL-1", str(cm.exception))
        self.assertEqual(cb.load("sms", base=room.tmp), {})
        self.assertEqual(room.liste, {})          # nothing written
        out = room.apply(action="connect", chat="+39333000111",
                         accept_seal_downgrade=True)
        self.assertEqual(out["bound"], "+39333000111")
        self.assertEqual(room.accepted, [("sms", 1)])

    def test_the_manifest_cap_replaces_the_default(self):
        doc = _pack(BASE)
        doc["connectors"][0]["relay"]["seal_cap"] = "SEAL-2"
        room = _Room(self, "SEAL-2", doc)
        self.assertEqual(room.apply(action="connect", chat="+39333000111")["bound"],
                         "+39333000111")
        self.assertEqual(room.accepted, [])
        room3 = _Room(self, "SEAL-3", doc)
        with self.assertRaises(ca.ActionError):
            room3.apply(action="connect", chat="+39333000112")
        connector, action = ca.find("sms", "sms-link")
        self.assertEqual(ca.state(connector, action, "SEAL-3", "acme")["seal"]["cap"],
                         "SEAL-2")

    def test_bad_seal_caps_are_refused(self):
        for cap in ("SEAL-5", "P1", "1", "seal-1", 2):
            with self.subTest(cap=cap):
                with self.assertRaises(ManifestError):
                    _parse(**{"relay": {"service": "sms-relay", "base": BASE,
                                        "label": "SMS", "seal_cap": cap}})

    def test_telegram_keeps_its_table(self):
        from .connectors.actions import channel_cap
        reg = resolved.registry()
        self.assertEqual(channel_cap(reg.by_id("telegram")), 1)


# --------------------------------------------------------------------------
# E) channel.deliver over a relay
# --------------------------------------------------------------------------

ROOM = ("SEAL-2", "preventivi")


class DeliverTests(unittest.TestCase):
    def setUp(self):
        self.sent: list = []
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(_installed(_pack(BASE)))
        self.cfg = {"agents": {"segretario": {"allowed_tools": ["channel.deliver"],
                                              "denied_tools": []}},
                    "egress_allow": [],
                    "scope_egress_allow": {f"{ROOM[0]}/{ROOM[1]}":
                                           ["sms:+39333000111"]}}
        tok = whitelist.set_current_agent("segretario")
        self.addCleanup(whitelist.reset_current_agent, tok)

        async def _send(conn, chat, text, thread_id=None):
            self.sent.append((conn.id, chat, text, thread_id))
            return {"ok": True, "message_id": "m-9"}
        self.gate = AsyncMock(return_value={})
        for p in (patch.object(whitelist, "CONFIG", self.cfg),
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
                  patch.object(M._tlm, "record", lambda *a, **k: None),
                  patch.object(channels_api, "relay_send", _send)):
            stack.enter_context(p)

    def call(self, name, args):
        return asyncio.run(M.call_tool(name, args))[0].text

    def test_a_declared_destination_goes_out_through_the_relay(self):
        out = self.call("channel.deliver", {"destination": "sms:+39333000111",
                                            "text": "ciao", "thread_id": 3})
        self.assertFalse(out.startswith(("DENIED", "ERROR")), out)
        self.assertEqual(self.sent, [("sms", "+39333000111", "ciao", 3)])
        self.assertIn("channel.relay_send", out)

    def test_an_undeclared_destination_is_refused_by_the_egress_pdp(self):
        out = self.call("channel.deliver", {"destination": "sms:+39333000999",
                                            "text": "x"})
        self.assertTrue(out.startswith("DENIED"), out)
        self.assertIn("sms:+39333000999", out)
        self.assertEqual(self.sent, [])

    def test_in_gate_mode_an_undeclared_destination_asks_the_owner(self):
        with patch.object(egress, "mode", lambda: "gate"), \
                patch.object(egress, "remember", lambda *a, **k: []):
            out = self.call("channel.deliver", {"destination": "sms:+39333000999",
                                                "text": "x"})
        self.assertFalse(out.startswith(("DENIED", "ERROR")), out)
        keys = [c.args[1] for c in self.gate.await_args_list]
        self.assertIn("egress:channel:sms:+39333000999", keys)

    def test_a_value_outside_the_forms_is_refused_before_anything(self):
        out = self.call("channel.deliver", {"destination": "sms:pippo", "text": "x"})
        self.assertTrue(out.startswith("ERROR"), out)
        self.assertEqual(self.sent, [])

    def test_attachments_are_refused(self):
        out = self.call("channel.deliver", {"destination": "sms:+39333000111",
                                            "text": "x", "attachments": ["files/a"]})
        self.assertTrue(out.startswith("ERROR"), out)
        self.assertEqual(self.sent, [])

    def test_the_relay_verb_is_unreachable_outside_a_delivery(self):
        self.cfg["agents"]["segretario"]["allowed_tools"].append("channel.relay_send")
        out = self.call("channel.relay_send", {"destination": "sms:+39333000111",
                                               "text": "x"})
        self.assertTrue(out.startswith(("DENIED", "ERROR")), out)
        self.assertEqual(self.sent, [])
        self.assertNotIn("channel.relay_send",
                         {t.name for t in M._all_native_tools()})

    def test_a_service_failure_surfaces_as_an_error(self):
        async def _down(conn, chat, text, thread_id=None):
            raise channels_api.RelayUnavailable("service not reachable")
        with patch.object(channels_api, "relay_send", _down):
            out = self.call("channel.deliver", {"destination": "sms:+39333000111",
                                                "text": "x"})
        self.assertTrue(out.startswith("ERROR"), out)
        self.assertIn("non disponibile", out)


class DeliverProfileAndOwnershipTests(DeliverTests):
    """B2 and follow-up 4, on the same harness as `DeliverTests`."""

    def test_a_profile_listing_channel_deliver_raises_no_card(self):
        self.cfg["agents"]["segretario"]["profile_tools"] = ["channel.deliver"]
        out = self.call("channel.deliver", {"destination": "sms:+39333000111",
                                            "text": "ciao"})
        self.assertFalse(out.startswith(("DENIED", "ERROR")), out)
        self.assertEqual(self.sent, [("sms", "+39333000111", "ciao", None)])
        self.gate.assert_not_awaited()

    def test_a_profile_without_channel_deliver_still_asks(self):
        self.cfg["agents"]["segretario"]["profile_tools"] = ["topic.open"]
        self.call("channel.deliver", {"destination": "sms:+39333000111",
                                      "text": "ciao"})
        self.assertTrue(self.gate.await_args_list)

    def test_a_pack_scheme_without_relay_is_never_mailed(self):
        mailed = []
        with _installed(_pack(BASE, with_relay=False)), \
                patch.object(M, "_room_outbox_account",
                             lambda *a: mailed.append(a) or "info"):
            out = self.call("channel.deliver", {"destination": "sms:+39333000111",
                                                "text": "x"})
        self.assertTrue(out.startswith("ERROR"), out)
        self.assertIn("'sms'", out)
        self.assertEqual((mailed, self.sent), ([], []))

    def test_a_relay_excluded_by_the_profile_is_an_explicit_error(self):
        from . import instance_profile
        with patch.object(instance_profile, "connector_allowed",
                          lambda cid: cid != "sms"):
            out = self.call("channel.deliver", {"destination": "sms:+39333000111",
                                                "text": "x"})
        self.assertTrue(out.startswith("ERROR"), out)
        self.assertIn("non ha un canale", out)
        self.assertEqual(self.sent, [])


class ServiceAddressTests(unittest.TestCase):
    """S1: the base is where the named service listens; one port, one owner."""

    def _with_health(self, health):
        raw = _connector(BASE)
        if health is None:
            raw["services"][0].pop("health")
        else:
            raw["services"][0]["health"] = health
        return raw

    def test_the_base_must_match_the_health_target(self):
        for health in (None,
                       {"kind": "command", "target": "true"},
                       {"kind": "tcp", "target": "127.0.0.1:8732"},
                       {"kind": "http", "target": "http://127.0.0.1:9999/health"},
                       {"kind": "tcp", "target": "localhost:8731"}):
            with self.subTest(health=health):
                with self.assertRaises(ManifestError):
                    parse_connector(self._with_health(health), pack="p",
                                    reserved=frozenset())

    def test_an_http_health_on_the_same_address_is_accepted(self):
        c = parse_connector(self._with_health(
            {"kind": "http", "target": "http://127.0.0.1:8731/health"}),
            pack="p", reserved=frozenset())
        self.assertEqual(c.relay.base, BASE)

    def test_two_connectors_may_not_share_a_port(self):
        other = _pack("http://localhost:8731")
        other["name"] = "other-pack"
        oc = other["connectors"][0]
        oc.update(id="sms2", namespace="sms2", label="SMS 2")
        oc["schemes"][0]["scheme"] = "sms2"
        oc["topic_actions"][0]["adds"] = {"ingress": ["sms2:{chat}"],
                                          "egress": ["sms2:{chat}"]}
        with self.assertRaises(ManifestError) as cm:
            build_registry({"sms-demo-pack": _pack(BASE), "other-pack": other},
                           reserved=frozenset())
        self.assertIn("8731", str(cm.exception))
        self.assertEqual(set(cm.exception.packs), {"sms-demo-pack", "other-pack"})


class ServiceTokenTests(_RouteCase):
    """S2: every forwarded call carries the per-start token."""

    def test_the_token_is_sent_and_a_wrong_one_is_refused_by_the_service(self):
        self.svc.answers["POST /send"] = (200, {"ok": True, "message_id": 1})
        self.assertEqual(self.post("/internal/channels/sms/send",
                                   {"chat_id": "+1", "text": "x"}).status_code, 200)
        self.assertEqual(self.svc.refused, 0)
        with patch.object(channels_api, "service_token", lambda c, s: "stale"):
            r = self.post("/internal/channels/sms/send", {"chat_id": "+1", "text": "x"})
        self.assertEqual(r.status_code, 502)
        self.assertEqual(self.svc.refused, 1)

    def test_no_token_means_unavailable(self):
        with self.assertRaises(channels_api.RelayUnavailable):
            asyncio.run(channels_api.forward(self.svc.base, "/send", {}, timeout=1,
                                             max_bytes=100, token=""))
        self.assertEqual(self.svc.calls, [])


class SupervisorTokenTests(unittest.TestCase):
    """S2: the supervisor makes a new secret per start, injects it, forgets it."""

    def test_token_injected_per_start_and_cleared_on_stop(self):
        import os
        import sys
        import tempfile
        import time
        from pathlib import Path
        from .connectors.manifest import Service
        from .services import launch
        from .services.supervisor import Supervisor
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        script = ("import os,time;"
                  "open(os.path.join(os.environ['CLODIA_SERVICE_STATE_DIR'],'tok'),'w')"
                  ".write(os.environ.get('CLODIA_SERVICE_TOKEN',''));time.sleep(300)")
        svc = Service(name="listener", pack="demo-pack", namespace="demo",
                      command=(sys.executable, "-c", script))
        with patch.dict(os.environ, {"CLODIA_DATA": tmp.name,
                                     "CLODIA_SERVICE_ISOLATION": "off"}):
            sup = Supervisor(lambda: [svc], isolation_probe=lambda p: "")
            self.addCleanup(sup.stop_all)
            sup.reconcile()
            path = Path(tmp.name) / "services/demo-pack/listener/tok"
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and not (path.exists()
                                                        and path.read_text()):
                time.sleep(0.02)
            token = sup.service_token("demo-pack", "listener")
            self.assertTrue(token and len(token) >= 32)
            self.assertEqual(path.read_text(), token)
            self.assertNotIn(token, json.dumps(sup.snapshot()))
            self.assertNotIn(token, repr(sup._entries))
            self.assertIsNone(sup.service_token("demo-pack", "other"))
            sup.stop_all()
            self.assertIsNone(sup.service_token("demo-pack", "listener"))
        self.assertEqual(launch.SERVICE_TOKEN_ENV, "CLODIA_SERVICE_TOKEN")
        self.assertNotEqual(launch.new_service_token(), launch.new_service_token())


class _QueueService:
    """A relay's poll queue with cursors, as a conforming service keeps it."""

    def __init__(self, rows):
        self.queue = list(enumerate(rows, start=1))
        self.acks: list = []

    def __call__(self, body):
        ack = body.get("ack")
        self.acks.append(ack)
        if ack is not None:
            self.queue = [(n, r) for n, r in self.queue if n > int(ack)]
        if not self.queue:
            return 200, {"messages": []}
        return 200, {"messages": [r for _n, r in self.queue],
                     "cursor": str(self.queue[-1][0])}


class PollCursorTests(_RouteCase):
    """BLOCKER-1: ack in, cursor out, whatever rows are dropped."""

    GOOD = {"chat_id": "+39333000111", "chat_uri": "sms:+39333000111", "text": "a"}
    BAD = {"chat_id": "-1", "chat_uri": "tg:-1", "text": "dropped"}

    def test_round_trip_ack_removes_what_the_cursor_covered(self):
        q = _QueueService([self.GOOD, self.BAD])
        self.svc.answers["POST /poll"] = q
        r = self.post("/internal/channels/sms/poll", {"timeout": 1}).json()
        self.assertEqual((r["messages"], r["cursor"]), ([self.GOOD], "2"))
        r2 = self.post("/internal/channels/sms/poll",
                       {"timeout": 1, "ack": r["cursor"]}).json()
        self.assertEqual(r2["messages"], [])
        self.assertNotIn("cursor", r2)
        self.assertEqual(q.acks, [None, "2"])
        self.assertEqual(self.svc.calls[-1][2], {"timeout": 1, "ack": "2"})

    def test_the_cursor_survives_when_every_row_is_dropped(self):
        q = _QueueService([self.BAD, self.BAD])
        self.svc.answers["POST /poll"] = q
        r = self.post("/internal/channels/sms/poll", {"timeout": 1}).json()
        self.assertEqual((r["messages"], r["cursor"]), ([], "2"))
        self.post("/internal/channels/sms/poll", {"timeout": 1, "ack": "2"})
        self.assertEqual(q.queue, [])

    def test_a_bad_ack_is_400_and_a_bad_cursor_is_dropped(self):
        for ack in (5, "", "x" * 513, "a\nb", ["1"]):
            with self.subTest(ack=ack):
                self.assertEqual(self.post("/internal/channels/sms/poll",
                                           {"ack": ack}).status_code, 400)
        self.assertEqual(self.svc.calls, [])
        for cursor in (7, "x" * 513, "a\x00b", {"c": 1}):
            with self.subTest(cursor=cursor):
                self.svc.answers["POST /poll"] = (200, {"messages": [self.GOOD],
                                                        "cursor": cursor})
                r = self.post("/internal/channels/sms/poll", {"timeout": 1}).json()
                self.assertEqual(r["messages"], [self.GOOD])
                self.assertNotIn("cursor", r)


class RetierTests(unittest.TestCase):
    """M2: every connector's bindings follow the room; a pack cap holds."""

    def setUp(self):
        import shutil
        import tempfile
        from pathlib import Path
        from . import taint
        from .topics import retier
        from .topics.local_fs import LocalFsStorage
        from .topics.service import TopicService
        from .tools import channel_bindings as cb
        from .tools import telegram_bindings as tb
        self.retier, self.cb, self.tb = retier, cb, tb
        root = tempfile.mkdtemp()
        self.state = tempfile.mkdtemp()
        for d in (root, self.state):
            self.addCleanup(shutil.rmtree, d, True)
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        for p in (_installed(_pack(BASE)),
                  patch.object(whitelist, "CONFIG", {}),
                  patch.object(whitelist, "save_config", lambda: None),
                  patch.object(whitelist, "reload_config", lambda: None),
                  patch.object(tb, "_path",
                               lambda: Path(self.state) / "telegram-bindings.json"),
                  patch.object(taint, "_path", lambda: Path(self.state) / "taint.json"),
                  patch("server.instance_profile.topic_default_participants",
                        return_value=[])):
            stack.enter_context(p)
        self.svc = TopicService(LocalFsStorage(root))
        self.svc.new("SEAL-1", "acme", {"title": "Acme", "owner": "davide"})
        tb.set_binding("-100", "messaggero", "SEAL-1", "acme")
        cb.set_binding("sms", "+39333000111", "messaggero", "SEAL-1", "acme",
                       base=self.state)

    def test_every_connectors_binding_moves_within_the_cap(self):
        doc = _pack(BASE)
        doc["connectors"][0]["relay"]["seal_cap"] = "SEAL-2"
        with _installed(doc):
            esito = self.retier.apply(self.svc, "SEAL-1", "acme", "SEAL-2",
                                      by="davide", reason="x")
        self.assertEqual(set(esito["bindings"]), {"-100", "sms:+39333000111"})
        self.assertEqual(self.tb.get("-100")["tier"], "SEAL-2")
        self.assertEqual(self.cb.get("sms", "+39333000111", base=self.state)["tier"],
                         "SEAL-2")

    def test_above_a_pack_cap_it_is_refused_without_the_ack(self):
        from .topics.service import TopicError, channel_ack
        with self.assertRaises(TopicError) as cm:
            self.retier.apply(self.svc, "SEAL-1", "acme", "SEAL-2", by="davide",
                              reason="x")
        self.assertIn("'sms'", str(cm.exception))
        self.assertEqual(self.svc.open("SEAL-1", "acme")["meta"]["tier"], "SEAL-1")
        self.assertEqual(self.cb.get("sms", "+39333000111", base=self.state)["tier"],
                         "SEAL-1")
        self.retier.apply(self.svc, "SEAL-1", "acme", "SEAL-2", by="davide",
                          reason="x", accept_seal_downgrade=True)
        ack = channel_ack(self.svc.open("SEAL-2", "acme")["meta"], "sms")
        self.assertEqual((ack["tier"], ack["cap"], ack["by"]),
                         ("SEAL-2", "SEAL-1", "davide"))

    def test_rollback_restores_every_connector(self):
        with patch.object(self.retier, "_rekey_taint",
                          side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                self.retier.apply(self.svc, "SEAL-1", "acme", "SEAL-2",
                                  by="davide", reason="x",
                                  accept_seal_downgrade=True)
        self.assertEqual(self.tb.get("-100")["tier"], "SEAL-1")
        self.assertEqual(self.cb.get("sms", "+39333000111", base=self.state)["tier"],
                         "SEAL-1")
        self.assertNotIn("channel_seal_ack", self.svc.open("SEAL-1", "acme")["meta"])


class AckPerConnectorTests(unittest.TestCase):
    """M3: one acknowledgement per connector; legacy slot readable."""

    def _svc(self):
        import shutil
        import tempfile
        from .topics.local_fs import LocalFsStorage
        from .topics.service import TopicService
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        with patch("server.instance_profile.topic_default_participants",
                   return_value=[]):
            svc = TopicService(LocalFsStorage(root))
            svc.new("SEAL-2", "acme", {"owner": "davide"})
        return svc

    def test_two_acks_and_revoking_one(self):
        from .topics.service import channel_ack, channel_cap_acked
        svc = self._svc()
        svc.accept_channel_cap("SEAL-2", "acme", "telegram", by="davide")
        svc.accept_channel_cap("SEAL-2", "acme", "sms", by="davide", cap=1)
        meta = svc.open("SEAL-2", "acme")["meta"]
        self.assertTrue(channel_cap_acked(meta, "telegram"))
        self.assertTrue(channel_cap_acked(meta, "sms"))
        svc.revoke_channel_cap_ack("SEAL-2", "acme", "sms")
        meta = svc.open("SEAL-2", "acme")["meta"]
        self.assertTrue(channel_cap_acked(meta, "telegram"))
        self.assertIsNone(channel_ack(meta, "sms"))
        svc.revoke_channel_cap_ack("SEAL-2", "acme", "telegram")
        self.assertNotIn("channel_seal_ack", svc.open("SEAL-2", "acme")["meta"])

    def test_the_legacy_single_slot_is_telegrams_and_migrates(self):
        from .topics.service import CHANNEL_SEAL_ACK, channel_ack, channel_cap_acked
        svc = self._svc()
        meta, ver = svc._read_meta("SEAL-2", "acme")
        meta[CHANNEL_SEAL_ACK] = {"channel": "telegram", "tier": "SEAL-2",
                                  "cap": "SEAL-1", "by": "davide", "at": "t"}
        svc._write_meta("SEAL-2", "acme", meta, base_version=ver)
        meta = svc.open("SEAL-2", "acme")["meta"]
        self.assertTrue(channel_cap_acked(meta, "telegram"))
        self.assertFalse(channel_cap_acked(meta, "sms"))
        svc.accept_channel_cap("SEAL-2", "acme", "sms", by="davide", cap=1)
        raw = svc.open("SEAL-2", "acme")["meta"][CHANNEL_SEAL_ACK]
        self.assertEqual(set(raw), {"telegram", "sms"})
        self.assertEqual(channel_ack({CHANNEL_SEAL_ACK: raw}, "telegram")["by"],
                         "davide")

    def test_disconnecting_a_relay_revokes_only_its_ack(self):
        room = _Room(self, "SEAL-2", _pack(BASE))
        room.apply(action="connect", chat="+39333000111", accept_seal_downgrade=True)
        room.apply(action="disconnect")
        self.assertEqual(room.revoked, ["sms"])


class ServiceAddressUniquenessTests(unittest.TestCase):
    """M4: no two services of the registry share a health address."""

    def _plain(self, pack, cid, target, kind="tcp"):
        return {"name": pack, "connectors": [{
            "id": cid, "manifest_version": 1, "namespace": cid.replace("-", ""),
            "taint": [f"{cid.replace('-', '')}.read"],
            "services": [{"name": "svc", "command": ["x"],
                          "health": {"kind": kind, "target": target}}]}]}

    def test_duplicates_across_packs_are_refused(self):
        for a, b in (("127.0.0.1:9100", "127.0.0.1:9100"),
                     ("127.0.0.1:9100", "localhost:9100"),
                     ("127.0.0.1:9100", "http://[::1]:9100/health")):
            with self.subTest(a=a, b=b):
                kb = "http" if b.startswith("http") else "tcp"
                with self.assertRaises(ManifestError) as cm:
                    build_registry({"pa": self._plain("pa", "ca", a),
                                    "pb": self._plain("pb", "cb", b, kb)},
                                   reserved=frozenset())
                self.assertEqual(set(cm.exception.packs), {"pa", "pb"})

    def test_distinct_addresses_and_command_checks_are_fine(self):
        reg = build_registry({"pa": self._plain("pa", "ca", "127.0.0.1:9100"),
                              "pb": self._plain("pb", "cb", "127.0.0.1:9101"),
                              "pc": self._plain("pc", "cc", "true", "command"),
                              "pd": self._plain("pd", "cd", "true", "command")},
                             reserved=frozenset())
        self.assertEqual(len(reg.services()), 4)

    def test_a_relay_on_another_packs_service_port_is_refused(self):
        with self.assertRaises(ManifestError):
            build_registry({"sms-demo-pack": _pack(BASE),
                            "pa": self._plain("pa", "ca", "127.0.0.1:8731")},
                           reserved=frozenset())


class SupervisorExitClearsEnvTests(unittest.TestCase):
    """Low: an exited process leaves neither its env nor its token behind."""

    def test_exit_clears_env_and_token(self):
        import os
        import sys
        import tempfile
        import time
        from .connectors.manifest import Service
        from .services.supervisor import Supervisor
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        svc = Service(name="once", pack="demo-pack", namespace="demo",
                      command=(sys.executable, "-c", "import sys; sys.exit(0)"),
                      restart="never")
        with patch.dict(os.environ, {"CLODIA_DATA": tmp.name,
                                     "CLODIA_SERVICE_ISOLATION": "off"}):
            sup = Supervisor(lambda: [svc], isolation_probe=lambda p: "")
            self.addCleanup(sup.stop_all)
            sup.reconcile()
            entry = next(iter(sup._entries.values()))
            self.assertIn("CLODIA_SERVICE_TOKEN", entry.env)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and entry.proc.poll() is None:
                time.sleep(0.02)
            sup.reconcile()
            self.assertEqual(entry.state, "exited")
            self.assertIsNone(entry.env)
            self.assertEqual(entry.token, "")
            self.assertIsNone(sup.service_token("demo-pack", "once"))


# --------------------------------------------------------------------------
# F) message kind `channel`
# --------------------------------------------------------------------------

class MessageKindTests(unittest.TestCase):
    def _svc(self):
        import tempfile
        from .topics.local_fs import LocalFsStorage
        from .topics.service import TopicService
        root = tempfile.mkdtemp()
        self.addCleanup(__import__("shutil").rmtree, root, True)
        svc = TopicService(LocalFsStorage(root))
        svc.new("SEAL-1", "acme", {"owner": "davide"})
        return svc

    def test_channel_is_a_kind_carries_its_transport_and_does_not_taint(self):
        from . import taint
        svc = self._svc()
        marks = []
        with patch.object(taint, "mark", lambda *a, **k: marks.append(a)), \
                patch("server.tools.runtime.announce_message", lambda *a, **k: None):
            msg = svc.post_message("SEAL-1", "acme", "+39333000111", "ciao",
                                   kind="channel", transport="SMS")
            svc.post_message("SEAL-1", "acme", "x", "y", kind="proxy")
        self.assertEqual((msg["kind"], msg["transport"]), ("channel", "SMS"))
        self.assertEqual(len(marks), 1)          # the proxy one only
        self.assertIn("proxy", marks[0][2])

    def test_a_channel_message_needs_a_transport_label(self):
        from .topics.service import TopicError
        svc = self._svc()
        for label in (None, "", "x" * 33, "a\nb"):
            with self.subTest(label=label), \
                    patch("server.tools.runtime.announce_message", lambda *a, **k: None):
                with self.assertRaises(TopicError):
                    svc.post_message("SEAL-1", "acme", "a", "t", kind="channel",
                                     transport=label)

    def test_other_kinds_ignore_the_transport(self):
        svc = self._svc()
        with patch("server.tools.runtime.announce_message", lambda *a, **k: None):
            msg = svc.post_message("SEAL-1", "acme", "a", "t", kind="telegram",
                                   transport="SMS")
        self.assertNotIn("transport", msg)

    def test_the_route_passes_transport_and_refuses_it_missing(self):
        svc = MagicMock()
        svc.post_message.return_value = {"id": "1"}
        with patch.object(topics_api, "_service", lambda: svc), \
                patch.object(topics_api, "_authorize", lambda r: ("clodia", None)):
            c = TestClient(Starlette(routes=topics_api.routes))
            r = c.post("/internal/topics/SEAL-1/acme/messages", headers=_H,
                       json={"author": "+39333", "text": "x", "kind": "channel",
                             "transport": "SMS"})
            self.assertEqual(r.status_code, 200, r.text)
            self.assertEqual(svc.post_message.call_args.kwargs["transport"], "SMS")
            r = c.post("/internal/topics/SEAL-1/acme/messages", headers=_H,
                       json={"author": "+39333", "text": "x", "kind": "channel"})
            self.assertEqual(r.status_code, 400)
            r = c.post("/internal/topics/SEAL-1/acme/messages", headers=_H,
                       json={"author": "a", "text": "x", "kind": "telegram"})
            self.assertEqual(r.status_code, 200)
            self.assertNotIn("transport", svc.post_message.call_args.kwargs)

    def test_the_topic_index_treats_it_like_telegram(self):
        from . import topic_index
        self.assertEqual(topic_index._messages_provenance([{"kind": "channel"}], False),
                         "untrusted")


# --------------------------------------------------------------------------
# G) pairing (#639)
# --------------------------------------------------------------------------

class PairingTests(unittest.TestCase):
    def setUp(self):
        self.svc = _Service()
        self.addCleanup(self.svc.close)
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(_installed(_pack(self.svc.base)))
        self.running = True
        stack.enter_context(patch.object(
            channels_api, "service_token",
            lambda c, s: self.svc.token if self.running else None))
        self.admin = True
        stack.enter_context(patch.object(tools_api, "_authorized_owner",
                                         lambda r: self.admin))
        self.client = TestClient(Starlette(routes=tools_api.routes))

    def test_status_returns_only_the_declared_fields(self):
        self.svc.answers["GET /status"] = (200, {
            "state": "pairing", "code": "ABCD-1234", "qr": "2@xyz,abc",
            "me": 5, "secret": "s3cr3t", "error": "x" * 500})
        with self.assertLogs("clodia-tools.tools_api", level="INFO") as logs:
            r = self.client.get("/tools/connectors/sms/pairing", headers=_H)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(set(r.json()), {"state", "code", "qr", "error"})
        self.assertEqual(r.json()["code"], "ABCD-1234")
        self.assertEqual(len(r.json()["error"]), 300)
        self.assertEqual(self.svc.calls, [("GET", "/status", {})])
        joined = "\n".join(logs.output)
        self.assertNotIn("ABCD-1234", joined)
        self.assertNotIn("2@xyz", joined)

    def test_post_starts_pairing(self):
        self.svc.answers["POST /pair"] = (200, {"state": "pairing", "code": "9999"})
        r = self.client.post("/tools/connectors/sms/pairing", headers=_H)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json(), {"state": "pairing", "code": "9999"})
        self.assertEqual(self.svc.calls[-1][:2], ("POST", "/pair"))

    def test_open_shows_me(self):
        self.svc.answers["GET /status"] = (200, {"state": "open", "me": "+39333"})
        self.assertEqual(self.client.get("/tools/connectors/sms/pairing",
                                         headers=_H).json(),
                         {"state": "open", "me": "+39333"})

    def test_a_code_smuggled_in_state_does_not_reach_the_log(self):
        self.svc.answers["GET /status"] = (200, {"state": "CODE 1234-5678"})
        with self.assertLogs("clodia-tools.tools_api", level="INFO") as logs:
            self.client.get("/tools/connectors/sms/pairing", headers=_H)
        self.assertNotIn("1234-5678", "\n".join(logs.output))

    def test_non_admin_is_refused(self):
        self.admin = False
        for method in ("get", "post"):
            r = getattr(self.client, method)("/tools/connectors/sms/pairing",
                                             headers=_H)
            self.assertEqual(r.status_code, 401)
        self.assertEqual(self.svc.calls, [])

    def test_404_without_pairing_and_503_when_down(self):
        for cid in ("telegram", "nope"):
            self.assertEqual(self.client.get(f"/tools/connectors/{cid}/pairing",
                                             headers=_H).status_code, 404)
        self.running = False
        self.assertEqual(self.client.get("/tools/connectors/sms/pairing",
                                         headers=_H).status_code, 503)
        self.running = True
        self.svc.close()
        self.assertEqual(self.client.post("/tools/connectors/sms/pairing",
                                          headers=_H).status_code, 503)

    def test_the_real_admin_check_refuses_an_agent_token(self):
        """`role: agent-server` passes `_authorized`, not `_authorized_owner`:
        the pairing code is not the agent-server's."""
        from . import pki_verify
        with patch.object(tools_api, "_authorized_owner",
                          _REAL_AUTHORIZED_OWNER), \
                patch.object(tools_api, "_UI_TOKEN", "ui-token"), \
                patch.object(pki_verify, "verify_session_token",
                             lambda t: {"agent": "clodia",
                                        "role": "agent-server"}), \
                patch.object(tools_api, "_revocata", lambda p: False), \
                patch.object(tools_api, "_is_human_admin", lambda n: False):
            r = self.client.get("/tools/connectors/sms/pairing", headers=_H)
        self.assertEqual(r.status_code, 401)


class PairingFollowUpTests(PairingTests):
    def test_a_service_4xx_comes_back_filtered_with_its_status(self):
        self.svc.answers["POST /pair"] = (409, {"state": "open", "me": "+39",
                                               "error": "already paired",
                                               "secret": "x"})
        r = self.client.post("/tools/connectors/sms/pairing", headers=_H)
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.json(), {"state": "open", "me": "+39",
                                    "error": "already paired"})

    def test_a_service_refusing_the_gateway_is_502_not_401(self):
        with patch.object(channels_api, "service_token", lambda c, s: "stale"):
            r = self.client.get("/tools/connectors/sms/pairing", headers=_H)
        self.assertEqual(r.status_code, 502)
        self.assertEqual(self.svc.refused, 1)

    def test_pairing_start_is_audited_without_the_code(self):
        from .audit import control
        events = []
        self.svc.answers["POST /pair"] = (200, {"state": "pairing", "code": "C0DE-42"})
        self.svc.answers["GET /status"] = (200, {"state": "pairing", "code": "C0DE-42"})
        with patch.object(control, "emit", lambda *a, **k: events.append((a, k))), \
                patch.object(tools_api, "_admin_principal", lambda r: "davide"):
            self.client.get("/tools/connectors/sms/pairing", headers=_H)
            self.assertEqual(events, [])
            self.client.post("/tools/connectors/sms/pairing", headers=_H)
        self.assertEqual(events, [(("connector", "pairing_start", "sms"),
                                   {"admin": "davide", "pack": "sms-demo-pack"})])
        self.assertNotIn("C0DE", json.dumps(events))


_REAL_AUTHORIZED_OWNER = tools_api._authorized_owner


if __name__ == "__main__":
    unittest.main()

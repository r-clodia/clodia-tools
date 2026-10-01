"""clodia-platform#463 — W3C `traceparent`, and the egress proxy on the trail.

- The gateway accepts a `traceparent` header. It names the trace only when no
  spawn is behind the request (an internal agent-server call); under an
  announced turn it is a closer parent on the same trace, or a LINK on another
  one (a runtime's own OTel trace). An agent cannot re-label its turn with it.
- The egress proxy reports each request with the spawn credentials it received.
  With a valid tag the record is `egress.connect` under the trace of the
  spawn's current turn — the same trace id as the turn's `tool.call`. Without
  one, it is recorded without a spawn, never with the spawn it claims.
"""
from __future__ import annotations

import os
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from . import audit, egress_proxy_api
from .audit import trace
from .claims import ClaimsContext
from .test_433_450_trace_and_mint import SPAN, SPAWN_TOKEN, TRACE, _AuditEnv

OTHER_TRACE, OTHER_SPAN = "0af7651916cd43dd8448eb211c80319c", "b7ad6b7169203331"
PROXY_SECRET = "proxy-s"


class ParseTraceparentTests(_AuditEnv):
    def test_valid_and_invalid(self) -> None:
        self.assertEqual(trace.parse_traceparent(f"00-{TRACE}-{SPAN}-01"), (TRACE, SPAN))
        self.assertEqual(trace.parse_traceparent(f"00-{TRACE.upper()}-{SPAN}-00"), (TRACE, SPAN))
        # a future version may carry more fields; version 00 may not
        self.assertEqual(trace.parse_traceparent(f"01-{TRACE}-{SPAN}-01-xyz"), (TRACE, SPAN))
        for bad in ("", None, f"00-{TRACE}-{SPAN}-01-xyz", f"ff-{TRACE}-{SPAN}-01",
                    f"00-{'0' * 32}-{SPAN}-01", f"00-{TRACE}-{'0' * 16}-01",
                    f"00-{TRACE[:-1]}-{SPAN}-01", "garbage"):
            self.assertIsNone(trace.parse_traceparent(bad), bad)
        self.assertEqual(trace.format_traceparent(TRACE, SPAN), f"00-{TRACE}-{SPAN}-01")


class TraceparentOnTheTrailTests(_AuditEnv):
    """Through the real middleware, so the header really travels to `emit`."""

    def setUp(self) -> None:
        super().setUp()

        async def emit_one(request):
            claims = SPAWN_TOKEN if request.query_params.get("spawn") else {}
            with ClaimsContext(claims, "t"):
                rec = audit.emit("tool.call", identity="explicit", action="execute",
                                 resource="topic.open", actor={"type": "agent", "id": "x"})
            return JSONResponse({"id": rec["event_id"]})

        self.app = TestClient(Starlette(
            routes=[Route("/e", emit_one, methods=["POST"])],
            middleware=[Middleware(trace.TraceparentMiddleware)]))

    def post(self, *, spawn: bool, tp: str | None, paired: dict | None = None) -> dict:
        h = {"traceparent": tp} if tp else {}
        # The agent-server's internal calls carry its secret (see _AuditEnv).
        h.update(paired if paired is not None else ({} if spawn else self.h))
        self.app.post("/e" + ("?spawn=1" if spawn else ""), headers=h)
        return self.events()[-1]

    def test_an_internal_call_takes_the_trace_of_its_traceparent(self) -> None:
        ev = self.post(spawn=False, tp=f"00-{TRACE}-{SPAN}-01")
        self.assertEqual((ev["trace_id"], ev["parent_span_id"]), (TRACE, SPAN))
        self.assertNotIn("links", ev)

    def test_the_proxy_is_a_paired_caller_too(self) -> None:
        with patch.dict(os.environ, {"CLODIA_EGRESS_PROXY_SECRET": PROXY_SECRET}):
            ev = self.post(spawn=False, tp=f"00-{TRACE}-{SPAN}-01",
                           paired={"x-egress-proxy-secret": PROXY_SECRET})
        self.assertEqual(ev["trace_id"], TRACE)

    def test_an_unauthenticated_spawnless_call_cannot_name_a_trace(self) -> None:
        # #470 review: without a verified spawn AND without the agent-server's
        # (or the proxy's) secret, the header must not place the event in
        # someone else's turn. It is kept as a link, the caller's word.
        for paired in ({}, {"x-orchestrator-secret": "wrong"},
                       {"x-orchestrator-secret": "sé".encode("latin-1")}, {"x-egress-proxy-secret": "s"}):
            ev = self.post(spawn=False, tp=f"00-{TRACE}-{SPAN}-01", paired=paired)
            self.assertNotIn("trace_id", ev, paired)
            self.assertNotIn("parent_span_id", ev, paired)
            self.assertEqual(ev["links"][0]["trace_id"], TRACE, paired)

    def test_under_a_turn_a_foreign_traceparent_is_a_link_not_the_trace(self) -> None:
        trace.start("clodia-320", TRACE, SPAN)
        ev = self.post(spawn=True, tp=f"00-{OTHER_TRACE}-{OTHER_SPAN}-01")
        self.assertEqual((ev["trace_id"], ev["parent_span_id"]), (TRACE, SPAN))
        self.assertEqual(ev["links"], [{"trace_id": OTHER_TRACE, "span_id": OTHER_SPAN,
                                        "attributes": {"link.source": "traceparent"}}])

    def test_under_a_turn_the_same_trace_gives_a_closer_parent(self) -> None:
        trace.start("clodia-320", TRACE, SPAN)
        ev = self.post(spawn=True, tp=f"00-{TRACE}-{OTHER_SPAN}-01")
        self.assertEqual((ev["trace_id"], ev["parent_span_id"]), (TRACE, OTHER_SPAN))

    def test_a_spawn_between_turns_cannot_name_a_trace(self) -> None:
        ev = self.post(spawn=True, tp=f"00-{OTHER_TRACE}-{OTHER_SPAN}-01")
        self.assertNotIn("trace_id", ev)
        self.assertEqual(ev["links"][0]["trace_id"], OTHER_TRACE)

    def test_no_header_no_change(self) -> None:
        ev = self.post(spawn=False, tp=None)
        self.assertNotIn("trace_id", ev)
        self.assertNotIn("links", ev)
        ev = self.post(spawn=False, tp="00-nonsense")
        self.assertNotIn("trace_id", ev)


class ReportedLinksTests(_AuditEnv):
    def test_turn_start_keeps_valid_links_and_drops_the_rest(self) -> None:
        r = self.c.post("/internal/audit/event", headers=self.h, json={
            "type": "turn.start", "action": "start", "trace_id": TRACE, "span_id": SPAN,
            "agent": {"seed": "clodia", "spawn": "clodia-320"},
            "links": [{"trace_id": OTHER_TRACE, "attributes": {"link.source": "runtime",
                                                               "nested": {"x": 1}}},
                      {"trace_id": "0" * 32}, "junk"]})
        self.assertEqual(r.status_code, 200, r.text)
        ev = self.events()[-1]
        self.assertEqual(ev["links"], [{"trace_id": OTHER_TRACE,
                                        "attributes": {"link.source": "runtime"}}])


class EgressRecordTests(_AuditEnv):
    def setUp(self) -> None:
        super().setUp()
        env = patch.dict(os.environ, {"CLODIA_EGRESS_PROXY_SECRET": PROXY_SECRET})
        env.start()
        self.addCleanup(env.stop)
        self.now = [1000.0]
        den = patch.object(egress_proxy_api, "_denials",
                           egress_proxy_api._Denials(clock=lambda: self.now[0]))
        den.start()
        self.addCleanup(den.stop)
        self.proxy = TestClient(Starlette(routes=egress_proxy_api.routes))
        self.ph = {"x-egress-proxy-secret": PROXY_SECRET}

    def report(self, **kw) -> dict:
        body = {"host": "api.anthropic.com", "port": 443, "method": "CONNECT",
                "allowed": True, **kw}
        r = self.proxy.post("/internal/egress/record", headers=self.ph, json=body)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def test_the_proxy_record_and_the_tool_call_share_the_trace(self) -> None:
        self.c.post("/internal/audit/event", headers=self.h, json={
            "type": "turn.start", "action": "start", "trace_id": TRACE, "span_id": SPAN,
            "agent": {"seed": "clodia", "spawn": "clodia-320"}})
        self.call()                                           # tool.call + tool.result
        out = self.report(spawn="clodia-320", tag=trace.egress_tag("clodia-320"))
        self.assertEqual((out["trace_id"], out["spawn"], out["attribution"]),
                         (TRACE, "clodia-320", "verified"))
        evs = self.events()
        call = next(e for e in evs if e["event"]["type"] == "tool.call")
        eg = next(e for e in evs if e["event"]["type"] == "egress.connect")
        self.assertEqual(eg["trace_id"], call["trace_id"])
        self.assertEqual(eg["parent_span_id"], SPAN)
        self.assertEqual(eg["event_id"], out["event_id"])
        self.assertEqual(eg["event"]["resource"], "api.anthropic.com:443")
        self.assertEqual(eg["agent"], {"seed": "clodia", "spawn": "clodia-320"})
        self.assertEqual(eg["actor"]["source"], "egress-proxy")
        self.assertEqual(eg["security"], {"attribution": "verified"})
        self.assertNotIn(trace.egress_tag("clodia-320"), str(evs))   # the tag is not recorded

    def test_a_wrong_tag_is_not_attributed(self) -> None:
        trace.start("clodia-320", TRACE, SPAN)
        out = self.report(spawn="clodia-320", tag=trace.egress_tag("clodia-321"))
        self.assertEqual((out["trace_id"], out["spawn"], out["attribution"]),
                         (None, None, "unverified"))
        ev = self.events()[-1]
        self.assertNotIn("trace_id", ev)
        self.assertNotIn("agent", ev)

    def test_no_credentials_and_a_denied_host(self) -> None:
        out = self.report(host="evil.example", allowed=False, reason="filtered")
        self.assertEqual(out["attribution"], "none")
        ev = self.events()[-1]
        self.assertEqual(ev["event"]["action"], "deny")
        self.assertEqual(ev["decision"], {"allowed": False, "reason": "filtered"})

    def test_between_turns_the_spawn_is_known_but_no_trace(self) -> None:
        out = self.report(spawn="clodia-320", tag=trace.egress_tag("clodia-320"))
        self.assertEqual((out["spawn"], out["trace_id"]), ("clodia-320", None))

    def test_authentication_is_its_own_secret(self) -> None:
        body = {"host": "a.b", "port": 443, "method": "CONNECT", "allowed": True}
        self.assertEqual(self.proxy.post("/internal/egress/record", json=body).status_code, 401)
        # the orchestrator secret is not the proxy's
        self.assertEqual(self.proxy.post("/internal/egress/record", json=body,
                                         headers={"x-egress-proxy-secret": "s"}).status_code, 401)
        with patch.dict(os.environ, {"CLODIA_EGRESS_PROXY_SECRET": ""}):
            self.assertEqual(self.proxy.post("/internal/egress/record", json=body,
                                             headers=self.ph).status_code, 401)

    def test_a_non_ascii_secret_is_a_401_not_a_500(self) -> None:
        body = {"host": "a.b", "port": 443, "method": "CONNECT", "allowed": True}
        for got in ("prox\u00e9-s", "\u00ff" * 8):
            r = self.proxy.post("/internal/egress/record", json=body,
                                headers={"x-egress-proxy-secret": got.encode("latin-1")})
            self.assertEqual(r.status_code, 401, got)
        r = self.c.post("/internal/audit/checkpoint",
                        headers={"x-orchestrator-secret": "\u00e9".encode("latin-1")})
        self.assertEqual(r.status_code, 401)
        with patch.dict(os.environ, {"CLODIA_EGRESS_PROXY_SECRET": "s\u00e9cret"}):
            r = self.proxy.post("/internal/egress/record", json=body,
                                headers={"x-egress-proxy-secret": "s\u00e9cret".encode("utf-8")})
            self.assertEqual(r.status_code, 401)   # latin-1 decoded: not equal, no crash

    def test_a_non_ascii_or_malformed_tag_is_unverified_not_an_error(self) -> None:
        good = trace.egress_tag("clodia-320")
        for tag in ("\u00e9" * 32, good[:-1] + "\u00e9", good + "\x00", 42, ["x"], {}):
            self.assertFalse(trace.verify_egress("clodia-320", tag), repr(tag))
            out = self.report(spawn="clodia-320", tag=tag)
            self.assertEqual(out["attribution"], "unverified", repr(tag))
        self.assertTrue(trace.verify_egress("clodia-320", f" {good.upper()} "))
        self.assertTrue(trace.secret_equal("\u00e9", "\u00e9"))
        self.assertFalse(trace.secret_equal("", ""))
        self.assertFalse(trace.secret_equal("\u00e9", "e"))

    def test_a_trailing_newline_is_not_a_host_nor_an_id(self) -> None:
        for host in ("api.anthropic.com\n", "a.b\r\n", "a.b\x00"):
            body = {"host": host, "port": 443, "method": "CONNECT", "allowed": True}
            r = self.proxy.post("/internal/egress/record", headers=self.ph, json=body)
            self.assertEqual(r.status_code, 400, repr(host))
        self.assertFalse(trace.valid_trace_id(TRACE + "\n"))
        self.assertFalse(trace.valid_span_id(SPAN + "\n"))
        self.assertFalse(trace.valid_spawn_label("clodia-320\n"))
        self.assertIsNone(trace.parse_traceparent(f"00-{TRACE}-{SPAN}-01\n\n\x00"))

    def test_repeated_denials_are_one_event_and_a_count(self) -> None:
        deny = {"host": "evil.example", "allowed": False, "reason": "filtered"}
        first = self.report(**deny)
        self.assertTrue(first["recorded"])
        n0 = len(self.events())
        for _ in range(50):
            out = self.report(**deny)
            self.assertEqual((out["recorded"], out["coalesced"], out["event_id"]),
                             (False, True, first["event_id"]))
        self.assertEqual(len(self.events()), n0)            # the chain did not grow
        # a different destination, and an allowed request, are not coalesced
        self.assertTrue(self.report(host="other.example", allowed=False)["recorded"])
        self.assertTrue(self.report()["recorded"])
        self.assertTrue(self.report()["recorded"])
        # the window closes: the next report writes the summary of the repeats
        self.now[0] += 61
        self.report()
        summary = [e for e in self.events() if (e.get("decision") or {}).get("coalesced")]
        self.assertEqual(len(summary), 1)
        d = summary[0]["decision"]
        self.assertEqual((d["count"], d["first_event_id"], d["reason"], d["allowed"]),
                         (50, first["event_id"], "filtered", False))
        self.assertEqual(summary[0]["event"]["resource"], "evil.example:443")
        # other.example had no repeats: no summary for it; a new window records again
        self.assertTrue(self.report(**deny)["recorded"])

    def test_denials_are_coalesced_per_source(self) -> None:
        tag = trace.egress_tag("clodia-320")
        deny = {"host": "evil.example", "allowed": False, "reason": "filtered"}
        self.assertTrue(self.report(**deny)["recorded"])
        # the same destination from a verified spawn is another source
        self.assertTrue(self.report(spawn="clodia-320", tag=tag, **deny)["recorded"])
        self.assertTrue(self.report(spawn="clodia-320", tag=tag, **deny)["coalesced"])

    def test_varying_the_host_does_not_escape_the_limit(self) -> None:
        tag = trace.egress_tag("clodia-320")
        with patch.dict(os.environ, {"CLODIA_EGRESS_DENY_BURST": "5"}):
            n0 = len(self.events())
            outs = [self.report(spawn="clodia-320", tag=tag, host=f"h{i}.evil.example",
                                allowed=False, reason="filtered") for i in range(40)]
            self.assertEqual(sum(o["recorded"] for o in outs), 5)
            self.assertEqual(len(self.events()) - n0, 5)
            egress_proxy_api._denials.flush()
        over = [e for e in self.events() if (e.get("decision") or {}).get("reason") == "rate_limited"]
        self.assertEqual(len(over), 1)
        self.assertEqual(over[0]["decision"]["count"], 35)
        self.assertEqual(over[0]["agent"]["spawn"], "clodia-320")

    def test_an_address_refusal_keeps_its_reason(self) -> None:
        self.report(host="good.example", allowed=False, reason="address")
        self.assertEqual(self.events()[-1]["decision"], {"allowed": False, "reason": "address"})

    def test_malformed_reports_are_refused(self) -> None:
        for bad in ({"host": "a b"}, {"port": 0}, {"port": "x"}, {"method": "BREW"}):
            body = {"host": "a.b", "port": 443, "method": "CONNECT", "allowed": True, **bad}
            r = self.proxy.post("/internal/egress/record", headers=self.ph, json=body)
            self.assertEqual(r.status_code, 400, bad)

    def test_the_tag_depends_on_spawn_and_secret(self) -> None:
        a = trace.egress_tag("clodia-320")
        self.assertRegex(a, r"^[0-9a-f]{32}$")
        self.assertNotEqual(a, trace.egress_tag("clodia-321"))
        self.assertNotEqual(a, trace.egress_tag("clodia-320", secret="other"))
        self.assertIsNone(trace.egress_tag("clodia-320", secret=""))
        self.assertIsNone(trace.egress_tag("bad label"))
        self.assertTrue(trace.verify_egress("clodia-320", a))
        self.assertFalse(trace.verify_egress("clodia-320", None))


class WiringTests(_AuditEnv):
    def test_the_gateway_app_reads_traceparent_and_serves_the_proxy_route(self) -> None:
        from . import http_app
        app = http_app.build_app()
        self.assertIn(trace.TraceparentMiddleware, [m.cls for m in app.user_middleware])
        self.assertIn("/internal/egress/record", [getattr(r, "path", "") for r in app.routes])

    def test_the_inflight_log_label_falls_back_to_traceparent(self) -> None:
        from . import inflight
        scope = {"headers": [(b"traceparent", f"00-{TRACE}-{SPAN}-01".encode())]}
        self.assertEqual(inflight._trace_of(scope), TRACE)
        scope["headers"].append((b"x-clodia-trace-id", OTHER_TRACE.encode()))
        self.assertEqual(inflight._trace_of(scope), OTHER_TRACE)


class ChannelTriggerCarriesTheTurnTests(_AuditEnv):
    """#465: a turn woken by `runtime.channel_trigger` hangs under the caller's."""

    def sent_headers(self, claims: dict) -> dict:
        from unittest.mock import MagicMock
        from .tools import runtime
        client = MagicMock()
        client.post.return_value = MagicMock(status_code=200, json=lambda: {"ok": True})
        ctx = MagicMock()
        ctx.__enter__.return_value = client
        with ClaimsContext(claims, "tok"), patch.object(runtime.httpx, "Client",
                                                        return_value=ctx):
            runtime.channel_trigger("SEAL-2", "titulon-tech", "@ophelia ciao", by="clodia")
        return client.post.call_args.kwargs["headers"]

    def test_inside_a_turn_the_traceparent_is_the_callers_turn(self) -> None:
        trace.start("clodia-320", TRACE, SPAN)
        h = self.sent_headers(SPAWN_TOKEN)
        self.assertEqual(h["traceparent"], f"00-{TRACE}-{SPAN}-01")
        self.assertEqual(h["Authorization"], "Bearer tok")   # only with authentication

    def test_outside_a_turn_or_without_a_spawn_nothing_is_invented(self) -> None:
        self.assertNotIn("traceparent", self.sent_headers(SPAWN_TOKEN))
        trace.start("clodia-320", TRACE, SPAN)
        self.assertNotIn("traceparent", self.sent_headers({"agent": "clodia"}))


if __name__ == "__main__":
    import unittest
    unittest.main()

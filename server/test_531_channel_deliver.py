"""#531 — `channel.deliver`: an agent of the room sends outside through the
destination's own verb, every check of `call_tool` included; its grant on
`channel.deliver` stands in for that one verb, for that one call."""
from __future__ import annotations

import asyncio
import contextlib
import json
import unittest
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, patch

from mcp.types import Tool

from . import egress, main as M, whitelist

ROOM = ("SEAL-2", "preventivi")


class _Env:
    def __init__(self, test, *, allowed=("channel.deliver",), denied=(),
                 egress_scope=("mailto:cliente@x.it", "outbox:info@tomato.blue"),
                 room=ROOM):
        self.sent = []
        cfg = {"agents": {"segretario": {"allowed_tools": list(allowed),
                                         "denied_tools": list(denied)}},
               "egress_allow": [],
               "scope_egress_allow": {f"{ROOM[0]}/{ROOM[1]}": list(egress_scope)}}
        # No component verb is reached by these deliveries any more (Telegram's
        # were the last, #683): mail is the gateway's own `email.send`.
        spec: dict = {}
        tok = whitelist.set_current_agent("segretario")
        test.addCleanup(whitelist.reset_current_agent, tok)
        stack = contextlib.ExitStack()
        test.addCleanup(stack.close)
        for p in (patch.object(whitelist, "CONFIG", cfg),
                  patch.object(M, "_current_topic", lambda: room),
                  patch.object(M, "_topics", lambda: NS(open=lambda t, n: {"meta": {"title": "Preventivi"}})),
                  patch("server.tools.mail_switch.system_mailboxes",
                        return_value=[{"account": "info", "email": "info@tomato.blue"}]),
                  patch.object(M, "_component_verb", lambda n: spec.get(n)),
                  # #683: `email.send` is the gateway's own delivery-only verb.
                  patch("server.mail.verbs.send",
                        lambda a: self.sent.append(("email.send", a)) or {"sent": True}),
                  patch.object(M, "_component_pdp_arguments", lambda _s, _n, a: a),
                  patch.object(M, "_check_component", lambda n: None),
                  patch.object(M, "_check_pack_connector_held", lambda n: None),
                  patch.object(M, "_unattended_denial", lambda n: None),
                  patch.object(M.origin, "evaluate", return_value={"action": "allow"}),
                  patch.object(M, "_require_gate_consent", AsyncMock(return_value={})),
                  patch.object(egress, "mode", lambda: "on"),
                  patch.object(egress, "_scope_of_call", lambda: f"{room[0]}/{room[1]}" if room[0] else None),
                  patch.object(M._taint, "note_verb", lambda *a, **k: None),
                  patch.object(M._tlm, "record", lambda *a, **k: None)):
            stack.enter_context(p)

    def call(self, name, args):
        return asyncio.run(M.call_tool(name, args))[0].text


class ChannelDeliverTests(unittest.TestCase):
    """Since #736 mail is not sent during the turn: `channel.deliver` to a
    `mailto:` destination queues it on the courier (and opens the room's gate
    for a new recipient); the courier sends at its pass."""

    def _queue(self, env, known=True):
        posted, reqs = [], []
        p1 = patch("server.transfer_channel._post",
                   lambda path, body: posted.append((path, body)) or {"id": "q7"})
        p2 = patch("server.gate.request",
                   lambda *a, **k: reqs.append((a, k)) or {"id": "rid"})
        p3 = patch("server.courier_send.allowed", lambda a, s: known)
        for p in (p1, p2, p3):
            p.start(); self.addCleanup(p.stop)
        return posted, reqs

    def test_mail_is_queued_on_the_courier_from_the_rooms_mailbox(self):
        env = _Env(self)
        posted, reqs = self._queue(env)
        out = env.call("channel.deliver", {"destination": "mailto:cliente@x.it",
                                           "text": "Ecco l'offerta.",
                                           "attachments": ["files/offerta.pdf"]})
        self.assertFalse(out.startswith(("DENIED", "ERROR")), out)
        self.assertEqual(env.sent, [])                    # nothing during the turn
        (path, body), = posted
        self.assertEqual(path, "/internal/courier/enqueue")
        self.assertEqual((body["to"], body["account"], body["body"], body["subject"],
                          body["state"]),
                         ("cliente@x.it", "info", "Ecco l'offerta.", "Preventivi", "queued"))
        self.assertEqual(body["attachments"], ["files/offerta.pdf"])
        self.assertEqual(reqs, [])
        self.assertEqual(json.loads(out)["queued"][0]["queue_id"], "q7")

    def test_a_new_recipient_waits_for_the_rooms_decision(self):
        env = _Env(self)
        posted, reqs = self._queue(env, known=False)
        out = env.call("channel.deliver", {"destination": "altro@y.it", "text": "x"})
        self.assertFalse(out.startswith(("DENIED", "ERROR")), out)
        self.assertEqual(posted[0][1]["state"], "pending_gate")
        (args, kw), = reqs
        self.assertEqual((args[2], kw["mode"]), ("egress:email:mailto:altro@y.it", "async"))
        self.assertEqual(env.sent, [])

    def test_the_grant_does_not_outlive_the_call(self):
        env = _Env(self)
        self._queue(env)
        env.call("channel.deliver", {"destination": "cliente@x.it", "text": "x"})
        out = env.call("email.send", {"to": "cliente@x.it", "subject": "s", "body": "b",
                                      "account": "info"})
        self.assertTrue(out.startswith("DENIED"), out)
        self.assertEqual(env.sent, [])

    def test_nothing_is_sent_during_the_turn(self):
        env = _Env(self, denied=("email.send",))
        posted, _ = self._queue(env)
        env.call("channel.deliver", {"destination": "cliente@x.it", "text": "x"})
        self.assertEqual(env.sent, [])
        self.assertEqual(len(posted), 1)

    def test_without_the_grant_nothing_goes_out(self):
        env = _Env(self, allowed=("topic.open",))
        out = env.call("channel.deliver", {"destination": "cliente@x.it", "text": "x"})
        self.assertTrue(out.startswith("DENIED"), out)
        self.assertEqual(env.sent, [])

    def test_outside_a_room_it_is_refused(self):
        env = _Env(self, room=(None, None))
        out = env.call("channel.deliver", {"destination": "cliente@x.it", "text": "x"})
        self.assertTrue(out.startswith(("DENIED", "ERROR")), out)
        self.assertEqual(env.sent, [])

    def test_two_room_mailboxes_need_an_account(self):
        env = _Env(self, egress_scope=("mailto:cliente@x.it", "outbox:info@tomato.blue",
                                       "outbox:studio@x.it"))
        with patch("server.tools.mail_switch.system_mailboxes", return_value=[
                {"account": "info", "email": "info@tomato.blue"},
                {"account": "studio", "email": "studio@x.it"}]):
            out = env.call("channel.deliver", {"destination": "cliente@x.it", "text": "x"})
        self.assertTrue(out.startswith("ERROR"), out)
        self.assertIn("account", out)


class NativeMailDeliveryTests(unittest.TestCase):
    """#683: the delivery reaches the gateway's own `email.send`, whose send
    does NOT ask the agent's whitelist again. With `email.*` denied to every
    agent (`authz_shadow.PLATFORM_TUPLES`), asking again refused the delivery
    the gateway had just allowed (the regression of 2.173.0)."""

    def test_the_send_does_not_ask_the_agents_whitelist(self):
        from .mail import mail
        runs = []
        with patch.object(mail, "_run_cli",
                          lambda acct, argv, **k: runs.append((acct, argv)) or {"stdout": "ok"}), \
                patch("server.whitelist.tool_allowed",
                      side_effect=AssertionError("asked the whitelist")):
            out = mail.send("cliente@x.it", "Offerta", "Testo", account="info")
        self.assertTrue(out["ok"])
        (acct, argv), = runs
        self.assertEqual(acct, "info")
        self.assertEqual(argv[:3], ["send", "--to", "cliente@x.it"])

    def test_the_couriers_pass_runs_the_native_verb(self):
        """#736: the courier's pass (`send_now`) reaches the gateway's own
        `email.send` for a recipient the room declares."""
        from . import courier_send
        from .mail import verbs
        real_send = verbs.send          # before `_Env` stands a recorder in
        env = _Env(self)
        got = []
        with patch.object(verbs.mail, "send",
                          lambda to, subject, body, **k: got.append((to, k["account"])) or {"ok": True}), \
                patch("server.mail.verbs.send", real_send), \
                patch.object(verbs.mail, "available_accounts", lambda _a: ["info"]):
            out = asyncio.run(courier_send.send_now(
                tier=ROOM[0], name=ROOM[1], account="", to="cliente@x.it",
                subject="s", body="x"))
        self.assertTrue(out["ok"], out)
        self.assertEqual(got, [("cliente@x.it", "info")])


if __name__ == "__main__":
    unittest.main()


from .connectors import first_party_fixture as _first_party


def setUpModule() -> None:
    from . import testkit_authz as _tk_authz
    _tk_authz.module_start()   # reachability is the tuples' (#656)
    # The first-party packs, installed as on every instance: since the switch
    # was retired (#526) the tables pinned here are theirs, not the gateway's.
    _first_party.install()


def tearDownModule() -> None:
    from . import testkit_authz as _tk_authz
    _tk_authz.module_stop()
    _first_party.uninstall()

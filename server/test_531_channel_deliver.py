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
        spec = {v: NS(pack="comms-pack", component="comms-pack/comms", offload=False,
                      tool=Tool(name=v, description="", inputSchema={"type": "object",
                                "properties": {k: {} for k in (
                                    "to", "subject", "body", "account", "topic_files",
                                    "tier", "name", "chat_id", "text", "path", "thread_id")}}),
                      handler=lambda a, _v=v: self.sent.append((_v, a)) or {"sent": True})
                for v in ("email.send", "telegram.send", "telegram.send_file")}
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
    def test_mail_goes_out_through_email_send_from_the_rooms_mailbox(self):
        env = _Env(self)
        out = env.call("channel.deliver", {"destination": "mailto:cliente@x.it",
                                           "text": "Ecco l'offerta.",
                                           "attachments": ["files/offerta.pdf"]})
        self.assertFalse(out.startswith(("DENIED", "ERROR")), out)
        (verb, args), = env.sent
        self.assertEqual(verb, "email.send")
        self.assertEqual((args["to"], args["account"], args["body"], args["subject"]),
                         ("cliente@x.it", "info", "Ecco l'offerta.", "Preventivi"))
        self.assertEqual(args["topic_files"], ["files/offerta.pdf"])

    def test_an_undeclared_destination_is_refused_by_the_pdp(self):
        env = _Env(self)
        out = env.call("channel.deliver", {"destination": "altro@y.it", "text": "x"})
        self.assertTrue(out.startswith("DENIED"), out)
        self.assertEqual(env.sent, [])

    def test_the_grant_does_not_outlive_the_call(self):
        env = _Env(self)
        env.call("channel.deliver", {"destination": "cliente@x.it", "text": "x"})
        out = env.call("email.send", {"to": "cliente@x.it", "subject": "s", "body": "b",
                                      "account": "info"})
        self.assertTrue(out.startswith("DENIED"), out)
        self.assertIn("non in whitelist", out)
        self.assertEqual(len(env.sent), 1)

    def test_a_denied_verb_stays_denied_through_deliver(self):
        env = _Env(self, denied=("email.send",))
        out = env.call("channel.deliver", {"destination": "cliente@x.it", "text": "x"})
        self.assertTrue(out.startswith("DENIED"), out)
        self.assertEqual(env.sent, [])

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

    def test_telegram_text_then_files(self):
        env = _Env(self, egress_scope=("tg:-100123",))
        out = env.call("channel.deliver", {"destination": "tg:-100123", "text": "ciao",
                                           "attachments": ["files/a.png"], "thread_id": 7})
        self.assertFalse(out.startswith(("DENIED", "ERROR")), out)
        self.assertEqual([v for v, _ in env.sent], ["telegram.send", "telegram.send_file"])
        self.assertEqual(env.sent[0][1], {"chat_id": "-100123", "text": "ciao", "thread_id": 7})
        self.assertEqual(env.sent[1][1]["path"], "files/a.png")

    def test_two_room_mailboxes_need_an_account(self):
        env = _Env(self, egress_scope=("mailto:cliente@x.it", "outbox:info@tomato.blue",
                                       "outbox:studio@x.it"))
        with patch("server.tools.mail_switch.system_mailboxes", return_value=[
                {"account": "info", "email": "info@tomato.blue"},
                {"account": "studio", "email": "studio@x.it"}]):
            out = env.call("channel.deliver", {"destination": "cliente@x.it", "text": "x"})
        self.assertTrue(out.startswith("ERROR"), out)
        self.assertIn("account", out)


    def test_a_failed_file_after_the_text_names_the_partial_delivery(self):
        env = _Env(self, egress_scope=("tg:-100123",))
        real = M._component_verb

        def _verb(n):
            v = real(n)
            if n == "telegram.send_file":
                return NS(**{**vars(v), "handler": lambda a: {"error": "file troppo grande"}})
            return v
        with patch.object(M, "_component_verb", _verb):
            out = env.call("channel.deliver", {"destination": "tg:-100123", "text": "ciao",
                                               "attachments": ["files/a.png"]})
        self.assertTrue(out.startswith("ERROR"), out)
        self.assertIn("file troppo grande", out)
        self.assertIn("già consegnato: telegram.send", out)

if __name__ == "__main__":
    unittest.main()


from .connectors import first_party_fixture as _first_party


def setUpModule() -> None:
    # The first-party packs, installed as on every instance: since the switch
    # was retired (#526) the tables pinned here are theirs, not the gateway's.
    _first_party.install()


def tearDownModule() -> None:
    _first_party.uninstall()

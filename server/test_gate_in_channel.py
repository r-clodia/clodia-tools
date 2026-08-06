"""Tests for the fourth gate reason: gated only INSIDE a channel.

Why a fourth reason instead of widening `gated_tools`. For a postman, sending is
not an anomaly: outside a channel — triaging incoming mail, a direct conversation
with the owner — it is the trade, and asking every time would make the gate a
reflex. A gate that has become a reflex is worse than no gate, because it is
approved without being read.

Inside a channel exactly one thing changes: **who can ask**. Participants are not
the owner, and the content they can cause to leave is everything in the room. So
the condition is not on the verb and not on the agent — it is on the CONTEXT.

The property that makes it a control rather than a convention: the discriminator
is the `chat` claim of the session token, SIGNED by the agent-server. An agent
cannot declare itself outside a channel to escape the gate, nor borrow another
channel's identity. And only an admin can approve a gate (`_can_approve` on the
agent-server side), which is what "the grant comes from the admin" means in
executable terms.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import whitelist as w

CFG = {"agents": {
    "messaggero": {"allowed_tools": ["email.*", "topic.open"],
                   "gated_in_channel": ["email.send", "email.reply"]},
    "clodia": {"allowed_tools": ["*"]},
}}


def _cfg():
    return patch.object(w, "CONFIG", CFG)


class _Chat:
    """Imposta il claim `chat` come fa il middleware del gateway."""

    def __init__(self, value):
        self.value = value

    def __enter__(self):
        self.tok = w.set_current_chat(self.value)
        return self

    def __exit__(self, *a):
        w.reset_current_chat(self.tok)
        return False


CHAN = "chan:SEAL-1:proof-of-flex:messaggero"


class InChannelTests(unittest.TestCase):
    def test_inside_a_channel_the_send_is_gated(self):
        with _cfg(), _Chat(CHAN):
            self.assertTrue(w.agent_gates_in_channel("email.send", "messaggero"))
            self.assertTrue(w.agent_gates_in_channel("email.reply", "messaggero"))

    def test_outside_a_channel_it_is_not(self):
        """Il postino fuori dal canale fa il suo mestiere senza chiedere: è la
        ragione per cui questa lista è separata da `gated_tools`."""
        with _cfg(), _Chat(None):
            self.assertFalse(w.agent_gates_in_channel("email.send", "messaggero"))
        with _cfg(), _Chat("dm:davide:messaggero"):
            self.assertFalse(w.agent_gates_in_channel("email.send", "messaggero"))

    def test_reading_stays_free_inside_a_channel(self):
        """Smistare la posta in arrivo dentro un canale è lavoro legittimo:
        gatarlo toglierebbe il mestiere invece di sorvegliare l'uscita."""
        with _cfg(), _Chat(CHAN):
            for verb in ("email.list", "email.read", "email.search", "email.folders"):
                self.assertFalse(w.agent_gates_in_channel(verb, "messaggero"), verb)

    def test_an_agent_without_the_field_is_unaffected(self):
        with _cfg(), _Chat(CHAN):
            self.assertFalse(w.agent_gates_in_channel("email.send", "clodia"))

    def test_an_unknown_agent_does_not_raise(self):
        with _cfg(), _Chat(CHAN):
            self.assertFalse(w.agent_gates_in_channel("email.send", "ignoto"))


class DiscriminatorTests(unittest.TestCase):
    """Il discriminante viene dal token firmato, non da un argomento."""

    def test_only_a_chan_prefix_counts_as_a_channel(self):
        for value, expected in ((CHAN, True),
                                ("chan:SEAL-0:x:y", True),
                                ("dm:davide:clodia", False),
                                ("", False),
                                (None, False),
                                ("job:notturno", False)):
            with _Chat(value):
                self.assertEqual(w.in_channel(), expected, repr(value))

    def test_the_channel_is_reported_as_tier_slash_topic(self):
        with _Chat(CHAN):
            self.assertEqual(w.current_channel(), "SEAL-1/proof-of-flex")
        with _Chat("chan:SEAL-1:proof-of-flex:messaggero#2"):
            self.assertEqual(w.current_channel(), "SEAL-1/proof-of-flex")
        with _Chat("dm:x:y"):
            self.assertIsNone(w.current_channel())

    def test_a_malformed_chan_claim_does_not_raise(self):
        with _Chat("chan:"):
            w.in_channel()
            self.assertIsNone(w.current_channel())


class DispatchTests(unittest.TestCase):
    """Il quarto motivo deve raggiungere la decisione, non solo esistere."""

    def test_the_gate_condition_includes_the_channel_reason(self):
        import inspect
        from . import main
        src = inspect.getsource(main.call_tool)
        self.assertIn("agent_gates_in_channel", src)
        self.assertIn("_in_chan", src)

    def test_the_reason_names_the_room_and_says_who_approves(self):
        """Un admin che approva senza sapere in quale stanza sta l'agente non sta
        valutando niente. È la stessa lacuna di #150 sul richiedente."""
        import inspect
        from . import main
        src = inspect.getsource(main.call_tool)
        i = src.find("elif _in_chan:")
        self.assertGreater(i, 0, "il ramo del messaggio non esiste")
        block = src[i:i + 700]
        self.assertIn("current_channel()", block)
        self.assertIn("admin", block)

    def test_no_pre_signed_delegation_for_a_channel_gate(self):
        """Una delega renderebbe silenziosi gli invii successivi per tutta la sua
        finestra, cioè l'opposto del motivo per cui il gate esiste."""
        import inspect
        from . import main
        src = inspect.getsource(main.call_tool)
        self.assertIn("allow_delegation=(not _in_chan)", src)


class DeclarationReachesTheGatewayTests(unittest.TestCase):
    """La dichiarazione nel seed deve ARRIVARE alla config del gateway.

    Il modo in cui questa funzione fallisce non è una decisione sbagliata: è una
    dichiarazione che nessuno trasporta. Un `gated_in_channel` scritto nel pack e
    mai letto dal gateway è un controllo che sembra esserci e non c'è — è già
    successo oggi due volte, con `profile_tools` e con `gated_tools`.
    """

    def test_upsert_carries_the_field(self):
        import tempfile, os, yaml
        from pathlib import Path
        from unittest.mock import patch as _p
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c.yaml")
            with open(path, "w") as f:
                yaml.safe_dump({"workspace_root": ".", "agents": {}}, f)
            with _p.object(w, "CONFIG_PATH", Path(path)), _p.object(w, "CONFIG", {}):
                w.reload_config()
                w.upsert_agent("messaggero", allowed_tools=["email.*"],
                               gated_in_channel=["email.send"])
                on_disk = yaml.safe_load(open(path))
        self.assertEqual(
            on_disk["agents"]["messaggero"]["gated_in_channel"], ["email.send"])

    def test_omitting_it_does_not_clear_it(self):
        """Una registrazione parziale non deve togliere il gate per omissione."""
        import tempfile, os, yaml
        from pathlib import Path
        from unittest.mock import patch as _p
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "c.yaml")
            with open(path, "w") as f:
                yaml.safe_dump({"workspace_root": ".", "agents": {"messaggero": {
                    "allowed_tools": ["email.*"],
                    "gated_in_channel": ["email.send"]}}}, f)
            with _p.object(w, "CONFIG_PATH", Path(path)), _p.object(w, "CONFIG", {}):
                w.reload_config()
                w.upsert_agent("messaggero", allowed_tools=["email.*"])  # niente campo
                on_disk = yaml.safe_load(open(path))
        self.assertEqual(
            on_disk["agents"]["messaggero"]["gated_in_channel"], ["email.send"],
            "omettere il campo lo ha azzerato: gate rimosso in silenzio")

    def test_the_registration_endpoint_forwards_it(self):
        import inspect
        from . import agents_api
        src = inspect.getsource(agents_api)
        self.assertIn('gated_in_channel=body.get("gated_in_channel")', src)


if __name__ == "__main__":
    unittest.main()

"""A pack connector's declared `context:`, filled by the gateway; a pack's
credential reached through `${VAULT:…}`; the grammar of `context:`.

Born with clodia-platform#522 (Telegram's move into comms-pack, its switch
retired by #526, Telegram itself removed by #683). What stays here is
generic, measured on the documented `chat-pack` example of `SCHEMA.md`,
written into a fake data dir so the registry reads it from the real path
(`$CLODIA_DATA/packs/<pack>/pack.yaml`).
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from .. import instance_profile
from . import builtin as B
from . import manifest as M
from . import resolved

PACK = "chat-pack"


def _chat_pack() -> dict:
    """The documented example pack (`SCHEMA.md`)."""
    from .test_manifest import _examples
    return _examples()[PACK]


class _Istanza(unittest.TestCase):
    """A fake instance: a data dir with the example pack installed and a
    profile written for real."""

    def setUp(self) -> None:
        # PRIMO `addCleanup`, quindi ULTIMO a girare: il profilo e il registry
        # vanno riletti DOPO che l'ambiente finto è stato smontato, se no la
        # cache di modulo resta ferma sull'istanza di questo test. (Successo:
        # 103 rossi sparsi, nessuno dei quali nominava questo file.)
        self.addCleanup(self._ricarica)
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.dir,
                                                            ignore_errors=True))
        pack = self.dir / "packs" / PACK
        pack.mkdir(parents=True)
        (pack / "pack.yaml").write_text(json.dumps(_chat_pack()),
                                        encoding="utf-8")
        env = patch.dict(os.environ, {"CLODIA_DATA": str(self.dir)})
        env.start()
        self.addCleanup(env.stop)
        data = patch.object(resolved, "_DATA", self.dir)
        data.start()
        self.addCleanup(data.stop)
        seen = patch.object(resolved, "_first_seen_path",
                            lambda: self.dir / "first-seen.json")
        seen.start()
        self.addCleanup(seen.stop)
        self.posizione()

    def _ricarica(self) -> None:
        instance_profile.load(force=True)
        resolved.invalidate()

    def posizione(self, *_retired: str) -> None:
        """Writes the profile (the retired `connectors:` switch of #522 is not
        written: it no longer moves anything, #526)."""
        (self.dir / "profile.yaml").write_text("edition: full\n", encoding="utf-8")
        self._ricarica()


class ContextIsTheGatewaysToFillTests(_Istanza):
    """Canale e agente li mette il gateway, e sovrascrive il chiamante."""

    def setUp(self) -> None:
        super().setUp()
        self.posizione("pack")

    def test_the_declaration_is_read(self):
        self.assertEqual(resolved.context_arguments("chat.send"),
                         {"channel": "channel", "agent": "agent"})

    def test_it_applies_to_every_verb_of_the_namespace(self):
        """Anche a quelli che non dichiarano una destinazione: `chat.inbox`
        non compare in `verbs:` e ha comunque bisogno di sapere chi chiede."""
        self.assertTrue(resolved.context_arguments("chat.inbox"))

    def test_a_foreign_verb_gets_nothing(self):
        for verbo in ("email.send", "topic.post_message", "chat", ""):
            with self.subTest(verbo=verbo):
                self.assertEqual(resolved.context_arguments(verbo), {})

    def test_a_forged_value_is_overwritten_not_merged(self):
        """Il caso che la decisione nomina: un agente che si dichiara in una
        stanza che non è la sua. Se il valore del chiamante sopravvivesse,
        «manda alla chat di questo topic» tornerebbe a essere «manda alla chat
        che dico io» — l'invio al gruppo sbagliato del 23 set 2026."""
        detto = resolved.fill_context(
            "chat.send",
            {"text": "ciao", "channel": "SEAL-3/consiglio", "agent": "clodia"},
            {"channel": "SEAL-1/software-house", "agent": "fullstack-dev"})
        self.assertEqual(detto["channel"], "SEAL-1/software-house")
        self.assertEqual(detto["agent"], "fullstack-dev")
        self.assertEqual(detto["text"], "ciao")

    def test_what_the_gateway_does_not_know_is_removed_not_blanked(self):
        """Fuori da una stanza non c'è un canale. Una stringa vuota sarebbe una
        risposta («il canale si chiama ''»), e il connettore non potrebbe più
        distinguere «non lo so» da «è vuoto»."""
        detto = resolved.fill_context(
            "chat.send", {"channel": "SEAL-3/consiglio", "text": "ciao"},
            {"channel": "", "agent": "fullstack-dev"})
        self.assertNotIn("channel", detto)
        self.assertEqual(detto["agent"], "fullstack-dev")

    def test_the_callers_dict_is_not_mutated(self):
        originale = {"channel": "SEAL-3/consiglio"}
        resolved.fill_context("chat.send", originale,
                              {"channel": "SEAL-1/software-house"})
        self.assertEqual(originale, {"channel": "SEAL-3/consiglio"})

    def test_the_gateway_fills_it_on_a_real_call(self):
        """Il punto d'innesto: `main._fill_declared_context` è ciò che gira
        PRIMA dell'audit, del PDP e del gate, così tutti e tre vedono la
        chiamata che parte davvero."""
        from .. import main
        from ..whitelist import (reset_current_chat, set_current_chat)
        tok = set_current_chat("SEAL-1/software-house")
        try:
            with patch.object(main, "agent_name", return_value="messaggero"):
                detto = main._fill_declared_context(
                    "chat.send", {"text": "ciao", "channel": "SEAL-3/x",
                                      "agent": "clodia"})
        finally:
            reset_current_chat(tok)
        self.assertEqual(detto["channel"], "SEAL-1/software-house")
        self.assertEqual(detto["agent"], "messaggero")

    def test_without_identity_the_agent_argument_is_removed_not_forged(self):
        """Review of #374: `agent_name_safe()` answers "?", which would have
        become the caller's identity. No identity → the argument goes."""
        from .. import main

        def _none():
            raise PermissionError("identità agente non impostata")
        with patch.object(main, "agent_name", _none):
            detto = main._fill_declared_context(
                "chat.lease_acquire", {"chat_id": "1", "agent": "messaggero"})
        self.assertNotIn("agent", detto)

    def test_a_refused_pack_connector_refuses_its_verbs(self):
        """Review of #374: the pack's connector refused (bad manifest) while
        its backend is still mounted. The call must
        not reach the pack with the caller's `agent` — fail closed."""
        import asyncio
        from .. import main
        broken = _chat_pack()
        broken["connectors"][0]["context"] = [{"arg": "agent", "value": "bogus"}]
        (self.dir / "packs" / PACK / "pack.yaml").write_text(
            json.dumps(broken), encoding="utf-8")
        resolved.invalidate()
        self.assertFalse(resolved.held_by_pack("chat"))
        out = asyncio.run(main.call_tool("chat.lease_acquire",
                                         {"chat_id": "1", "agent": "messaggero"}))
        self.assertTrue(out[0].text.startswith("DENIED:"), out[0].text)

    def test_a_held_pack_connector_is_served(self):
        self.assertTrue(resolved.held_by_pack("chat"))

    def test_a_native_verb_is_left_exactly_as_it_was(self):
        from .. import main
        args = {"tier": "SEAL-1", "name": "software-house"}
        self.assertIs(main._fill_declared_context("topic.open", args), args)


class ThePackReachesItsCredentialTests(unittest.TestCase):
    """`${VAULT:cred.campo}` — come il server MCP del pack prende il token.

    L'implementazione di un pack gira in un processo che il gateway
    monta come backend MCP, e il segreto gli arriva per env attraverso un
    placeholder `${VAULT:…}`. Ma un bundle non è sempre `{"value": …}`: un
    token di bot può essere `{"token", "bot_username", "bot_id"}`. Con la sola
    forma senza campo il pack partiva con il token **stringa vuota**, il
    servizio rispondeva 401 e il sintomo era «il token del bot è sbagliato»
    (il caso Telegram, #522): il posto giusto dove non guardare.
    """

    def _con_bundle(self, bundle):
        from .. import proxy
        return patch.object(proxy.vault, "read_internal",
                            lambda _n, _b=bundle: _b)

    def test_a_field_of_the_bundle_is_reachable(self):
        from .. import proxy
        with self._con_bundle({"token": "123:ABC", "bot_username": "clodia_bot"}):
            self.assertEqual(
                proxy._resolve_secrets(
                    {"env": {"TOKEN": "${VAULT:chat_bot_token.token}"}}),
                {"env": {"TOKEN": "123:ABC"}})

    def test_the_old_form_still_means_value(self):
        from .. import proxy
        with self._con_bundle({"value": "segreto"}):
            self.assertEqual(proxy._resolve_secrets("${VAULT:qualcosa}"),
                             "segreto")

    def test_a_missing_field_leaves_the_placeholder_alone(self):
        """E NON una stringa vuota. Un segreto vuoto è indistinguibile da un
        segreto sbagliato; un `${VAULT:…}` letterale arrivato fino alla API di
        un vendor è un errore che nomina sé stesso."""
        from .. import proxy
        with self._con_bundle({"token": "123:ABC"}):
            self.assertEqual(proxy._resolve_secrets("${VAULT:chat_bot_token}"),
                             "${VAULT:chat_bot_token}")
            self.assertEqual(
                proxy._resolve_secrets("${VAULT:chat_bot_token.assente}"),
                "${VAULT:chat_bot_token.assente}")

    def test_an_absent_credential_is_still_left_alone(self):
        from .. import proxy

        def _esplode(_n):
            raise RuntimeError("assente")
        with patch.object(proxy.vault, "read_internal", _esplode):
            self.assertEqual(proxy._resolve_secrets("${VAULT:niente.token}"),
                             "${VAULT:niente.token}")


class TheRegisteredHandlerIsStillCallToolTests(unittest.TestCase):
    """`@app.call_tool()` decora `call_tool`, e nient'altro.

    Scritto perché è già successo, in questa PR: infilando
    `_fill_declared_context` fra il decoratore e la funzione, il server MCP si
    è registrato la funzione sbagliata. La suite è rimasta VERDE — i test
    chiamano `main.call_tool` direttamente — e il guasto sarebbe arrivato in
    produzione come «il gateway non risponde a nessun verbo». Due righe perché
    non succeda di nuovo.
    """

    def test_the_mcp_server_dispatches_to_call_tool(self):
        import inspect

        import mcp.types as t

        from .. import main
        handler = main.app.request_handlers[t.CallToolRequest]
        registrata = inspect.getclosurevars(handler).nonlocals["func"]
        self.assertIs(registrata, main.call_tool)


class ContextIsRefusedWhereItIsNotDeclaredTests(_Istanza):
    """Senza il connettore del pack non c'è contesto da riempire — e il verbo
    non si serve: niente arriva al pack con il canale del chiamante."""

    def test_without_the_packs_connector_nothing_is_filled_and_it_is_refused(self):
        (self.dir / "packs" / PACK / "pack.yaml").unlink()
        resolved.invalidate()
        self.assertEqual(resolved.context_arguments("chat.send"), {})
        import asyncio
        from .. import main
        out = asyncio.run(main.call_tool("chat.send", {"chat_id": "1", "text": "x",
                                                       "channel": "SEAL-3/x"}))
        self.assertTrue(out[0].text.startswith(("DENIED:", "ERROR:")), out[0].text)


class TheGrammarRefusesWhatItCannotFillTests(unittest.TestCase):
    """`context:` nomina un fatto, non lo definisce."""

    def _connettore(self, **extra) -> dict:
        return {"id": "sms", "manifest_version": 1, "namespace": "sms",
                "schemes": [{"scheme": "sms", "direction": "egress",
                             "forms": [{"pattern": r"^\+\d+$",
                                        "example": "+39333"}]}], **extra}

    def test_an_invented_fact_is_refused(self):
        with self.assertRaises(M.ManifestError) as e:
            M.parse_connector(
                self._connettore(context=[{"arg": "ruolo", "value": "clearance"}]),
                pack="sms-pack", reserved=())
        self.assertIn("clearance", str(e.exception))

    def test_the_same_argument_twice_is_refused(self):
        with self.assertRaises(M.ManifestError):
            M.parse_connector(
                self._connettore(context=[{"arg": "chi", "value": "agent"},
                                          {"arg": "chi", "value": "channel"}]),
                pack="sms-pack", reserved=())

    def test_a_contributor_may_not_declare_it(self):
        """`extends` aggiunge un provider, non un significato: il contesto è una
        frase sui verbi, e i verbi sono di chi possiede il vocabolario."""
        with self.assertRaises(M.ManifestError) as e:
            M.parse_connector(
                {"id": "sms-bis", "manifest_version": 1, "namespace": "smsbis",
                 "extends": "sms",
                 "providers": [{"id": "p"}],
                 "context": [{"arg": "agent", "value": "agent"}]},
                pack="sms-pack", reserved=())
        self.assertIn("context", str(e.exception))

    def test_it_may_not_fill_an_argument_the_pdp_reads(self):
        """La destinazione è una proprietà della CHIAMATA, non del manifest.

        Senza questa guardia un connettore potrebbe puntare il contesto
        sull'argomento da cui il PDP ricava la destinazione: un fatto che il
        gateway non ha lo svuoterebbe, e un estrattore senza valore è un verbo
        senza destinazione dichiarata — il PDP disarmato, in silenzio, su quel
        verbo.
        """
        with self.assertRaises(M.ManifestError) as e:
            M.parse_connector(
                self._connettore(
                    verbs=[{"verb": "sms.send", "direction": "egress",
                            "scheme": "sms", "arg": "to"}],
                    context=[{"arg": "to", "value": "channel"}]),
                pack="sms-pack", reserved=())
        self.assertIn("'to'", str(e.exception))

    def test_an_argument_the_pdp_does_not_read_is_fine(self):
        c = M.parse_connector(
            self._connettore(
                verbs=[{"verb": "sms.send", "direction": "egress",
                        "scheme": "sms", "arg": "to"}],
                context=[{"arg": "channel", "value": "channel"}]),
            pack="sms-pack", reserved=())
        self.assertEqual(c.context[0].arg, "channel")

    def test_a_gateway_manifest_may_not_declare_one(self):
        """Da #373. Un connettore che il GATEWAY implementa il contesto ce
        l'ha già — lo legge dal claim firmato della sessione — e scriverlo in
        un argomento sovrascriverebbe un argomento vero del verbo nativo.
        `context:` è per chi gira fuori di qui."""
        with self.assertRaises(M.ManifestError) as e:
            M.parse_connector(
                self._connettore(context=[{"arg": "channel", "value": "channel"}]),
                pack="gateway-sms", reserved=(), builtin=True)
        self.assertIn("PACK", str(e.exception))

    def test_no_builtin_manifest_declares_one(self):
        """E nessuno dei file che il gateway spedisce lo fa: la regola di sopra
        è una porta chiusa, non una porta che qualcuno sta già forzando."""
        for nome, doc in B._all().items():
            for entry in doc.get("connectors") or []:
                with self.subTest(pack=nome, connettore=entry.get("id")):
                    self.assertNotIn("context", entry)

    def test_it_is_optional(self):
        c = M.parse_connector(self._connettore(), pack="sms-pack", reserved=())
        self.assertEqual(c.context, ())


def setUpModule() -> None:
    # google-pack and it-pack as on every instance (#526); comms-pack is this
    # module's own (the SCHEMA.md example `_Istanza` writes).
    from . import first_party_fixture
    first_party_fixture.install(without=("comms-pack",))


def tearDownModule() -> None:
    from . import first_party_fixture
    first_party_fixture.uninstall()


if __name__ == "__main__":
    unittest.main()

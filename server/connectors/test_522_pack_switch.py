"""L'interruttore di #522: lo stesso connettore, dal gateway o dal pack.

clodia-platform#522, criterio 1 («parity tests green with the switch in both
positions») e decisione G3 dell'epic #527: il nativo e il pack **convivono
dietro un interruttore per istanza**, l'owner lo gira sulla propria, verifica su
traffico vero, e solo allora si cancella il codice nativo.

Due cose si misurano qui, e la seconda è quella che vale.

1. **L'interruttore sposta davvero il connettore.** Su `native` è il file
   `builtin_manifests/telegram.yaml` a stare nel registry e la dichiarazione di
   comms-pack è rifiutata per collisione; su `pack` è il contrario, e insieme
   cadono le tre riserve che la tenevano fuori — il manifest builtin, i verbi
   nativi nel catalogo, il namespace e il prefisso di vault.

2. **Le risposte non cambiano.** Non il confronto fra due manifest, che
   potrebbero essere scritti diversi e valere uguale (o uguali e applicati
   diversi): le stesse domande pubbliche del PDP — `check_grantable`,
   `danger_note`, `spec_for`, `taints`, l'azione di topic, la credenziale —
   poste nelle due posizioni, e nessuna risposta deve differire. Una batteria,
   non un campione.

   Un confronto fra due risposte è verde anche quando entrambe sono vuote, cioè
   proprio quando il connettore è sparito: perciò `test_the_answers_are_not_
   vacuous` pretende che nelle due posizioni le risposte *dicano* qualcosa, e
   `SwitchParityCanFailTests` dimostra che il confronto sa diventare rosso.

Il manifest che fa da pack installato è l'esempio comms-pack di `SCHEMA.md` —
lo stesso che la fase 1 ha messo in comms-pack (clodia-logic PR #515) — scritto
in una data dir finta, così il registry lo legge dalla strada vera
(`$CLODIA_DATA/packs/<pack>/pack.yaml`) invece che da un'iniezione.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from .. import egress, instance_profile, taint
from . import builtin as B
from . import manifest as M
from . import resolved
from .test_522_telegram_parity import CAMPIONI

#: Il verbo con cui si misura che il catalogo nativo si è spostato.
UN_VERBO_NATIVO = "telegram.send"


def _comms_pack() -> dict:
    """La dichiarazione di comms-pack, dall'esempio documentato in SCHEMA.md."""
    from .test_manifest import _examples
    return _examples()["comms-pack"]


class _Istanza(unittest.TestCase):
    """Una istanza finta: una data dir con comms-pack installato e un profilo.

    L'interruttore si gira scrivendo `profile.yaml` per davvero, non patchando
    `instance_profile.load`: il profilo è il punto in cui l'owner agisce, e un
    test che lo salta misurerebbe la funzione invece della leva.
    """

    def setUp(self) -> None:
        # PRIMO `addCleanup`, quindi ULTIMO a girare: il profilo e il registry
        # vanno riletti DOPO che l'ambiente finto è stato smontato, se no la
        # cache di modulo resta ferma sull'istanza di questo test e il resto
        # della suite gira con Telegram affidato a un pack. (Successo: 103
        # rossi sparsi, nessuno dei quali nominava questo file.)
        self.addCleanup(self._ricarica)
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.dir,
                                                            ignore_errors=True))
        pack = self.dir / "packs" / "comms-pack"
        pack.mkdir(parents=True)
        (pack / "pack.yaml").write_text(json.dumps(_comms_pack()),
                                        encoding="utf-8")
        env = patch.dict(os.environ, {"CLODIA_DATA": str(self.dir)})
        env.start()
        self.addCleanup(env.stop)
        data = patch.object(resolved, "_DATA", self.dir)
        data.start()
        self.addCleanup(data.stop)
        self.posizione("native")

    def _ricarica(self) -> None:
        instance_profile.load(force=True)
        resolved.invalidate()

    def posizione(self, *modi: str) -> None:
        """Scrive il profilo con l'interruttore in quella posizione.

        `modi` vuoto = nessuna sezione `connectors:`, cioè il profilo che hanno
        tutte le istanze oggi.
        """
        righe = ["edition: full"]
        if modi:
            righe.append("connectors:")
            righe += [f"  telegram: {m}" for m in modi]
        (self.dir / "profile.yaml").write_text("\n".join(righe) + "\n",
                                               encoding="utf-8")
        self._ricarica()


class TheSwitchMovesTheConnectorTests(_Istanza):
    """Su `pack` il gateway si fa da parte, e il pack subentra."""

    def test_on_native_the_builtin_holds_it_and_the_pack_is_refused(self):
        self.posizione("native")
        telegram = resolved.registry().by_id("telegram")
        self.assertIsNotNone(telegram)
        self.assertTrue(telegram.builtin)
        self.assertEqual(telegram.pack, "gateway-telegram")
        self.assertTrue(any("telegram" in r for r in resolved.registry().refused),
                        "senza l'interruttore la dichiarazione del pack deve "
                        "restare rifiutata per collisione")

    def test_on_pack_the_packs_declaration_is_the_one_that_counts(self):
        self.posizione("pack")
        telegram = resolved.registry().by_id("telegram")
        self.assertIsNotNone(telegram)
        self.assertFalse(telegram.builtin)
        self.assertEqual(telegram.pack, "comms-pack")
        self.assertNotIn("gateway-telegram", B.manifests())

    def test_on_pack_the_three_reservations_fall_together(self):
        """Namespace, prefisso di vault e verbi nativi: se ne restasse anche
        solo uno, il connettore del pack sarebbe caricato a metà o per niente —
        ed è il genere di guasto che si legge come «il pack non fa nulla»."""
        self.posizione("pack")
        self.assertNotIn("telegram", M.reserved_namespaces())
        self.assertNotIn("telegram", M.core_namespaces())
        self.assertEqual(
            M.vault_entry_problem("telegram_bot_token", "telegram"), "")
        from .. import main
        self.assertNotIn(UN_VERBO_NATIVO, main.all_native_verb_names())
        self.assertNotIn("telegram", main._native_tool_namespaces())
        self.assertTrue(main._is_packaged_verb(UN_VERBO_NATIVO))

    def test_on_native_nothing_of_that_has_moved(self):
        self.posizione("native")
        self.assertIn("telegram", M.reserved_namespaces())
        self.assertIn("telegram", M.core_namespaces())
        self.assertTrue(M.vault_entry_problem("telegram_bot_token", "telegram"))
        from .. import main
        self.assertIn(UN_VERBO_NATIVO, main.all_native_verb_names())
        self.assertIn("telegram", main._native_tool_namespaces())
        self.assertFalse(main._is_packaged_verb(UN_VERBO_NATIVO))

    def test_no_section_means_native(self):
        """Una migrazione si accende. Il profilo di tutte le istanze di oggi non
        ha questa sezione, e deve continuare a significare «come ieri»."""
        self.posizione()
        self.assertEqual(instance_profile.connector_mode("telegram"), "native")
        self.assertEqual(instance_profile.packaged_connectors(), frozenset())
        self.assertTrue(resolved.registry().by_id("telegram").builtin)

    def test_a_misspelt_value_falls_back_to_native(self):
        """Fail-safe nella direzione giusta: un valore che questo lettore non
        capisce non deve poter spegnere il connettore. Il profilo intero ricade
        su FULL, dove `connectors` è vuoto."""
        self.posizione("packs")  # "packs", non "pack"
        self.assertEqual(instance_profile.connector_mode("telegram"), "native")
        self.assertTrue(resolved.registry().by_id("telegram").builtin)

    def test_the_other_connectors_do_not_move(self):
        """L'interruttore nomina UN connettore: gli altri file builtin restano
        dove sono, e con loro i namespace riservati."""
        self.posizione("pack")
        self.assertIn("gateway-mail", B.manifests())
        self.assertIsNotNone(resolved.registry().by_id("mail"))
        self.assertTrue(resolved.registry().by_id("mail").builtin)
        self.assertIn("google", M.reserved_namespaces())


def _risposte() -> dict:
    """Le domande pubbliche del PDP su Telegram, e le loro risposte.

    Poste attraverso le funzioni che restano — `egress`, `taint`, il registry —
    e non leggendo il manifest: due manifest scritti diversi possono valere
    uguale, e due scritti uguali possono essere applicati diversi. Conta la
    risposta.
    """
    def grantable(direzione: str, resto: str) -> bool:
        try:
            egress.check_grantable(direzione, f"tg:{resto}")
        except ValueError:
            return False
        return True

    out: dict = {
        "forme": {f"{d}:{r}": grantable(d, r)
                  for d in ("egress", "ingress") for r in CAMPIONI},
        "danger": egress.danger_note("tg:-1001234567890"),
        "taint": {v: taint.taints(v) for v in (
            "telegram.inbox", "telegram.receive", "telegram.pull",
            "telegram.send", "telegram.send_file", "telegram.listen")},
        "schemi": (tuple(resolved.registry().scheme_names("egress")),
                   tuple(resolved.registry().scheme_names("source"))),
    }
    for verbo in ("telegram.send", "telegram.send_file", "telegram.inbox",
                  "telegram.poll", "telegram.listen", "telegram.roster"):
        spec = egress.spec_for(verbo)
        out[f"spec:{verbo}"] = None if spec is None else (
            spec[0], tuple(spec[1]({"chat_id": "-1001234567890"})))
    connettore = resolved.registry().by_id("telegram")
    if connettore is not None:
        azione = next((a for a in connettore.topic_actions
                       if a.id == "telegram-link"), None)
        if azione is not None:
            valori = {azione.fields[0].name: "-1001234567890"}
            out["azione"] = (
                azione.binding,
                tuple(t.format(**valori) for t in azione.adds_ingress),
                tuple(t.format(**valori) for t in azione.adds_egress))
        out["credenziale"] = tuple(
            p.credential.vault_entry for p in connettore.providers
            if p.credential)
    return out


class SwitchParityTests(_Istanza):
    """Le stesse domande, nelle due posizioni, con le stesse risposte."""

    def _confronto(self) -> tuple[dict, dict]:
        self.posizione("native")
        self.assertTrue(resolved.registry().by_id("telegram").builtin,
                        "chi risponde in posizione `native` deve essere il "
                        "manifest del gateway")
        nativo = _risposte()
        self.posizione("pack")
        # Senza questo controllo il confronto sarebbe VACUO: se l'interruttore
        # non spostasse niente, a rispondere sarebbe il gateway tutte e due le
        # volte e la parità verrebbe verde senza aver misurato il pack.
        self.assertEqual(resolved.registry().by_id("telegram").pack, "comms-pack")
        da_pack = _risposte()
        return nativo, da_pack

    def test_every_answer_is_the_same_in_both_positions(self):
        nativo, da_pack = self._confronto()
        self.assertEqual(set(nativo), set(da_pack))
        for chiave in sorted(nativo):
            with self.subTest(domanda=chiave):
                self.assertEqual(nativo[chiave], da_pack[chiave])

    def test_the_answers_are_not_vacuous(self):
        """Il confronto di sopra è verde anche se nelle due posizioni non
        risponde nessuno: è proprio il caso in cui il connettore è sparito.
        Qui si pretende che le risposte dicano qualcosa."""
        for posizione, atteso in (("native", "gateway-telegram"),
                                  ("pack", "comms-pack")):
            with self.subTest(posizione=posizione):
                self.posizione(posizione)
                self.assertEqual(
                    resolved.registry().by_id("telegram").pack, atteso)
                r = _risposte()
                self.assertTrue(r["forme"]["egress:-1001234567890"])
                self.assertFalse(r["forme"]["egress:*"])
                self.assertTrue(r["danger"])
                self.assertTrue(r["taint"]["telegram.inbox"])
                self.assertEqual(r["spec:telegram.send"],
                                 ("telegram", ("tg:-1001234567890",)))
                self.assertIsNone(r["spec:telegram.inbox"])
                self.assertIn("tg", r["schemi"][0])
                self.assertEqual(r["credenziale"], ("telegram_bot_token",))
                self.assertEqual(r["azione"][0], "channel")


class SwitchParityCanFailTests(_Istanza):
    """La prova che il confronto di sopra sa diventare rosso.

    Un test di parità è verde per costruzione finché le due parti coincidono: la
    dimostrazione che coglie una differenza è perturbare la dichiarazione del
    pack e vedere il rosso. Una perturbazione per famiglia di risposta, perché
    una sola proverebbe che il confronto guarda UN campo.
    """

    def _con(self, muta) -> dict:
        doc = _comms_pack()
        doc["connectors"] = [muta(dict(c)) if c["id"] == "telegram" else c
                             for c in doc["connectors"]]
        (self.dir / "packs" / "comms-pack" / "pack.yaml").write_text(
            json.dumps(doc), encoding="utf-8")
        self.posizione("pack")
        return _risposte()

    def setUp(self) -> None:
        super().setUp()
        self.posizione("native")
        self.nativo = _risposte()

    def test_a_looser_handle_is_caught(self):
        def muta(c):
            c["schemes"] = [{**s, "forms": [
                f if f["label"] != "person"
                else {**f, "pattern": r"^@[A-Za-z0-9_]{4,32}$", "example": "@abcd"}
                for f in s["forms"]]} for s in c["schemes"]]
            return c
        self.assertNotEqual(self.nativo["forme"], self._con(muta)["forme"])

    def test_a_rewritten_danger_sentence_is_caught(self):
        def muta(c):
            c["schemes"] = [{**s, "danger": "una chat, niente di che."}
                            for s in c["schemes"]]
            return c
        self.assertNotEqual(self.nativo["danger"], self._con(muta)["danger"])

    def test_a_dropped_verb_is_caught(self):
        def muta(c):
            c["verbs"] = [v for v in c["verbs"] if v["verb"] != "telegram.send"]
            return c
        self.assertNotEqual(self.nativo["spec:telegram.send"],
                            self._con(muta)["spec:telegram.send"])

    def test_a_dropped_taint_prefix_is_caught(self):
        def muta(c):
            c["taint"] = [t for t in c["taint"] if t != "telegram.inbox"]
            return c
        self.assertNotEqual(self.nativo["taint"], self._con(muta)["taint"])

    def test_a_renamed_vault_entry_is_caught(self):
        def muta(c):
            c["providers"] = [{**p, "credential": {
                **p["credential"], "vault_entry": "telegram_token"}}
                if p.get("credential") else p for p in c["providers"]]
            return c
        self.assertNotEqual(self.nativo["credenziale"],
                            self._con(muta)["credenziale"])

    def test_a_button_that_writes_one_direction_only_is_caught(self):
        def muta(c):
            c["topic_actions"] = [{**a, "adds": {**a["adds"], "ingress": []}}
                                  for a in c["topic_actions"]]
            return c
        self.assertNotEqual(self.nativo["azione"], self._con(muta)["azione"])


class ContextIsTheGatewaysToFillTests(_Istanza):
    """Canale e agente li mette il gateway, e sovrascrive il chiamante."""

    def setUp(self) -> None:
        super().setUp()
        self.posizione("pack")

    def test_the_declaration_is_read(self):
        self.assertEqual(resolved.context_arguments("telegram.send"),
                         {"channel": "channel", "agent": "agent"})

    def test_it_applies_to_every_verb_of_the_namespace(self):
        """Anche a quelli che non dichiarano una destinazione: `telegram.inbox`
        non compare in `verbs:` e ha comunque bisogno di sapere chi chiede."""
        self.assertTrue(resolved.context_arguments("telegram.inbox"))

    def test_a_foreign_verb_gets_nothing(self):
        for verbo in ("email.send", "topic.post_message", "telegram", ""):
            with self.subTest(verbo=verbo):
                self.assertEqual(resolved.context_arguments(verbo), {})

    def test_a_forged_value_is_overwritten_not_merged(self):
        """Il caso che la decisione nomina: un agente che si dichiara in una
        stanza che non è la sua. Se il valore del chiamante sopravvivesse,
        «manda alla chat di questo topic» tornerebbe a essere «manda alla chat
        che dico io» — l'invio al gruppo sbagliato del 23 set 2026."""
        detto = resolved.fill_context(
            "telegram.send",
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
            "telegram.send", {"channel": "SEAL-3/consiglio", "text": "ciao"},
            {"channel": "", "agent": "fullstack-dev"})
        self.assertNotIn("channel", detto)
        self.assertEqual(detto["agent"], "fullstack-dev")

    def test_the_callers_dict_is_not_mutated(self):
        originale = {"channel": "SEAL-3/consiglio"}
        resolved.fill_context("telegram.send", originale,
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
            with patch.object(main, "agent_name_safe", return_value="messaggero"):
                detto = main._fill_declared_context(
                    "telegram.send", {"text": "ciao", "channel": "SEAL-3/x",
                                      "agent": "clodia"})
        finally:
            reset_current_chat(tok)
        self.assertEqual(detto["channel"], "SEAL-1/software-house")
        self.assertEqual(detto["agent"], "messaggero")

    def test_a_native_verb_is_left_exactly_as_it_was(self):
        from .. import main
        args = {"tier": "SEAL-1", "name": "software-house"}
        self.assertIs(main._fill_declared_context("topic.open", args), args)


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
    """Senza l'interruttore non c'è contesto da riempire: il connettore del
    pack non è nel registry, e il verbo nativo prende canale e agente dal
    processo come ha sempre fatto."""

    def test_on_native_nothing_is_filled(self):
        self.posizione("native")
        self.assertEqual(resolved.context_arguments("telegram.send"), {})
        from .. import main
        args = {"text": "ciao", "channel": "SEAL-3/x"}
        self.assertIs(main._fill_declared_context("telegram.send", args), args)


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

    def test_it_is_optional(self):
        c = M.parse_connector(self._connettore(), pack="sms-pack", reserved=())
        self.assertEqual(c.context, ())


class NoVerbIsLeftBehindTests(_Istanza):
    """Nessun verbo resta indietro quando il namespace cambia padrone.

    Il difetto che questo test ha trovato: `telegram.roster` è dichiarato
    dentro `_TOPIC_TOOLS`, non in `_TELEGRAM_TOOLS`. Una migrazione che
    togliesse i GRUPPI invece dei NAMESPACE lo lascerebbe esposto e servito dal
    gateway mentre il pack lo dichiara suo — e non darebbe errore: funzionerebbe
    dalla parte sbagliata, che è il modo in cui questi guasti non si vedono.
    """

    def test_not_one_verb_of_the_namespace_survives(self):
        self.posizione("pack")
        from .. import main
        rimasti = [n for n in main.all_native_verb_names()
                   if n.startswith("telegram.")]
        self.assertEqual(rimasti, [])
        self.assertTrue(main._is_packaged_verb("telegram.roster"))

    def test_they_are_all_there_in_the_other_position(self):
        """Il controllo gemello: l'interruttore su `native` non deve togliere
        niente. Senza questa metà, un elenco vuoto sarebbe verde due volte."""
        self.posizione("native")
        from .. import main
        rimasti = {n for n in main.all_native_verb_names()
                   if n.startswith("telegram.")}
        self.assertIn("telegram.send", rimasti)
        self.assertIn("telegram.roster", rimasti)

    def test_the_namespace_comes_from_the_builtin_manifest(self):
        """E non da una lista scritta nel dispatch: è il manifest builtin a dire
        quale namespace quel connettore occupa."""
        self.posizione("pack")
        namespaces, prefissi = B.released()
        self.assertEqual(namespaces, frozenset({"telegram"}))
        self.assertEqual(prefissi, frozenset({"telegram_"}))
        dichiarato = {str(e.get("id")): str(e.get("namespace"))
                      for doc in B._all().values()
                      for e in (doc.get("connectors") or [])}
        self.assertEqual(dichiarato["telegram"], "telegram")

    def test_a_prefix_a_remaining_connector_still_uses_is_not_released(self):
        """Un prefisso di vault si libera solo se NESSUN connettore rimasto nel
        gateway lo usa. Oggi è uno a uno; la migrazione dopo è google-pack
        (#523), che di prefissi ne ha tre — e liberarne uno che serve ancora
        al gateway lo consegnerebbe a un pack mentre il gateway ci scrive."""
        self.posizione("pack")
        with patch.object(B, "_all", lambda: {
            "gateway-telegram": {"connectors": [
                {"id": "telegram", "namespace": "telegram", "providers": [
                    {"id": "bot", "credential": {"vault_entry": "telegram_bot_token"}}]}]},
            "gateway-altro": {"connectors": [
                {"id": "altro", "namespace": "altro", "providers": [
                    {"id": "x", "credential": {"vault_entry": "telegram_shared"}}]}]},
        }):
            B._RELEASED.clear()
            self.addCleanup(B._RELEASED.clear)
            namespaces, prefissi = B.released()
        self.assertEqual(namespaces, frozenset({"telegram"}))
        self.assertEqual(prefissi, frozenset())


if __name__ == "__main__":
    unittest.main()

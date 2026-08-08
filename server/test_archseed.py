"""L'arciseed, e i tre percorsi che ora danno la stessa risposta.

Specification §1.3 e §1.4. Un seed **astratto**, che non si può spawnare, tiene i
verbi base; ogni seed ne discende e li acquisisce per ereditarietà. Il genitore è
un **default**, non un tetto: il contenimento viene dai gate, dalle liste dello
scope e dall'intersezione della catena, mai dall'antenato.

**La cosa più importante di questo file non è l'ereditarietà: è che i lettori
della matrice erano TRE e non erano d'accordo.**

    main._declared_tools        · config, poi il seed sulla datadir
    origin._agent_may           · config, e il deny per primo
    whitelist.tool_allowed · config, e il deny NON lo guardava affatto

Innestare l'arciseed in uno solo avrebbe prodotto un verbo consentito da un
percorso e negato da un altro — e nessuno se ne sarebbe accorto, perché nessuno
confronta i tre esiti. Ora passano tutti da `effective_tools`, e l'ultimo test di
questo file confronta i tre esiti su ogni verbo, che è il controllo che mancava.

La regola di appartenenza all'arciseed: un verbo ci sta quando il suo BERSAGLIO è
l'agente stesso o la stanza in cui lo spawn già si trova. Tutto il resto
attraversa qualcosa, e attraversare è mestiere.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import main as M
from . import origin
from . import whitelist as w


CFG = {"agents": {
    "clodia": {"allowed_tools": ["email.*"]},
    "segretario": {"allowed_tools": ["topic.save_summary"],
                   "denied_tools": ["topic.post_message"]},
    "professionista": {"allowed_tools": ["gdocs.*"], "abstract": True},
    "avvocato": {"allowed_tools": ["email.send"], "parents": ["professionista"]},
    "ciclo_a": {"allowed_tools": ["fs.list_dir"], "parents": ["ciclo_b"]},
    "ciclo_b": {"allowed_tools": ["logs.tail"], "parents": ["ciclo_a"]},
}}


def _cfg(c=None):
    return patch.object(w, "CONFIG", c or CFG)


SEED_ARCH = {"name": "archseed", "abstract": True, "tool_permissions": [
    "memory.*", "topic.open", "topic.files", "topic.read_file",
    "topic.read_document", "topic.search", "topic.list", "topic.fetch",
    "topic.post_message"]}


def _seed(d=None):
    from . import human as H
    return patch.object(H, "_seed", lambda n: (d if d is not None else SEED_ARCH)
                        if n == "archseed" else {})


class SourceTests(unittest.TestCase):
    """L'arciseed è un seed del base-pack, e si legge da lì.

    Osservazione di Davide, 8 ago 2026: «l'archseed fa parte del base-pack, non
    istanziabile in quanto abstract, ma vive lì». Aveva ragione contro il mio
    primo disegno, che lo teneva come tupla Python: **un seed è un file**, si
    legge, si diffa e si revisiona in una PR.

    L'obiezione che avevo — l'autorità non deve stare dove il soggetto la
    riscrive — resta soddisfatta: `/datadir/agents/` è `drwx------ root` e gli
    spawn girano unprivileged, quindi il confine lo mette il kernel. È lo stesso
    posto da cui si legge il ruolo di un umano.
    """

    def test_the_verbs_come_from_the_seed(self):
        with _cfg(), _seed():
            self.assertEqual(sorted(w.archseed_tools()),
                             sorted(SEED_ARCH["tool_permissions"]))

    def test_a_changed_seed_changes_the_floor(self):
        """La prova che la fonte è il file e non il codice."""
        with _cfg(), _seed({"tool_permissions": ["topic.open"]}):
            self.assertEqual(w.archseed_tools(), ["topic.open"])

    def test_config_can_override_the_instance(self):
        with patch.object(w, "CONFIG", {"agents": {},
                                        "archseed": {"allowed_tools": ["memory.*"]}}), \
             _seed({}):
            self.assertEqual(w.archseed_tools(), ["memory.*"])

    def test_the_builtin_is_only_a_bootstrap_floor(self):
        """Prima che il pack sia materializzato. Senza, ogni agente resterebbe
        senza verbi base proprio nel momento in cui l'istanza nasce — e «i due
        livelli esistono» sarebbe falso alla nascita."""
        with _cfg(), _seed({}):
            self.assertTrue(w.archseed_tools())

    def test_a_seed_that_declares_itself_abstract_is_abstract(self):
        """Anche se non è registrato nella config del gateway: altrimenti
        resterebbe spawnabile nonostante si dichiari astratto."""
        from . import human as H
        with _cfg(), patch.object(H, "_seed", lambda n: {"abstract": True}):
            self.assertTrue(w.is_abstract("un-antenato"))


class ExistenceTests(unittest.TestCase):
    def test_the_archseed_has_a_floor_even_at_bootstrap(self):
        with _cfg():
            self.assertTrue(w.archseed_tools())

    def test_it_holds_the_agents_own_memory(self):
        with _cfg():
            self.assertIn("memory.*", w.archseed_tools())

    def test_it_holds_the_reading_floor_of_the_current_scope(self):
        with _cfg():
            t = w.archseed_tools()
            for v in ("topic.open", "topic.files", "topic.read_file",
                      "topic.read_document", "topic.search", "topic.list",
                      "topic.fetch"):
                with self.subTest(verbo=v):
                    self.assertIn(v, t)

    def test_speaking_is_in_it(self):
        """Uno spawn che non può parlare nella propria stanza non può fare
        niente. Parlare non è mutare (§2.9)."""
        with _cfg():
            self.assertIn("topic.post_message", w.archseed_tools())

    def test_crossing_verbs_are_not_in_it(self):
        """Scrivere, spostare i muri, uscire: è mestiere, e il mestiere è del
        seed."""
        with _cfg():
            t = w.archseed_tools()
            for v in ("topic.put", "topic.write_file", "topic.delete_file",
                      "topic.add_participant", "topic.remote_enable",
                      "email.send", "web.post", "settings.set"):
                with self.subTest(verbo=v):
                    self.assertNotIn(v, t)

    def test_config_may_override_it(self):
        with _cfg({"agents": {}, "archseed": {"allowed_tools": ["topic.open"]}}):
            self.assertEqual(w.archseed_tools(), ["topic.open"])


class InheritanceTests(unittest.TestCase):
    def test_every_seed_inherits_the_archseed_without_declaring_it(self):
        """Se andasse dichiarato, un seed potrebbe ometterlo e uscire dal
        modello senza che si veda."""
        with _cfg():
            self.assertIn("memory.*", w.effective_tools("clodia"))

    def test_its_own_verbs_survive(self):
        with _cfg():
            self.assertIn("email.*", w.effective_tools("clodia"))

    def test_a_declared_parent_is_inherited_too(self):
        with _cfg():
            eff = w.effective_tools("avvocato")
            self.assertIn("gdocs.*", eff)      # dal genitore
            self.assertIn("email.send", eff)   # proprio
            self.assertIn("memory.*", eff)     # dall'arciseed

    def test_the_parent_is_a_default_not_a_ceiling(self):
        """Un derivato può avere ciò che il genitore non ha: il contenimento
        viene dai gate e dalle liste, non dall'antenato."""
        with _cfg():
            self.assertIn("email.send", w.effective_tools("avvocato"))
            self.assertNotIn("email.send", w.effective_tools("professionista"))

    def test_a_cycle_does_not_hang(self):
        """Un ciclo non deve diventare un gateway che non risponde."""
        with _cfg():
            eff = w.effective_tools("ciclo_a")
            self.assertIn("fs.list_dir", eff)
            self.assertIn("logs.tail", eff)

    def test_an_unregistered_principal_falls_back_to_its_seed(self):
        """Umani e cloni per-topic non stanno in config: senza il ripiego
        l'intersezione li azzererebbe."""
        seed = {"type": "human", "role": "member",
                "tool_permissions": ["topic.save_summary"]}
        with _cfg({"agents": {}}), patch.object(w, "CONFIG", {"agents": {}}):
            from . import human as H
            with patch.object(H, "_seed", lambda n: seed):
                self.assertIn("topic.save_summary", w.effective_tools("giovanni"))


class SubtractionTests(unittest.TestCase):
    """Il verso che impedisce all'arciseed di allargare chi era stretto."""

    def test_a_denied_verb_is_refused_even_though_inherited(self):
        with _cfg():
            self.assertTrue(w.agent_denies("topic.post_message", "segretario"))
            self.assertFalse(origin._agent_may("segretario", "topic.post_message"))

    def test_the_rest_of_the_inheritance_survives_the_subtraction(self):
        with _cfg():
            self.assertTrue(origin._agent_may("segretario", "topic.open"))


class AbstractTests(unittest.TestCase):
    def test_the_archseed_is_abstract(self):
        with _cfg():
            self.assertTrue(w.is_abstract(w.ARCHSEED))

    def test_a_seed_may_declare_itself_abstract(self):
        with _cfg():
            self.assertTrue(w.is_abstract("professionista"))

    def test_an_ordinary_seed_is_not(self):
        with _cfg():
            self.assertFalse(w.is_abstract("clodia"))

    def test_an_unknown_name_is_not_abstract(self):
        with _cfg():
            self.assertFalse(w.is_abstract("mai-visto"))


class OneAnswerTests(unittest.TestCase):
    """Il test che questo file esiste per portare.

    Tre lettori della stessa matrice davano tre risposte possibili, e la
    differenza era invisibile perché nessuno le confrontava. Qui si confrontano.
    """

    VERBI = ("topic.open", "topic.put", "memory.list", "email.send",
             "settings.set", "topic.post_message", "fs.list_dir")

    def _tre_esiti(self, agente, verbo):
        """I tre esiti come li produce il DISPATCH, non come li produce un
        helper interno.

        La prima versione confrontava `_tool_allowed(verbo, _declared_tools(a))`
        — che è solo la metà «whitelist» — contro due decisioni complete, e
        segnalava un disaccordo che non esiste: il dispatch di `main` consulta
        `agent_denies` subito dopo la whitelist. Terza volta in un giorno che un
        test costruito su un pezzo interno indica un difetto dove non c'è. La
        regola: confrontare decisioni, non aiutanti.
        """
        da_main = ((M._tool_allowed(verbo, M._declared_tools(agente))
                    or M._connector_allows(verbo, agente))
                   and not w.agent_denies(verbo, agente))
        da_origin = origin._agent_may(agente, verbo)
        try:
            with patch.object(w, "agent_name", lambda: agente):
                w.tool_allowed(verbo)
            da_ensure = True
        except PermissionError:
            da_ensure = False
        return da_main, da_origin, da_ensure

    def test_the_three_paths_agree(self):
        with _cfg(), patch.object(M, "_is_super", lambda n: False), \
             patch.object(w, "_SUPER_AGENTS", set()), \
             patch.object(M, "_connector_allows", lambda v, a: False):
            for agente in ("clodia", "segretario", "avvocato"):
                for verbo in self.VERBI:
                    with self.subTest(agente=agente, verbo=verbo):
                        m, o, e = self._tre_esiti(agente, verbo)
                        self.assertEqual(
                            (m, o, e), (m, m, m),
                            f"i tre percorsi non concordano su {agente}/{verbo}: "
                            f"main={m} origin={o} ensure={e}")

    def test_the_deny_is_honoured_on_every_path(self):
        """Il percorso `tool_allowed` non guardava affatto i
        `denied_tools`: rispondeva «consentito» su un verbo che gli altri due
        negavano."""
        with _cfg(), patch.object(M, "_is_super", lambda n: False), \
             patch.object(w, "_SUPER_AGENTS", set()), \
             patch.object(M, "_connector_allows", lambda v, a: False):
            m, o, e = self._tre_esiti("segretario", "topic.post_message")
            self.assertEqual((m, o, e), (False, False, False))


if __name__ == "__main__":
    unittest.main()


class ProvenanceTests(unittest.TestCase):
    """Terza condizione della §1.4, e senza di essa l'ereditarietà sarebbe un
    cattivo affare.

    Prima si leggeva un file e si sapeva cosa un agente potesse fare; con
    l'ereditarietà non più. **Una duplicazione la vedi, un'opacità no** — quindi
    l'insieme risolto deve dire da dove viene ogni pezzo.

    E serve a una cosa pratica: capire se un verbo si toglie togliendolo
    dall'agente o se va sottratto con `denied_tools` perché arriva da un
    antenato. Sono due rimedi diversi, e sbagliarli significa modificare un file
    e vedere che non cambia niente.
    """

    def test_an_own_verb_says_own(self):
        with _cfg():
            self.assertEqual(w.tools_with_provenance("clodia").get("email.*"), "own")

    def test_an_inherited_verb_names_the_ancestor(self):
        """«Ereditato» non basta: serve DA CHI, perché è il file da aprire."""
        with _cfg():
            self.assertEqual(
                w.tools_with_provenance("avvocato").get("gdocs.*"), "professionista")

    def test_a_base_verb_says_archseed(self):
        with _cfg():
            self.assertEqual(
                w.tools_with_provenance("clodia").get("memory.*"), w.ARCHSEED)

    def test_a_denied_verb_stays_visible_and_is_marked(self):
        """Se sparisse dall'elenco, chi legge non saprebbe se non sia mai stato
        ereditato — e la risposta che serve è «c'è, ed è stato sottratto qui»."""
        with _cfg():
            v = w.tools_with_provenance("segretario").get("topic.post_message", "")
            self.assertIn("negato", v)
            self.assertIn(w.ARCHSEED, v)

    def test_the_resolved_set_matches_the_one_used_to_decide(self):
        """Una scheda che mostrasse un insieme diverso da quello che decide
        sarebbe peggio di nessuna scheda: si guarderebbe la cosa sbagliata
        credendo di guardare quella giusta."""
        with _cfg():
            for a in ("clodia", "avvocato", "segretario"):
                with self.subTest(agente=a):
                    self.assertEqual(set(w.tools_with_provenance(a)),
                                     w.effective_tools(a))

    def test_the_card_carries_it(self):
        import inspect
        from .tools import agents_admin
        src = inspect.getsource(agents_admin.show)
        self.assertIn("tools_with_provenance", src)
        self.assertIn("tool_permissions", src)   # la dichiarazione resta accanto


class InspectableTests(unittest.TestCase):
    """L'arciseed non è un file, ma dev'essere ispezionabile.

    Osservazione di Davide, 8 ago 2026: «non vedo l'archseed tra i seed del
    base-pack». Giusto, e deliberato: i seed del pack vivono nella datadir, che
    l'agent-server scrive, mentre l'autorità dev'essere irraggiungibile dal suo
    soggetto (§3.5). Come codice sul volume del gateway, «i due livelli
    esistono» è vero su ogni istanza invece di dipendere da un file che qualcuno
    deve aver creato.

    **Ma non essere un file non è una ragione per essere invisibile.** Si vedeva
    che un verbo veniva dall'arciseed e non si poteva aprire l'arciseed: metà
    della domanda senza risposta, e la §1.4 chiede il contrario.
    """

    def _adm(self):
        from .tools import agents_admin
        return agents_admin

    def test_its_card_opens(self):
        with _cfg():
            c = self._adm().show(w.ARCHSEED)
            self.assertEqual(c["name"], w.ARCHSEED)

    def test_the_card_lists_the_base_verbs(self):
        with _cfg():
            c = self._adm().show(w.ARCHSEED)
            self.assertEqual(sorted(c["tool_permissions"]),
                             sorted(w.archseed_tools()))

    def test_it_says_it_cannot_be_spawned(self):
        with _cfg():
            self.assertTrue(self._adm().show(w.ARCHSEED)["abstract"])

    def test_it_says_where_it_comes_from(self):
        """`source: gateway` risponde alla domanda vera di chi la legge: non si
        modifica da qui, e non perché sia protetto — perché non è un file."""
        with _cfg():
            c = self._adm().show(w.ARCHSEED)
            self.assertEqual(c["source"], "gateway")
            self.assertTrue(c["immutable"])

    def test_it_appears_in_the_list(self):
        """Un elenco che lo omette fa sembrare che i verbi base vengano dal
        nulla."""
        with _cfg(), patch.object(self._adm(), "_all_agents", lambda: []):
            nomi = [a["name"] for a in self._adm().list_agents()["agents"]]
            self.assertIn(w.ARCHSEED, nomi)

    def test_the_card_matches_what_the_gateway_actually_grants(self):
        """Una scheda che mostrasse verbi diversi da quelli ereditati sarebbe
        peggio dell'assenza: si guarderebbe la cosa sbagliata."""
        with _cfg():
            c = self._adm().show(w.ARCHSEED)
            self.assertTrue(set(c["tool_permissions"]) <= w.effective_tools("clodia"))

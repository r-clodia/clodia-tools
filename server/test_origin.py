"""Tests for the origin chain and the intersection of authorities (§4).

The property under test is not "delegation is restricted". It is the *direction*
of the restriction, and the two directions fail differently:

- **substitution** (run the call on the initiator's authority) would let Davide
  ask a postman for `fs.list_dir` and succeed. The agent borrows the human's
  power — silently, and available by simply asking.
- **intersection** refuses unless BOTH may. That is the rule, and the tests below
  pin both halves, because a test suite that only checks the deny case would pass
  on an implementation that refuses everything.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import human, origin
from . import whitelist as w

# messaggero: postino — posta sì, shell no.
# segretario: solo riassunti.
# clodia: super, wildcard.
CFG = {"agents": {
    "clodia": {"allowed_tools": ["*"]},
    "messaggero": {"allowed_tools": ["email.*", "topic.open", "topic.post_message"]},
    "segretario": {"allowed_tools": ["topic.open", "topic.save_summary"]},
    # sysadmin amministra: ha `fs.list_dir`, che il postino non ha. Verbi REALI,
    # verificati nell'elenco nativo del gateway — un test che illustra la regola
    # centrale con un verbo inventato fa credere che il modello sia stato
    # progettato contro un sistema immaginario.
    "sysadmin": {"allowed_tools": ["fs.list_dir", "agents.*", "topic.open"]},
    "impiegato": {"allowed_tools": ["email.*"], "denied_tools": ["email.send"]},
}}

# davide: admin, tutto. giovanni: membro, solo lettura di topic. matteo: senza
# matrice dichiarata → si ricade sulla regola precedente.
SEEDS = {
    "davide": {"type": "human", "role": "superadmin", "tool_permissions": ["*"]},
    "giovanni": {"type": "human", "role": "member",
                 "tool_permissions": ["topic.open", "topic.files", "topic.read_file"]},
    "matteo": {"type": "human", "role": "member"},          # nessuna matrice
    "chiuso": {"type": "human", "role": "member", "tool_permissions": []},
}


def _env():
    return (patch.object(w, "CONFIG", CFG),
            patch.object(human, "_seed", lambda n: SEEDS.get(n, {})))


class Base(unittest.TestCase):
    def setUp(self):
        self.ctx = _env()
        for c in self.ctx:
            c.start()
        self.addCleanup(lambda: [c.stop() for c in self.ctx])
        human.reset_cache()

    def verdict(self, chain, verb):
        return origin.evaluate(origin.parse(chain), verb)


class TheRuleTests(Base):
    def test_the_owner_asking_a_postman_to_send_is_allowed(self):
        """Il caso legittimo. Se questo si rompe, il modello ha reso la
        piattaforma inutilizzabile e verrà spento, che è il modo peggiore in cui
        un controllo può fallire."""
        v = self.verdict(["human:davide", "agent:messaggero"], "email.send")
        self.assertEqual(v["action"], "allow")

    def test_a_member_without_the_permission_asking_the_same_is_refused(self):
        """L'incidente descritto: Giovanni non ha permessi sulla posta, chiede a
        messaggero, e messaggero ce li ha."""
        v = self.verdict(["human:giovanni", "agent:messaggero"], "email.send")
        self.assertEqual(v["action"], "deny")
        self.assertEqual(v["refused_by"], "human:giovanni")

    def test_the_owner_cannot_borrow_the_agents_body_for_a_verb_it_lacks(self):
        """LA prova della sostituzione contro l'intersezione.

        Davide può `fs.list_dir`; messaggero no. Con la sostituzione questa
        chiamata passerebbe, e sarebbe escalation attraverso un agente —
        silenziosa e disponibile a chiunque sappia chiedere.

        Il verbo è reale ed è quello che serve: il primo giro di questo test
        usava `shell.exec`, che in questa piattaforma **non esiste**, quindi
        passava per la ragione sbagliata (un verbo ignoto non è nella lista di
        nessuno) e non avrebbe visto la sostituzione se ci fosse stata.
        """
        v = self.verdict(["human:davide", "agent:messaggero"], "fs.list_dir")
        self.assertEqual(v["action"], "deny")
        self.assertEqual(v["refused_by"], "agent:messaggero")
        # e con l'agente che DAVVERO ha il verbo, la stessa richiesta passa:
        # senza questa metà, un'implementazione che nega tutto passerebbe il test
        self.assertEqual(
            self.verdict(["human:davide", "agent:sysadmin"], "fs.list_dir")["action"],
            "allow")

    def test_the_verbs_used_in_these_tests_actually_exist(self):
        """Guardia contro l'errore appena corretto.

        Un test costruito su un verbo inesistente verifica il caso «verbo ignoto»
        credendo di verificare la regola. Qui si confronta con l'elenco nativo del
        gateway, così il giorno che un verbo viene rinominato il test lo dice
        invece di continuare a passare per il motivo sbagliato.
        """
        from . import main as m
        nativi = set(m.all_native_verb_names())
        for verbo in ("fs.list_dir", "email.send", "email.read", "topic.open"):
            with self.subTest(verbo=verbo):
                self.assertIn(verbo, nativi, f"'{verbo}' non è un verbo del gateway")

    def test_every_link_narrows_the_chain_not_just_the_ends(self):
        """Un anello intermedio con meno autorità deve restringere. Intersecare
        solo capo e coda lascerebbe un ponte."""
        v = self.verdict(["human:davide", "agent:segretario", "agent:messaggero"],
                         "email.send")
        self.assertEqual(v["action"], "deny")
        self.assertEqual(v["refused_by"], "agent:segretario")

    def test_a_super_agent_in_the_middle_does_not_widen(self):
        v = self.verdict(["human:giovanni", "agent:clodia", "agent:messaggero"],
                         "email.send")
        self.assertEqual(v["action"], "deny")
        self.assertEqual(v["refused_by"], "human:giovanni")

    def test_a_deny_beats_a_wildcard_inside_the_chain(self):
        """`denied_tools` vince su `email.*`: se un allow potesse sovrascriverlo
        non toglierebbe nulla."""
        v = self.verdict(["human:davide", "agent:impiegato"], "email.send")
        self.assertEqual(v["action"], "deny")
        self.assertEqual(v["refused_by"], "agent:impiegato")
        self.assertEqual(self.verdict(["human:davide", "agent:impiegato"],
                                      "email.read")["action"], "allow")


class HumanMatrixTests(Base):
    def test_a_human_with_no_declared_matrix_falls_back_to_the_previous_rule(self):
        """Direzione della retrocompatibilità: «come prima», non «tutto chiuso».

        Introdurre il modello non deve disconnettere gli utenti esistenti — che
        oggi non hanno matrice — perché un controllo che rompe il lavoro viene
        spento, e allora non protegge niente. La modalità di osservazione serve a
        scoprire quali matrici scrivere prima che il rifiuto diventi reale.
        """
        v = self.verdict(["human:matteo", "agent:messaggero"], "email.send")
        self.assertEqual(v["action"], "allow")

    def test_but_a_gated_verb_still_needs_admin_in_the_fallback(self):
        with patch("server.gate.is_gated", lambda v: v == "packs.remove"):
            self.assertEqual(
                self.verdict(["human:matteo", "agent:clodia"], "packs.remove")["action"],
                "deny")
            self.assertEqual(
                self.verdict(["human:davide", "agent:clodia"], "packs.remove")["action"],
                "allow")

    def test_an_empty_matrix_is_not_the_same_as_an_absent_one(self):
        """`[]` = «nessun verbo»; assente = «non mi pronuncio». Confonderli
        renderebbe impossibile dichiarare un utente di sola lettura, oppure
        disconnetterebbe tutti al primo deploy."""
        self.assertEqual(human.matrix("chiuso"), [])
        self.assertIsNone(human.matrix("matteo"))
        self.assertEqual(
            self.verdict(["human:chiuso", "agent:messaggero"], "email.send")["action"],
            "deny")

    def test_a_wildcard_matrix_permits_everything(self):
        self.assertEqual(
            self.verdict(["human:davide", "agent:clodia"], "fs.list_dir")["action"],
            "allow")

    def test_a_non_human_seed_has_no_matrix_and_no_role(self):
        self.assertIsNone(human.matrix("messaggero"))
        self.assertEqual(human.role("messaggero"), "user")


class UnknownChainTests(Base):
    def test_an_absent_chain_is_unknown_not_permitted(self):
        """Un agent-server non aggiornato manda un token senza `origin`. Quel
        caso non deve diventare un via libera silenzioso: si dichiara, e chi
        legge decide."""
        self.assertEqual(origin.evaluate([], "email.send")["action"], "unknown")

    def test_malformed_links_are_dropped_not_interpreted(self):
        """Un anello illeggibile non deve diventare un anello permissivo."""
        chain = origin.parse(["human:giovanni", "spazzatura", "agent:", ":x"])
        self.assertEqual(chain, [("human", "giovanni")])


class ModeTests(unittest.TestCase):
    def test_the_default_is_observation_not_enforcement(self):
        """L'enforcement segue la misura. Accenderlo alla cieca produce rifiuti su
        lavoro legittimo, e il controllo viene spento prima di essere capito — è
        successo con la whitelist delle destinazioni, che nasce vuota di
        proposito."""
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(origin.mode(), "report")

    def test_an_unknown_value_does_not_silently_disable(self):
        with patch.dict("os.environ", {"CLODIA_ORIGIN_ENFORCE": "sì-grazie"}):
            self.assertEqual(origin.mode(), "report")

    def test_it_can_be_turned_on_and_off_explicitly(self):
        for value, expected in (("on", "on"), ("off", "off"), ("REPORT", "report")):
            with patch.dict("os.environ", {"CLODIA_ORIGIN_ENFORCE": value}):
                self.assertEqual(origin.mode(), expected)


class MessageTests(Base):
    def test_a_human_refusal_points_at_the_escalation(self):
        """Il rifiuto porta l'alternativa, o produce il guasto già visto: un
        agente che riprova, o che riferisce «permessi» a un umano che non ha modo
        di sapere cosa gli manca. Qui l'alternativa è un'approvazione."""
        v = self.verdict(["human:giovanni", "agent:messaggero"], "email.send")
        m = origin.denial_message(v)
        self.assertIn("giovanni", m)
        self.assertIn("admin", m)
        self.assertIn("email.send", m)
        self.assertIn("→", m, "la catena va mostrata")

    def test_an_agent_refusal_says_a_mandate_does_not_confer_the_verb(self):
        """Caso diverso, rimedio diverso: qui approvare non serve, serve un altro
        agente. Un messaggio che li confonde manda l'umano a cercare
        un'autorizzazione che non risolve."""
        v = self.verdict(["human:davide", "agent:messaggero"], "fs.list_dir")
        m = origin.denial_message(v)
        self.assertIn("messaggero", m)
        self.assertNotIn("approvazione di un admin", m)


class DispatchTests(unittest.TestCase):
    def test_the_intersection_runs_before_the_gates(self):
        """Se la catena non regge, chiedere l'approvazione del VERBO è la domanda
        sbagliata: nasconde il fatto rilevante, che è «chi ha chiesto non ha
        questo permesso e sta usando un agente per averlo»."""
        import inspect
        from . import main
        src = inspect.getsource(main.call_tool)
        i_org = src.find("origin.evaluate")
        i_gate = src.find("M-gate:")
        self.assertGreater(i_org, 0, "l'intersezione non è nel dispatch")
        self.assertGreater(i_gate, i_org, "l'intersezione deve precedere i gate")

    def test_report_mode_records_instead_of_blocking(self):
        import inspect
        from . import main
        src = inspect.getsource(main.call_tool)
        self.assertIn('_obs_o.note("would_deny"', src)

    def test_the_fallback_chain_is_explicit(self):
        """Quando il claim non c'è si ricostruisce il minimo noto, e non si
        inventa un permesso."""
        import inspect
        from . import main
        src = inspect.getsource(main._origin_chain)
        self.assertIn("current_origin()", src)
        self.assertIn("is_on_behalf()", src)


if __name__ == "__main__":
    unittest.main()

"""L'obiettivo di un canale vive nel meta, non nella cronologia.

clodia-platform#457. Un messaggio dell'utente può essere promosso a OBIETTIVO:
da quel momento è un requisito vincolante che l'orchestratore deve portare a
termine, e togliere il pin è ciò che ferma l'esecuzione della strategia.

I test che contano:
  - il goal sopravvive nel meta e torna da `open` (se scorresse via con i
    messaggi, il pin non varrebbe niente);
  - `pinned_by`/`pinned_at` non li decide il richiedente, e non si riscrivono
    quando lo stesso obiettivo avanza di stato — altrimenti «chi l'ha chiesto e
    quando» diventa «chi ha toccato il goal per ultimo»;
  - un meta con un goal corrotto resta APRIBILE: il read-path è tollerante come
    per la deadline, o un campo nuovo può far sparire un topic dalla lista.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from .local_fs import LocalFsStorage
from .service import TopicService, TopicError


class Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="goal-"))
        self.svc = TopicService(LocalFsStorage(str(self.root)))
        self.svc.new("SEAL-1", "progetto", {"title": "Progetto", "owner": "davide"})

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _pin(self, **extra):
        goal = {"text": "Portare il sito in produzione entro ottobre",
                "message_id": "20260930-180000-abcd"}
        goal.update(extra)
        return self.svc.set_goal("SEAL-1", "progetto", goal, by="davide")["goal"]

    def _meta(self) -> dict:
        return self.svc.open("SEAL-1", "progetto")["meta"]


class PinTests(Base):
    def test_pinned_goal_is_in_the_meta_and_comes_back_from_open(self):
        """Il cuore di #457: il pin è metadata, allo stesso rango di summary e
        tldr. Chi apre il canale lo legge senza ricostruire la cronologia."""
        self._pin()
        goal = self._meta().get("goal")
        self.assertEqual(goal["text"], "Portare il sito in produzione entro ottobre")
        self.assertEqual(goal["message_id"], "20260930-180000-abcd")
        self.assertEqual(goal["state"], "pinned")
        self.assertEqual(goal["pinned_by"], "davide")
        self.assertTrue(goal["pinned_at"])

    def test_the_requester_cannot_sign_the_pin_for_someone_else(self):
        """`pinned_by` viene dal principal verificato, non dal corpo della
        richiesta: un campo autodichiarato non è una firma."""
        goal = self._pin(pinned_by="clodia")
        self.assertEqual(goal["pinned_by"], "davide")

    def test_advancing_the_same_goal_keeps_who_pinned_it_and_when(self):
        """Stesso `message_id` ⇒ stesso obiettivo che cambia stato. L'origine
        non si riscrive, altrimenti il goal finisce attribuito all'ultimo che
        l'ha toccato — tipicamente un agente, non la persona che l'ha chiesto."""
        primo = self._pin()
        avanzato = self.svc.set_goal(
            "SEAL-1", "progetto",
            {"text": "Portare il sito in produzione entro ottobre",
             "message_id": "20260930-180000-abcd",
             "state": "in-progress",
             "strategy_path": "local/goals/strategy.md"},
            by="clodia")["goal"]
        self.assertEqual(avanzato["state"], "in-progress")
        self.assertEqual(avanzato["pinned_by"], "davide")
        self.assertEqual(avanzato["pinned_at"], primo["pinned_at"])
        self.assertEqual(avanzato["strategy_path"], "local/goals/strategy.md")

    def test_a_different_message_is_a_different_goal(self):
        """Obiettivo nuovo: origine e istante ripartono, e la strategia del
        precedente non viene ereditata (sarebbe il piano di un altro scopo)."""
        self._pin(state="in-progress", strategy_path="local/goals/vecchia.md")
        nuovo = self.svc.set_goal(
            "SEAL-1", "progetto",
            {"text": "Altro obiettivo", "message_id": "20260930-190000-zzzz"},
            by="clodia")["goal"]
        self.assertEqual(nuovo["pinned_by"], "clodia")
        self.assertIsNone(nuovo["strategy_path"])
        self.assertEqual(nuovo["state"], "pinned")

    def test_long_text_is_truncated_not_refused(self):
        """Il testo è una copia di comodo: `message_id` resta il riferimento
        all'originale, quindi si tronca. Rifiutare impedirebbe di fissare come
        obiettivo una richiesta lunga, che è il caso normale."""
        goal = self._pin(text="x" * 9000)
        self.assertLessEqual(len(goal["text"]), 4000)
        self.assertTrue(goal["text"].endswith("…"))


class UnpinTests(Base):
    def test_unpin_removes_the_goal(self):
        """Togliere il pin è l'atto che ferma l'esecuzione della strategia:
        deve lasciare il meta SENZA goal, non con un goal vuoto."""
        self._pin()
        res = self.svc.set_goal("SEAL-1", "progetto", None, by="davide")
        self.assertIsNone(res["goal"])
        self.assertTrue(res["unpinned"])
        self.assertNotIn("goal", self._meta())

    def test_unpin_without_a_goal_is_not_an_error(self):
        res = self.svc.set_goal("SEAL-1", "progetto", None, by="davide")
        self.assertIsNone(res["goal"])
        self.assertFalse(res["unpinned"])


class ValidationTests(Base):
    def test_empty_text_is_refused(self):
        with self.assertRaises(TopicError):
            self.svc.set_goal("SEAL-1", "progetto", {"text": "   "}, by="davide")

    def test_unknown_state_is_refused(self):
        with self.assertRaises(TopicError):
            self._pin(state="quasi-fatto")

    def test_non_object_goal_is_refused(self):
        with self.assertRaises(TopicError):
            self.svc.set_goal("SEAL-1", "progetto", "fai una cosa", by="davide")


class ReadPathTests(Base):
    def test_a_corrupt_goal_does_not_make_the_topic_unopenable(self):
        """Come per la deadline: la validazione stretta sta in scrittura. In
        lettura un valore non conforme diventa None con un warning — un campo
        nuovo non può far sparire un topic dalla lista."""
        from .service import _coerce_goal
        self.assertIsNone(_coerce_goal({"note": "senza testo"}))
        self.assertIsNone(_coerce_goal("stringa legacy"))

    def test_unknown_state_in_a_stored_goal_falls_back_to_pinned(self):
        from .service import _coerce_goal
        letto = _coerce_goal({"text": "obiettivo", "state": "boh"})
        self.assertEqual(letto["state"], "pinned")


class AdvanceTests(Base):
    """`advance_goal` è la porta degli AGENTI: può far avanzare, mai fissare o
    ritirare. Un orchestratore che potesse pinnarsi gli obiettivi non starebbe
    eseguendo un requisito, se lo starebbe scrivendo."""

    def test_an_agent_can_move_the_goal_forward(self):
        self._pin()
        g = self.svc.advance_goal("SEAL-1", "progetto", "strategy-review",
                                  "local/goals/strategia.md", by="clodia")["goal"]
        self.assertEqual(g["state"], "strategy-review")
        self.assertEqual(g["strategy_path"], "local/goals/strategia.md")
        self.assertEqual(g["pinned_by"], "davide")  # l'origine resta dell'owner

    def test_advancing_without_a_pinned_goal_is_refused(self):
        """Il verbo non è una porta di servizio per creare un obiettivo."""
        with self.assertRaises(TopicError):
            self.svc.advance_goal("SEAL-1", "progetto", "in-progress", by="clodia")

    def test_an_agent_cannot_close_the_goal_by_itself(self):
        """`done` è l'accettazione dell'owner: un agente arriva al massimo a
        `claimed-done`, che è una richiesta di verifica, non un verdetto.
        Il vocabolario del verbo MCP lo dichiara nello schema; qui si difende
        l'invariante nel punto in cui è scritta."""
        from .. import main as gw
        schema = next(t for t in gw._TOPIC_TOOLS
                      if t.name == "topic.goal_progress").inputSchema
        self.assertEqual(schema["properties"]["state"]["enum"],
                         ["strategy-review", "in-progress", "claimed-done"])
        self.assertIn("goal_progress", gw._TOPIC_SCOPED_VERBS)
        self.assertIn("goal_progress", gw._TOPIC_MUTATING_VERBS)


class RouteTests(Base):
    """La rotta interna esiste ed è quella che l'agent-server chiamerà. Senza
    questo, un refactor delle `routes` lascia il verbo lato logic a parlare con
    un 404 che sembra un topic mancante."""

    def setUp(self):
        super().setUp()
        from unittest.mock import patch
        from starlette.applications import Starlette
        from starlette.testclient import TestClient
        from .. import topics_api

        p = [patch.object(topics_api, "_svc", self.svc),
             patch.object(topics_api, "_authorize", lambda _r: ("davide", None))]
        for x in p:
            x.start()
        self.addCleanup(lambda: [x.stop() for x in reversed(p)])
        self.client = TestClient(Starlette(routes=topics_api.routes))

    def test_post_pins_and_unpins_through_the_internal_route(self):
        r = self.client.post(
            "/internal/topics/SEAL-1/progetto/goal",
            json={"goal": {"text": "Andare in produzione", "message_id": "m1"},
                  "by": "davide"},
            headers={"Authorization": "Bearer ckt1.finto"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["goal"]["pinned_by"], "davide")
        r = self.client.post("/internal/topics/SEAL-1/progetto/goal",
                             json={"goal": None, "by": "davide"},
                             headers={"Authorization": "Bearer ckt1.finto"})
        self.assertIsNone(r.json()["goal"])

    def test_an_invalid_goal_is_a_400_not_a_500(self):
        r = self.client.post("/internal/topics/SEAL-1/progetto/goal",
                             json={"goal": {"text": ""}, "by": "davide"},
                             headers={"Authorization": "Bearer ckt1.finto"})
        self.assertEqual(r.status_code, 400)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

"""Un owner di scope è sempre umano.

Invariante 1 della specifica (§2.9, §7), **scritta e non asserita da nulla** fino
all'8 ago 2026.

Non è una preferenza di disegno. Dal 7 agosto l'owner **sblocca i gate del
proprio scope** (voce 24): uno scope di proprietà di un agente sbloccherebbe
quindi i propri gate — il confused deputy nella sua forma più pulita, e per
giunta legittimato dal disegno invece che sfuggito.

Che il rischio fosse concreto si è visto lo stesso giorno: il topic di
configurazione, creato senza guardia, avrebbe avuto `clodia` come owner, perché
`owner` ripiega su `contact_agent`. Lì è stato chiuso per quel solo topic; qui
vale per ogni scope.

**La direzione del rifiuto è la parte pensata.** Si rifiuta ciò che si SA essere
un agente, non ciò che non si riconosce: non tutti gli owner legittimi stanno nel
registro degli umani — un'istanza appena reclamata, un principal creato fuori
banda — e rifiutare l'ignoto trasformerebbe una lacuna del registro in un topic
senza owner.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import human as H
from . import whitelist as w
from .topics.service import TopicService as T, TopicError


CFG = {"agents": {"clodia": {}, "segretario": {}}}
SEEDS = {"davide": {"type": "human", "role": "superadmin"},
         "giovanni": {"type": "human", "role": "member"}}


def _env():
    return (patch.object(w, "CONFIG", CFG),
            patch.object(H, "_seed", lambda n: SEEDS.get(n, {})))


class Base(unittest.TestCase):
    def run_with(self, fn):
        ctx = _env()
        for c in ctx:
            c.start()
        try:
            return fn()
        finally:
            [c.stop() for c in ctx]


class OwnershipTests(Base):
    def test_a_human_may_own_a_scope(self):
        self.run_with(lambda: T._require_human_owner("davide", "SEAL-1", "acme"))

    def test_any_human_may_not_only_the_admin(self):
        """La proprietà di uno scope non è un privilegio d'istanza: Giovanni
        possiede il proprio topic."""
        self.run_with(lambda: T._require_human_owner("giovanni", "SEAL-1", "acme"))

    def test_an_agent_may_not(self):
        def go():
            with self.assertRaises(TopicError) as cm:
                T._require_human_owner("clodia", "SEAL-1", "acme")
            return str(cm.exception)
        self.assertIn("agente", self.run_with(go))

    def test_the_refusal_says_why_it_matters(self):
        """«Non puoi» non basta: chi legge deve capire che non è una regola
        arbitraria ma la conseguenza di chi sblocca i gate."""
        def go():
            with self.assertRaises(TopicError) as cm:
                T._require_human_owner("segretario", "SEAL-1", "acme")
            return str(cm.exception)
        t = self.run_with(go)
        self.assertIn("sblocca i gate", t)
        self.assertIn("persona", t)


class DirectionTests(Base):
    def test_an_unknown_principal_is_not_refused(self):
        """Si rifiuta ciò che si sa essere un agente, non ciò che non si
        riconosce: rifiutare l'ignoto trasformerebbe una lacuna del registro in
        un topic senza owner."""
        self.run_with(lambda: T._require_human_owner("mai-visto", "SEAL-1", "acme"))

    def test_an_empty_owner_is_not_refused_here(self):
        """Un topic può nascere senza owner — è visibile e si corregge. Un topic
        che non nasce affatto no."""
        self.run_with(lambda: T._require_human_owner("", "SEAL-1", "acme"))

    def test_an_unreadable_registry_does_not_decide(self):
        """Non sapere non è una ragione per rifiutare: sarebbe un guasto
        travestito da decisione."""
        def rotto(n):
            raise RuntimeError("registro giù")
        with patch.object(w, "CONFIG", CFG), patch.object(H, "_seed", rotto):
            T._require_human_owner("chiunque", "SEAL-1", "acme")


class WiringTests(unittest.TestCase):
    def test_the_check_guards_the_assignment(self):
        """Se stesse su una rotta della webui, un verbo del gateway la
        aggirerebbe."""
        import inspect
        self.assertIn("_require_human_owner", inspect.getsource(T.set_owner))

    def test_it_runs_before_the_write(self):
        import inspect
        src = inspect.getsource(T.set_owner)
        self.assertLess(src.index("_require_human_owner"), src.index("_write_meta"))

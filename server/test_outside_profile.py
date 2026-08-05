"""Un verbo raggiungibile ma fuori dal profilo dichiarato passa da un gate.

Sposta la least authority dalla RIMOZIONE alla SUPERVISIONE. Un verbo tolto a un
super è un verbo che l'owner deve fare a mano; un verbo fuori profilo è un verbo
che il super fa con la sua approvazione — stesso umano coinvolto, ma niente si
rompe. Togliere verbi per disciplina si è già rotto addosso una volta: a un
postino, levandogli `post_message`, cioè il mestiere.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import whitelist as wl


def _cfg(profile=None, allowed=("*",), gated=()):
    return {"agents": {"clodia": {"allowed_tools": list(allowed),
                                  "profile_tools": list(profile or []),
                                  "gated_tools": list(gated)}}}


class OutsideProfileTests(unittest.TestCase):
    def test_a_verb_in_the_profile_is_not_gated_by_it(self):
        with patch.object(wl, "CONFIG", _cfg(profile=["topic.open", "email.read"])):
            self.assertFalse(wl.outside_profile("topic.open", "clodia"))
            self.assertFalse(wl.outside_profile("email.read", "clodia"))

    def test_a_verb_outside_the_profile_is(self):
        """`email.send` fuori dal profilo di un coordinatore: legge la posta e
        chiede prima di spedirla. Era il principio enunciato ad agosto."""
        with patch.object(wl, "CONFIG", _cfg(profile=["email.read"])):
            self.assertTrue(wl.outside_profile("email.send", "clodia"))

    def test_an_empty_profile_constrains_nothing(self):
        """Un agente che non dichiara un profilo non è un agente senza mestiere:
        è uno che non l'ha ancora dichiarato. Trattarlo come «tutto gated»
        renderebbe la piattaforma inservibile al primo aggiornamento incompleto."""
        with patch.object(wl, "CONFIG", _cfg(profile=[])):
            self.assertFalse(wl.outside_profile("email.send", "clodia"))
        with patch.object(wl, "CONFIG", {"agents": {"clodia": {"allowed_tools": ["*"]}}}):
            self.assertFalse(wl.outside_profile("email.send", "clodia"))

    def test_a_namespace_in_the_profile_covers_its_verbs(self):
        with patch.object(wl, "CONFIG", _cfg(profile=["topic.*"])):
            self.assertFalse(wl.outside_profile("topic.read_file", "clodia"))
            self.assertTrue(wl.outside_profile("email.send", "clodia"))

    def test_an_unknown_agent_is_not_constrained(self):
        with patch.object(wl, "CONFIG", _cfg(profile=["topic.open"])):
            self.assertFalse(wl.outside_profile("email.send", "fantasma"))


if __name__ == "__main__":
    unittest.main()

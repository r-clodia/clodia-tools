"""L'allowlist dei job logici resta una LISTA, non una regola.

Un job logico esegue verbi **senza M-gate**: l'owner l'ha approvato alla
creazione, e l'esecuzione ricorrente è pre-autorizzata. Per non trasformare
quella pre-autorizzazione in un bypass generico dei verbi gated, l'esecuzione è
ristretta a verbi scelti **uno per volta**, e allargarla richiede un deploy.

Il 10 ago 2026 la guardia ha fatto il suo mestiere: il job che recapita le
notifiche di menzione ha preso 403 al primo fire. Non era un difetto — era il
disegno — e il verbo è stato aggiunto deliberatamente, con il criterio scritto
accanto.
"""
from __future__ import annotations

import unittest

from . import logic_api


class AllowlistTests(unittest.TestCase):
    def test_it_stays_small_and_explicit(self):
        """Se un giorno diventasse lunga, o contenesse un prefisso, avrebbe
        smesso di essere una lista di decisioni e sarebbe una regola."""
        self.assertLessEqual(len(logic_api._ALLOWED), 8)
        for verbo in logic_api._ALLOWED:
            with self.subTest(verbo):
                self.assertNotIn("*", verbo, "un wildcard non è una decisione")

    def test_the_flush_is_admitted(self):
        self.assertIn("telegram.notify_flush", logic_api._ALLOWED)

    def test_a_verb_outside_the_list_is_refused(self):
        """Il caso che la lista esiste per fermare: un verbo gated qualunque
        eseguito senza nessuno che guardi."""
        for verbo in ("web.post", "email.send", "topic.telegram_bind",
                      "github.push", "agents.grant_tool"):
            with self.subTest(verbo):
                self.assertNotIn(verbo, logic_api._ALLOWED)

    def test_every_entry_is_callable(self):
        """Una voce che non si può chiamare è una promessa di esecuzione che
        fallisce solo quando qualcuno ci prova."""
        for verbo, fn in logic_api._ALLOWED.items():
            with self.subTest(verbo):
                self.assertTrue(callable(fn))


if __name__ == "__main__":
    unittest.main()

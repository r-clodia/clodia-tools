"""`topic.search` non deve rivelare topic di cui l'agente non è partecipante.

Difetto trovato spiegando i verbi di avvocato. `_filter_member_rows` esisteva
proprio per questo, ma decideva su `participants`/`owner` — campi che
`service.search` NON restituiva. Il suo ramo difensivo («righe con shape diversa
restano invariate») era quindi l'UNICO percorso vivo, e il filtro non filtrava
niente.

Misurato in produzione prima della correzione: `segretario` — il cui mandato è un
summary e un tldr — con una query generica riceveva 97 righe, 27 delle quali
SEAL-2, con titolo e tldr. Il tldr è la prima riga del summary: la riga più
informativa di un dossier.

Un default che ammette ciò che non sa valutare non è difensivo: è una porta aperta
con un commento rassicurante sopra.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import main


def _row(tier, name, participants=(), owner="davide", **extra):
    r = {"tier": tier, "name": name, "title": name, "tldr": "segreto di %s" % name,
         "owner": owner, "participants": list(participants)}
    r.update(extra)
    return r


class NeedToKnowTests(unittest.TestCase):
    def setUp(self):
        self._c = patch.object(main, "current_clearance", lambda: "SEAL-2")
        self._c.start()
        self.addCleanup(self._c.stop)

    def test_a_topic_i_am_not_in_is_not_returned(self):
        rows = [_row("SEAL-1", "mio", participants=["avvocato"]),
                _row("SEAL-1", "altrui", participants=["commercialista"])]
        got = [r["name"] for r in main._filter_member_rows(rows, "avvocato")]
        self.assertEqual(got, ["mio"])

    def test_the_owner_sees_their_own(self):
        rows = [_row("SEAL-1", "suo", participants=[], owner="avvocato")]
        self.assertEqual(len(main._filter_member_rows(rows, "avvocato")), 1)

    def test_a_row_without_the_fields_is_EXCLUDED(self):
        """Il cuore del difetto: prima passava invariata.

        Ed è la forma che `search` restituiva davvero — quindi il filtro
        ammetteva l'intero archivio."""
        rows = [{"tier": "SEAL-2", "name": "x", "title": "x", "tldr": "riservato"}]
        self.assertEqual(main._filter_member_rows(rows, "avvocato"), [])

    def test_above_my_clearance_is_not_returned_even_if_participant(self):
        """Le due condizioni sono la stessa regola di `open`: un elenco più largo
        è un modo di leggere ciò che non si potrebbe aprire."""
        rows = [_row("SEAL-3", "riservato", participants=["avvocato"]),
                _row("SEAL-2", "ok", participants=["avvocato"])]
        got = [r["name"] for r in main._filter_member_rows(rows, "avvocato")]
        self.assertEqual(got, ["ok"])

    def test_a_row_that_is_not_a_dict_is_dropped(self):
        self.assertEqual(main._filter_member_rows(["stringa", None, 7], "avvocato"), [])

    def test_an_empty_list_stays_empty(self):
        self.assertEqual(main._filter_member_rows([], "avvocato"), [])


class SearchRowShapeTests(unittest.TestCase):
    """La forma delle righe è parte del contratto, non un dettaglio.

    Se `search` smette di restituire `participants`/`owner`, il filtro (ora
    fail-closed) restituisce zero invece di tutto: si nota subito, ed è la
    direzione d'errore giusta. Questo test fissa il contratto perché la rottura
    si veda qui e non in produzione.
    """

    def test_search_rows_carry_the_fields_the_filter_needs(self):
        import inspect
        from .topics import service
        src = inspect.getsource(service.TopicService.search)
        for field in ('"owner"', '"participants"', '"tier"', '"tldr"'):
            with self.subTest(field=field):
                self.assertIn(field, src)


if __name__ == "__main__":
    unittest.main()

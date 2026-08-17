"""L'owner può azzerare il primo bit senza dover approvare un'uscita.

Fino al 17 ago 2026 `taint.clear()` viveva solo dentro l'approvazione di un gate
di contesto: l'unico modo di declassificare un canale era approvare un invio. Il
«reset trifecta» ha bisogno della stessa operazione da sola —

    «il reset approva lo stato corrente come sicuro e da lì si riparte a misurare
     le contaminazioni ed i rischi»

— quindi la rotta esiste, ed è INTERNA: chi decide se il richiedente è l'owner è
l'agent-server, che conosce i ruoli dello scope. Il gateway non li conosce e
fingere di deciderlo qui sarebbe un controllo che non controlla nulla.
"""
from __future__ import annotations

import json
import os
import unittest
from tempfile import TemporaryDirectory
from unittest.mock import patch


class TaintClearRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = TemporaryDirectory()
        self._env = patch.dict(os.environ, {"CLODIA_TOOLS_STATE_DIR": self._tmp.name})
        self._env.start()

    def tearDown(self) -> None:
        self._env.stop()
        self._tmp.cleanup()

    def test_the_route_is_registered_and_is_a_post(self) -> None:
        from server import topics_api
        rotte = [(r.path, sorted(r.methods or [])) for r in topics_api.routes]
        self.assertIn(("/internal/topics/{tier}/{name}/taint/clear", ["POST"]),
                      [(p, [m for m in ms if m != "HEAD"]) for p, ms in rotte])

    def test_clearing_archives_the_sources_instead_of_deleting_them(self) -> None:
        """Un azzeramento che cancella le prove non è un'approvazione, è una gomma:
        dopo, l'audit non può più dire PERCHÉ era stata chiesta."""
        from server import taint as t
        t.mark("chan:SEAL-1:ops:clodia", "verb", "web.fetch", "clodia")
        prima = t.status("chan:SEAL-1:ops:clodia")
        self.assertTrue(prima.get("tainted"), "mark() non ha contaminato: il test "
                        "sta scrivendo in un altro posto e non misura niente")
        dopo = t.clear("chan:SEAL-1:ops:clodia", by="davide")
        self.assertFalse(dopo["tainted"])
        stato = t.status("chan:SEAL-1:ops:clodia")
        self.assertFalse(stato["tainted"])

    def test_a_new_arrival_lights_it_again(self) -> None:
        """Il punto della definizione: dopo il reset si RIPARTE a misurare, non si
        smette. Un ingresso successivo riaccende il bit da sé."""
        from server import taint as t
        ch = "chan:SEAL-1:ops2:clodia"
        t.mark(ch, "verb", "web.fetch", "clodia")
        t.clear(ch, by="davide")
        self.assertFalse(t.status(ch)["tainted"])
        t.mark(ch, "verb", "web.fetch", "clodia")
        self.assertTrue(t.status(ch)["tainted"],
                        "dopo un reset il canale non torna a contaminarsi: "
                        "il reset avrebbe spento la misura invece di ribasarla")


if __name__ == "__main__":
    unittest.main()

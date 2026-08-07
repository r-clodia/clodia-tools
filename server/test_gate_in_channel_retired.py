"""`gated_in_channel` è stato ritirato. Questo file tiene il posto e la ragione.

Il meccanismo, aggiunto il 6 ago 2026, gatava certi verbi solo DENTRO un canale.
Rispondeva alla domanda «chi sta chiedendo?» per approssimazione — *qualcuno è in
un canale* — e l'approssimazione era grossolana due volte:

  - una DM È un canale, quindi il criterio reale era «sempre tranne nei job»:
    chiedeva l'approvazione anche all'owner per la propria richiesta, nella
    propria DM;
  - non guardava affatto CHI avesse chiesto, che è precisamente ciò che diceva di
    proteggere.

Dal 7 ago quella domanda ha una risposta esatta: la catena `origin` nomina
`human:giovanni` o `human:davide` e ne interseca il RUOLO nella stanza (B2). Un
surrogato che sopravvive alla cosa che surrogava diventa un secondo controllo che
dice altro — e due controlli sulla stessa domanda divergono, come è successo tre
volte in un solo giorno su altri fronti.

I test qui sotto verificano la RIMOZIONE, non il comportamento: che il campo non
torni per inerzia in un `upsert`, e che la preoccupazione che copriva sia
effettivamente coperta.
"""
from __future__ import annotations

import unittest
import inspect

from . import whitelist as w
from . import main as M
from . import origin


class RetirementTests(unittest.TestCase):
    def test_the_mechanism_is_gone_from_the_whitelist(self):
        self.assertFalse(hasattr(w, "agent_gates_in_channel"),
                         "la funzione è tornata: due controlli sulla stessa "
                         "domanda divergono")

    def test_upsert_no_longer_carries_the_field(self):
        """Se il campo tornasse nel trasporto, tornerebbe anche nella config —
        e resterebbe a decidere senza che nessuno lo legga più."""
        self.assertNotIn("gated_in_channel",
                         inspect.signature(w.upsert_agent).parameters)

    def test_the_dispatch_no_longer_consults_it(self):
        src = inspect.getsource(M.call_tool) if hasattr(M, "call_tool") else ""
        self.assertNotIn("agent_gates_in_channel", src)


class TheConcernIsCoveredTests(unittest.TestCase):
    """La preoccupazione era reale: dentro una stanza chi chiede può non essere
    l'owner. Rimuovere il surrogato è lecito solo perché la domanda ha ora una
    risposta migliore."""

    def test_the_chain_intersects_the_role_in_the_room(self):
        src = inspect.getsource(origin.principal_may)
        self.assertIn("_scope_allows", src)

    def test_the_room_comes_from_the_signed_claim(self):
        src = inspect.getsource(origin._scope_role_of)
        self.assertIn("current_channel()", src)


if __name__ == "__main__":
    unittest.main()

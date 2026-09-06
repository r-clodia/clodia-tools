"""La entry registrata si può RILEGGERE, alla lettera (clodia-platform#203).

La dichiarazione di un seed raggiungeva il gateway solo all'import del pack: da
lì in poi `config.yaml` è la fotografia di quel giorno, e nessuno la rileggeva.
Tre guasti reali sono usciti da quella gamba mancante — quattro giorni di 500
sulla rotta di registrazione senza che nessuno se ne accorgesse, un `*`
sopravvissuto al proprio ritiro, un confinamento che non è cambiato finché non è
stato riscritto a mano su due istanze — e sono tutti e tre *silenziosi*.

Confrontare richiede di poter leggere. `/verbs` non serve: è una vista da
pannello (espande i wildcard, salta i grant che sono anche `denied`, unisce
quattro sorgenti), e ricostruire la lista registrata da lì darebbe una seconda
verità — cioè il difetto che un rilevatore di divergenze dovrebbe scoprire, non
commettere.

Qui si misura una cosa sola: che questa rotta risponda ciò che è SCRITTO.
"""
from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import patch

from . import agents_api


class _Req:
    def __init__(self, name="avvocato"):
        self.headers = {"authorization": "Bearer tok"}
        self.path_params = {"name": name}


def _call(name="avvocato", cfg=None, authorized=True):
    from . import whitelist as wl

    def _auth(_r):
        return ("clodia", None) if authorized else (None, "403")

    with patch.object(agents_api, "_authorize", _auth), \
            patch.object(wl, "CONFIG", {"agents": cfg or {}}):
        r = asyncio.run(agents_api.registration(_Req(name)))
    return r if not authorized else json.loads(r.body)


class ReadbackTests(unittest.TestCase):
    def test_the_stored_lists_come_back_verbatim(self):
        """Alla lettera: nessuna espansione, nessun filtro. Un wildcard resta
        un wildcard, e un verbo che è insieme concesso e negato resta in
        entrambe le liste — è precisamente la forma su cui `/verbs` mente."""
        b = _call(cfg={"avvocato": {
            "allowed_tools": ["topic.*", "email.send"],
            "denied_tools": ["email.send"],
            "gated_tools": ["topic.remote_push"],
            "profile_tools": ["topic.open"]}})
        self.assertTrue(b["registered"])
        self.assertEqual(b["allowed_tools"], ["topic.*", "email.send"])
        self.assertEqual(b["denied_tools"], ["email.send"])
        self.assertEqual(b["gated_tools"], ["topic.remote_push"])
        self.assertEqual(b["profile_tools"], ["topic.open"])

    def test_an_unregistered_agent_says_so(self):
        """`registered: false` è una chiave, non un dizionario vuoto da
        interpretare: senza entry l'agente non ha «meno verbi», ne ha ZERO —
        `agent_config()` solleva e la lista torna vuota."""
        b = _call(name="fantasma", cfg={"avvocato": {"allowed_tools": ["topic.open"]}})
        self.assertFalse(b["registered"])
        self.assertEqual(b["agent"], "fantasma")
        self.assertNotIn("allowed_tools", b)

    def test_absent_lists_read_as_empty(self):
        """Assente e vuoto si comportano identici all'enforcement
        (`spec.get(...) or []`), quindi qui coincidono: chi confronta non deve
        vedere una divergenza dove il gateway si comporta allo stesso modo."""
        b = _call(cfg={"avvocato": {"allowed_tools": ["topic.open"]}})
        self.assertEqual(b["gated_tools"], [])
        self.assertEqual(b["denied_tools"], [])
        self.assertEqual(b["profile_tools"], [])

    def test_untransported_fields_are_not_invented(self):
        """`carries` e `gated_in_channel` viaggiano con la registrazione ma il
        gateway non li conserva. Restituirli come `[]` farebbe leggere «il
        gateway li ha azzerati» a chi confronta: una divergenza permanente e
        falsa su OGNI agente, cioè un rilevatore che nessuno rilegge."""
        b = _call(cfg={"avvocato": {"allowed_tools": ["topic.open"]}})
        self.assertNotIn("carries", b)
        self.assertNotIn("gated_in_channel", b)

    def test_it_is_read_only(self):
        """Non registra e non ripara: la decisione su una divergenza sta a chi
        la legge, e una lettura che scrive è il modo in cui un rilevatore
        diventa la causa di ciò che rileva."""
        import ast
        import inspect
        import textwrap
        # Sul CODICE, non sul testo: il docstring nomina `upsert_agent` per dire
        # che non lo chiama, e una ricerca testuale leggerebbe la spiegazione
        # come se fosse la cosa spiegata.
        fn = ast.parse(textwrap.dedent(inspect.getsource(agents_api.registration))).body[0]
        chiamate = {getattr(n.func, "id", None) or getattr(n.func, "attr", None)
                    for n in ast.walk(fn) if isinstance(n, ast.Call)}
        for scrittura in ("upsert_agent", "save_config", "set_agent_tool",
                          "reload_config"):
            self.assertNotIn(scrittura, chiamate)

    def test_the_route_is_declared(self):
        paths = [getattr(r, "path", "") for r in agents_api.routes]
        self.assertIn("/internal/agents/{name}/registration", paths)

    def test_authorization_is_the_shared_rule(self):
        """Stessa guardia delle altre rotte interne: un errore di `_authorize`
        torna al chiamante invece di essere aggirato."""
        err = _call(authorized=False)
        self.assertEqual(err, "403")


if __name__ == "__main__":
    unittest.main()

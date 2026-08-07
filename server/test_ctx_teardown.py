"""I contextvar della richiesta si rilasciano per NOME, non per posizione.

Il difetto, 7 ago 2026. Davide riceveva:

    HTTP 403 — azione 'packs.import_url' riservata agli admin

pur essendo superadmin. Non era un problema di permessi: `/internal/authorize`
DECIDEVA correttamente — misurato dentro il processo, `consentito: True` — e poi
sollevava in `__exit__`:

    ValueError: <Token var=ContextVar 'mcp_current_origin'>
                was created by a different ContextVar

I token erano una lista rilasciata per indice, e il 5 ago l'aggiunta di `origin`
per la catena di delega ha spostato tutto di uno: al reset di `scoped_tools`
arrivava il token di `origin`, e `origin` non veniva rilasciato affatto.

Il gateway rispondeva 500, il chiamante traduce ogni non-200 in «negato», e
all'utente arrivava un messaggio sui permessi. Tre giri a cercare un problema di
autorizzazione per un difetto di teardown.

Due proprietà da tenere, e nessuna delle due riguarda i permessi:
  1. aggiungere una variabile non deve poter disallineare le altre;
  2. un reset che fallisce non deve impedire i successivi — un contextvar che
     resta impostato inquina la richiesta dopo, sullo stesso task.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import whitelist
from .tool_api import _Ctx


PAYLOAD = {"agent": "clodia", "principal": "davide", "on_behalf": True,
           "human_role": "admin", "chat": "chan:SEAL-1:acme:clodia",
           "clearance": "SEAL-2", "origin": ["human:davide"],
           "scoped_tools": ["fs.list_dir"]}


class TeardownTests(unittest.TestCase):
    def test_entering_and_leaving_raises_nothing(self):
        """Il caso di Davide: la decisione era giusta, l'uscita esplodeva."""
        with _Ctx(PAYLOAD, "tok"):
            pass

    def test_every_var_is_restored(self):
        """Nessun contextvar deve sopravvivere all'uscita: quello che resta
        impostato diventa il contesto di qualcun altro."""
        prima = self._snapshot()
        with _Ctx(PAYLOAD, "tok"):
            self.assertEqual(whitelist.agent_name(), "clodia")
            self.assertTrue(whitelist.is_on_behalf())
        self.assertEqual(self._snapshot(), prima)

    def test_origin_is_restored_too(self):
        """La variabile che il codice per indice non rilasciava MAI."""
        prima = whitelist.current_origin()
        with _Ctx(PAYLOAD, "tok"):
            # `current_origin` normalizza in tupla: si confronta il contenuto,
            # non il tipo del contenitore.
            self.assertEqual(list(whitelist.current_origin()), ["human:davide"])
        self.assertEqual(whitelist.current_origin(), prima)

    def test_a_failing_reset_does_not_block_the_others(self):
        """Se un rilascio solleva, gli altri devono comunque avvenire —
        altrimenti un errore isolato lascia mezza richiesta appiccicata a quella
        dopo."""
        prima = self._snapshot()
        with patch.object(whitelist, "reset_current_scoped_tools",
                          side_effect=RuntimeError("boom")):
            with _Ctx(PAYLOAD, "tok"):
                pass
        try:
            self.assertEqual(self._snapshot(), prima)
        finally:
            # Questo test IMPEDISCE davvero un reset, quindi `scoped_tools`
            # resta impostata: va ripulita a mano o inquina i test successivi.
            # Se ne è accorta la suite — passava da sola e falliva insieme agli
            # altri, che è il modo in cui un test cattivo cittadino si manifesta.
            whitelist.set_current_scoped_tools(None)

    def test_an_exception_inside_the_block_still_restores(self):
        prima = self._snapshot()
        with self.assertRaises(ValueError):
            with _Ctx(PAYLOAD, "tok"):
                raise ValueError("errore nel corpo")
        self.assertEqual(self._snapshot(), prima)

    def _snapshot(self):
        """Fuori da un contesto `agent_name()` SOLLEVA per disegno — un'identità
        assente non è una stringa vuota. Lo cattura invece di pretendere un
        valore."""
        def _safe(f):
            try:
                return f()
            except Exception as e:  # noqa: BLE001
                return type(e).__name__
        return tuple(_safe(f) for f in (
            whitelist.agent_name, whitelist.is_on_behalf,
            whitelist.current_chat, whitelist.current_origin))


class NoPositionalTokensTests(unittest.TestCase):
    """La causa, non il sintomo. Con i token per posizione il difetto torna alla
    prossima variabile aggiunta, e torna silenzioso."""

    def test_the_tokens_are_keyed_by_name(self):
        """Cerca l'indicizzazione NUMERICA, non la parentesi quadra: `_toks[nome]`
        è accesso per chiave ed è esattamente ciò che si vuole. È la seconda
        volta oggi che un test sul sorgente inciampa su una sottostringa
        innocente — cercare stringhe nel codice richiede di dire con precisione
        quale forma è quella sbagliata."""
        import inspect, re
        src = inspect.getsource(_Ctx)
        posizionali = re.findall(r"_toks\[\s*\d", src)
        self.assertEqual(posizionali, [],
                         "indicizzazione posizionale: la prossima variabile "
                         "aggiunta disallineerà di nuovo i reset")

    def test_every_declared_var_has_a_setter_and_a_resetter(self):
        for nome, setter, resetter, _val in _Ctx._VARS:
            with self.subTest(var=nome):
                self.assertTrue(hasattr(whitelist, setter), setter)
                self.assertTrue(hasattr(whitelist, resetter), resetter)


if __name__ == "__main__":
    unittest.main()

"""Il trigger di un canale porta il token di chi ha parlato.

clodia-platform#413, punto 1. `runtime._post` sa inoltrare il session token
ckt1 del chiamante (`auth=True`) dal 2026 e il suo docstring descrive esattamente
questo caso — «così agent-server verifica l'identità firmata e non deve fidarsi
di un campo auto-dichiarato nel body» — ma nessun chiamante lo passava.

L'unica porta che si accorge della differenza è `trigger/internal`: senza Bearer
l'agent-server classifica la provenienza `external` per costruzione (fail-closed
della #221), qualunque cosa il body dichiari in `by`. Finivano lì TUTTI i trigger
della colonia, e due cose ne cadevano:

- una persona che scrive da un client MCP senza @menzione non riceve risposta —
  `run_topic_turn` sceglie un responder per rilevanza solo se il trigger è
  `human`, ed è proprio il caso che `topic.post_message` dichiara di servire;
- la direttiva «contenuto di provenienza non fidata», accesa su traffico interno
  legittimo, smette di distinguere qualcosa.

Qui si fissa la sola cosa che questo repo controlla: che il token parta.
"""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from .. import whitelist
from . import runtime


class _Risposta:
    status_code = 200
    text = "{}"
    content = b"{}"

    def json(self):
        return {"triggered": True}

    def raise_for_status(self):
        return self


def _client_spia() -> tuple[MagicMock, MagicMock]:
    """Un `httpx.Client` finto che registra la chiamata POST."""
    client = MagicMock()
    client.post.return_value = _Risposta()
    ctx = MagicMock()
    ctx.__enter__.return_value = client
    ctx.__exit__.return_value = False
    fabbrica = MagicMock(return_value=ctx)
    return fabbrica, client


class TriggerCarriesTheTokenTests(unittest.TestCase):

    def _chiama(self, token: str | None) -> dict:
        fabbrica, client = _client_spia()
        tok = whitelist.set_current_token(token)
        try:
            with patch.object(runtime.httpx, "Client", fabbrica):
                runtime.channel_trigger("SEAL-1", "acme", "ciao canale",
                                        by="giovanni")
        finally:
            whitelist.reset_current_token(tok)
        return client.post.call_args.kwargs.get("headers") or {}

    def test_the_caller_token_travels_with_the_trigger(self) -> None:
        headers = self._chiama("ckt1.finto.firma")
        self.assertEqual(headers.get("Authorization"), "Bearer ckt1.finto.firma")

    def test_without_a_token_nothing_is_invented(self) -> None:
        """Nessun token nel contesto → nessun header: la porta a valle resta
        fail-closed, non riceve una firma vuota da interpretare."""
        self.assertNotIn("Authorization", self._chiama(None))

    def test_the_body_still_declares_who_spoke(self) -> None:
        """Il token si aggiunge a `by`, non lo sostituisce: a valle
        l'appartenenza al canale si verifica ancora sul nome dichiarato."""
        fabbrica, client = _client_spia()
        tok = whitelist.set_current_token("ckt1.finto.firma")
        try:
            with patch.object(runtime.httpx, "Client", fabbrica):
                runtime.channel_trigger("SEAL-1", "acme", "ciao", by="giovanni")
        finally:
            whitelist.reset_current_token(tok)
        self.assertEqual(client.post.call_args.kwargs.get("json"),
                         {"text": "ciao", "by": "giovanni"})

    def test_the_announcement_still_travels_unsigned(self) -> None:
        """Controllo di confine: `auth=True` è per QUESTA chiamata, non per
        tutto `runtime`. L'annuncio parte dallo store, non da un principal, e
        continua a usare il secret orchestrator."""
        fabbrica, client = _client_spia()
        tok = whitelist.set_current_token("ckt1.finto.firma")
        try:
            with patch.object(runtime.httpx, "Client", fabbrica):
                runtime.suggest_team("SEAL-1", "un team")
        finally:
            whitelist.reset_current_token(tok)
        headers = client.post.call_args.kwargs.get("headers") or {}
        self.assertNotIn("Authorization", headers)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

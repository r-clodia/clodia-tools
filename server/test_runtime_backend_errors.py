"""Il seguito di clodia-platform#297 su `runtime.*` e `agent.spawn`.

`platform_ops` è stato corretto perché un 403 arrivava all'agente come metodo +
URL, col motivo buttato via da `raise_for_status()`. Gli altri due proxy verso
l'agent-server facevano lo stesso, e su `runtime._post` è **peggio**: le rotte
che serve non dicono solo perché rifiutano, dicono cosa fare —
«'<x>' non è owner/partecipante di questo canale», «aggiungi un agent/utente
registrato». Un rimedio scritto dal backend e scartato dal proxy è un rimedio
che non esiste.

Asimmetria deliberata fra i due helper, decisa in `#software-house`:

- `_post` MUTA e le sue rotte autorizzano → 403 = rifiuto = `PermissionError`,
  che `call_tool` registra come `DENIED` nel run record dei rifiuti (#206);
- `_get` legge metadati su rotte anonime, dove nessun 403 può nascere da una
  policy: lì un 403 verrebbe da un intermediario, e chiamarlo «rifiuto» conta
  come decisione di policy quello che è un guasto — la confusione che la #297 è
  costata, al contrario. Il motivo passa, la classe resta `ValueError`.
"""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

import httpx

from .tools import agent as agent_tool
from .tools import runtime


class _Errore:
    """Una risposta di rifiuto vera: `.json()` restituisce il corpo, non un mock
    che gli somiglia, e `raise_for_status()` fa quel che fa httpx — nomina
    metodo e URL, ignora il corpo."""

    def __init__(self, status: int, payload=None, text: str = ""):
        self.status_code = status
        self._payload = payload
        self.text = text if text else ("" if payload is None else str(payload))
        self.content = (self.text or "").encode()

    def json(self):
        if self._payload is None:
            raise ValueError("corpo non JSON")
        return self._payload

    def raise_for_status(self):
        if self.status_code < 400:
            return self
        url = "http://agent-server:7842/clodia/channels/SEAL-1/x/participants/internal"
        raise httpx.HTTPStatusError(
            f"Client error '{self.status_code}' for url '{url}'",
            request=httpx.Request("POST", url), response=None)


def _client(response, *, verb: str = "post") -> MagicMock:
    client = MagicMock()
    getattr(client, verb).return_value = response
    ctx = MagicMock()
    ctx.__enter__.return_value = client
    return ctx


class RuntimeMutatingCallsSayWhyTests(unittest.TestCase):

    def _post(self, response):
        with patch.object(runtime.httpx, "Client", return_value=_client(response)):
            return runtime.set_participant("SEAL-1", "software-house",
                                           "segretario", by="sysadmin", add=True)

    def test_403_carries_the_remedy_not_the_url(self):
        motivo = "'sysadmin' non è owner/partecipante di questo canale"
        with self.assertRaises(PermissionError) as caught:
            self._post(_Errore(403, {"detail": motivo}))
        self.assertEqual(str(caught.exception), motivo)
        self.assertNotIn("agent-server", str(caught.exception))

    def test_404_says_what_to_do(self):
        with self.assertRaises(ValueError) as caught:
            self._post(_Errore(404, {"detail": "'x' non esiste: aggiungi un "
                                               "agent/utente registrato"}))
        self.assertIn("aggiungi un agent/utente registrato", str(caught.exception))

    def test_400_error_field_reaches_the_caller(self):
        with self.assertRaises(ValueError) as caught:
            self._post(_Errore(400, {"error": "agent e by richiesti"}))
        self.assertIn("agent e by richiesti", str(caught.exception))

    def test_success_is_unchanged(self):
        with patch.object(runtime.httpx, "Client",
                          return_value=_client(_Errore(200, {"ok": True}))):
            self.assertEqual(
                runtime.channel_trigger("SEAL-1", "software-house", "@x ciao",
                                        by="sysadmin"),
                {"ok": True})


class RuntimeReadsStayFailuresTests(unittest.TestCase):
    """Il motivo passa; la CLASSE no. Su una GET di metadati un 403 non è una
    decisione di policy, e registrarlo come rifiuto sporcherebbe il registro
    che serve a contare i rifiuti veri."""

    def _get(self, response):
        with patch.object(runtime.httpx, "Client",
                          return_value=_client(response, verb="get")):
            return runtime._get("/api/agents")

    def test_403_on_a_metadata_read_is_not_a_denial(self):
        with self.assertRaises(ValueError) as caught:
            self._get(_Errore(403, {"detail": "bloccato da un intermediario"}))
        self.assertNotIsInstance(caught.exception, PermissionError)
        self.assertIn("bloccato da un intermediario", str(caught.exception))

    def test_502_body_is_reported(self):
        with self.assertRaises(ValueError) as caught:
            self._get(_Errore(502, None, text="<html>Bad Gateway</html>"))
        self.assertIn("Bad Gateway", str(caught.exception))

    def test_success_is_unchanged(self):
        with patch.object(runtime.httpx, "Client",
                          return_value=_client(_Errore(200, {"agents": []}), verb="get")):
            self.assertEqual(runtime._get("/api/agents"), {"agents": []})


class SpawnSaysWhyItFailedTests(unittest.TestCase):
    """`agent.spawn` fa due POST in fila: se la prima fallisce, l'agente vedeva
    un URL e nient'altro — e la seconda non parte, quindi non c'è un secondo
    messaggio da cui dedurre il motivo."""

    def test_create_chat_error_reaches_the_caller(self):
        with (
            patch.object(agent_tool, "tool_allowed", lambda *_: True),
            patch.object(agent_tool.httpx, "Client",
                         return_value=_client(_Errore(400, {"detail": "kind non valido"}))),
        ):
            with self.assertRaises(ValueError) as caught:
                agent_tool.spawn("ada", "un task")
        self.assertIn("kind non valido", str(caught.exception))

    def test_403_here_is_not_a_policy_denial_either(self):
        """Il permesso su `agent.spawn` lo ha già deciso `tool_allowed` prima
        della chiamata, e `/clodia/chats` non autorizza per verbo: un 403 di
        ritorno non è la policy della colonia."""
        with (
            patch.object(agent_tool, "tool_allowed", lambda *_: True),
            patch.object(agent_tool.httpx, "Client",
                         return_value=_client(_Errore(403, {"detail": "proxy"}))),
        ):
            with self.assertRaises(ValueError) as caught:
                agent_tool.spawn("ada", "un task")
        self.assertNotIsInstance(caught.exception, PermissionError)
        self.assertIn("proxy", str(caught.exception))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

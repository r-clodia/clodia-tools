"""Il proxy verso l'agent-server, e il MOTIVO di un rifiuto.

Questi test erano scritti come funzioni a livello di modulo (stile pytest). Il
solo comando sanzionato dal repository è `make test`, cioè
`python -m unittest discover`: da un file così non raccoglie niente — `Ran 0
tests`. Sono qui in forma `TestCase` perché un controllo che non gira è
silenzioso quanto il difetto che dovrebbe fermare.
"""
import unittest
from unittest.mock import MagicMock, patch

import httpx

from . import platform_ops


def _response(payload: dict) -> MagicMock:
    response = MagicMock()
    response.status_code = 200
    response.content = b'{"ok":true}'
    response.json.return_value = payload
    return response


class _Errore:
    """La risposta di un backend che rifiuta. Non un `MagicMock`: qui il corpo
    conta, e un mock risponde a `.json()` con un altro mock — cioè con qualcosa
    che somiglia a un motivo senza esserlo."""

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
        """Quel che faceva `_req` prima della correzione, riprodotto fedelmente:
        `httpx` nomina metodo e URL e non guarda il corpo. È esattamente la
        stringa che la #297 riporta come sintomo."""
        if self.status_code < 400:
            return self
        url = "http://agent-server:7842/clodia/packs/studio-legale/setup-done"
        raise httpx.HTTPStatusError(
            f"Client error '{self.status_code}' for url '{url}'",
            request=httpx.Request("POST", url), response=None)


def _client(response) -> MagicMock:
    client = MagicMock()
    client.request.return_value = response
    ctx = MagicMock()
    ctx.__enter__.return_value = client
    return ctx


class ProxyForwardsTheCallerTokenTests(unittest.TestCase):

    def test_req_forwards_current_caller_token(self):
        client = MagicMock()
        client.request.return_value = _response({"ok": True})
        client_context = MagicMock()
        client_context.__enter__.return_value = client

        with (
            patch.object(platform_ops.whitelist, "current_token", return_value="ckt1.signed"),
            patch.object(platform_ops.httpx, "Client", return_value=client_context),
        ):
            result = platform_ops.packs_import_url("https://example.test/pack.zip")

        self.assertEqual(result, {"ok": True})
        client.request.assert_called_once_with(
            "POST",
            f"{platform_ops.AGENT_SERVER_URL}/clodia/packs/import-url",
            json={"url": "https://example.test/pack.zip"},
            headers={"Authorization": "Bearer ckt1.signed"},
        )

    def test_req_keeps_anonymous_reads_without_authorization_header(self):
        client = MagicMock()
        client.request.return_value = _response({"packs": []})
        client_context = MagicMock()
        client_context.__enter__.return_value = client

        with (
            patch.object(platform_ops.whitelist, "current_token", return_value=None),
            patch.object(platform_ops.httpx, "Client", return_value=client_context),
        ):
            result = platform_ops.packs_list()

        self.assertEqual(result, {"packs": []})
        client.request.assert_called_once_with(
            "GET",
            f"{platform_ops.AGENT_SERVER_URL}/clodia/packs",
            json=None,
            headers={},
        )


class BackendRefusalsReachTheAgentTests(unittest.TestCase):
    """clodia-platform#297. Il grant era la prima metà (già in main: clodia-logic
    #365, clodia-tools #242); questa è la seconda — «un messaggio d'errore
    esplicito invece di un 403 generico».

    Il 403 che la issue riporta (`403 Forbidden — POST http://agent-server:7842/
    clodia/packs/studio-legale/setup-done`) è il testo di `raise_for_status()`:
    nomina il metodo e l'URL, cioè le due cose che l'agente sapeva già, e butta
    via l'unica che non sapeva. Il motivo il backend lo scrive nel corpo.
    """

    def _chiama(self, response):
        with (
            patch.object(platform_ops.whitelist, "current_token", return_value="ckt1.signed"),
            patch.object(platform_ops.httpx, "Client", return_value=_client(response)),
        ):
            return platform_ops.packs_setup_done("studio-legale")

    def test_403_says_which_verb_was_denied(self):
        motivo = ("verbo 'packs.setup_done' non concesso all'agente 'sysadmin': "
                  "il gateway ha deciso sui grant del suo seed.")
        with self.assertRaises(PermissionError) as caught:
            self._chiama(_Errore(403, {"detail": motivo}))
        self.assertEqual(str(caught.exception), motivo)
        # Non solo «c'è un motivo»: NON è più l'URL. `call_tool` stampa questo
        # testo all'agente, ed è lì che si decide se la diagnosi parte dal verbo
        # o da un indirizzo di rete.
        self.assertNotIn("agent-server", str(caught.exception))

    def test_403_is_a_denial_not_a_generic_error(self):
        """La CLASSE, non solo il testo: `call_tool` smista per eccezione —
        `PermissionError` → `DENIED:` e il rifiuto finisce nel run record
        (clodia-platform#206). Un `HTTPStatusError` lo conta come guasto, e un
        rifiuto contato come guasto non si vede né come l'uno né come l'altro."""
        with self.assertRaises(PermissionError):
            self._chiama(_Errore(403, {"detail": "negato"}))

    def test_400_error_field_reaches_the_caller(self):
        """Le rotte di `clodia-logic` rispondono `{"error": ...}` (JSONResponse)
        dove `HTTPException` dà `{"detail": ...}`. Leggerne solo uno lascia metà
        dei motivi nel corpo."""
        with self.assertRaises(ValueError) as caught:
            self._chiama(_Errore(400, {"error": "nome non valido"}))
        self.assertIn("nome non valido", str(caught.exception))

    def test_503_stays_a_failure_and_not_a_denial(self):
        """Il PDP che non ha DECISO non è un rifiuto: 503, e il testo lo dice.
        Tradurlo in `PermissionError` rimanderebbe a cercare un permesso che
        c'è — la diagnosi che la #297 è costata tre volte."""
        motivo = ("impossibile decidere su 'packs.setup_done': gateway "
                  "irraggiungibile. Non è un problema di permessi")
        with self.assertRaises(ValueError) as caught:
            self._chiama(_Errore(503, {"detail": motivo}))
        self.assertNotIsInstance(caught.exception, PermissionError)
        self.assertIn("Non è un problema di permessi", str(caught.exception))

    def test_non_json_body_still_says_something(self):
        with self.assertRaises(ValueError) as caught:
            self._chiama(_Errore(502, None, text="<html>Bad Gateway</html>"))
        self.assertIn("Bad Gateway", str(caught.exception))

    def test_empty_error_body_names_the_status(self):
        """Un corpo vuoto non deve produrre un'eccezione muta: se il backend non
        spiega, si dice almeno lo status invece di `PermissionError()`."""
        with self.assertRaises(PermissionError) as caught:
            self._chiama(_Errore(403, None, text=""))
        self.assertIn("403", str(caught.exception))

    def test_success_with_empty_body_still_ok(self):
        with (
            patch.object(platform_ops.whitelist, "current_token", return_value="ckt1.signed"),
            patch.object(platform_ops.httpx, "Client",
                         return_value=_client(_Errore(204, None, text=""))),
        ):
            self.assertEqual(platform_ops.packs_remove("studio-legale"), {"ok": True})


class TheSameRuleForAgentsAdminTests(unittest.TestCase):
    """`agents_admin` faceva la cosa giusta da sé, in DUE copie (`_patch_caps` e
    `_request`). Il difetto della #297 era la terza copia mancante in
    `platform_ops`: la correzione è un solo posto, e questo test è ciò che
    impedisce che le copie tornino a divergere — qui la prova è il campo
    `error`, che le copie inline non leggevano."""

    def test_error_field_is_read_here_too(self):
        from . import agents_admin

        client = MagicMock()
        client.request.return_value = _Errore(403, {"error": "agente immutabile"})
        ctx = MagicMock()
        ctx.__enter__.return_value = client
        with (
            patch.object(agents_admin.whitelist, "current_token", return_value="ckt1.signed"),
            patch.object(agents_admin.httpx, "Client", return_value=ctx),
        ):
            with self.assertRaises(PermissionError) as caught:
                agents_admin._request("GET", "/api/agents/wainston/scoped-overrides")
        self.assertIn("agente immutabile", str(caught.exception))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

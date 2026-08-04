"""Il `dest` di topic.fetch e il motivo di un rifiuto.

Guasto reale: `topic.fetch` su un file di 430KB tornava `400 Bad Request` da
`/internal/transfers/deliver`, e tre agenti (commercialista, messaggero, clodia)
hanno concluso — ognuno per conto proprio — che il servizio era guasto e che serviva
un intervento infrastrutturale.

Non era guasto. Il `dest` era obbligatorio e doveva essere un path ASSOLUTO sotto
lo scratch, ma lo scratch è `<spawn>/scratch` mentre la cwd dell'agente è la
RADICE dello spawn: un agente che compone il path da `pwd` finisce accanto allo
scratch e viene respinto su un path appena letto dal proprio ambiente. E il motivo
calcolato a monte veniva buttato via da `raise_for_status()`, quindi non arrivava
a nessuno.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

import httpx

from . import transfer_channel


class _Resp:
    def __init__(self, status, payload=None, text=""):
        self.status_code = status
        self._payload = payload
        self.text = text

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class ErrorDetailTests(unittest.TestCase):
    """Un errore che non arriva a chi può correggerlo non è un errore."""

    def _post(self, resp):
        class C:
            def __enter__(s): return s
            def __exit__(s, *a): return False
            def post(s, *a, **k): return resp
        with patch.object(httpx, "Client", lambda *a, **k: C()), \
                patch.dict("os.environ", {"CLODIA_ORCHESTRATOR_SECRET": "s3cr3t"}):
            return transfer_channel._post("/internal/transfers/deliver", {})

    def test_the_detail_reaches_the_caller(self):
        with self.assertRaises(ValueError) as cm:
            self._post(_Resp(400, {"detail": "'x.zip' non sta nel tuo scratch. "
                                             "Lo scratch è /datadir/spawns/a-1/scratch"}))
        msg = str(cm.exception)
        self.assertIn("scratch", msg)
        self.assertIn("/datadir/spawns/a-1/scratch", msg)

    def test_a_non_json_body_still_says_something(self):
        with self.assertRaises(ValueError) as cm:
            self._post(_Resp(502, None, text="upstream down"))
        self.assertIn("upstream down", str(cm.exception))

    def test_an_empty_body_names_the_status_instead_of_nothing(self):
        with self.assertRaises(ValueError) as cm:
            self._post(_Resp(400, None, text=""))
        self.assertIn("400", str(cm.exception))

    def test_a_success_returns_the_payload(self):
        self.assertEqual(self._post(_Resp(200, {"local_path": "/s/x.zip"})),
                         {"local_path": "/s/x.zip"})


class OptionalDestTests(unittest.TestCase):
    """Senza `dest`, il file prende il proprio nome — nessun path da indovinare."""

    def test_dest_is_not_required_by_the_schema(self):
        from . import main
        tool = next(t for t in main._TOPIC_TOOLS if t.name == "topic.fetch")
        self.assertNotIn("dest", tool.inputSchema["required"])

    def test_the_description_warns_that_pwd_is_not_the_scratch(self):
        """È il punto in cui gli agenti sbagliavano: la cwd è la radice dello
        spawn, un livello SOPRA lo scratch. Un path composto da `pwd` è
        plausibile e sbagliato, che è il modo peggiore di essere sbagliato."""
        from . import main
        tool = next(t for t in main._TOPIC_TOOLS if t.name == "topic.fetch")
        self.assertIn("pwd", tool.description)
        self.assertIn("local_path", tool.description)


if __name__ == "__main__":
    unittest.main()

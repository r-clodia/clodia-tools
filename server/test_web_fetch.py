from __future__ import annotations

import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import httpx

from . import egress, gate, taint
from .tools import web_fetch


def _client(handler, seen: dict):
    """Un `httpx.Client` che parla con `handler` invece che con la rete."""
    real_client = httpx.Client

    class Client:
        def __init__(self, **kwargs):
            seen["kwargs"] = kwargs
            self._client = real_client(transport=httpx.MockTransport(handler), **kwargs)

        def __enter__(self):
            return self._client

        def __exit__(self, *args):
            self._client.close()

    return Client


class WebFetchTests(unittest.TestCase):
    def test_reading_is_not_gated(self):
        """Leggere non attraversa un confine verso fuori: nessun consenso umano.

        Il controllo su `web.fetch` è la FONTE (ingress → taint), non un dialog:
        gatare ogni lettura di un digest da cento feed sarebbe consent fatigue,
        cioè la condizione che #77 pone per non introdurre gate.
        """
        self.assertFalse(gate.is_gated("web.fetch"))
        self.assertTrue(gate.is_gated("web.post"))

    def test_fetching_taints_the_channel_unless_the_source_is_vetted(self):
        """Il verbo è già nella tabella del taint: qui si fissa che ci resti."""
        self.assertTrue(taint.taints("web.fetch"))

    def test_the_destination_extractor_reads_the_url(self):
        """`egress.py` sa già ridurre un URL a schema://host/ — vale anche in
        ingresso, ed è quello che `_source_vetted` interroga per web.*."""
        self.assertEqual(
            egress._http({"url": "https://EUR-Lex.europa.eu/legal-content/IT/"}),
            ["https://eur-lex.europa.eu/"],
        )

    def test_private_destinations_are_refused(self):
        """Nessun umano approva una fetch, quindi il controllo SSRF sta nel codice.

        `web.post` può permetterle perché il gate per-invocazione È il controllo;
        qui il gateway parlerebbe con la propria rete interna su richiesta di una
        pagina web.
        """
        for ip in ("127.0.0.1", "192.168.1.45", "169.254.169.254", "10.0.0.7"):
            with self.subTest(ip=ip):
                with patch.object(web_fetch.socket, "getaddrinfo",
                                  return_value=[(2, 1, 6, "", (ip, 80))]):
                    with self.assertRaises(PermissionError):
                        web_fetch.fetch({"url": "http://interno.example/"}, agent="clodia")

    def test_one_private_address_is_enough_to_refuse(self):
        """Un nome che risolve a un pubblico E a un privato è la forma
        dell'attacco: accettarlo perché «uno dei due va bene» lascerebbe la
        decisione al resolver."""
        with patch.object(web_fetch.socket, "getaddrinfo",
                          return_value=[(2, 1, 6, "", ("93.184.216.34", 80)),
                                        (2, 1, 6, "", ("127.0.0.1", 80))]):
            with self.assertRaises(PermissionError):
                web_fetch.fetch({"url": "http://doppio.example/"}, agent="clodia")

    def test_redirects_are_reported_not_followed(self):
        """Il taint è deciso sull'URL CHIESTO. Seguire un rimbalzo verso un host
        non vagliato darebbe per fidati byte che nessuno ha vagliato."""
        with TemporaryDirectory() as tmp:
            seen: dict = {}

            def handler(request: httpx.Request) -> httpx.Response:
                seen["request"] = request
                return httpx.Response(301, headers={"location": "https://altrove.example/x"},
                                      content=b"")

            with patch.object(web_fetch.httpx, "Client", _client(handler, seen)), \
                    patch.object(web_fetch, "_public_ips", return_value=["93.184.216.34"]), \
                    patch.dict(os.environ, {"CLODIA_VAULT_DIR": tmp}):
                result = web_fetch.fetch({"url": "https://fidata.example/feed"},
                                         agent="clodia")

            self.assertFalse(seen["kwargs"]["follow_redirects"])
            self.assertEqual(result["status"], 301)
            self.assertEqual(result["redirect_to"], "https://altrove.example/x")
            self.assertIn("redirect non seguito", result["note"])

    def test_binary_content_is_refused_and_audited(self):
        with TemporaryDirectory() as tmp:
            seen: dict = {}

            def handler(request: httpx.Request) -> httpx.Response:
                return httpx.Response(200, headers={"content-type": "application/zip"},
                                      content=b"PK\x03\x04")

            with patch.object(web_fetch.httpx, "Client", _client(handler, seen)), \
                    patch.object(web_fetch, "_public_ips", return_value=["93.184.216.34"]), \
                    patch.dict(os.environ, {"CLODIA_VAULT_DIR": tmp}):
                with self.assertRaises(ValueError):
                    web_fetch.fetch({"url": "https://fidata.example/a.zip"}, agent="clodia")

            righe = [json.loads(x) for x in
                     (Path(tmp) / "web-fetch-audit.log").read_text().splitlines()]
            self.assertEqual(righe[-1]["result"], "REFUSED")
            self.assertEqual(righe[-1]["action"], "web.fetch")

    def test_feeds_and_json_go_through(self):
        for ct in ("application/rss+xml", "application/json", "text/html; charset=utf-8",
                   "application/atom+xml", ""):
            with self.subTest(content_type=ct):
                self.assertTrue(web_fetch._readable(ct))
        self.assertFalse(web_fetch._readable("image/png"))
        self.assertFalse(web_fetch._readable("application/octet-stream"))

    def test_response_is_bounded_and_audited(self):
        with TemporaryDirectory() as tmp:
            seen: dict = {}
            grosso = b"x" * (web_fetch.DEFAULT_RESPONSE_BYTES + 5000)

            def handler(request: httpx.Request) -> httpx.Response:
                return httpx.Response(200, headers={"content-type": "text/plain"},
                                      content=grosso)

            with patch.object(web_fetch.httpx, "Client", _client(handler, seen)), \
                    patch.object(web_fetch, "_public_ips", return_value=["93.184.216.34"]), \
                    patch.dict(os.environ, {"CLODIA_VAULT_DIR": tmp}):
                result = web_fetch.fetch({"url": "https://fidata.example/big"},
                                         agent="clodia")

            self.assertTrue(result["truncated"])
            # il limite di default, non il tetto fisico: quello si raggiunge solo
            # chiedendolo con `max_bytes` (vedi ContextCostTests)
            self.assertEqual(result["response_bytes"], web_fetch.DEFAULT_RESPONSE_BYTES)
            righe = [json.loads(x) for x in
                     (Path(tmp) / "web-fetch-audit.log").read_text().splitlines()]
            self.assertEqual(righe[-1]["result"], "OK")
            self.assertEqual(righe[-1]["agent"], "clodia")

    def test_session_headers_never_come_back(self):
        """`Set-Cookie` non torna: un agente non ne ha uso, e ripeterlo nel
        contesto è il modo in cui proseguirebbe altrove."""
        with TemporaryDirectory() as tmp:
            seen: dict = {}

            def handler(request: httpx.Request) -> httpx.Response:
                return httpx.Response(200, headers={"content-type": "text/plain",
                                                    "set-cookie": "sid=segreto"},
                                      content=b"ciao")

            with patch.object(web_fetch.httpx, "Client", _client(handler, seen)), \
                    patch.object(web_fetch, "_public_ips", return_value=["93.184.216.34"]), \
                    patch.dict(os.environ, {"CLODIA_VAULT_DIR": tmp}):
                result = web_fetch.fetch({"url": "https://fidata.example/"}, agent="clodia")

            self.assertNotIn("set-cookie", {k.lower() for k in result["headers"]})
            self.assertEqual(result["body"], "ciao")

    def test_credentials_and_session_headers_are_rejected_in_input(self):
        for bad in ({"Cookie": "sid=1"}, {"Authorization": "Bearer x"}, {"Host": "altro"}):
            with self.subTest(header=bad):
                with self.assertRaises(ValueError):
                    web_fetch.fetch({"url": "https://fidata.example/", "headers": bad},
                                    agent="clodia")
        with self.assertRaises(ValueError):
            web_fetch.fetch({"url": "https://user:pw@fidata.example/"}, agent="clodia")

    def test_only_http_schemes(self):
        for url in ("file:///etc/passwd", "ftp://host/x", "gopher://host"):
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    web_fetch.fetch({"url": url}, agent="clodia")


class ContextCostTests(unittest.TestCase):
    """Quanto di una pagina entra nel CONTESTO, e come si chiede il resto.

    clodia-platform#228. Il primo limite era 512 KB, scelto guardando «quanto è
    grande una pagina». Criterio sbagliato: un risultato di tool entra nella
    conversazione della sessione e ci RESTA — costa una volta per essere prodotto
    e una per ogni round trip successivo del turno. 512 KB sono ~130.000 token
    riletti a ogni azione, e su un digest da venticinque fonti è la ragione per
    cui un turno prende minuti.
    """

    def _fetch(self, contenuto: bytes, **extra):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, headers={"content-type": "text/plain"},
                                  content=contenuto)

        with TemporaryDirectory() as tmp, \
                patch.object(web_fetch.httpx, "Client", _client(handler, seen)), \
                patch.object(web_fetch, "_public_ips", return_value=["93.184.216.34"]), \
                patch.dict(os.environ, {"CLODIA_VAULT_DIR": tmp}):
            return web_fetch.fetch({"url": "https://fidata.example/x", **extra},
                                   agent="clodia")

    def test_the_default_is_the_small_one(self) -> None:
        r = self._fetch(b"y" * (web_fetch.MAX_RESPONSE_BYTES + 1000))
        self.assertEqual(web_fetch.DEFAULT_RESPONSE_BYTES, r["response_bytes"])
        self.assertTrue(r["truncated"])

    def test_a_truncated_body_says_how_to_ask_for_the_rest(self) -> None:
        """Un taglio silenzioso fa concludere che la pagina finisce lì: è il modo
        in cui un limite diventa un errore di lettura."""
        r = self._fetch(b"y" * (web_fetch.DEFAULT_RESPONSE_BYTES + 10))
        self.assertIn("max_bytes", r.get("note", ""))
        self.assertIn(str(web_fetch.MAX_RESPONSE_BYTES), r.get("note", ""))

    def test_max_bytes_raises_the_limit_up_to_the_ceiling(self) -> None:
        grosso = b"y" * (web_fetch.MAX_RESPONSE_BYTES + 5000)
        r = self._fetch(grosso, max_bytes=200_000)
        self.assertEqual(200_000, r["response_bytes"])
        # oltre il tetto fisico non si va nemmeno chiedendolo
        r2 = self._fetch(grosso, max_bytes=10_000_000)
        self.assertEqual(web_fetch.MAX_RESPONSE_BYTES, r2["response_bytes"])

    def test_a_small_page_is_untouched_and_says_nothing(self) -> None:
        r = self._fetch(b"ciao")
        self.assertFalse(r["truncated"])
        self.assertEqual("ciao", r["body"])
        self.assertNotIn("note", r)

    def test_a_nonsense_max_bytes_is_refused_not_ignored(self) -> None:
        for cattivo in ("molti", 0, -5):
            with self.subTest(max_bytes=cattivo):
                with self.assertRaises(ValueError):
                    self._fetch(b"x", max_bytes=cattivo)


if __name__ == "__main__":
    unittest.main()

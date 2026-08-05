"""Tests for /tools/gdrive/confinement.

La proprietà che conta qui non è che il pannello funzioni: è **chi** può muovere
il confine. Allargare il perimetro è più privilegiato di qualunque uso del
perimetro, quindi la route non può accettare gli stessi chiamanti delle altre
route di Tools — `_authorized` fa passare `clodia` e `ophelia`, e un agente che
può spostare il proprio confine non ha un confine.
"""
from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import patch

from . import tools_api


class _Req:
    def __init__(self, token=None, body=None):
        self.headers = {"authorization": f"Bearer {token}"} if token else {}
        self._body = body or {}

    async def json(self):
        return self._body


def _get(req):
    return asyncio.run(tools_api.gdrive_confinement(req))


def _post(req):
    return asyncio.run(tools_api.gdrive_confinement_set(req))


def _as_agent(name, on_behalf=False, human_role="user"):
    p = {"agent": name}
    if on_behalf:
        p = {"on_behalf": True, "human_role": human_role, "agent": name}
    return patch("server.pki_verify.verify_session_token", lambda _t: p)


class AuthTests(unittest.TestCase):
    def test_a_super_agent_cannot_move_its_own_boundary(self):
        """Il punto centrale di questa route.

        `clodia` passa `_authorized` — giustamente, per gestire i connettori. Ma
        se passasse anche qui potrebbe allargare da sé il proprio accesso a Drive,
        e allora il confinamento non sarebbe un confine: sarebbe una preferenza.
        """
        with patch.object(tools_api, "_UI_TOKEN", None), _as_agent("clodia"), \
                patch.object(tools_api, "_is_human_admin", lambda _n: False):
            self.assertEqual(_get(_Req("t")).status_code, 401)
            self.assertEqual(_post(_Req("t", {"account": "x"})).status_code, 401)

    def test_a_human_admin_can(self):
        with patch.object(tools_api, "_UI_TOKEN", None), _as_agent("davide"), \
                patch.object(tools_api, "_is_human_admin", lambda _n: True), \
                patch("server.tools.gdrive.gworkspace_accounts", lambda: []):
            self.assertEqual(_get(_Req("t")).status_code, 200)

    def test_a_non_admin_human_cannot(self):
        with patch.object(tools_api, "_UI_TOKEN", None), \
                _as_agent("matteo", on_behalf=True, human_role="user"):
            self.assertEqual(_get(_Req("t")).status_code, 401)

    def test_without_a_token_it_is_unauthorized(self):
        with patch.object(tools_api, "_UI_TOKEN", None):
            self.assertEqual(_get(_Req()).status_code, 401)


class UrlTests(unittest.TestCase):
    """Incollare la URL è ciò che una persona fa davvero."""

    def test_it_accepts_a_drive_url(self):
        self.assertEqual(
            tools_api._folder_id("https://drive.google.com/drive/folders/1AbC_x-9?usp=sharing"),
            "1AbC_x-9")

    def test_it_accepts_a_bare_id(self):
        self.assertEqual(tools_api._folder_id("  1AbC_x-9 "), "1AbC_x-9")

    def test_it_accepts_an_open_url(self):
        self.assertEqual(tools_api._folder_id("https://drive.google.com/open?id=1AbC"),
                         "1AbC")


class _Ok:
    def __init__(self, meta):
        self.meta = meta

    def files(self):
        return self

    def get(self, **kw):
        self.last = kw
        return self

    def execute(self):
        return self.meta


class WriteTests(unittest.TestCase):
    def setUp(self):
        self.admin = (patch.object(tools_api, "_UI_TOKEN", None),
                      _as_agent("davide"),
                      patch.object(tools_api, "_is_human_admin", lambda _n: True))
        for c in self.admin:
            c.start()
        self.addCleanup(lambda: [c.stop() for c in self.admin])

    def _with_account(self, meta):
        return (patch("server.tools.gdrive.gworkspace_accounts", lambda: ["conto"]),
                patch("server.tools.gdrive._service", lambda *a, **k: (_Ok(meta), "conto")))

    def test_a_folder_is_written_and_echoed_by_name(self):
        """Si conferma un NOME, non un id: 33 caratteri non sono verificabili a
        occhio, e l'unico errore possibile — la cartella sbagliata — sarebbe
        invisibile."""
        meta = {"id": "1AbC", "name": "Proof-of-Flex",
                "mimeType": "application/vnd.google-apps.folder"}
        written = {}
        with self._with_account(meta)[0], self._with_account(meta)[1], \
                patch("server.whitelist.set_gdrive_roots",
                      lambda a, f: written.setdefault(a, f) or f):
            r = _post(_Req("t", {"account": "conto", "folders": [
                "https://drive.google.com/drive/folders/1AbC"]}))
        self.assertEqual(r.status_code, 200)
        b = json.loads(r.body)
        self.assertTrue(b["confined"])
        self.assertEqual(b["folders"][0]["name"], "Proof-of-Flex")
        self.assertEqual(written, {"conto": ["1AbC"]})

    def test_a_file_that_is_not_a_folder_is_refused(self):
        """Un confinamento a qualcosa che non è una cartella non è «più stretto»:
        è un tool rotto, e qualcuno lo riaprirà per sbloccarsi."""
        meta = {"id": "1AbC", "name": "foglio.xlsx", "mimeType": "application/pdf"}
        with self._with_account(meta)[0], self._with_account(meta)[1]:
            r = _post(_Req("t", {"account": "conto", "folders": ["1AbC"]}))
        self.assertEqual(r.status_code, 400)

    def test_an_unreachable_id_is_refused_not_written(self):
        called = []
        with patch("server.tools.gdrive.gworkspace_accounts", lambda: ["conto"]), \
                patch("server.tools.gdrive._service",
                      lambda *a, **k: (_Boom(), "conto")), \
                patch("server.whitelist.set_gdrive_roots",
                      lambda a, f: called.append(f)):
            r = _post(_Req("t", {"account": "conto", "folders": ["MAI_VISTO"]}))
        self.assertEqual(r.status_code, 400)
        self.assertEqual(called, [], "niente deve essere scritto")

    def test_an_unconnected_account_is_refused(self):
        with patch("server.tools.gdrive.gworkspace_accounts", lambda: ["altro"]):
            r = _post(_Req("t", {"account": "conto", "folders": ["1AbC"]}))
        self.assertEqual(r.status_code, 400)

    def test_removing_the_confinement_needs_an_explicit_confirmation(self):
        """È la sola azione qui che CONCEDE: da «vede una cartella» a «vede tutto
        il Drive». L'attrito non è decorativo."""
        called = []
        with patch("server.tools.gdrive.gworkspace_accounts", lambda: ["conto"]), \
                patch("server.whitelist.set_gdrive_roots",
                      lambda a, f: called.append(f)):
            r = _post(_Req("t", {"account": "conto", "folders": []}))
            self.assertEqual(r.status_code, 409)
            self.assertIn("TUTTO", json.loads(r.body)["error"])
            self.assertEqual(called, [])
            r2 = _post(_Req("t", {"account": "conto", "folders": [],
                                  "confirm_widen": True}))
        self.assertEqual(r2.status_code, 200)
        self.assertFalse(json.loads(r2.body)["confined"])
        self.assertEqual(called, [[]])


class _Boom:
    def files(self):
        return self

    def get(self, **kw):
        return self

    def execute(self):
        raise RuntimeError("404 notFound")


class DisclosureTests(unittest.TestCase):
    def test_the_read_says_what_confining_costs(self):
        """Il costo va detto dove si prende la decisione. Chi confina perde
        `gcalendar.*`, e scoprirlo dopo significa riaprire tutto per rimettere a
        posto un'agenda."""
        with patch.object(tools_api, "_UI_TOKEN", None), _as_agent("davide"), \
                patch.object(tools_api, "_is_human_admin", lambda _n: True), \
                patch("server.tools.gdrive.gworkspace_accounts", lambda: []):
            b = json.loads(_get(_Req("t")).body)
        self.assertIn("gcalendar.*", b["closes_verbs"])
        self.assertIn("gcalendar", b["note"])


if __name__ == "__main__":
    unittest.main()

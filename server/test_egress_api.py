"""Tests for /internal/egress (clodia-platform#104 §7 property 4).

Two things must hold and are easy to break by accident: the endpoint is
server-to-server only, and it never returns the destinations themselves.
"""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from . import egress_api


class _Req:
    def __init__(self, secret=None, uri=None):
        self.headers = {"x-orchestrator-secret": secret} if secret else {}
        self.query_params = {"uri": uri} if uri else {}


def _call(req):
    return asyncio.run(egress_api.profile(req))


_CFG = {"egress_allow": ["mailto:a@b.it", "mailto:*@tomato.blue"],
        "source_allow": ["https://eur-lex.europa.eu/legal-content/"],
        "agents": {}}


def _with(cfg):
    from . import whitelist as wl
    from unittest.mock import patch as _p
    return _p.object(wl, "CONFIG", cfg)


class AuthTests(unittest.TestCase):
    def test_without_the_secret_it_is_unauthorized(self):
        with patch.dict("os.environ", {"CLODIA_ORCHESTRATOR_SECRET": "s3cr3t"}):
            self.assertEqual(_call(_Req()).status_code, 401)
            self.assertEqual(_call(_Req("wrong")).status_code, 401)

    def test_with_no_secret_configured_it_fails_closed(self):
        """Un secret non impostato non deve significare «nessuna autenticazione»."""
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(_call(_Req("anything")).status_code, 401)


class ShapeTests(unittest.TestCase):
    def _body(self):
        import json
        with patch.dict("os.environ", {"CLODIA_ORCHESTRATOR_SECRET": "s3cr3t",
                                       "CLODIA_EGRESS_ENFORCE": "gate"}), _with(_CFG):
            r = _call(_Req("s3cr3t"))
        self.assertEqual(r.status_code, 200)
        return json.loads(r.body)

    def test_the_destinations_are_never_returned(self):
        """Una rubrica è dato privato, e al punteggio non serve per distinguere
        uscita circoscritta da arbitraria. Restituirla metterebbe i contatti
        dell'owner nel contesto di qualunque cosa renderizzi il numero."""
        raw = str(self._body())
        for leaked in ("a@b.it", "tomato.blue", "eur-lex"):
            self.assertNotIn(leaked, raw)

    def test_it_reports_the_shape_of_both_lists(self):
        b = self._body()
        self.assertEqual(b["mode"], "gate")
        self.assertEqual(b["egress"], {"scope": "listed", "count": 2,
                                       "schemes": ["mailto"]})
        self.assertEqual(b["source"]["scope"], "listed")

    def test_a_star_is_wide_not_circumscribed(self):
        import json
        cfg = {"egress_allow": ["*", "mailto:a@b.it"], "agents": {}}
        with patch.dict("os.environ", {"CLODIA_ORCHESTRATOR_SECRET": "s3cr3t"}), _with(cfg):
            b = json.loads(_call(_Req("s3cr3t")).body)
        self.assertEqual(b["egress"]["scope"], "wide")

    def test_an_empty_list_is_none_not_muted(self):
        import json
        with patch.dict("os.environ", {"CLODIA_ORCHESTRATOR_SECRET": "s3cr3t"}), \
                _with({"agents": {}}):
            b = json.loads(_call(_Req("s3cr3t")).body)
        self.assertEqual(b["egress"]["scope"], "none")
        self.assertEqual(b["source"]["scope"], "none")


class MembershipQueryTests(unittest.TestCase):
    """`?uri=` risponde sì/no senza restituire la lista.

    Il punteggio trifecta deve sapere se il remote di un canale punta a una
    destinazione vagliata. Chiedendolo non impara nulla che non sappia già —
    l'URI viene dal meta del topic; ricevendo la lista imparerebbe tutto.
    """

    def _q(self, uri, cfg):
        import json
        with patch.dict("os.environ", {"CLODIA_ORCHESTRATOR_SECRET": "s3cr3t"}), _with(cfg):
            return json.loads(_call(_Req("s3cr3t", uri=uri)).body)

    def test_a_whitelisted_uri_answers_true(self):
        b = self._q("gdrive:folder/1AbC", {"egress_allow": ["gdrive:folder/1AbC"],
                                           "agents": {}})
        self.assertTrue(b["allowed"])
        self.assertEqual(b["query"], "gdrive:folder/1AbC")

    def test_an_unlisted_uri_answers_false(self):
        b = self._q("gdrive:folder/ALTRA", {"egress_allow": ["gdrive:folder/1AbC"],
                                            "agents": {}})
        self.assertFalse(b["allowed"])

    def test_the_answer_does_not_carry_the_list(self):
        b = self._q("gdrive:folder/X", {"egress_allow": ["gdrive:folder/SEGRETA"],
                                        "agents": {}})
        self.assertNotIn("SEGRETA", str(b))

    def test_without_the_query_nothing_is_answered(self):
        import json
        with patch.dict("os.environ", {"CLODIA_ORCHESTRATOR_SECRET": "s3cr3t"}), \
                _with({"agents": {}}):
            b = json.loads(_call(_Req("s3cr3t")).body)
        self.assertNotIn("allowed", b)


if __name__ == "__main__":
    unittest.main()

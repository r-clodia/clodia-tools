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
    def __init__(self, secret=None, uri=None, path_params=None):
        self.headers = {"x-orchestrator-secret": secret} if secret else {}
        self.query_params = {"uri": uri} if uri else {}
        self.path_params = path_params or {}


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


class ScopeWhitelistViewTests(unittest.TestCase):
    """`/internal/egress/whitelist/scope/{tier}/{name}` — le due liste LOCALI
    di un topic, distinte da quella globale (`whitelist_view`).

    Sidebar "Egress/Ingress" della webui (9 set 2026): la lista globale era già
    leggibile, quella per-scope no — `scope_uris` esisteva solo come funzione
    interna usata da `effective_uris` per fare l'unione, mai esposta.
    """

    def _call(self, tier, name, secret="s3cr3t"):
        return asyncio.run(egress_api.scope_whitelist_view(
            _Req(secret, path_params={"tier": tier, "name": name})))

    def _cfg(self):
        return {
            "agents": {},
            "egress_allow": ["mailto:globale@tomato.blue"],
            "scope_egress_allow": {"SEAL-1/acme": ["gdrive:folder/1AbC"]},
            "scope_source_allow": {"SEAL-1/acme": ["https://esempio.it/feed"]},
        }

    def test_without_the_secret_it_is_unauthorized(self):
        with patch.dict("os.environ", {"CLODIA_ORCHESTRATOR_SECRET": "s3cr3t"}):
            self.assertEqual(self._call("SEAL-1", "acme", secret=None).status_code, 401)

    def test_the_scope_s_own_entries_come_back(self):
        import json
        with patch.dict("os.environ", {"CLODIA_ORCHESTRATOR_SECRET": "s3cr3t"}), \
                _with(self._cfg()):
            r = self._call("SEAL-1", "acme")
        self.assertEqual(r.status_code, 200)
        b = json.loads(r.body)
        self.assertEqual(b["egress"], ["gdrive:folder/1AbC"])
        self.assertEqual(b["ingress"], ["https://esempio.it/feed"])

    def test_the_global_list_is_not_mixed_in(self):
        """Questa rotta è la lista SOLO locale: l'unione con la globale la fa
        `effective_uris` altrove, non qui — mischiarle renderebbe la sidebar
        del topic indistinguibile dalle impostazioni globali."""
        import json
        with patch.dict("os.environ", {"CLODIA_ORCHESTRATOR_SECRET": "s3cr3t"}), \
                _with(self._cfg()):
            r = self._call("SEAL-1", "acme")
        b = json.loads(r.body)
        self.assertNotIn("mailto:globale@tomato.blue", b["egress"])

    def test_a_scope_with_no_entries_answers_empty_not_an_error(self):
        import json
        with patch.dict("os.environ", {"CLODIA_ORCHESTRATOR_SECRET": "s3cr3t"}), \
                _with(self._cfg()):
            r = self._call("SEAL-1", "un-altro-topic")
        b = json.loads(r.body)
        self.assertEqual(b, {"egress": [], "ingress": []})

    def test_the_legacy_tier_alias_still_resolves(self):
        """`P1/acme` e `SEAL-1/acme` sono lo stesso posto (`_norm_scope_key`):
        una voce scritta con l'alias vecchio non deve sparire da qui."""
        import json
        cfg = {"agents": {}, "scope_egress_allow": {"P1/acme": ["mailto:x@y.it"]}}
        with patch.dict("os.environ", {"CLODIA_ORCHESTRATOR_SECRET": "s3cr3t"}), \
                _with(cfg):
            r = self._call("SEAL-1", "acme")
        b = json.loads(r.body)
        self.assertEqual(b["egress"], ["mailto:x@y.it"])


if __name__ == "__main__":
    unittest.main()

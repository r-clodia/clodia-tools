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
    def __init__(self, secret=None):
        self.headers = {"x-orchestrator-secret": secret} if secret else {}


def _call(req):
    return asyncio.run(egress_api.profile(req))


_CFG = {"agents": {
    "messaggero": {"egress_allow": {"email": ["a@b.it", "@tomato.blue"],
                                    "telegram": []}},
    "clodia": {"egress_allow": {"http": ["*"]}},
    "segretario": {},
}}


class AuthTests(unittest.TestCase):
    def test_without_the_secret_it_is_unauthorized(self):
        with patch.dict("os.environ", {"CLODIA_ORCHESTRATOR_SECRET": "s3cr3t"}):
            self.assertEqual(_call(_Req()).status_code, 401)
            self.assertEqual(_call(_Req("wrong")).status_code, 401)

    def test_with_no_secret_configured_it_fails_closed(self):
        """An unset secret must not mean 'no authentication required'."""
        with patch.dict("os.environ", {}, clear=True):
            self.assertEqual(_call(_Req("anything")).status_code, 401)


class PayloadTests(unittest.TestCase):
    def _body(self):
        import json
        with patch.dict("os.environ", {"CLODIA_ORCHESTRATOR_SECRET": "s3cr3t",
                                       "CLODIA_EGRESS_ENFORCE": "gate"}), \
             patch("server.whitelist.CONFIG", _CFG):
            r = _call(_Req("s3cr3t"))
        self.assertEqual(r.status_code, 200)
        return json.loads(r.body)

    def test_the_destinations_are_never_returned(self):
        """An address book is private data, and the score does not need it to
        tell arbitrary egress from circumscribed egress. Returning it would put
        the owner's contacts into the context of whatever renders the score."""
        raw = str(self._body())
        for leaked in ("a@b.it", "@tomato.blue"):
            self.assertNotIn(leaked, raw)

    def test_it_reports_the_shape_per_agent_and_type(self):
        b = self._body()
        self.assertEqual(b["mode"], "gate")
        self.assertEqual(b["agents"]["messaggero"]["email"],
                         {"scope": "listed", "count": 2})
        # declared empty = muted, distinct from "never declared"
        self.assertEqual(b["agents"]["messaggero"]["telegram"]["scope"], "muted")
        self.assertEqual(b["agents"]["segretario"], {})

    def test_a_star_rule_is_wide_not_circumscribed(self):
        """`["*"]` is declared but constrains nothing. Reporting it as
        circumscribed is the one direction of error this measure cannot afford."""
        self.assertEqual(self._body()["agents"]["clodia"]["http"]["scope"], "wide")


if __name__ == "__main__":
    unittest.main()

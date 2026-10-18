"""clodia-platform#569 — a URL outside the ingress lists is not loaded before
a person approves it.

On 18 Oct 2026 clodia read https://www.myfitcoach.app/ on request: the gateway
marked the source `not_vetted` and fetched it anyway, because ingress lists
decided trust, not access. Measured here:

1. a source in the lists is read with no gate;
2. a source outside them opens a gate on the SITE (time-boxed, no
   delegation) BEFORE any request; approved → read;
3. refused or timed out → no request at all;
4. an unattended session is refused without a gate;
5. the site key: scheme + host (+ non-default port), path and query dropped.
"""
from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from . import egress, main
from .claims import ClaimsContext

TOKEN = {"agent": "clodia", "execution_id": "clodia-606", "principal": "davide",
         "origin": ["human:davide", "agent:clodia"]}


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        p = patch.dict(os.environ, {"CLODIA_AUDIT_DIR": str(base / "audit"),
                                    "CLODIA_AUDIT_KEY_DIR": str(base / "k"),
                                    "CLODIA_DATA": str(base / "data")})
        p.start()
        self.addCleanup(p.stop)
        self.fetch = MagicMock(return_value={"ok": True, "status": 200, "text": "x"})
        self.gate = AsyncMock(return_value={})

    def call(self, url: str, *, vetted: bool, unattended: bool = False,
             verb: str = "web.fetch") -> str:
        async def go():
            with ClaimsContext(TOKEN, "t"), \
                    patch.object(egress, "is_vetted_source", return_value=vetted), \
                    patch.object(main, "is_unattended", return_value=unattended), \
                    patch.object(main, "_require_gate_consent", self.gate), \
                    patch.object(main.web_fetch, "fetch", self.fetch), \
                    patch.object(main.web_fetch, "download", self.fetch), \
                    patch.object(main, "_safe_scratch_path", lambda p: p), \
                    patch.object(main._os, "makedirs", lambda *a, **k: None):
                args = {"url": url}
                if verb == "web.download":
                    args["dest"] = "/tmp/x"
                return await main.call_tool(verb, args)
        return asyncio.run(go())[0].text


def _web_gates(mock) -> list:
    """The web-source gates among the gates awaited (other gates — e.g. a verb
    outside the test seed's profile — are not this test's subject)."""
    return [c for c in mock.await_args_list
            if len(c.args) > 1 and str(c.args[1]).startswith(main.WEB_SOURCE_GATE)]


class WebSourceGateTests(_Base):
    def test_a_listed_source_is_read_without_a_gate(self) -> None:
        out = self.call("https://www.ok.it/a", vetted=True)
        self.assertFalse(out.startswith(("DENIED", "ERROR")), out)
        self.assertEqual(_web_gates(self.gate), [])
        self.fetch.assert_called_once()

    def test_an_unlisted_source_asks_first_on_the_site(self) -> None:
        out = self.call("https://www.MyFitCoach.app/en?x=1", vetted=False)
        self.assertFalse(out.startswith(("DENIED", "ERROR")), out)
        ((agent, key), kw), = [(c.args, c.kwargs) for c in _web_gates(self.gate)]
        self.assertEqual(key, "web-source:https://www.myfitcoach.app/")
        self.assertFalse(kw["consume"])            # the site, for the gate's validity
        self.assertFalse(kw["allow_delegation"])
        self.fetch.assert_called_once()

    def test_a_refusal_means_no_request(self) -> None:
        async def refuse(agent, key, **kw):
            if str(key).startswith(main.WEB_SOURCE_GATE):
                raise PermissionError("gate: negato dall'operatore")
            return {}
        self.gate.side_effect = refuse
        for verb in ("web.fetch", "web.download"):
            out = self.call("https://evil.example/", vetted=False, verb=verb)
            self.assertTrue(out.startswith(("DENIED", "ERROR")), out)
        self.fetch.assert_not_called()

    def test_unattended_is_refused_without_a_gate(self) -> None:
        out = self.call("https://evil.example/", vetted=False, unattended=True)
        self.assertTrue(out.startswith(("DENIED", "ERROR")), out)
        self.assertIn("non è presidiata", out)
        self.assertEqual(_web_gates(self.gate), [])
        self.fetch.assert_not_called()


class OriginTests(unittest.TestCase):
    def test_the_site_key(self) -> None:
        self.assertEqual(main._web_origin("https://www.x.it/a/b?q=1#f"), "https://www.x.it/")
        self.assertEqual(main._web_origin("HTTP://X.it:8080/p"), "http://x.it:8080/")
        self.assertEqual(main._web_origin("https://x.it:443/"), "https://x.it/")
        self.assertEqual(main._web_origin("https://user:pw@x.it/"), "https://x.it/")
        self.assertEqual(main._web_origin("not a url"), "")


if __name__ == "__main__":
    unittest.main()

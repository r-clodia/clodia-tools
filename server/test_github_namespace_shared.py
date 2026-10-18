"""Il namespace `github.` è conteso, e il dispatch deve saperlo.

Quattro verbi `github.*` sono le azioni git che escono dallo scope (clone, pull,
push, pull_request): li serve il componente gateway di it-pack
(clodia-platform#525; prima li implementava il gateway). Il backend MCP
ufficiale di GitHub è montato **con lo stesso nome**, quindi i suoi tool si
chiamano anch'essi `github.<qualcosa>`: `issue_write`, `list_issues`,
`search_code`.

Il dispatch sceglieva per PREFISSO. Risultato misurato su venere l'11 ago:
`github.issue_write` era nella whitelist di `sysadmin`, compariva nella lista dei
tool e rispondeva «unknown github verb» alla chiamata. Il rischio opposto vale
ancora: un verbo git che nessun componente serve non deve finire al backend.
"""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from . import main as M


class TheGitVerbsAreNamedTests(unittest.TestCase):
    def test_the_four_git_verbs(self):
        self.assertEqual(M._GITHUB_NATIVE_NAMES, frozenset({
            "github.clone", "github.pull", "github.push", "github.pull_request"}))

    def test_a_backend_verb_is_not_a_git_verb(self):
        for v in ("github.issue_write", "github.list_issues", "github.search_code"):
            self.assertNotIn(v, M._GITHUB_NATIVE_NAMES)

    def test_no_native_implementation_is_left(self):
        self.assertFalse(hasattr(M, "_dispatch_github"))
        self.assertFalse(hasattr(M, "_push_destination"))
        names = {t.name for t in M._all_native_tools()}
        self.assertFalse(names & M._GITHUB_NATIVE_NAMES)


class TheCallActuallyRoutesTests(unittest.TestCase):
    """Il controllo statico dice dove va il ramo; questo lo percorre."""

    def _call(self, verb: str, args: dict):
        from . import whitelist as w, proxy as P

        async def proxied(name, a):
            return f"PROXY:{name}"

        cfg = {"agents": {"sysadmin": {"allowed_tools": ["github.*"],
                                       "allowed_paths": ["."]}},
               "egress_allow": ["https://github.com/r-clodia/clodia-platform"]}
        tok = w.set_current_agent("sysadmin")
        try:
            with patch.object(w, "CONFIG", cfg), \
                    patch.object(P, "call_proxied", proxied), \
                    patch.object(P, "is_proxied", lambda n: n.startswith("github.")), \
                    patch.object(M._taint, "note_verb", lambda *a, **k: None), \
                    patch.object(M._tlm, "record", lambda *a, **k: None):
                r = asyncio.run(M.call_tool(verb, args))
            return r[0].text
        finally:
            w.reset_current_agent(tok)

    def test_a_backend_verb_reaches_the_proxy(self):
        out = self._call("github.issue_write",
                         {"owner": "r-clodia", "repo": "clodia-platform",
                          "title": "t"})
        self.assertEqual(out, "PROXY:github.issue_write")

    def test_a_git_verb_never_reaches_the_backend(self):
        """On `native` (the default) the git verbs have no implementation: the
        call is refused and says how to get one, never proxied."""
        out = self._call("github.clone", {"repo": "r", "dest": "d"})
        self.assertTrue(out.startswith("DENIED:"), out)
        self.assertIn("github: pack", out)


if __name__ == "__main__":
    unittest.main()

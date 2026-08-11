"""Il namespace `github.` è conteso, e il dispatch deve saperlo.

Il gateway implementa da sé quattro verbi `github.*` — le azioni git che escono
dallo scope (clone, pull, push, pull_request). Il backend MCP ufficiale di GitHub
è montato **con lo stesso nome**, quindi i suoi 44 tool si chiamano anch'essi
`github.<qualcosa>`: `issue_write`, `list_issues`, `search_code`.

Il dispatch sceglieva per PREFISSO. Risultato misurato su venere l'11 ago:
`github.issue_write` era nella whitelist di `sysadmin`, compariva nella lista dei
tool (che concatena nativi e proxati) e rispondeva «unknown github verb» alla
chiamata. Chi la riceveva concludeva che il connettore non fosse montato, e ha
cercato il guasto nel vault e nella rete — mentre il backend rispondeva
correttamente a un metro di distanza.

Un tool che si vede e non si può chiamare è peggio di uno assente: manda a
diagnosticare l'infrastruttura sbagliata.
"""
from __future__ import annotations

import asyncio
import inspect
import unittest
from unittest.mock import patch

from . import main as M


class TheNativeSetIsDerivedTests(unittest.TestCase):
    def test_the_native_names_come_from_the_declared_tools(self):
        """Non un elenco riscritto a mano: divergerebbe al primo verbo aggiunto."""
        self.assertEqual(M._GITHUB_NATIVE_NAMES,
                         frozenset(t.name for t in M._GITHUB_TOOLS))

    def test_the_four_git_verbs_are_in_it(self):
        for v in ("github.clone", "github.pull", "github.push",
                  "github.pull_request"):
            self.assertIn(v, M._GITHUB_NATIVE_NAMES)


class TheDispatchDoesNotSwallowTheBackendTests(unittest.TestCase):
    """Statico sul sorgente del dispatch: il ramo nativo non può selezionare
    per prefisso, o riprende tutti i verbi del backend."""

    def _dispatch_src(self) -> str:
        return inspect.getsource(M.call_tool)

    def test_the_native_branch_matches_by_name_not_by_prefix(self):
        src = self._dispatch_src()
        self.assertNotIn('name.startswith("github.")', src,
                         "selezionare per prefisso riprende anche i verbi del "
                         "backend montato con lo stesso namespace")
        self.assertIn("_GITHUB_NATIVE_NAMES", src)

    def test_the_native_branch_comes_before_the_proxy_branch(self):
        """L'ordine resta questo: i verbi che il gateway implementa DAVVERO
        vincono sul backend omonimo. È l'unico modo per cui un backend montato
        non può sostituire un verbo nativo — che è il rischio opposto e
        peggiore."""
        src = self._dispatch_src()
        self.assertLess(src.index("_GITHUB_NATIVE_NAMES"),
                        src.index("proxy.is_proxied(name)"))

    def test_a_backend_verb_is_not_a_native_one(self):
        for v in ("github.issue_write", "github.list_issues", "github.search_code"):
            self.assertNotIn(v, M._GITHUB_NATIVE_NAMES)


class TheCallActuallyRoutesTests(unittest.TestCase):
    """Il controllo statico dice dove va il ramo; questo lo percorre.

    Il difetto era in una riga che nessun test attraversava: una verifica del
    solo testo, da sola, ripeterebbe l'errore di misura.
    """

    def _call(self, verb: str, args: dict, native):
        from . import whitelist as w, proxy as P

        async def proxied(name, a):
            return f"PROXY:{name}"

        cfg = {"agents": {"sysadmin": {"allowed_tools": ["github.*"],
                                       "allowed_paths": ["."]}},
               "egress_allow": ["https://github.com/r-clodia/clodia-platform"]}
        tok = w.set_current_agent("sysadmin")
        try:
            with patch.object(w, "CONFIG", cfg), \
                    patch.object(M, "_dispatch_github", native), \
                    patch.object(P, "call_proxied", proxied), \
                    patch.object(P, "is_proxied", lambda n: n.startswith("github.")), \
                    patch.object(M._taint, "note_verb", lambda *a, **k: None), \
                    patch.object(M._tlm, "record", lambda *a, **k: None):
                r = asyncio.run(M.call_tool(verb, args))
            return r[0].text
        finally:
            w.reset_current_agent(tok)

    def test_a_backend_verb_reaches_the_proxy(self):
        def native(name, a):
            raise AssertionError("ramo nativo scelto per un verbo del backend")

        out = self._call("github.issue_write",
                         {"owner": "r-clodia", "repo": "clodia-platform",
                          "title": "t"}, native)
        self.assertEqual(out, "PROXY:github.issue_write")

    def test_a_native_verb_still_goes_native(self):
        """Il rischio opposto: un backend montato che sostituisce un verbo che il
        gateway implementa — e che passa dai suoi controlli di perimetro."""
        out = self._call("github.clone", {"repo": "r", "dest": "d"},
                         lambda n, a: "NATIVO")
        self.assertIn("NATIVO", out)


if __name__ == "__main__":
    unittest.main()

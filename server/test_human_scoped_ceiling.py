"""`scoped_tools` in una chiamata umana: un tetto, non un'aggiunta.

Il claim esiste da mesi, è firmato, e sul ramo on-behalf **non lo leggeva
nessuno**. `_human_tool_allowed` decide sul ruolo: gated → admin, tutto il resto
→ chiunque. Quindi un token coniato per far parlare Giovanni in *una* stanza gli
apriva ogni verbo non-gated del gateway: leggere qualunque topic, scrivere file
ovunque, invocare i connettori.

È il difetto ricorrente «qualcosa di dichiarato che nessuno porta», nella
variante peggiore: la dichiarazione *somiglia* già a una restrizione, quindi
guardando il token si conclude che il confine c'è.

Il rimedio è asimmetrico di proposito. Sul ramo degli agenti il claim continua a
SOMMARE — lì il token concede, ed è la semantica della delega. Sul ramo umano
INTERSECA. Stessa parola, due direzioni, perché le due chiamate chiedono cose
opposte: l'agente riceve un permesso in più, la persona riceve un perimetro.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import main as M
from . import whitelist


VERBI_UMANI = ["topic.open", "topic.messages", "topic.post_message",
               "topic.files", "topic.read_file"]


class _Tetto:
    """Un token on-behalf con un tetto dichiarato, per la durata del blocco."""

    def __init__(self, tools, ruolo="user", chi="giovanni"):
        self._t = (tools, ruolo, chi)

    def __enter__(self):
        tools, ruolo, chi = self._t
        self._tok = (whitelist.set_current_scoped_tools(tools),
                     whitelist.set_current_on_behalf(True),
                     whitelist.set_current_human_role(ruolo),
                     whitelist.set_current_principal(chi))
        return self

    def __exit__(self, *a):
        st, ob, hr, pr = self._tok
        whitelist.reset_current_principal(pr)
        whitelist.reset_current_human_role(hr)
        whitelist.reset_current_on_behalf(ob)
        whitelist.reset_current_scoped_tools(st)
        return False


class CeilingTests(unittest.TestCase):
    def test_a_declared_verb_passes(self):
        with _Tetto(VERBI_UMANI):
            self.assertTrue(M._scoped_ceiling_ok("topic.post_message"))

    def test_an_undeclared_verb_is_refused(self):
        """Il caso che dà il senso alla modifica: `topic.delete_file` non è
        gated, quindi la RBAC del ruolo lo concedeva a chiunque."""
        with _Tetto(VERBI_UMANI):
            self.assertFalse(M._scoped_ceiling_ok("topic.delete_file"))
            self.assertFalse(M._scoped_ceiling_ok("fs.write_file"))
            self.assertFalse(M._scoped_ceiling_ok("email.send"))

    def test_no_ceiling_means_the_role_still_decides(self):
        """Un tetto assente non è un tetto vuoto. Le sessioni umane della webui
        non portano `scoped_tools`: leggerlo come «niente è permesso» le
        spegnerebbe tutte."""
        with _Tetto(None):
            self.assertTrue(M._scoped_ceiling_ok("topic.open"))
            self.assertTrue(M._scoped_ceiling_ok("email.send"))

    def test_a_namespace_wildcard_still_works(self):
        """È così che si concede un backend MCP montato per intero."""
        with _Tetto(["gdrive.*"]):
            self.assertTrue(M._scoped_ceiling_ok("gdrive.list"))
            self.assertFalse(M._scoped_ceiling_ok("gcalendar.list"))

    def test_a_bare_star_is_refused_at_minting(self):
        """Il `*` nudo non lo chiude il tetto: lo chiude il minter. Un secondo
        controllo sulla stessa cosa è una duplicazione, e le duplicazioni di una
        regola divergono — qui si verifica che quello vero ci sia."""
        from . import pki_mint
        with self.assertRaises(PermissionError):
            pki_mint.mint_session_token("clodia", scoped_tools=["*"])
        with self.assertRaises(PermissionError):
            pki_mint.mint_session_token("clodia", scoped_tools=["agents.spawn"])


class TheAgentBranchIsUnchangedTests(unittest.TestCase):
    """La delega fra agenti continua a SOMMARE.

    Se il tetto si applicasse anche lì, ogni agente che riceve una delega
    perderebbe di colpo i propri verbi — un guasto molto più rumoroso del difetto
    che questa modifica ripara, e in una parte del sistema che funziona.
    """

    def test_scoped_tools_still_widen_for_an_agent(self):
        with patch.object(M, "_declared_tools", return_value={"topic.open"}), \
             patch.object(M, "current_scoped_tools", return_value=("email.send",)), \
             patch.object(M, "_connector_allows", return_value=False):
            self.assertTrue(M._agent_tool_reachable("topic.open", "messaggero"))
            self.assertTrue(M._agent_tool_reachable("email.send", "messaggero"))
            self.assertFalse(M._agent_tool_reachable("settings.set", "messaggero"))

    def test_the_ceiling_is_only_consulted_on_behalf(self):
        import inspect
        src = inspect.getsource(M.call_tool)
        prima = src.index("if is_on_behalf():")
        dopo = src.index("elif not _is_super(_ag)")
        self.assertIn("_scoped_ceiling_ok", src[prima:dopo])
        self.assertNotIn("_scoped_ceiling_ok", src[dopo:])


class TheListMatchesTheDispatchTests(unittest.TestCase):
    """Elencare e permettere devono dire la stessa cosa.

    Un tool elencato e poi rifiutato insegna a ignorare l'elenco; uno permesso e
    non elencato è una funzione che nessuno trova. È la coppia di difetti che
    nasce ogni volta che due punti decidono separatamente la stessa cosa.
    """

    def test_list_tools_applies_the_ceiling_too(self):
        import inspect
        src = inspect.getsource(M.list_tools)
        self.assertIn("_scoped_ceiling_ok", src)


if __name__ == "__main__":
    unittest.main()

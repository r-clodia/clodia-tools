"""Nessun agente bypassa più la whitelist per il proprio nome.

`clodia` era uscita dai due insiemi super il 6 ago 2026; `ophelia` esce il 7. E
togliere **l'ultima** è ciò che rende il concetto verificabile invece che
convenzionale: finché uno solo resta dentro, la matrice non è mai davvero il
documento che decide — c'è sempre un nome per cui non vale.

**Gli insiemi erano due**, e sono due test distinti: `main._SUPER_AGENTS` (il
dispatch) e `whitelist._SUPER_AGENTS` (il gate a livello adapter). Toglierla da
uno solo l'avrebbe lasciata bypassare dall'altro, che è precisamente il modo in
cui un concetto sopravvive alla propria rimozione.

**Ciò che portava lo stesso nome e non era autorità dell'agente**: l'identità di
SERVIZIO con cui l'agent-server conia un token per conto di un umano — i profili
umani non hanno una chiave lato server per firmare a proprio nome. È `clodia`, in
`gate.py`, e non passa da qui. Misurato prima di toccare nulla: `ophelia` non
conia niente, quindi questa rimozione non tocca l'autenticazione.

Su `ophelia` resta il wildcard? No: scende ai soli verbi dell'arciseed. `[]` non
vuol dire «nessun verbo» ma «nessun verbo PROPRIO» — nessun mestiere ancora
dichiarato. La revisione seed per seed è un lavoro a parte.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import main as M
from . import whitelist as w


class BothSetsTests(unittest.TestCase):
    def test_the_dispatch_set_is_empty(self):
        self.assertEqual(M._SUPER_AGENTS, set())

    def test_the_adapter_set_is_empty(self):
        """Il secondo insieme: toglierla da uno solo l'avrebbe lasciata
        bypassare dall'altro."""
        with patch.dict("os.environ", {}, clear=False):
            self.assertNotIn("ophelia", w._SUPER_AGENTS)

    def test_ophelia_is_not_super(self):
        self.assertFalse(M._is_super("ophelia"))

    def test_clodia_is_not_super_either(self):
        self.assertFalse(M._is_super("clodia"))


class StillReachableTests(unittest.TestCase):
    """Togliere `super` non deve rendere muto un agente: i verbi base arrivano
    dall'arciseed, e quello è il punto del disegno."""

    CFG = {"agents": {"ophelia": {"allowed_tools": []}}}

    def test_it_keeps_the_base_verbs_by_inheritance(self):
        with patch.object(w, "CONFIG", self.CFG):
            eff = w.effective_tools("ophelia")
            self.assertIn("memory.*", eff)
            self.assertIn("topic.open", eff)
            self.assertIn("topic.post_message", eff)

    def test_it_no_longer_reaches_everything(self):
        with patch.object(w, "CONFIG", self.CFG):
            eff = w.effective_tools("ophelia")
            for v in ("settings.set", "email.send", "topic.put"):
                with self.subTest(verbo=v):
                    self.assertNotIn(v, eff)

    def test_an_empty_own_list_is_not_an_empty_effective_list(self):
        """`[]` significa «nessun mestiere dichiarato», non «nessun verbo»."""
        with patch.object(w, "CONFIG", self.CFG):
            self.assertTrue(w.effective_tools("ophelia"))


class ServiceIdentityTests(unittest.TestCase):
    def test_the_env_escape_hatch_survives(self):
        """Rimettere un nome resta possibile, ma deve essere un atto esplicito
        di chi amministra — non un default che nessuno ha scelto."""
        import inspect
        self.assertIn("CLODIA_SUPER_AGENTS", inspect.getsource(w))


if __name__ == "__main__":
    unittest.main()

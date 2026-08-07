"""`memory.*` si dichiara, come ogni altro verbo.

Punto aperto 3 del notebook, chiuso da Davide il 7 ago 2026: «lasciamo i verbi
`memory.*` espliciti».

`memory` era l'unico namespace **universale**: concesso a ogni agente senza
comparire da nessuna parte. Il costo non era la concessione — la memoria di un
agente è la sua, confinata alla sua cartella — ma l'invisibilità: leggendo la
configurazione di un agente non si poteva sapere che li aveva, e non si potevano
togliere a uno in particolare.

**L'ordine è la sostanza di questo cambiamento.** Misurato prima di toccare
nulla: togliendo la scorciatoia, `memory` sarebbe sparito a **6 agenti su 8 su
venere e a 5 su 5 su marte** — e in silenzio, perché un verbo che esce da un
insieme implicito non lascia traccia in nessun file: l'agente lo scopre mentre
lavora. Quindi prima si scrive in chiaro ciò che già valeva, poi si toglie la
scorciatoia.

La migrazione **non concede nulla di nuovo**, e passa una volta sola: chi domani
toglie `memory.*` di proposito non se lo deve ritrovare rimesso. È la differenza
fra una migrazione e una regola che sovrascrive una decisione.
"""
from __future__ import annotations

import unittest

from . import main as M
from . import whitelist as w


class NoUniversalNamespaceTests(unittest.TestCase):
    def test_nothing_is_universal_any_more(self):
        self.assertEqual(M._UNIVERSAL_NS, set())

    def test_a_declared_memory_verb_is_allowed(self):
        self.assertTrue(M._tool_allowed("memory.put_document", {"memory.*"}))

    def test_an_undeclared_memory_verb_is_not(self):
        """Il comportamento che cambia: prima passava per il namespace."""
        self.assertFalse(M._tool_allowed("memory.put_document", {"topic.*"}))

    def test_a_wildcard_still_covers_it(self):
        self.assertTrue(M._tool_allowed("memory.put_document", {"*"}))

    def test_a_single_memory_verb_can_be_granted_alone(self):
        """Ciò che il namespace universale rendeva impossibile: distinguere."""
        self.assertTrue(M._tool_allowed("memory.list", {"memory.list"}))
        self.assertFalse(M._tool_allowed("memory.put_document", {"memory.list"}))


class MigrationTests(unittest.TestCase):
    def test_an_agent_without_memory_gets_it_written_out(self):
        a = {"x": {"allowed_tools": ["topic.*"]}}
        self.assertTrue(w._declare_memory(a))
        self.assertIn("memory.*", a["x"]["allowed_tools"])

    def test_the_migration_grants_nothing_new(self):
        """Scrive ciò che quell'agente già poteva fare attraverso il namespace:
        se aggiungesse altro non sarebbe una migrazione, sarebbe un regalo."""
        a = {"x": {"allowed_tools": ["topic.*"]}}
        w._declare_memory(a)
        self.assertEqual(sorted(a["x"]["allowed_tools"]), ["memory.*", "topic.*"])

    def test_a_wildcard_agent_is_left_alone(self):
        a = {"s": {"allowed_tools": ["*"]}}
        w._declare_memory(a)
        self.assertEqual(a["s"]["allowed_tools"], ["*"])

    def test_an_agent_that_already_declares_a_memory_verb_is_left_alone(self):
        """Chi ne aveva UNO non deve ritrovarsi tutto il namespace."""
        a = {"g": {"allowed_tools": ["memory.list"]}}
        w._declare_memory(a)
        self.assertEqual(a["g"]["allowed_tools"], ["memory.list"])

    def test_it_runs_only_once(self):
        a = {"x": {"allowed_tools": ["topic.*"]}}
        self.assertTrue(w._declare_memory(a))
        self.assertFalse(w._declare_memory(a))

    def test_a_later_removal_is_not_undone(self):
        """Il caso che il marcatore esiste per proteggere: chi toglie
        `memory.*` di proposito ha preso una decisione, e una migrazione che
        gliela riscrive sopra è un bug che sembra una feature."""
        a = {"x": {"allowed_tools": ["topic.*"]}}
        w._declare_memory(a)
        a["x"]["allowed_tools"].remove("memory.*")
        w._declare_memory(a)
        self.assertNotIn("memory.*", a["x"]["allowed_tools"])

    def test_a_malformed_entry_does_not_break_the_load(self):
        """La config si carica all'avvio: un'eccezione qui è un gateway che non
        parte."""
        a = {"rotto": "non-un-dizionario", "lista": {"allowed_tools": "no"}}
        w._declare_memory(a)      # non solleva

    def test_a_non_dict_is_ignored(self):
        self.assertFalse(w._declare_memory(None))


class WiringTests(unittest.TestCase):
    def test_the_migration_runs_when_the_config_is_loaded(self):
        """Se non girasse al load, la rimozione della scorciatoia arriverebbe
        prima della dichiarazione — l'ordine sbagliato, che è tutto il rischio
        di questo cambiamento."""
        import inspect
        self.assertIn("_declare_memory", inspect.getsource(w._load_config))


if __name__ == "__main__":
    unittest.main()

"""Due namespace rimossi, e la prova che la rimozione non è a metà.

Davide, 6 ago 2026: «rimuoviamo completamente trello e workflow». Il 7 agosto
erano ancora lì, e a trovarli è stato il test di completezza sulle classi dei
gate: `workflows.start` era gated **senza una classe**. Cioè la rimozione era
stata decisa, annotata («in attesa di rimozione») e non fatta — e a segnalarlo
non è stato un test sulla rimozione, che non esisteva, ma un test su un'altra
proprietà che è inciampato nel residuo.

Questo file esiste perché la prossima volta lo dica chi di dovere. Una rimozione
lasciata a metà è peggio di una non fatta: il verbo non c'è più nella lista dei
tool, quindi nessuno lo chiama e nessuno se ne accorge, ma la voce di gate, il
grant nel vault e la riga di taint restano — e continuano a decidere.

Misurato prima di rimuovere, su venere: **nessuna credenziale Trello nel vault**
e **zero run di workflow** nello store. Non è un dettaglio di cronaca: senza
quella misura, «non lo usa nessuno» sarebbe stata un'opinione.
"""
from __future__ import annotations

import pathlib
import unittest

RADICE = pathlib.Path(__file__).parent
RIMOSSI = ("trello", "workflows")

#: File che parlano della rimozione invece di implementarla: la memoria di
#: perché una cosa non c'è più è utile e non è un residuo.
ESENTI = {"test_removed_namespaces.py"}


def _sorgenti():
    for f in RADICE.rglob("*.py"):
        if f.name in ESENTI or "__pycache__" in f.parts:
            continue
        yield f


class NoVerbsTests(unittest.TestCase):
    def test_no_tool_is_declared(self):
        from . import main
        nomi = [t.name for t in main._all_tools()] if hasattr(main, "_all_tools") else []
        if not nomi:  # la lista si costruisce dentro list_tools: si compone a mano
            nomi = [t.name for lst in
                    (getattr(main, n) for n in dir(main) if n.endswith("_TOOLS"))
                    for t in lst]
        for ns in RIMOSSI:
            with self.subTest(ns):
                self.assertEqual([n for n in nomi if n.startswith(f"{ns}.")], [])

    def test_nothing_is_gated(self):
        """Il residuo più insidioso: un gate su un verbo che non esiste più non
        dà mai errore — semplicemente non scatta mai, e resta a dire il falso
        sulla superficie di controllo."""
        from . import gate
        for ns in RIMOSSI:
            with self.subTest(ns):
                pref, exact = gate._configured()
                self.assertEqual([v for v in exact if v.startswith(f"{ns}.")], [])
                self.assertEqual([v for v in pref if v.startswith(ns)], [])
                self.assertIsNone(gate.gate_class(f"{ns}.qualunque"))

    def test_nothing_taints(self):
        from . import taint
        for ns in RIMOSSI:
            with self.subTest(ns):
                self.assertEqual(
                    [v for v in taint._TAINTING_EXACT if v.startswith(f"{ns}.")], [])


class NoPlumbingTests(unittest.TestCase):
    def test_no_dispatcher_survives(self):
        from . import main
        for ns in RIMOSSI:
            with self.subTest(ns):
                self.assertFalse(hasattr(main, f"_dispatch_{ns}"))

    def test_no_source_file_mentions_them_outside_this_test(self):
        """Il conto, non l'ispezione di un punto. È l'aritmetica ad aver fatto
        danno finora: si convertono undici occorrenze su dodici e la dodicesima
        continua a lavorare."""
        colpevoli = []
        for f in _sorgenti():
            testo = f.read_text(errors="ignore").lower()
            for ns in RIMOSSI:
                if f"{ns}." in testo or f'"{ns}"' in testo:
                    colpevoli.append(f"{f.relative_to(RADICE)}:{ns}")
        self.assertEqual(colpevoli, [], f"residui: {colpevoli}")

    def test_the_connector_is_gone(self):
        """Un connettore che resta nella lista offre di collegare un servizio i
        cui verbi non esistono più: si connette, e poi non succede niente."""
        import inspect

        from . import connectors_api, tools_api
        for mod in (tools_api, connectors_api):
            with self.subTest(mod.__name__):
                self.assertNotIn("trello", inspect.getsource(mod).lower())


if __name__ == "__main__":
    unittest.main()

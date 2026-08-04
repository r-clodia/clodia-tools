"""Dichiarazioni di flusso nel manifest di un pack (clodia-platform#104).

Un pack può dichiarare `egress:` e `ingress:`. È una dichiarazione di **flusso**,
non di permessi — «il contenuto che arriva da qui non contamina ciò che potrai
fare dopo» — e per questo non è una concessione: i pack arrivano da repo di terzi,
e se `ingress:` fosse fiducia automatica sarebbe l'autore del pack a decidere cosa
non contamina il canale di chi lo installa, nella direzione d'errore silenziosa.

Il criterio NON è l'appartenenza a un pack: un pack vaglia il SERVER, non i byte
che il server ripete. `web.fetch` sta in un pack e ripete il web aperto.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import egress


class McpSourceSchemeTests(unittest.TestCase):
    """`mcp:<namespace>.` — la fonte è il server, uno per namespace."""

    def _with(self, sources):
        from . import whitelist as wl
        return patch.object(wl, "CONFIG", {"source_allow": sources, "agents": {}})

    def test_a_namespace_covers_its_verbs(self):
        with self._with(["mcp:normattiva."]):
            self.assertTrue(egress.is_vetted_source("mcp:normattiva.search"))
            self.assertTrue(egress.is_vetted_source("mcp:normattiva.get_article"))

    def test_it_does_not_cover_a_similarly_named_server(self):
        """Il prefisso è sul namespace, non sulla stringa: `normattiva-mirror`
        è un altro server, e potrebbe essere di chiunque."""
        with self._with(["mcp:normattiva."]):
            self.assertFalse(egress.is_vetted_source("mcp:normattiva-mirror.search"))

    def test_a_bare_scheme_is_degenerate(self):
        """`mcp:` dichiarerebbe fidato ogni server montato, presente e FUTURO —
        cioè spegnerebbe il taint su cose non ancora installate."""
        for bad in ("mcp:", "mcp:."):
            with self.subTest(uri=bad):
                self.assertTrue(egress._is_degenerate(bad))
                with self.assertRaises(ValueError):
                    egress.check_grantable("ingress", bad)

    def test_mcp_is_not_an_egress_scheme(self):
        """Un server MCP è una fonte, non una destinazione: metterlo nella lista
        d'uscita è un errore di configurazione e va rifiutato, non ignorato."""
        with self.assertRaises(ValueError) as cm:
            egress.check_grantable("egress", "mcp:normattiva.")
        self.assertIn("non ammesso", str(cm.exception))


class CheckGrantableTests(unittest.TestCase):
    """Convalidare senza concedere: l'installazione mostra, non scrive."""

    def test_it_does_not_touch_the_lists(self):
        from . import whitelist as wl
        cfg = {"source_allow": [], "egress_allow": [], "agents": {}}
        saved = []
        with patch.object(wl, "CONFIG", cfg), \
                patch.object(wl, "save_config", lambda *a, **k: saved.append(1)):
            egress.check_grantable("ingress", "mcp:normattiva.")
            egress.check_grantable("egress", "mailto:studio@davidecarboni.it")
        self.assertEqual(cfg["source_allow"], [])
        self.assertEqual(cfg["egress_allow"], [])
        self.assertEqual(saved, [], "una convalida non deve scrivere la config")

    def test_a_star_is_not_grantable_from_a_manifest_either(self):
        """Se `*` non si concede con un verbo approvato da un umano, tanto meno
        dal manifest di un pack scaricato da un repo."""
        with self.assertRaises(ValueError) as cm:
            egress.check_grantable("egress", "*")
        self.assertIn("config del gateway", str(cm.exception))

    def test_the_returned_uri_is_canonical(self):
        self.assertEqual(egress.check_grantable("egress", "MAILTO:A@B.it"),
                         egress.canonical("MAILTO:A@B.it"))


class VettedProxiedSourceTests(unittest.TestCase):
    """Il discriminante è `is_proxied`, non il nome del verbo.

    Senza, un `mcp:email.` in lista spegnerebbe il taint sulla posta in arrivo —
    che ha una fonte diversa a ogni messaggio e si valuta sul risultato.
    """

    def _vetted(self, verb, sources, proxied):
        from . import main, whitelist as wl
        with patch.object(wl, "CONFIG", {"source_allow": sources, "agents": {}}), \
                patch.object(main.proxy, "is_proxied", lambda n: n in proxied):
            return main._source_vetted(verb, {})

    def test_a_proxied_verb_of_a_vetted_server_does_not_taint(self):
        self.assertIs(self._vetted("normattiva.search", ["mcp:normattiva."],
                                   {"normattiva.search"}), True)

    def test_a_proxied_verb_of_an_undeclared_server_taints(self):
        self.assertIs(self._vetted("web.fetch", ["mcp:normattiva."],
                                   {"web.fetch"}), False)

    def test_a_native_verb_is_not_vetted_by_an_mcp_entry(self):
        """`email.list` mescola più mittenti in una risposta: non c'è una fonte da
        vagliare, e nessuna voce `mcp:` deve poter dire il contrario."""
        self.assertIsNot(self._vetted("email.list", ["mcp:email."], set()), True)


if __name__ == "__main__":
    unittest.main()

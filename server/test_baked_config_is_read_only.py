"""Il `config.yaml` baked non si riscrive mai.

**È già successo, il 7 ago 2026, e questo file esiste perché non succeda di
nuovo.**

Cosa è andato storto, nell'ordine. Stavo provando in locale una migrazione poi
abbandonata; eseguirla ha chiamato il caricamento della config, che ha riscritto
`config.yaml` con `yaml.safe_dump`. Quel dump **perde i commenti**: 109 righe che
documentavano `gdrive_roots`, il senso del wildcard dei super, il costo
consapevole su `gcalendar`. Poi `git add -A` ha portato il file spogliato dentro
una PR che parlava di tutt'altro (la portabilità, 1.56.0), insieme alla
migrazione che avevo deciso di non spedire. Ed è finita in esercizio.

Due lezioni, e la seconda vale più della prima:

1. **Il default baked è di sola lettura.** Lo stato che cambia vive sul volume
   del gateway, che è generato e non ha commenti da perdere. In locale i due path
   coincidono — ed è esattamente lì che il danno è avvenuto.
2. **`git add -A` con un working tree sporco di un disegno abbandonato spedisce
   il disegno abbandonato.** Il codice rimosso lo si recupera; i dati che ha
   scritto in produzione restano — su venere sei agenti si sono ritrovati
   `memory.*` in whitelist, scritto da un meccanismo che nel frattempo non
   esisteva più.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import whitelist as w


class ReadOnlyTests(unittest.TestCase):
    def test_saving_does_not_touch_the_baked_default(self):
        """Il caso reale: nessun volume di stato, quindi i due path coincidono."""
        prima = w._DEFAULT_CONFIG_PATH.read_bytes()
        with patch.object(w, "CONFIG_PATH", w._DEFAULT_CONFIG_PATH):
            w.save_config()
        self.assertEqual(w._DEFAULT_CONFIG_PATH.read_bytes(), prima)

    def test_the_comments_are_still_there(self):
        """Non è decorazione: sono la documentazione operativa del gateway, e
        senza di esse chi legge la config non sa perché una chiave esista."""
        testo = w._DEFAULT_CONFIG_PATH.read_text()
        for atteso in ("gdrive_roots", "gcalendar", "profile_tools"):
            with self.subTest(voce=atteso):
                self.assertIn(atteso, testo)
        self.assertGreater(testo.count("#"), 40,
                           "i commenti del default sono spariti: probabilmente "
                           "qualcuno ha riscritto il file con yaml.safe_dump")

    def test_saving_to_a_state_volume_still_works(self):
        """La sola lettura vale per il default, non per lo stato: se bloccasse
        anche quello, nessuna modifica a runtime verrebbe più persistita."""
        d = Path(tempfile.mkdtemp(prefix="stato-"))
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        p = d / "clodia-tools-config.yaml"
        with patch.object(w, "CONFIG_PATH", p), \
             patch.object(w, "_LOADED", {}), \
             patch.object(w, "CONFIG", {"agents": {"x": {"allowed_tools": []}}}):
            w.save_config()
        self.assertTrue(p.is_file())

    def test_seeding_does_not_write_over_the_default_either(self):
        import inspect
        src = inspect.getsource(w._load_config)
        self.assertIn("_DEFAULT_CONFIG_PATH.resolve()", src)


if __name__ == "__main__":
    unittest.main()

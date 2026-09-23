"""`save_summary` ripara un testo che è finito su disco ANCORA JSON-escaped.

Trovato da Davide il 23 set 2026 sul topic `impianto-dentale-studio-serri`:
il segretario, su un turno OpenCode/gemma-4-26b-a4b-it interrotto per
timeout, ha scritto un summary di 19KB con `\n`/`\"` letterali al posto di
newline e virgolette reali — zero newline VERI in tutto il file, la firma
inequivocabile di un `json.dumps()` mai ridecodificato con `json.loads()`
prima della scrittura (bug nel client OpenCode/modello, non nel gateway).

Il TLDR (e ogni altra estrazione strutturata: action point, heading) legge
`summary.splitlines()` — con zero newline reali l'intero summary diventa UNA
riga sola, e il TLDR mostrato è quella riga tagliata a caso.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from .local_fs import LocalFsStorage
from .service import TopicService, _unescape_leaked_json_string


class Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="summary-json-leak-"))
        self.svc = TopicService(LocalFsStorage(str(self.root)))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)


class UnescapeHelperTests(unittest.TestCase):
    def test_a_json_escaped_text_is_decoded(self):
        leaked = 'Titolo\\n\\n## Sezione\\nUn \\"termine\\" fra virgolette.'
        fixed = _unescape_leaked_json_string(leaked)
        self.assertEqual(fixed, 'Titolo\n\n## Sezione\nUn "termine" fra virgolette.')

    def test_a_normal_multiparagraph_text_is_untouched(self):
        """Il falso positivo è impossibile per costruzione: un testo
        autentico ha sempre almeno un newline vero."""
        normale = "Titolo\n\n## Sezione\nTesto normale, anche con \\n scritto apposta come esempio."
        self.assertEqual(_unescape_leaked_json_string(normale), normale)

    def test_a_plain_single_line_text_is_untouched(self):
        """Nessun \\n letterale → niente da riparare, anche se a riga
        singola: il criterio non scatta su «corto», scatta su «impossibile
        da produrre onestamente»."""
        testo = "Una riga sola, senza newline di alcun tipo."
        self.assertEqual(_unescape_leaked_json_string(testo), testo)

    def test_malformed_escaping_is_left_alone_not_crashed(self):
        """Un \\n letterale che non decodifica in JSON valido (es. una
        backslash isolata) non deve sollevare: si lascia il testo com'è,
        meglio un summary sporco che un save fallito."""
        rotto = 'testo con backslash isolata \\ e poi \\n'
        self.assertEqual(_unescape_leaked_json_string(rotto), rotto)

    def test_empty_text_is_untouched(self):
        self.assertEqual(_unescape_leaked_json_string(""), "")


class SaveSummaryIntegrationTests(Base):
    def test_a_leaked_summary_is_repaired_on_save(self):
        self.svc.new("SEAL-1", "acme", {"title": "Acme"})
        leaked = 'Diario visite.\\n\\n## Stato attuale\\nPrimo fatto. Un \\"dettaglio\\" citato.'
        self.svc.save_summary("SEAL-1", "acme", leaked, base_version=None)
        info = self.svc.open("SEAL-1", "acme")
        self.assertIn("\n", info["summary"])
        self.assertNotIn("\\n", info["summary"])
        self.assertEqual(info["tldr"], "Diario visite.")

    def test_a_normal_summary_round_trips_unchanged(self):
        self.svc.new("SEAL-1", "beta", {"title": "Beta"})
        testo = "Titolo del topic.\n\n## Sezione\nUn paragrafo normale."
        self.svc.save_summary("SEAL-1", "beta", testo, base_version=None)
        info = self.svc.open("SEAL-1", "beta")
        self.assertEqual(info["summary"], testo)


if __name__ == "__main__":
    unittest.main()

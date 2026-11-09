"""#664 — the TLDR is one telegraphic line; a longer one is saved and reported.

Owner, 9 Nov 2026: «la TLDR deve essere veramente di 1 riga e in formato
telegrafico. Esempio: discovery chiusa. Stima 3 mesi 300k euro. Next action
decidere escrow.»
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from .local_fs import LocalFsStorage
from .service import TLDR_MAX, TopicService


class TldrOneLineTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="tldr-664-"))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.svc = TopicService(LocalFsStorage(str(self.root)))
        self.svc.new("SEAL-1", "acme", {"title": "Acme"})

    def test_a_telegraphic_line_has_no_warning(self):
        r = self.svc.save_summary(
            "SEAL-1", "acme",
            "Discovery chiusa. Stima 3 mesi 300k euro. Next action decidere escrow.\n\n"
            "## Prossimi passi\n- decidere escrow\n", base_version=None)
        self.assertEqual(r["tldr"], "Discovery chiusa. Stima 3 mesi 300k euro. Next action decidere escrow.")
        self.assertNotIn("tldr_warning", r)

    def test_a_long_first_line_is_saved_and_reported(self):
        long = "Progetto Acme: " + "la discovery è stata chiusa dopo molte riunioni " * 4
        r = self.svc.save_summary("SEAL-1", "acme", long + "\n\nAltro.\n", base_version=None)
        self.assertGreater(len(r["tldr"]), TLDR_MAX)
        self.assertIn("UNA riga telegrafica", r["tldr_warning"])
        self.assertEqual(self.svc.open("SEAL-1", "acme")["summary"].splitlines()[0], long)


if __name__ == "__main__":
    unittest.main()

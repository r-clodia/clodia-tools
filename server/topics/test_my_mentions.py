"""«Mi ha chiamato qualcuno?» — la domanda che un client MCP può fare.

MCP è domanda-risposta: verso il Claude Code di Giovanni non esiste un push. Chi
vuole essere svegliato ha Telegram; chi lavora da un client CHIEDE. I due canali
non competono — uno spinge, l'altro si consulta.

Il segnaposto è un ISTANTE, non un elenco di id già visti: un elenco cresce senza
fine e trasforma «già letto» in una cosa da mantenere. Funziona perché i messaggi
sono append-only e ordinati per timestamp.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from .service import TopicService
from .local_fs import LocalFsStorage


class Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="mentions-"))
        self.svc = TopicService(LocalFsStorage(str(self.root)))
        self.svc.new("SEAL-1", "acme", {"title": "Acme", "owner": "davide"})

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _post(self, autore, testo, kind="human"):
        return self.svc.post_message("SEAL-1", "acme", autore, testo, kind=kind)


class WhatComesBackTests(Base):
    def test_only_my_mentions_come_back(self):
        self._post("davide", "@giovanni puoi guardare il preventivo?")
        self._post("davide", "@matteo e tu il contratto")
        r = self.svc.my_mentions("SEAL-1", "acme", "giovanni")
        self.assertEqual(r["count"], 1)
        self.assertIn("preventivo", r["mentions"][0]["text"])

    def test_the_case_of_the_name_does_not_matter(self):
        self._post("davide", "@Giovanni ci sei?")
        self.assertEqual(self.svc.my_mentions("SEAL-1", "acme", "GIOVANNI")["count"], 1)

    def test_a_quoted_mention_is_not_a_call(self):
        """La regola sta nel parser delle menzioni e vale anche qui: citare una
        riga che nomina Giovanni non è chiamarlo."""
        self._post("davide", "> @giovanni aveva detto di sì\nio direi ok")
        self.assertEqual(self.svc.my_mentions("SEAL-1", "acme", "giovanni")["count"], 0)


class TheBookmarkTests(Base):
    def test_marking_seen_empties_the_list(self):
        self._post("davide", "@giovanni uno")
        r = self.svc.my_mentions("SEAL-1", "acme", "giovanni")
        self.svc.mark_seen("SEAL-1", "acme", "giovanni", r["seen_through"])
        self.assertEqual(self.svc.my_mentions("SEAL-1", "acme", "giovanni")["count"], 0)

    def test_what_arrived_after_the_read_is_not_lost(self):
        """Il motivo per cui `my_mentions` ritorna `seen_through` invece di
        lasciar marcare «adesso»: fra la lettura e la marcatura può arrivare una
        menzione, e marcare l'istante la farebbe sparire senza che nessuno
        l'abbia vista. È il difetto che non lascia traccia — nessuno può
        accorgersi di una chiamata che non ha mai visto."""
        self._post("davide", "@giovanni uno")
        r = self.svc.my_mentions("SEAL-1", "acme", "giovanni")
        import time
        time.sleep(1.05)                      # ts al secondo: serve un istante nuovo
        self._post("davide", "@giovanni due")
        self.svc.mark_seen("SEAL-1", "acme", "giovanni", r["seen_through"])
        dopo = self.svc.my_mentions("SEAL-1", "acme", "giovanni")
        self.assertEqual(dopo["count"], 1)
        self.assertIn("due", dopo["mentions"][0]["text"])

    def test_the_bookmark_never_goes_backwards(self):
        """Due client della stessa persona, o una rilettura: nessuno dei due deve
        poter far riapparire una menzione archiviata."""
        self._post("davide", "@giovanni uno")
        r = self.svc.my_mentions("SEAL-1", "acme", "giovanni")
        self.svc.mark_seen("SEAL-1", "acme", "giovanni", r["seen_through"])
        self.svc.mark_seen("SEAL-1", "acme", "giovanni", "2000-01-01T00:00:00")
        self.assertEqual(self.svc.my_mentions("SEAL-1", "acme", "giovanni")["count"], 0)

    def test_only_unseen_false_shows_the_history(self):
        self._post("davide", "@giovanni uno")
        r = self.svc.my_mentions("SEAL-1", "acme", "giovanni")
        self.svc.mark_seen("SEAL-1", "acme", "giovanni", r["seen_through"])
        self.assertEqual(self.svc.my_mentions("SEAL-1", "acme", "giovanni",
                                              only_unseen=False)["count"], 1)

    def test_two_people_have_two_bookmarks(self):
        self._post("davide", "@giovanni e @matteo, guardate")
        r = self.svc.my_mentions("SEAL-1", "acme", "giovanni")
        self.svc.mark_seen("SEAL-1", "acme", "giovanni", r["seen_through"])
        self.assertEqual(self.svc.my_mentions("SEAL-1", "acme", "matteo")["count"], 1)


class TheBookmarkIsNotAMessageTests(Base):
    """Il segnaposto sta FUORI da `.messages/`.

    `list_messages` prende ogni `.json` di quella cartella: un segnaposto messo
    lì comparirebbe in chat come un messaggio senza autore né testo, e sarebbe
    passato per un difetto di rendering invece che per quello che è.
    """

    def test_the_conversation_stays_clean(self):
        self._post("davide", "@giovanni ciao")
        self.svc.mark_seen("SEAL-1", "acme", "giovanni")
        msgs = self.svc.list_messages("SEAL-1", "acme")
        self.assertEqual(len(msgs), 1)
        self.assertTrue(all(m.get("author") for m in msgs))

    def test_a_weird_name_cannot_escape_the_folder(self):
        """Il nome arriva da un claim firmato, quindi non è arbitrario — ma un
        path costruito da un'identità è comunque un path costruito."""
        p = self.svc._seen_path("SEAL-1", "acme", "../../etc/passwd")
        self.assertNotIn("..", p)


if __name__ == "__main__":
    unittest.main()

"""Un rifiuto deve dire cosa usare al posto del verbo tolto.

Sintomo reale: a `messaggero` è negato `topic.put`, e il messaggio diceva «non è
un'operazione da turno di chat, va eseguita da un job o da un amministratore» —
la ragione scritta per `mcp.add` di clodia, non per i verbi sui file di un
postino. Con la ragione sbagliata l'agente ha provato tre strade (base64 in /tmp,
topic.put, topic.write_file), ha concluso che mancava un grant o che il server era
rotto, e ha chiesto aiuto in chat.

Un rifiuto senza alternativa è un vicolo cieco, e il modello ci sbatte dentro con
l'insistenza di chi non ha altre mosse.
"""
from __future__ import annotations

import unittest

from . import main


class DenyHintTests(unittest.TestCase):
    def test_the_file_verbs_point_at_the_by_reference_path(self):
        """I verbi tolti al postino hanno tutti un sostituto che non richiede di
        vedere i byte: è il motivo per cui toglierli non gli toglie il mestiere."""
        for verb, needle in (("topic.put", "email.save_attachment"),
                             ("topic.write_file", "email.save_attachment"),
                             ("topic.read_file", "topic_files"),
                             ("topic.read_document", "topic_files"),
                             ("topic.fetch", "topic_files")):
            with self.subTest(verb=verb):
                self.assertIn(needle, main._DENY_HINT[verb])

    def test_the_listing_hint_explains_why_it_is_absent(self):
        """`topic.files` non ha un sostituto, e dirlo è meglio che tacere: il path
        arriva nella conversazione, non da un elenco."""
        self.assertIn("di proposito", main._DENY_HINT["topic.files"])

    def test_the_chat_turn_reason_stays_only_where_it_is_true(self):
        """Quella ragione vale per l'installazione dei pack e il backup, non per i
        file di un topic — usarla per tutto era il difetto."""
        for verb in ("mcp.add", "packs.install_pip", "settings.backup_run"):
            with self.subTest(verb=verb):
                h = main._DENY_HINT[verb]
                self.assertTrue("Packs" in h or "job" in h)
        for verb in ("topic.put", "topic.read_file"):
            with self.subTest(verb=verb):
                self.assertNotIn("turno di chat", main._DENY_HINT[verb])

    def test_a_verb_without_a_hint_still_gets_an_honest_message(self):
        """Non si inventa un'alternativa che non esiste: si dice che è
        deliberato e a chi rivolgersi."""
        self.assertNotIn("topic.suggest_team", main._DENY_HINT)


if __name__ == "__main__":
    unittest.main()


class ScratchPathErrorTests(unittest.TestCase):
    """Il ramo d'errore va percorso da un test, o non è codice eseguito.

    Riscrivendo questo messaggio ho sbagliato il nome della variabile e il ramo
    sollevava `NameError` invece del testo: il rifiuto diventava un errore
    interno, cioè esattamente il segnale che aveva mandato messaggero a cercare
    un guasto del server. Nessun test attraversava il percorso di fallimento.
    """

    def test_a_path_outside_the_scratch_is_refused_with_the_alternative(self):
        with self.assertRaises(ValueError) as cm:
            main._safe_scratch_path("/tmp/f24.pdf")
        msg = str(cm.exception)
        self.assertIn("/tmp/f24.pdf", msg)
        self.assertIn(main._SPAWNS_ROOT, msg)
        self.assertIn("email.save_attachment", msg)

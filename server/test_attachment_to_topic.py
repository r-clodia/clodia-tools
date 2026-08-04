"""Ricezione per riferimento di un allegato (§8 di clodia-platform#104).

Il §8 ha tolto `topic.put` al postino, e il flusso documentato per archiviare un
allegato era `email.save_attachment` → `topic.put`. Risultato: chi RICEVE la posta
non poteva archiviare ciò che riceve. Avevamo costruito l'invio per riferimento e
non la ricezione.

Questi test provano le tre proprietà che rendono la ricezione accettabile: i byte
non passano dallo scratch, il file nasce `untrusted`, e il canale risulta
contaminato.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import taint
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicService


class SaveAttachmentToTopicTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.svc = TopicService(LocalFsStorage(self.tmp.name))
        self.svc.new("SEAL-1", "ch", {"title": "ch", "owner": "davide",
                                      "participants": ["davide", "messaggero"]})
        p = patch.object(taint, "_path",
                         side_effect=lambda: Path(self.tmp.name) / "taint.json")
        p.start()
        self.addCleanup(p.stop)

    def _store(self, data=b"%PDF ostile", fn="contratto.pdf"):
        """Replica ciò che fa il dispatch per il ramo tier+name."""
        r = self.svc.put_file("SEAL-1", "ch", fn, data, "untrusted", by="messaggero")
        taint.mark("SEAL-1/ch", "file", fn, "messaggero")
        return r

    def test_the_attachment_lands_in_the_topic_as_untrusted(self):
        """Provenienza `untrusted` d'ufficio: un file introdotto da un verbo non ha
        nessuno da interrogare (#104 §3), e la posta in arrivo è la definizione di
        sorgente non controllata."""
        r = self._store()
        self.assertEqual(r["provenance"], "untrusted")
        entry = [f for f in self.svc.list_files("SEAL-1", "ch", "files")
                 if f["name"] == "contratto.pdf"][0]
        self.assertEqual(entry["provenance"], "untrusted")

    def test_archiving_taints_the_channel(self):
        """Senza questo, archiviare sarebbe un modo di far entrare un PDF ostile
        senza lasciare traccia nel flag — e la prima uscita successiva non
        chiederebbe niente."""
        self.assertFalse(taint.status("chan:SEAL-1:ch:messaggero")["tainted"])
        self._store()
        st = taint.status("chan:SEAL-1:ch:messaggero")
        self.assertTrue(st["tainted"])
        self.assertEqual(st["sources"][-1]["detail"], "contratto.pdf")

    def test_the_bytes_never_touch_the_agent_scratch(self):
        """È il punto dell'intera operazione: il postino archivia senza vedere.
        Il file esiste solo nel topic."""
        self._store()
        names = [f["name"] for f in self.svc.list_files("SEAL-1", "ch", "files")]
        self.assertIn("contratto.pdf", names)
        # nessun file scritto fuori dal topic store
        stray = [p for p in Path(self.tmp.name).rglob("contratto.pdf")
                 if "SEAL-1" not in str(p)]
        self.assertEqual(stray, [])

    def test_a_second_attachment_with_the_same_name_overwrites_but_stays_labelled(self):
        self._store(b"v1")
        r = self._store(b"v2")
        self.assertEqual(r["provenance"], "untrusted")
        self.assertEqual(self.svc.read_file("SEAL-1", "ch", "files/contratto.pdf"), b"v2")


if __name__ == "__main__":
    unittest.main()


class CurrentTopicDefaultTests(unittest.TestCase):
    """Il topic si ricava dal CANALE, non si chiede all'agente.

    Sintomo reale: messaggero ha chiesto in chat «quale topic devo usare? (tier +
    nome)» tre volte nello stesso messaggio. Non era confusione del modello — era
    l'unica mossa che gli restava: `topic.open` richiede a sua volta tier+name, e i
    verbi di elenco a un postino sono negati dal §8, quindi non aveva modo di
    scoprire dove si trovava. Il gateway invece lo sa, dal claim firmato nel token.
    """

    def test_the_channel_key_yields_tier_and_name(self):
        from . import main
        # `main` importa `current_chat` a livello di modulo, quindi il patch va sul
        # SUO namespace: patchare `server.whitelist.current_chat` non lo
        # raggiungerebbe. (In `taint` funziona perché l'import è dentro la funzione.)
        with patch("server.main.current_chat",
                   return_value="chan:SEAL-1:bilancio-tomato-2026:messaggero#2"):
            self.assertEqual(main._current_topic(),
                             ("SEAL-1", "bilancio-tomato-2026"))

    def test_an_explicit_topic_still_wins(self):
        """L'argomento esplicito serve per operare su un ALTRO topic — e in quel
        caso scatta il gate cross-topic, che è la differenza fra «archivia qui» e
        «archivia là»."""
        from . import main
        with patch("server.main.current_chat",
                   return_value="chan:SEAL-1:qui:messaggero"):
            self.assertEqual(main._topic_of({"tier": "SEAL-2", "name": "la"}),
                             ("SEAL-2", "la"))

    def test_a_partial_argument_falls_back_to_the_channel(self):
        """`tier` senza `name` non identifica niente: meglio il canale corrente
        che un errore su un argomento incompleto."""
        from . import main
        with patch("server.main.current_chat",
                   return_value="chan:SEAL-1:qui:messaggero"):
            self.assertEqual(main._topic_of({"tier": "SEAL-2"}), ("SEAL-1", "qui"))

    def test_outside_a_channel_there_is_no_default(self):
        """In una sessione senza canale (job, DM non normalizzata) non si inventa
        un topic: l'errore dice cosa passare."""
        from . import main
        with patch("server.main.current_chat", return_value=None):
            self.assertEqual(main._topic_of({}), (None, None))

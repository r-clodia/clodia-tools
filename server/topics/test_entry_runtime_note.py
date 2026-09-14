"""L'annuncio d'ingresso di un bot cita provider/modello/SEAL effettivi — un
fatto scritto dalla piattaforma, non un'istruzione lasciata al modello
(Davide, 14 set 2026: «deve essere deterministico, no random»).

`clodia-tools` non ha questi dati (vivono nella risoluzione runtime di
`clodia-logic`): `_entry_runtime_note` li chiede via `tools.runtime.
runtime_facts`, best-effort — un `clodia-logic` irraggiungibile non deve
impedire l'ingresso del partecipante, solo lasciare il messaggio come oggi
(nessuna coda)."""
from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from .local_fs import LocalFsStorage
from .service import TopicService


class EntryRuntimeNoteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.svc = TopicService(LocalFsStorage(tempfile.mkdtemp()))
        with patch("server.instance_profile.topic_default_participants", return_value=[]):
            self.svc.new("P1", "ch", {"title": "Canale", "owner": "owner"})

    def _entra(self, agent: str, fatti: dict):
        with patch("server.tools.runtime.runtime_facts", return_value=fatti):
            self.svc.add_participant("P1", "ch", agent)
        return self.svc.list_messages("P1", "ch")[-1]["text"]

    def test_an_eligible_bot_gets_the_facts_appended(self) -> None:
        testo = self._entra("content-creator", {
            "is_bot": True, "eligible": True,
            "provider": "anthropic-api", "model": "claude-sonnet-4-5",
            "seal": "SEAL-2",
        })
        self.assertEqual(
            testo,
            "content-creator è entrato nel topic come contributor — "
            "provider: anthropic-api · modello: claude-sonnet-4-5 · SEAL: SEAL-2",
        )

    def test_a_bot_with_no_eligible_provider_gets_an_explicit_warning(self) -> None:
        testo = self._entra("content-creator", {"is_bot": True, "eligible": False})
        self.assertIn("nessun provider connesso regge questo tier", testo)
        self.assertNotIn("provider:", testo)

    def test_a_human_gets_the_plain_message_unchanged(self) -> None:
        testo = self._entra("davide", {"is_bot": False})
        self.assertEqual(testo, "davide è entrato nel topic come contributor")

    def test_an_unreachable_clodia_logic_degrades_to_the_plain_message(self) -> None:
        """Best-effort: l'ingresso del partecipante non deve MAI dipendere
        dalla raggiungibilità di clodia-logic."""
        with patch("server.tools.runtime.runtime_facts",
                   side_effect=RuntimeError("agent-server giù")):
            out = self.svc.add_participant("P1", "ch", "content-creator")
        self.assertTrue(out["added"])
        testo = self.svc.list_messages("P1", "ch")[-1]["text"]
        self.assertEqual(testo, "content-creator è entrato nel topic come contributor")


if __name__ == "__main__":
    unittest.main()

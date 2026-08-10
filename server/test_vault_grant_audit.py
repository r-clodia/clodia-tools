"""Chi cambia l'autorità lascia una riga.

L'11 ago 2026 un grant su `mailbox_team` è sparito fra la sera e la mattina:
concesso e verificato due volte, assente il giorno dopo. L'audit registrava
letture e rifiuti — quindi alla domanda «chi l'ha tolto?» si poteva solo
rispondere con un'ipotesi, e infatti ho perso mezz'ora a formularne.

Un permesso che scompare senza traccia è peggio di un permesso mancante: il
secondo si vede subito, il primo si scopre quando qualcosa smette di funzionare,
e manda a cercare la causa in un posto qualunque — nella visibilità
dell'account, nel restart, nel nome della casella.

Questi test non riparano quella sparizione: non è più ricostruibile. Rendono
rispondibile la prossima.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import vault


class _Vault:
    """Un vault vero su una cartella temporanea: qui interessa il FILE."""

    def __enter__(self):
        self._d = tempfile.TemporaryDirectory()
        self._p = patch.object(vault, "vault_dir", lambda: Path(self._d.name))
        self._p.start()
        return Path(self._d.name)

    def __exit__(self, *a):
        self._p.stop()
        self._d.cleanup()
        return False


def _righe(d: Path) -> list[dict]:
    f = d / "audit.log"
    if not f.is_file():
        return []
    return [json.loads(r) for r in f.read_text().splitlines() if r.strip()]


class GrantChangesAreRecordedTests(unittest.TestCase):
    def test_granting_writes_a_line(self):
        with _Vault() as d:
            vault.set_grant("mailbox_team", "messaggero", True)
            r = [x for x in _righe(d) if x["action"] == "grant"]
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]["credential"], "mailbox_team")
        self.assertEqual(r[0]["agent"], "messaggero")

    def test_revoking_writes_a_line_too(self):
        """Ed è la riga che serviva davvero: una concessione che sparisce."""
        with _Vault() as d:
            vault.set_grant("mailbox_team", "messaggero", True)
            vault.set_grant("mailbox_team", "messaggero", False)
            r = [x for x in _righe(d) if x["action"] == "revoke"]
        self.assertEqual(len(r), 1)
        self.assertTrue(r[0]["was_granted"])

    def test_the_line_says_who_did_it(self):
        """Senza il `by`, l'audit direbbe che è successo e non da dove: la UI e
        un `docker exec` a mano portano in due direzioni opposte."""
        with _Vault() as d:
            vault.set_grant("x", "y", True)
            r = _righe(d)[-1]
        self.assertIn("by", r)
        self.assertTrue(r["by"])

    def test_a_no_op_revoke_is_recorded_as_such(self):
        """«Era già così» è un'informazione: distingue «nessuno l'ha toccato» da
        «nessuno lo sa»."""
        with _Vault() as d:
            vault.set_grant("x", "mai-concesso", False)
            r = _righe(d)[-1]
        self.assertEqual(r["action"], "revoke")
        self.assertFalse(r["was_granted"])


class DepositIsAdditiveAndSaysSoTests(unittest.TestCase):
    """`deposit` promette di non togliere grant. La riga d'audit lo rende
    verificabile sui fatti invece che sulla docstring."""

    def test_depositing_again_keeps_an_existing_grant(self):
        with _Vault() as d:
            vault.deposit("mailbox_team", {"email": "t@x.it"}, cred_type="mailbox",
                          grant_agents=["clodia"])
            vault.set_grant("mailbox_team", "messaggero", True)
            vault.deposit("mailbox_team", {"email": "t@x.it", "smtp_server": "s"},
                          cred_type="mailbox", grant_agents=["clodia"])
            self.assertIn("messaggero", vault.agents_with_grant("mailbox_team"))
            dep = [x for x in _righe(d) if x["action"] == "deposit"][-1]
        self.assertIn("messaggero", dep["grants_after"])

    def test_the_audit_never_carries_the_secret(self):
        """Il bundle contiene password. L'audit è un file che si legge per
        capire, e ciò che si legge per capire finisce incollato altrove."""
        with _Vault() as d:
            vault.deposit("mailbox_team", {"email": "t@x.it", "password": "SEGRETO"},
                          cred_type="mailbox", grant_agents=["clodia"])
            testo = (d / "audit.log").read_text()
        self.assertNotIn("SEGRETO", testo)


if __name__ == "__main__":
    unittest.main()

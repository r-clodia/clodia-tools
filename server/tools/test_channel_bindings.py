"""Registro generale dei binding di canale (clodia-platform#521).

Tre cose che devono restare vere, e ognuna ha un modo di rompersi in silenzio:
la chiave è connettore + chat (non la sola chat); la migrazione dal file
Telegram è one-shot e non resuscita ciò che è stato staccato; la facciata
`telegram_bindings` — che sette chiamanti del gateway usano senza sapere del
registro — legge e scrive esattamente dove scrive il registro.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import channel_bindings as cb
from . import telegram_bindings as tb


class _Base(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="channel-bindings-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    @property
    def nuovo(self) -> Path:
        return self.dir / cb.FILENAME

    @property
    def vecchio(self) -> Path:
        return self.dir / cb.LEGACY_FILENAME

    def scrivi_vecchio(self, d: dict) -> None:
        self.vecchio.write_text(json.dumps(d), encoding="utf-8")


class ChiaveTests(_Base):
    def test_la_chiave_e_connettore_piu_chat(self):
        """Due trasporti possono usare lo stesso id di chat: se la chiave fosse
        la sola chat, il secondo binding scalzerebbe il primo e un canale
        smetterebbe di ricevere senza che nessuno abbia tolto niente."""
        cb.set_binding("telegram", "42", "messaggero-1", "SEAL-1", "acme", base=self.dir)
        cb.set_binding("signal", "42", "messaggero-2", "SEAL-2", "altro", base=self.dir)
        self.assertEqual(cb.get("telegram", "42", base=self.dir)["topic"], "acme")
        self.assertEqual(cb.get("signal", "42", base=self.dir)["topic"], "altro")
        self.assertEqual(sorted(cb.connectors(base=self.dir)), ["signal", "telegram"])

    def test_una_chat_un_solo_binding_per_connettore(self):
        cb.set_binding("telegram", "42", "messaggero-1", "SEAL-1", "acme", base=self.dir)
        cb.set_binding("telegram", "42", "messaggero-1", "SEAL-1", "altro", base=self.dir)
        self.assertEqual(list(cb.load("telegram", base=self.dir)), ["42"])
        self.assertEqual(cb.get("telegram", "42", base=self.dir)["topic"], "altro")

    def test_remove_dice_se_cera_e_non_tocca_gli_altri(self):
        cb.set_binding("telegram", "42", "m", "SEAL-1", "acme", base=self.dir)
        cb.set_binding("telegram", "43", "m", "SEAL-1", "beta", base=self.dir)
        self.assertTrue(cb.remove("telegram", "42", base=self.dir))
        self.assertFalse(cb.remove("telegram", "42", base=self.dir))
        self.assertEqual(list(cb.load("telegram", base=self.dir)), ["43"])

    def test_replace_sostituisce_un_connettore_e_lascia_gli_altri(self):
        """Il ripristino di `retier` passa di qui: scrivere il documento intero
        da una transazione che ha guardato un solo trasporto cancellerebbe gli
        altri."""
        cb.set_binding("telegram", "42", "m", "SEAL-1", "acme", base=self.dir)
        cb.set_binding("signal", "99", "m", "SEAL-1", "acme", base=self.dir)
        cb.replace("telegram", {"7": {"instance": "m", "tier": "SEAL-2", "topic": "x"}},
                   base=self.dir)
        self.assertEqual(list(cb.load("telegram", base=self.dir)), ["7"])
        self.assertEqual(list(cb.load("signal", base=self.dir)), ["99"])

    def test_un_file_illeggibile_non_fa_esplodere_il_relay(self):
        self.nuovo.write_text("{ rotto", encoding="utf-8")
        self.assertEqual(cb.load(base=self.dir), {})


class MigrazioneTests(_Base):
    LEGACY = {"-100": {"instance": "messaggero-1", "tier": "SEAL-1", "topic": "acme"},
              "-200": {"instance": "messaggero-2", "tier": "SEAL-2", "topic": "beta"}}

    def test_la_prima_lettura_migra_da_sola(self):
        self.scrivi_vecchio(self.LEGACY)
        self.assertEqual(cb.load("telegram", base=self.dir), self.LEGACY)
        self.assertTrue(self.nuovo.is_file())
        doc = json.loads(self.nuovo.read_text(encoding="utf-8"))
        self.assertEqual(doc["version"], cb.VERSION)
        self.assertEqual(doc["connectors"]["telegram"], self.LEGACY)

    def test_il_file_vecchio_resta_dovera(self):
        """È il rollback e la prova di cosa c'era: cancellarlo renderebbe la
        migrazione irreversibile al primo errore."""
        self.scrivi_vecchio(self.LEGACY)
        cb.load(base=self.dir)
        self.assertTrue(self.vecchio.is_file())

    def test_e_idempotente(self):
        self.scrivi_vecchio(self.LEGACY)
        primo = cb.migrate_legacy(base=self.dir)
        secondo = cb.migrate_legacy(base=self.dir)
        self.assertEqual(primo["migrated"], ["-100", "-200"])
        self.assertFalse(primo["already"])
        self.assertEqual(secondo["migrated"], [])
        self.assertTrue(secondo["already"])

    def test_dopo_la_migrazione_un_binding_tolto_non_resuscita(self):
        """Il caso che la rende sicura: il file vecchio non viene più letto, e
        se qualcuno lo fa divergere le sue voci NON tornano dentro — sarebbero
        chat rimesse in stanze da cui erano state staccate. Si segnalano."""
        self.scrivi_vecchio(self.LEGACY)
        cb.load(base=self.dir)
        cb.remove("telegram", "-200", base=self.dir)
        esito = cb.migrate_legacy(base=self.dir)
        self.assertEqual(esito["orphans"], ["-200"])
        self.assertEqual(list(cb.load("telegram", base=self.dir)), ["-100"])

    def test_dry_run_non_scrive(self):
        self.scrivi_vecchio(self.LEGACY)
        esito = cb.migrate_legacy(base=self.dir, dry_run=True)
        self.assertEqual(esito["migrated"], ["-100", "-200"])
        self.assertFalse(self.nuovo.exists())

    def test_senza_file_vecchio_non_succede_niente(self):
        self.assertEqual(cb.load(base=self.dir), {})
        self.assertFalse(self.nuovo.exists())


class FacciataTelegramTests(_Base):
    """I sette chiamanti del gateway continuano a parlare di Telegram: devono
    leggere e scrivere nel registro, non in un secondo file dimenticato."""

    def setUp(self):
        super().setUp()
        p = patch.object(tb, "_path", lambda: self.dir / cb.LEGACY_FILENAME)
        p.start()
        self.addCleanup(p.stop)

    def test_cio_che_la_facciata_scrive_sta_nel_registro(self):
        tb.set_binding("-100", "messaggero-1", "SEAL-1", "acme")
        self.assertTrue(self.nuovo.is_file())
        self.assertEqual(cb.get("telegram", "-100", base=self.dir),
                         {"instance": "messaggero-1", "tier": "SEAL-1", "topic": "acme"})
        self.assertEqual(tb.load(), cb.load("telegram", base=self.dir))

    def test_get_for_topic_e_remove_restano_quelli_di_prima(self):
        tb.set_binding("-100", "messaggero-1", "SEAL-1", "acme")
        self.assertEqual(tb.get_for_topic("SEAL-1", "acme"), "-100")
        self.assertIsNone(tb.get_for_topic("SEAL-1", "altro"))
        self.assertTrue(tb.remove("-100"))
        self.assertIsNone(tb.get("-100"))

    def test_save_ripristina_solo_telegram(self):
        cb.set_binding("signal", "99", "m", "SEAL-1", "acme", base=self.dir)
        prima = {"-100": {"instance": "m", "tier": "SEAL-1", "topic": "acme"}}
        tb._save(prima)
        self.assertEqual(tb.load(), prima)
        self.assertEqual(list(cb.load("signal", base=self.dir)), ["99"])

    def test_la_facciata_migra_il_file_storico(self):
        """Il caso del deploy: il gateway riparte con un datadir che ha solo il
        file vecchio, e `telegram.send` deve risolvere il topic come ieri."""
        self.scrivi_vecchio({"-100": {"instance": "messaggero-1", "tier": "SEAL-1",
                                      "topic": "acme"}})
        self.assertEqual(tb.get_for_topic("SEAL-1", "acme"), "-100")


if __name__ == "__main__":
    unittest.main()

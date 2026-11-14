"""Registro generale dei binding di canale (clodia-platform#521).

Ciò che deve restare vero, e che si romperebbe in silenzio: la chiave è
connettore + chat (non la sola chat); un registro illeggibile non viene mai
sovrascritto; le scritture concorrenti non si perdono. (La migrazione dal file
Telegram e la facciata `telegram_bindings` sono state tolte con Telegram, #683.)
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from . import channel_bindings as cb


class _Base(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="channel-bindings-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    @property
    def nuovo(self) -> Path:
        return self.dir / cb.FILENAME

class ChiaveTests(_Base):
    def test_la_chiave_e_connettore_piu_chat(self):
        """Due trasporti possono usare lo stesso id di chat: se la chiave fosse
        la sola chat, il secondo binding scalzerebbe il primo e un canale
        smetterebbe di ricevere senza che nessuno abbia tolto niente."""
        cb.set_binding("whatsapp", "42", "messaggero-1", "SEAL-1", "acme", base=self.dir)
        cb.set_binding("signal", "42", "messaggero-2", "SEAL-2", "altro", base=self.dir)
        self.assertEqual(cb.get("whatsapp", "42", base=self.dir)["topic"], "acme")
        self.assertEqual(cb.get("signal", "42", base=self.dir)["topic"], "altro")
        self.assertEqual(sorted(cb.connectors(base=self.dir)), ["signal", "whatsapp"])

    def test_una_chat_un_solo_binding_per_connettore(self):
        cb.set_binding("whatsapp", "42", "messaggero-1", "SEAL-1", "acme", base=self.dir)
        cb.set_binding("whatsapp", "42", "messaggero-1", "SEAL-1", "altro", base=self.dir)
        self.assertEqual(list(cb.load("whatsapp", base=self.dir)), ["42"])
        self.assertEqual(cb.get("whatsapp", "42", base=self.dir)["topic"], "altro")

    def test_remove_dice_se_cera_e_non_tocca_gli_altri(self):
        cb.set_binding("whatsapp", "42", "m", "SEAL-1", "acme", base=self.dir)
        cb.set_binding("whatsapp", "43", "m", "SEAL-1", "beta", base=self.dir)
        self.assertTrue(cb.remove("whatsapp", "42", base=self.dir))
        self.assertFalse(cb.remove("whatsapp", "42", base=self.dir))
        self.assertEqual(list(cb.load("whatsapp", base=self.dir)), ["43"])

    def test_replace_sostituisce_un_connettore_e_lascia_gli_altri(self):
        """Il ripristino di `retier` passa di qui: scrivere il documento intero
        da una transazione che ha guardato un solo trasporto cancellerebbe gli
        altri."""
        cb.set_binding("whatsapp", "42", "m", "SEAL-1", "acme", base=self.dir)
        cb.set_binding("signal", "99", "m", "SEAL-1", "acme", base=self.dir)
        cb.replace("whatsapp", {"7": {"instance": "m", "tier": "SEAL-2", "topic": "x"}},
                   base=self.dir)
        self.assertEqual(list(cb.load("whatsapp", base=self.dir)), ["7"])
        self.assertEqual(list(cb.load("signal", base=self.dir)), ["99"])

    def test_un_file_illeggibile_non_fa_esplodere_il_relay(self):
        self.nuovo.write_text("{ rotto", encoding="utf-8")
        self.assertEqual(cb.load(base=self.dir), {})


class ConcorrenzaTests(_Base):
    """Review of tools#356: read-modify-write must be serialised and writes
    atomic, or concurrent listens lose each other's bindings."""

    N = 12

    def _lento(self):
        vero = cb._read_json

        def lento(p):
            d = vero(p)
            time.sleep(0.01)  # widen the read→write window
            return d
        return patch.object(cb, "_read_json", lento)

    def test_scritture_concorrenti_nei_thread_non_si_perdono(self):
        errori = []

        def scrivi(i):
            try:
                cb.set_binding("whatsapp", str(i), "m", "SEAL-1", f"t{i}", base=self.dir)
            except Exception as e:  # noqa: BLE001
                errori.append(e)

        with self._lento():
            th = [threading.Thread(target=scrivi, args=(i,)) for i in range(self.N)]
            for t in th:
                t.start()
            for t in th:
                t.join()
        self.assertEqual(errori, [])
        self.assertEqual(sorted(cb.load("whatsapp", base=self.dir), key=int),
                         [str(i) for i in range(self.N)])
        self.assertEqual([x.name for x in self.dir.iterdir() if x.suffix == ".tmp"], [])

    def test_scritture_concorrenti_fra_processi_non_si_perdono(self):
        """Two gateway processes on the same datadir: the flock serialises them."""
        codice = (
            "import sys, time\n"
            "from server.tools import channel_bindings as cb\n"
            "vero = cb._read_json\n"
            "def lento(p):\n"
            "    d = vero(p); time.sleep(0.01); return d\n"
            "cb._read_json = lento\n"
            "base, k = sys.argv[1], sys.argv[2]\n"
            "for i in range(6):\n"
            "    cb.set_binding('whatsapp', f'{k}{i}', 'm', 'SEAL-1', 't', base=base)\n"
        )
        root = Path(__file__).resolve().parents[2]
        procs = [subprocess.Popen([sys.executable, "-c", codice, str(self.dir), k], cwd=root)
                 for k in ("a", "b", "c")]
        for pr in procs:
            self.assertEqual(pr.wait(timeout=60), 0)
        self.assertEqual(len(cb.load("whatsapp", base=self.dir)), 18)


class RegistroIllegibileTests(_Base):
    """Coordinator follow-up on tools#356: a malformed `channel-bindings.json`
    reads as empty (ERROR log) but is never overwritten — every write refuses,
    so repairing the file restores the bindings."""

    BUONO = {"version": 1, "connectors": {"whatsapp": {
        "-100": {"instance": "m", "tier": "SEAL-1", "topic": "acme"}}}}

    def _assert_scritture_rifiutate(self, contenuto: str):
        self.nuovo.write_text(contenuto, encoding="utf-8")
        with self.assertLogs(cb.LOG, level="ERROR"):
            self.assertEqual(cb.load(base=self.dir), {})
        for scrivi in (
                lambda: cb.set_binding("whatsapp", "-9", "m", "SEAL-1", "x", base=self.dir),
                lambda: cb.remove("whatsapp", "-100", base=self.dir),
                lambda: cb.replace("whatsapp", {}, base=self.dir)):
            with self.assertRaises(cb.BindingsUnreadable):
                scrivi()
        self.assertEqual(self.nuovo.read_text(encoding="utf-8"), contenuto,
                         "a malformed registry must never be replaced")
        # Repair: the bindings are back, and writes work again.
        self.nuovo.write_text(json.dumps(self.BUONO), encoding="utf-8")
        self.assertEqual(list(cb.load("whatsapp", base=self.dir)), ["-100"])
        cb.set_binding("whatsapp", "-9", "m", "SEAL-1", "x", base=self.dir)
        self.assertEqual(sorted(cb.load("whatsapp", base=self.dir)), ["-100", "-9"])

    def test_json_rotto_scrittura_rifiutata(self):
        self._assert_scritture_rifiutate('{"version": 1, "connectors": {"whatsapp": {"-100": ')

    def test_json_lista_scrittura_rifiutata(self):
        self._assert_scritture_rifiutate("[1, 2]")

    def test_connectors_non_oggetto_scrittura_rifiutata(self):
        self._assert_scritture_rifiutate('{"version": 1, "connectors": ["whatsapp"]}')

    def test_connettore_non_oggetto_scrittura_rifiutata(self):
        self._assert_scritture_rifiutate('{"version": 1, "connectors": {"whatsapp": 7}}')

if __name__ == "__main__":
    unittest.main()

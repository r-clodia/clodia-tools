"""Uno scope può avere più mount.

Voce 33 (8 ago 2026): «non è corretto che esista un solo local ed un solo
remote mount, posso avere due o più remote mount … ognuno con le sue
credenziali». Fino a ieri `meta["remote"]` era un oggetto singolo, e collegare
una seconda cartella significava scollegare la prima — silenziosamente, perché
una scrittura che sostituisce non ha modo di segnalare cosa ha tolto.

Il rischio di questa conversione non è il modello, è l'aritmetica: `meta["remote"]`
era letto in **dodici** punti. Convertirne undici avrebbe lasciato il dodicesimo
a vedere una forma che non esiste più — e un lettore che non trova il remote non
dà errore, conclude che non ci sia. Da qui l'accessore unico, e da qui questi
test: la forma legacy deve continuare a leggersi, e nel meta non deve restare
una seconda forma da cui qualcuno possa ancora leggere.
"""
from __future__ import annotations

import unittest

from .service import _mount_id, mount_by_name, mounts


LEGACY = {"remote": {"type": "drive", "config": {"folder": "1AbC"}}}
PLURALE = {"mounts": [
    {"name": "drive", "type": "drive", "config": {"folder": "1AbC"}},
    {"name": "contratti", "type": "drive", "config": {"folder": "1XyZ"}},
]}


class LetturaTests(unittest.TestCase):
    def test_il_singolare_storico_si_legge_ancora(self):
        """Il meta su marte è quello di ieri: se smettesse di leggersi, i topic
        con Drive collegato diventerebbero topic senza Drive — e senza errore."""
        m = mounts(LEGACY)
        self.assertEqual(len(m), 1)
        self.assertEqual(m[0]["type"], "drive")
        self.assertEqual(m[0]["config"]["folder"], "1AbC")

    def test_il_legacy_prende_un_nome(self):
        """Un mount senza nome non è indirizzabile: `/remote/<nome>/` non
        avrebbe un segmento da scrivere."""
        self.assertTrue(mounts(LEGACY)[0]["name"])

    def test_nessun_mount_e_lista_vuota(self):
        self.assertEqual(mounts({}), [])

    def test_il_plurale_passa_intero(self):
        self.assertEqual([m["name"] for m in mounts(PLURALE)], ["drive", "contratti"])


class RicercaTests(unittest.TestCase):
    def test_per_nome(self):
        self.assertEqual(mount_by_name(PLURALE, "contratti")["config"]["folder"], "1XyZ")

    def test_senza_nome_ripiega_sul_primo(self):
        """I chiamanti storici non passano un nome perché il mount era uno solo.
        Farli fallire li romperebbe tutti insieme."""
        self.assertEqual(mount_by_name(PLURALE)["name"], "drive")

    def test_un_nome_sconosciuto_non_e_il_primo(self):
        """La direzione d'errore che conta: ripiegare sul primo quando il nome è
        sbagliato scriverebbe nel mount sbagliato — cioè nel Drive di qualcun
        altro, visto che ogni mount ha la credenziale del suo owner."""
        self.assertEqual(mount_by_name(PLURALE, "inesistente"), {})


class IdentificatoreTests(unittest.TestCase):
    def test_il_default_e_il_tipo(self):
        self.assertEqual(_mount_id("drive", {}), "drive")

    def test_una_collisione_non_sovrascrive(self):
        self.assertEqual(_mount_id("drive", PLURALE), "drive-2")

    def test_un_nome_umano_diventa_un_segmento_di_path(self):
        """Il nome del mount finisce in un path. Uno slash dentro creerebbe un
        livello che nessuno ha chiesto."""
        for grezzo in ("50 - Execution / Final", "../etc", "Contratti 2026"):
            with self.subTest(grezzo):
                mid = _mount_id(grezzo, {})
                self.assertNotIn("/", mid)
                self.assertNotIn("..", mid)
                self.assertTrue(mid)


class UnaFormaSolaTests(unittest.TestCase):
    """Due forme nel meta sono la stessa cosa di dodici lettori: una diverge."""

    def test_le_scritture_non_lasciano_il_singolare(self):
        import inspect

        from .service import TopicService
        for m in (TopicService.remote_enable, TopicService.remote_disable):
            with self.subTest(m.__name__):
                self.assertIn('meta.pop("remote"', inspect.getsource(m))

    def test_nessuno_scrive_piu_meta_remote(self):
        """Il conto, non l'ispezione di un singolo punto: è l'aritmetica ad
        aver fatto danno qui."""
        import pathlib
        src = pathlib.Path(__file__).with_name("service.py").read_text()
        self.assertNotIn('meta["remote"] =', src)


if __name__ == "__main__":
    unittest.main()

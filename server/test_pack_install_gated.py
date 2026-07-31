"""Regola di sicurezza: packs.install_pip/install_npm eseguono il codice del
pacchetto (setup.py/postinstall) nel gateway → devono passare dal gate umano,
come packs.import_url. check_command è read-only e resta NON gated."""
import unittest

from server import gate


class PackInstallGatedTest(unittest.TestCase):
    def test_install_verbs_are_gated(self):
        self.assertTrue(gate.is_gated("packs.install_pip"))
        self.assertTrue(gate.is_gated("packs.install_npm"))

    def test_check_command_is_not_gated(self):
        # verifica presenza binario: nessuna esecuzione di codice terzo
        self.assertFalse(gate.is_gated("packs.check_command"))

    def test_consistent_with_other_code_installing_verbs(self):
        # stessa classe di rischio di import_url (già gated)
        self.assertTrue(gate.is_gated("packs.import_url"))


if __name__ == "__main__":
    unittest.main()

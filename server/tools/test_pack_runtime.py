"""`pack_runtime`: cosa rifiuta di installare, e dove cerca i comandi.

Riscritto in `unittest` il 16 ago 2026. Era in stile pytest — funzioni sciolte e
`pytest.raises` — e pytest non è fra i requirements: il file non veniva
raccolto da `unittest discover`, quindi questi tre test **non giravano da
nessuna parte**. Nessuno se n'era accorto perché l'unico segno era una riga
`ERROR: server.tools.test_pack_runtime` in coda a una suite che era già rossa
per altro.

Vale la pena notare cosa proteggono, perché è la ragione per cui riscriverli
invece di cancellarli: `install_pip` e `install_npm` eseguono codice di terzi
nel gateway, e i due test fissano che un URL o un frammento di shell non
arrivino alla riga di comando.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import pack_runtime


class InstallRejectionTests(unittest.TestCase):
    def test_install_pip_rejects_urls_and_shell_fragments(self) -> None:
        for arg in ("https://example.test/pkg.whl", "mcp;touch /tmp/nope"):
            with self.subTest(arg=arg):
                with self.assertRaises(ValueError):
                    pack_runtime.install_pip([arg])

    def test_install_npm_rejects_shell_fragments(self) -> None:
        with self.assertRaises(ValueError):
            pack_runtime.install_npm(["@scope/pkg;whoami"])


class CommandLookupTests(unittest.TestCase):
    def test_check_command_uses_runtime_path(self) -> None:
        with patch.object(pack_runtime.shutil, "which",
                          return_value="/datadir/runtime/npm/bin/foo") as which:
            result = pack_runtime.check_command("foo")

        self.assertIs(True, result["found"])
        self.assertEqual("/datadir/runtime/npm/bin/foo", result["path"])
        path = which.call_args.kwargs["path"]
        self.assertIn("/runtime/venv/bin", path)
        self.assertIn("/runtime/npm/bin", path)


if __name__ == "__main__":
    unittest.main()

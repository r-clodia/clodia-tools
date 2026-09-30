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

import os
import subprocess
import sys
import sysconfig
import tempfile
import unittest
from pathlib import Path
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


class _TempRuntime(unittest.TestCase):
    """Base con un `CLODIA_DATA` e un venv finti sotto una directory temporanea."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.venv = self.root / "runtime" / "venv"
        self.site = self.venv / "lib" / "python3.13" / "site-packages"
        self.site.mkdir(parents=True)
        patcher = patch.multiple(pack_runtime, _DATA=self.root, _VENV=self.venv,
                                 _NPM_PREFIX=self.root / "runtime" / "npm")
        patcher.start()
        self.addCleanup(patcher.stop)

    def _pack(self, name: str, *, manifest: str | None = None,
              requirements: str | None = None) -> Path:
        pack = self.root / "plugins" / name
        pack.mkdir(parents=True)
        if manifest is not None:
            (pack / "plugin.yaml").write_text(manifest, encoding="utf-8")
        if requirements is not None:
            (pack / "mcp").mkdir()
            (pack / "mcp" / "requirements.txt").write_text(requirements, encoding="utf-8")
        return pack


class RuntimeEnvTests(_TempRuntime):
    """L'ambiente con cui si avviano i server MCP dei pack (#451).

    Il difetto era che non esisteva: `proxy._session` passava `os.environ` e
    basta, quindi il venv e il prefix npm persistenti — gli unici posti dove
    `packs.install_pip`/`install_npm` depositano qualcosa — non erano nel PATH
    né nel PYTHONPATH del processo che doveva usarli.
    """

    def test_path_e_pythonpath_puntano_al_runtime_persistente(self) -> None:
        env = pack_runtime.runtime_env({"PATH": "/usr/bin", "HOME": "/root"})

        path = env["PATH"].split(os.pathsep)
        self.assertEqual(str(self.venv / "bin"), path[0])
        self.assertEqual(str(self.root / "runtime" / "npm" / "bin"), path[1])
        self.assertIn("/usr/bin", path)
        self.assertEqual("/root", env["HOME"])

        pythonpath = env["PYTHONPATH"].split(os.pathsep)
        self.assertIn(str(self.site), pythonpath)

    def test_pythonpath_porta_anche_le_site_packages_dell_immagine(self) -> None:
        """Con venv/bin in testa al PATH, un pack che dichiara `command: python3`
        (la forma di tutti i pack first-party) finisce sull'interprete del venv:
        senza le site-packages dell'immagine non troverebbe nemmeno `mcp` e il
        server non partirebbe affatto."""
        env = pack_runtime.runtime_env({"PATH": "/usr/bin"})

        self.assertIn(sysconfig.get_path("purelib"),
                      env["PYTHONPATH"].split(os.pathsep))

    def test_pythonpath_preesistente_conservato_in_coda(self) -> None:
        env = pack_runtime.runtime_env({"PATH": "/usr/bin", "PYTHONPATH": "/app"})

        parts = env["PYTHONPATH"].split(os.pathsep)
        self.assertIn(str(self.site), parts)
        self.assertEqual("/app", parts[-1])

    def test_image_site_packages_win_over_the_venv(self) -> None:
        """clodia-platform#458: a pack's venv must not shadow what the image
        ships. With the venv first, mcp 2.x resolved by an unpinned
        `mcp>=1.2` hid the image's mcp 1.x and every pack server died on
        `mcp.server.fastmcp`."""
        env = pack_runtime.runtime_env({"PATH": "/usr/bin"})
        parts = env["PYTHONPATH"].split(os.pathsep)
        self.assertLess(parts.index(sysconfig.get_path("purelib")),
                        parts.index(str(self.site)))

    def test_a_broken_mcp_in_the_venv_does_not_break_fastmcp(self) -> None:
        """End to end: put a poisoned `mcp` package in the venv and start a
        real interpreter with the runtime env — the v1 FastMCP import that all
        first-party pack servers use must still resolve to the image's mcp."""
        poisoned = self.site / "mcp"
        poisoned.mkdir(parents=True, exist_ok=True)
        (poisoned / "__init__.py").write_text(
            "raise ImportError('venv mcp shadowed the image')\n", encoding="utf-8")
        env = pack_runtime.runtime_env({"PATH": os.environ.get("PATH", "")})
        run = subprocess.run(
            [sys.executable, "-c", "from mcp.server.fastmcp import FastMCP"],
            env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(0, run.returncode, run.stderr)


class VenvIsolationTests(_TempRuntime):
    def test_venv_creato_senza_system_site_packages(self) -> None:
        """Il flag renderebbe il venv permeabile in INSTALLAZIONE: pip
        dichiarerebbe «already satisfied» tutto ciò che sta nell'immagine e non
        lo scriverebbe sul volume — cioè il bug di #451 per un'altra strada, con
        la dipendenza che sparisce al rebuild successivo."""
        with patch.object(pack_runtime, "_run",
                          return_value={"ok": True, "returncode": 0,
                                        "stdout_tail": "", "stderr_tail": ""}) as run:
            pack_runtime._ensure_venv()

        argv = run.call_args.args[0]
        self.assertIn("venv", argv)
        self.assertNotIn("--system-site-packages", argv)

    def test_pip_non_vede_il_pythonpath_di_runtime(self) -> None:
        """Stessa ragione: se il PYTHONPATH di runtime arrivasse a pip, pip
        troverebbe soddisfatti i pacchetti dell'immagine e non installerebbe
        niente nel venv."""
        (self.venv / "bin").mkdir(parents=True)
        (self.venv / "bin" / "pip").write_text("#!/bin/sh\n", encoding="utf-8")
        with patch.dict(os.environ, {"PYTHONPATH": "/qualunque"}, clear=False), \
             patch.object(pack_runtime, "_run",
                          return_value={"ok": True, "returncode": 0,
                                        "stdout_tail": "", "stderr_tail": ""}) as run:
            pack_runtime.install_pip(["Pillow>=10.0"])

        self.assertNotIn("PYTHONPATH", run.call_args.kwargs["env"])


class MissingRequirementsTests(_TempRuntime):
    _MANIFEST = (
        "name: business-pack\n"
        "requires:\n"
        "  pip:\n"
        "    - mcp>=1.2\n"
        "    - Pillow>=10.0\n"
        "mcp_servers:\n"
        "  image_captions:\n"
        "    command: python3\n"
    )

    def test_nomina_il_pack_il_pacchetto_e_i_server_coinvolti(self) -> None:
        self._pack("business-pack", manifest=self._MANIFEST)
        with patch.object(pack_runtime, "_installed_distributions",
                          return_value={"mcp"}):
            gaps = pack_runtime.missing_requirements()

        self.assertEqual(1, len(gaps))
        self.assertEqual("business-pack", gaps[0]["pack"])
        self.assertEqual(["Pillow>=10.0"], gaps[0]["missing"])
        self.assertEqual(["image_captions"], gaps[0]["mcp_servers"])

    def test_niente_da_segnalare_quando_le_dipendenze_ci_sono(self) -> None:
        self._pack("business-pack", manifest=self._MANIFEST)
        with patch.object(pack_runtime, "_installed_distributions",
                          return_value={"mcp", "pillow"}):
            self.assertEqual([], pack_runtime.missing_requirements())

    def test_legge_anche_il_requirements_txt_del_server_mcp(self) -> None:
        """`studio-legale` e `studio-commercialista` — due dei pack rotti in
        #451 — NON hanno `requires` nel manifest: le dipendenze del loro server
        MCP stanno solo in `mcp/requirements.txt`. Guardare il solo manifest li
        lascerebbe fuori dal controllo."""
        self._pack("studio-legale",
                   manifest="name: studio-legale\nmcp_servers:\n  normattiva:\n    command: python3\n",
                   requirements="# commento\nmcp>=1.2\n\nhttpx>=0.27\n-r altro.txt\n")
        with patch.object(pack_runtime, "_installed_distributions",
                          return_value={"mcp"}):
            gaps = pack_runtime.missing_requirements()

        self.assertEqual([{"pack": "studio-legale", "missing": ["httpx>=0.27"],
                           "mcp_servers": ["normattiva"]}], gaps)

    def test_un_pack_senza_dipendenze_pip_non_compare(self) -> None:
        self._pack("base-pack", manifest="name: base-pack\n")
        with patch.object(pack_runtime, "_installed_distributions",
                          return_value=set()):
            self.assertEqual([], pack_runtime.missing_requirements())

    def test_le_distribuzioni_installate_includono_il_venv(self) -> None:
        """`_installed_distributions` deve guardare nel venv persistente, non
        solo nel `sys.path` del gateway: è lì che finisce `packs.install_pip`."""
        dist = self.site / "finta_lib-1.0.dist-info"
        dist.mkdir()
        (dist / "METADATA").write_text("Metadata-Version: 2.1\nName: Finta-Lib\nVersion: 1.0\n",
                                       encoding="utf-8")

        self.assertIn("finta-lib", pack_runtime._installed_distributions())


if __name__ == "__main__":
    unittest.main()

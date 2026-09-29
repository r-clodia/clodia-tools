"""#451 — le dipendenze dei pack devono arrivare a chi le usa, e il buco deve urlare.

Tre cablaggi, uno per ciascun punto in cui il difetto era invisibile:

1. `proxy._session` avviava i server MCP dei pack con `os.environ` puro. Il venv
   e il prefix npm persistenti — gli unici posti in cui `packs.install_pip` e
   `packs.install_npm` scrivono — non comparivano né in PATH né in PYTHONPATH:
   le dipendenze erano installate sul volume e invisibili al processo che
   doveva importarle. Funzionava per caso, finché la stessa libreria stava
   anche nell'immagine del gateway; il `docker compose build --no-cache` del
   29 set l'ha tolta e `image_captions` ha cominciato a rispondere
   `ModuleNotFoundError: No module named 'PIL'`.
2. il boot non diceva niente.
3. la UI mostrava il backend MCP come connesso, perché «montato» veniva
   confuso con «funzionante».
"""
from __future__ import annotations

import asyncio
import os
import unittest
from contextlib import asynccontextmanager
from unittest.mock import patch

from server import main, proxy, tools_api


class _FakeClientSession:
    def __init__(self, *_a, **_k) -> None:
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False

    async def initialize(self):
        return None


def _open_stdio_backend(backend: dict) -> dict:
    """Apre `_session` su un backend stdio finto e ritorna l'env del processo."""
    captured: dict = {}

    @asynccontextmanager
    async def _fake_stdio(params):
        captured["params"] = params
        yield (None, None)

    async def _go():
        with patch.object(proxy, "stdio_client", _fake_stdio), \
             patch.object(proxy, "ClientSession", _FakeClientSession):
            async with proxy._session(backend):
                pass

    asyncio.run(_go())
    return dict(captured["params"].env or {})


class SessionEnvTests(unittest.TestCase):
    def test_il_server_mcp_del_pack_vede_il_runtime_persistente(self) -> None:
        env = _open_stdio_backend({
            "name": "image-captions",
            "transport": "stdio",
            "command": "python3",
            "args": ["/datadir/plugins/business-pack/mcp/image_captions_mcp.py"],
        })

        from server.tools import pack_runtime

        self.assertEqual(pack_runtime.runtime_path().split(os.pathsep)[:2],
                         env["PATH"].split(os.pathsep)[:2])
        self.assertIn("PYTHONPATH", env)

    def test_l_env_dichiarato_dal_backend_resta_l_ultima_parola(self) -> None:
        env = _open_stdio_backend({
            "name": "x", "transport": "stdio", "command": "python3",
            "env": {"PYTHONPATH": "/solo/questo"},
        })

        self.assertEqual("/solo/questo", env["PYTHONPATH"])


class BootWarningTests(unittest.TestCase):
    def test_il_boot_nomina_pack_pacchetto_e_server_mcp(self) -> None:
        gap = {"pack": "business-pack", "missing": ["Pillow>=10.0"],
               "mcp_servers": ["image_captions"]}
        with patch("server.whitelist.CONFIG", {"agents": {}, "mcp_backends": []}), \
             patch.object(main.email, "credential_diagnostics", return_value=[]), \
             patch("server.tools.pack_runtime.missing_requirements", return_value=[gap]):
            warnings = main.runtime_configuration_warnings()

        self.assertEqual(1, len(warnings))
        for atteso in ("business-pack", "Pillow>=10.0", "image_captions",
                       "packs.install_pip"):
            self.assertIn(atteso, warnings[0])

    def test_nessun_warning_quando_i_pack_sono_a_posto(self) -> None:
        with patch("server.whitelist.CONFIG", {"agents": {}, "mcp_backends": []}), \
             patch.object(main.email, "credential_diagnostics", return_value=[]), \
             patch("server.tools.pack_runtime.missing_requirements", return_value=[]):
            self.assertEqual([], main.runtime_configuration_warnings())


class ConnectorSnapshotTests(unittest.TestCase):
    """Il nome del server nel manifest (`image_captions`) e lo slug del backend
    montato (`image-captions`) non coincidono: il confronto passa da `_slugify`,
    se no il gap non si attacca mai alla riga giusta."""

    def _snapshot(self, gaps: list[dict]) -> dict:
        config = {"mcp_backends": [{"name": "image-captions", "transport": "stdio"}]}
        with patch("server.whitelist.CONFIG", config), \
             patch.object(tools_api.email_tool, "credential_diagnostics", return_value=[]), \
             patch.object(tools_api.vault, "has_credential", return_value=False), \
             patch.object(tools_api.instance_profile, "connectors_allowed", return_value=None), \
             patch("server.tools.pack_runtime.missing_requirements", return_value=gaps):
            rows = tools_api.connectors_snapshot()
        return next(r for r in rows if r.get("id") == "image-captions")

    def test_backend_di_un_pack_incompleto_non_e_operativo(self) -> None:
        row = self._snapshot([{"pack": "business-pack", "missing": ["Pillow>=10.0"],
                               "mcp_servers": ["image_captions"]}])

        self.assertFalse(row["operational"])
        self.assertEqual("business-pack", row["issues"][0]["pack"])
        self.assertEqual(["Pillow>=10.0"], row["issues"][0]["missing"])

    def test_senza_gap_la_riga_resta_quella_di_prima(self) -> None:
        row = self._snapshot([])

        self.assertTrue(row["connected"])
        self.assertNotIn("issues", row)
        self.assertNotIn("operational", row)


if __name__ == "__main__":
    unittest.main()

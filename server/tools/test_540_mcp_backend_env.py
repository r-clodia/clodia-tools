"""#540 — a pack's MCP server process gets an environment BUILT FROM ZERO,
never the gateway's own (`CLODIA_ORCHESTRATOR_SECRET`, `CLODIA_VAULT_DIR`, …)."""
from __future__ import annotations

import ast
import asyncio
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

from . import pack_runtime

GATEWAY_ENV = {
    "PATH": "/usr/local/bin:/usr/bin", "HOME": "/root", "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8", "CLODIA_DATA": "/datadir",
    "CLODIA_ORCHESTRATOR_SECRET": "top-secret", "CLODIA_VAULT_DIR": "/vault",
    "ANTHROPIC_API_KEY": "sk-x", "GITHUB_TOKEN": "ghp_x", "SOMETHING_NEW": "?",
}


class BackendEnvTests(unittest.TestCase):
    def test_secrets_never_cross(self):
        env = pack_runtime.mcp_backend_env(GATEWAY_ENV)
        for k in ("CLODIA_ORCHESTRATOR_SECRET", "CLODIA_VAULT_DIR", "ANTHROPIC_API_KEY",
                  "GITHUB_TOKEN", "SOMETHING_NEW"):
            self.assertNotIn(k, env)
        self.assertNotIn("top-secret", repr(env))

    def test_what_a_process_needs_does(self):
        env = pack_runtime.mcp_backend_env(GATEWAY_ENV)
        for k in ("HOME", "LANG", "LC_ALL", "CLODIA_DATA"):
            self.assertEqual(env[k], GATEWAY_ENV[k])
        self.assertTrue(env["PATH"].endswith("/usr/local/bin:/usr/bin"))
        self.assertIn("venv/bin", env["PATH"])

    def test_the_proxy_starts_stdio_backends_with_it(self):
        """The real call site: the gateway's secret is in os.environ, the
        backend's declared env is added on top, nothing else."""
        from .. import proxy
        seen = {}

        @asynccontextmanager
        async def fake_stdio(params):
            seen["env"] = dict(params.env or {})
            raise RuntimeError("stop here")
            yield  # pragma: no cover

        b = {"name": "demo", "transport": "stdio", "command": "python3",
             "args": ["x.py"], "env": {"DEMO_KEY": "declared"}}
        with patch.dict("os.environ", {"CLODIA_ORCHESTRATOR_SECRET": "top-secret"}), \
                patch.object(proxy, "_resolve_secrets", lambda b: b), \
                patch.object(proxy, "stdio_client", fake_stdio):
            async def go():
                async with proxy._session(b):
                    pass
            with self.assertRaises(RuntimeError):
                asyncio.run(go())
        self.assertNotIn("CLODIA_ORCHESTRATOR_SECRET", seen["env"])
        self.assertEqual(seen["env"]["DEMO_KEY"], "declared")

    def test_no_server_code_hands_a_process_the_gateways_environment(self):
        """`runtime_env()` without a base copies os.environ: outside its own
        module and tests, nobody may call it that way again."""
        root = Path(__file__).resolve().parents[1]
        offenders = []
        for path in root.rglob("*.py"):
            if path.name.startswith("test_") or path.name == "pack_runtime.py":
                continue
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "runtime_env"
                        and not node.args and not node.keywords):
                    offenders.append(f"{path.relative_to(root)}:{node.lineno}")
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()

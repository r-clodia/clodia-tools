#!/usr/bin/env python3
"""mcp-tools-server CLI — start a stdio MCP server for a given agent."""
import argparse
import os
import sys
from pathlib import Path

TOOL_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOL_ROOT))

from server import __version__  # noqa: E402

POLICY_PATH = TOOL_ROOT / "POLICY.md"


def main() -> int:
    p = argparse.ArgumentParser(
        prog="mcp-tools-server",
        description="MCP stdio server exposing controlled tools to Clodia-family agents.",
    )
    p.add_argument("--version", action="version", version=f"mcp-tools-server {__version__}")
    p.add_argument("--policy", action="store_true", help="Print operational policy and exit")
    p.add_argument("--agent", help="Agent name (overrides MCP_AGENT_NAME env var) — solo stdio")
    p.add_argument("--http", action="store_true",
                   help="Avvia il microservizio MCP via HTTP (multi-agente, auth ckt1) invece dello stdio")
    p.add_argument("--host", default="0.0.0.0", help="Host HTTP (default 0.0.0.0)")
    p.add_argument("--port", type=int, default=7849, help="Porta HTTP (default 7849)")
    args = p.parse_args()

    if args.policy:
        print(POLICY_PATH.read_text())
        return 0

    if args.http:
        # Modalità microservizio: identità per-richiesta dal token, niente --agent.
        from server.http_app import run_http
        run_http(host=args.host, port=args.port)
        return 0

    if args.agent:
        os.environ["MCP_AGENT_NAME"] = args.agent

    import asyncio
    from server.main import main as run_server
    asyncio.run(run_server())
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""runtime.health — the post-deploy smoke checks as a read-only verb
(clodia-platform#703).

The checks that the operator runs by hand after a deploy, available to
sysadmin from inside the colony so that «is the platform healthy?» has an
answer that does not need a shell on the host:

- service versions: the gateway's own, the agent-server's (`/health`);
- the agent-server's health (reachable, status);
- every mounted MCP backend: a real `list_tools` (OK/FAIL and the number of
  tools — never their schemas, never a credential);
- the mail courier: how many rows it reads, with and without a tag (the
  message box rows vs the linked mailboxes) — counts only, no address;
- the gateway log's recent CRITICAL/ERROR lines, redacted like `logs.tail`
  (secrets, message text, topic names above the reader's clearance).

Contents never: no message, no file, no row, no address. Secrets never: a
backend failure is reported by its class and a redacted, capped detail.
"""
from __future__ import annotations

import asyncio
import logging

import httpx

LOG = logging.getLogger("clodia-tools.health")

#: Seconds a single backend probe may take; they run concurrently.
BACKEND_TIMEOUT_S = 20.0
#: How many recent CRITICAL/ERROR lines of the gateway log are shown.
ERROR_LINES = 20
#: How much of the gateway log is scanned for them (from the end).
_SCAN_LINES = 5000
_DETAIL_MAX = 160
_TIMEOUT = httpx.Timeout(connect=3.0, read=6.0, write=3.0, pool=3.0)


def _redact(text: str) -> str:
    from .logs import redact_line
    from ..whitelist import current_clearance
    try:
        cl = current_clearance()
    except Exception:  # noqa: BLE001 — no caller context: the lowest clearance
        cl = None
    return redact_line(str(text or ""), cl)[:_DETAIL_MAX]


def _agent_server() -> dict:
    from .runtime import AGENT_SERVER_URL
    try:
        with httpx.Client(timeout=_TIMEOUT) as c:
            r = c.get(f"{AGENT_SERVER_URL}/health")
        if r.status_code != 200:
            return {"ok": False, "detail": f"HTTP {r.status_code}"}
        data = r.json() if r.content else {}
        return {"ok": data.get("status") == "ok", "status": data.get("status"),
                "version": data.get("version"), "platform": data.get("platform")}
    except Exception as e:  # noqa: BLE001 — unreachable is an answer, not a crash
        return {"ok": False, "detail": type(e).__name__}


async def _backends() -> list[dict]:
    from .. import proxy
    names = []
    for name in sorted(proxy._backends()):
        try:
            if proxy._is_transport(name):
                continue                # a provider socket, not a verb (#523)
        except Exception:  # noqa: BLE001
            pass
        names.append(name)

    async def one(name: str) -> dict:
        try:
            res = await asyncio.wait_for(proxy.test_backend(name),
                                         timeout=BACKEND_TIMEOUT_S)
        except Exception as e:  # noqa: BLE001
            return {"name": name, "ok": False, "detail": type(e).__name__}
        row = {"name": name, "ok": bool(res.get("ok"))}
        if res.get("ok"):
            row["tools"] = len(res.get("tools") or [])
        else:
            row["detail"] = _redact(res.get("detail") or "")
        return row

    return list(await asyncio.gather(*(one(n) for n in names)))


def _courier() -> dict:
    try:
        from .. import mail_courier_api
        rows = mail_courier_api.rooms()
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "detail": type(e).__name__}
    tagged = sum(1 for r in rows if r.get("tag"))
    return {"ok": True, "rows": len(rows), "tagged": tagged,
            "untagged": len(rows) - tagged}


def _gateway_errors() -> dict:
    from .logs import _log_file
    f = _log_file("gateway")
    if not f.is_file():
        return {"file": "gateway", "count": 0, "lines": [],
                "note": "file di log non ancora presente"}
    try:
        rows = f.read_text(encoding="utf-8", errors="replace").splitlines()[-_SCAN_LINES:]
    except OSError as e:
        return {"file": "gateway", "count": 0, "lines": [], "detail": type(e).__name__}
    hits = [r for r in rows if " CRITICAL " in r or " ERROR " in r]
    out = [_redact(r) for r in hits[-ERROR_LINES:]]
    return {"file": "gateway", "count": len(hits), "lines": out}


def _gateway() -> dict:
    from .. import __version__
    return {"ok": True, "version": __version__}


async def health(*, backends: bool = True) -> dict:
    """The smoke checks. Each part answers on its own: one failing does not
    hide the others, and an exception becomes that part's `ok: false`."""
    agent_server, courier, errors = await asyncio.gather(
        asyncio.to_thread(_agent_server), asyncio.to_thread(_courier),
        asyncio.to_thread(_gateway_errors))
    mcp = await _backends() if backends else None
    out = {"gateway": _gateway(), "agent_server": agent_server,
           "courier": courier, "gateway_errors": errors}
    if mcp is not None:
        out["mcp_backends"] = {"count": len(mcp),
                               "failing": [b["name"] for b in mcp if not b["ok"]],
                               "backends": mcp}
    out["ok"] = bool(agent_server.get("ok") and courier.get("ok")
                     and (mcp is None or all(b["ok"] for b in mcp)))
    return out

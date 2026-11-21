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
  (secrets, message text, topic names above the reader's clearance);
- the RAG ingest token: present or missing, and from where (environment or
  file) — never its value (clodia-platform#499). It does not decide `ok`: an
  instance without the EU RAG has no token by design.

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


#: Seconds an answer is reused (#703 review): probing every backend costs
#: seconds and processes, and a widget, a retry or two agents asking at once
#: must not multiply it. Short enough that «I fixed it, check again» works
#: within a minute.
CACHE_TTL_S = 45.0
_cache: dict = {}
_inflight: dict = {}


def _cache_key(backends: bool) -> tuple:
    # The answer depends on the reader's clearance (topic names in the error
    # lines are redacted above it), so readers of different clearance never
    # share one.
    try:
        from ..whitelist import current_clearance
        cl = current_clearance()
    except Exception:  # noqa: BLE001
        cl = None
    # …and on whether the reader is an admin person: only then the answer
    # carries the stall diagnostics (#710).
    return (bool(backends), cl, _admin_reader())


def _admin_reader() -> bool:
    """Is the person behind this call a human admin (the same rule as the
    role tools, `authz_runtime.role_principal_ok`)? Fail closed."""
    try:
        from ..authz_runtime import role_principal_ok
        return bool(role_principal_ok())
    except Exception:  # noqa: BLE001
        return False


def _stalls() -> dict:
    """For admins (#710): is the SIGUSR1 dump armed, and the last stall the
    sampler caught — when, how long, the innermost frames of the loop thread
    and of the busy ones. Code locations only, redacted; the full dump is
    `GET /internal/diagnostics/stacks`."""
    from .. import stackdump
    return {"signal_dump": stackdump.signal_dump_installed(),
            "last_stall": stackdump.last_stall()}


def reset_cache() -> None:
    _cache.clear()
    _inflight.clear()


async def health(*, backends: bool = True) -> dict:
    """The smoke checks, cached `CACHE_TTL_S` seconds; concurrent calls for
    the same answer share ONE run instead of each probing every backend."""
    import time
    key = _cache_key(backends)
    hit = _cache.get(key)
    now = time.monotonic()
    if hit and now - hit[0] < CACHE_TTL_S:
        return {**hit[1], "cached_age_s": round(now - hit[0], 1)}
    fut = _inflight.get(key)
    if fut is not None:
        return await asyncio.shield(fut)
    fut = asyncio.get_running_loop().create_future()
    _inflight[key] = fut
    try:
        out = await _run(backends=backends)
        _cache[key] = (time.monotonic(), out)
        fut.set_result(out)
        return out
    except BaseException as e:
        fut.set_exception(e)
        fut.exception()        # retrieved: no «never retrieved» warning
        raise
    finally:
        _inflight.pop(key, None)


def _rag_ingest() -> dict:
    try:
        from .eu_corpus import ingest_token_status
        st = ingest_token_status()
    except Exception as e:  # noqa: BLE001 - one part failing hides nothing else
        return {"token": "unknown", "error": type(e).__name__}
    return {"token": "present" if st["present"] else "missing",
            "source": st["source"], "env": st["env"], "file": st["file"]}


async def _run(*, backends: bool = True) -> dict:
    """The smoke checks. Each part answers on its own: one failing does not
    hide the others, and an exception becomes that part's `ok: false`."""
    agent_server, courier, errors = await asyncio.gather(
        asyncio.to_thread(_agent_server), asyncio.to_thread(_courier),
        asyncio.to_thread(_gateway_errors))
    mcp = await _backends() if backends else None
    out = {"gateway": _gateway(), "agent_server": agent_server,
           "courier": courier, "gateway_errors": errors,
           "rag_ingest": _rag_ingest()}
    if mcp is not None:
        out["mcp_backends"] = {"count": len(mcp),
                               "failing": [b["name"] for b in mcp if not b["ok"]],
                               "backends": mcp}
    if _admin_reader():
        out["stalls"] = _stalls()
    out["ok"] = bool(agent_server.get("ok") and courier.get("ok")
                     and (mcp is None or all(b["ok"] for b in mcp)))
    return out

"""channels_api — the relay transport a pack connector declares (clodia-platform#638).

Telegram's relay routes (`/internal/telegram/{poll,send,download}`) are wired to
comms-pack's component. A pack that brings another chat channel declares a
`relay:` block on its connector instead (`connectors/manifest.Relay`): one of
its own services, listening on loopback, speaking a three-operation HTTP JSON
contract. These routes are the agent-server's door to it:

    POST /internal/channels/{connector}/poll      {timeout, ack?}      → {messages, cursor?}
    POST /internal/channels/{connector}/send      {chat_id, text, thread_id?}
                                                                       → {ok, message_id}
    POST /internal/channels/{connector}/download  {file_id}            → {content_b64, size, mime}

Rules, each closing a way the door could be misused:

- **Only a connector the live registry accepted with `relay:`.** The forward
  goes to `<relay.base><path>` — the base re-checked against the loopback rule
  at every call, because the manifest is a file on a volume the gateway does
  not own — and to exactly these three paths. Anything else is 404.
- **Identity is the gateway's to vet.** A polled row survives only if its
  `chat_uri` and its `sender_uri` (when present) parse in one of the
  connector's OWN schemes and match one of that scheme's `forms`. Dropped rows
  are logged. The agent-server builds the room's view of who wrote from those
  two URIs and nothing else.
- **Supervision is #515's.** A service the supervisor is not running, or that
  does not answer, is 503 — the relay retries; it never gets another way in.
- **Or a mounted MCP backend (#641).** With `relay.backend` the same three
  operations are the backend's tools `relay_poll`/`relay_send`/
  `relay_download` (`call_backend`); everything else here is identical.

Same authorisation as `telegram_api`: `internal_auth.authorize`, the
privileged principal of the agent-server's runner, no on-behalf sessions.
"""
from __future__ import annotations

import logging
from typing import Any

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import internal_auth
from .connectors import resolved as _resolved
from .connectors.manifest import Connector, loopback_base_problem

LOG = logging.getLogger("clodia-tools.channels_api")

#: Poll timeout bounds, as `/internal/telegram/poll`.
POLL_MIN, POLL_MAX, POLL_DEFAULT = 1, 50, 25
#: What the HTTP client waits beyond the poll timeout the service was given.
POLL_MARGIN = 10.0
#: Short operations: a send or a download that takes longer is not coming.
SEND_TIMEOUT = 20.0
DOWNLOAD_TIMEOUT = 60.0
#: Upper bounds on what a service may hand back, read before parsing.
MAX_POLL_BYTES = 4 * 1024 * 1024
MAX_SEND_BYTES = 64 * 1024
MAX_DOWNLOAD_BYTES = 48 * 1024 * 1024
#: Rows a single poll may return.
MAX_ROWS = 500
MAX_TEXT = 64 * 1024
MAX_ID = 512


class RelayUnavailable(RuntimeError):
    """The transport service is not running or does not answer → 503."""


class RelayFailed(RuntimeError):
    """The service answered, but not with what the contract says → 502.

    `status` and `payload` carry a 4xx answer of the service (its status and
    its JSON object, if any), for a caller that relays it (`tools_api`'s
    pairing routes). Nothing else reads them.
    """

    def __init__(self, message: str, status: int | None = None,
                 payload: dict | None = None):
        super().__init__(message)
        self.status = status
        self.payload = payload


class RelayRefused(ValueError):
    """The request names a connector or an operation that has no relay → 404."""


# --------------------------------------------------------------------------
# lookup and forwarding (shared with `main.channel.deliver`)
# --------------------------------------------------------------------------

def relay_connector(cid: str) -> Connector:
    """The registry's connector `cid`, if it declares a `relay:`; else refused."""
    from . import instance_profile
    try:
        allowed = instance_profile.connector_allowed(cid)
    except Exception:  # noqa: BLE001 — an unreadable profile allows nothing
        allowed = False
    connector = _resolved.registry().by_id(cid) if allowed else None
    if connector is None or connector.builtin or connector.relay is None:
        raise RelayRefused(f"connector '{cid}' has no relay on this instance")
    return connector


def service_token(connector: Connector, service: str) -> str | None:
    """The per-start secret of this connector's service, or None when the
    supervisor (#515) is not running it right now. None means 503: the
    gateway never calls a service it cannot authenticate itself to."""
    try:
        from . import services as _services
        return _services.service_token(connector.pack, service)
    except Exception as e:  # noqa: BLE001 — unknown is not running
        LOG.warning("channels: supervisor unavailable (%s)", type(e).__name__)
        return None


async def forward(base: str, path: str, body: dict, *, timeout: float,
                  max_bytes: int, token: str, method: str = "POST") -> dict:
    """One HTTP JSON call to a pack service on loopback. Never follows a
    redirect and never reads the environment's proxy settings: the target is
    the declared loopback base and nothing else.

    `token` is the service's per-start secret (`service_token`), sent as
    `X-Clodia-Service-Token`: the service refuses whoever does not have it,
    because every service uid can reach loopback too. Never logged.
    """
    problem = loopback_base_problem(base)
    if problem:
        # Refused at load already; a manifest on disk may have changed since.
        raise RelayRefused(f"service base refused: {problem}")
    if not token:
        raise RelayUnavailable("service not running (no token)")
    from .services.launch import SERVICE_TOKEN_HEADER
    import httpx
    url = f"{base}{path}"
    try:
        async with httpx.AsyncClient(timeout=timeout, trust_env=False,
                                     follow_redirects=False) as client:
            kwargs: dict = {"headers": {SERVICE_TOKEN_HEADER: token}}
            if method != "GET":
                kwargs["json"] = body
            async with client.stream(method, url, **kwargs) as resp:
                status = resp.status_code
                chunks: list[bytes] = []
                total = 0
                # Read with a cap, never the whole answer first: a service
                # that streams forever must not fill the gateway's memory.
                async for chunk in resp.aiter_bytes():
                    total += len(chunk)
                    if total > max_bytes:
                        raise RelayFailed(f"service answer over {max_bytes} bytes")
                    chunks.append(chunk)
    except (httpx.ConnectError, httpx.ConnectTimeout) as e:
        raise RelayUnavailable(f"service not reachable ({type(e).__name__})") from e
    except httpx.TimeoutException as e:
        raise RelayUnavailable(f"service did not answer in time ({type(e).__name__})") from e
    except httpx.HTTPError as e:
        raise RelayUnavailable(f"service call failed ({type(e).__name__})") from e
    if status == 503:
        raise RelayUnavailable("service unavailable (503)")
    import json as _json
    try:
        data = _json.loads(b"".join(chunks) or b"null")
    except ValueError as e:
        if not 200 <= status < 300:
            raise RelayFailed(f"service answered HTTP {status}", status) from e
        raise RelayFailed("service answer is not JSON") from e
    if not 200 <= status < 300:
        raise RelayFailed(f"service answered HTTP {status}", status,
                          data if isinstance(data, dict) else None)
    if not isinstance(data, dict):
        raise RelayFailed("service answer is not a JSON object")
    return data


#: Seconds added to a backend call's own timeout (#641 review): small, so a
#: relay poll answers before the agent-server's client gives up on it.
BACKEND_SESSION_MARGIN = 5.0


def _found(e: BaseException, cls):
    """The first `cls` in `e`, its exception group or its causes, or None."""
    if isinstance(e, cls):
        return e
    for sub in getattr(e, "exceptions", ()) or ():
        hit = _found(sub, cls)
        if hit is not None:
            return hit
    cause = e.__cause__ or e.__context__
    return _found(cause, cls) if cause is not None and cause is not e else None


async def call_backend(connector: Connector, backend: str, tool: str,
                       args: dict, *, timeout: float, max_bytes: int) -> dict:
    """One tool of a relay/pairing MCP backend (#641), off the event loop.

    Same contract as `forward`, so every caller is unchanged: the tool's text
    is parsed as a JSON object; the backend not mounted by the connector's own
    pack, not mounted at all, or not answering → `RelayUnavailable` (503); the
    tool's `isError` → `RelayFailed` — carrying status 400 and the tool's JSON
    object when it answered one (the equivalent of a service's 4xx, which the
    pairing routes relay), no status otherwise (502).
    """
    from . import proxy
    # Resolved ONCE: the entry whose stamp is checked is the entry called.
    entry = _resolved.owned_backend_entry(connector.pack, backend)
    if entry is None:
        LOG.warning("channels %s: backend '%s' is not mounted by pack '%s': "
                    "not called", connector.id, backend, connector.pack)
        raise RelayUnavailable(
            f"backend '{backend}' is not mounted by pack '{connector.pack}'")
    import asyncio
    import json as _json
    try:
        text = await asyncio.to_thread(
            proxy.call_backend_tool_sync, backend, tool, dict(args), timeout,
            # On the wire, not after buffering; with headroom for the JSON-RPC
            # envelope, which escapes the tool's JSON text once more.
            max_bytes=2 * max_bytes + 64 * 1024,
            margin=BACKEND_SESSION_MARGIN, entry=entry)
    except proxy.BackendResponseTooLarge as e:
        raise RelayFailed(f"{tool}: answer too large") from e
    except proxy.BackendUnavailable as e:
        raise RelayUnavailable(f"backend unavailable ({str(e)[:160]})") from e
    except proxy.BackendToolError as e:
        payload = None
        try:
            payload = _json.loads(getattr(e, "text", "") or "null")
        except ValueError:
            pass
        if isinstance(payload, dict):
            raise RelayFailed(f"{tool} refused the request", 400, payload) from e
        raise RelayFailed(f"{tool} failed") from e
    except Exception as e:  # noqa: BLE001
        # A backend that answers, but not as the contract says, is a FAILURE
        # (502) with a message that says which, not a «try later» (503): an
        # unknown tool (JSON-RPC error) or a session the vault rules refuse
        # (#568) will not fix itself by retrying.
        if _found(e, PermissionError):
            raise RelayFailed(f"backend '{backend}' refused: its credentials "
                              f"break the vault rules (#568)") from e
        from mcp.shared.exceptions import McpError
        mcp_err = _found(e, McpError)
        if mcp_err is not None:
            raise RelayFailed(f"backend '{backend}' does not serve '{tool}' "
                              f"({str(mcp_err)[:120]})") from e
        raise RelayUnavailable(f"backend not reachable ({type(e).__name__})") from e
    if len(text.encode("utf-8", "replace")) > max_bytes:
        raise RelayFailed(f"backend answer over {max_bytes} bytes")
    try:
        data = _json.loads(text or "null")
    except ValueError as e:
        raise RelayFailed("backend answer is not JSON") from e
    if not isinstance(data, dict):
        raise RelayFailed("backend answer is not a JSON object")
    return data


async def _call(connector: Connector, op: str, body: dict, *, timeout: float,
                max_bytes: int) -> dict:
    relay = connector.relay
    if relay.backend:
        return await call_backend(connector, relay.backend, f"relay_{op}", body,
                                  timeout=timeout, max_bytes=max_bytes)
    token = service_token(connector, relay.service)
    if not token:
        raise RelayUnavailable(
            f"service '{relay.service}' of pack '{connector.pack}' is not running")
    return await forward(relay.base, f"/{op}", body, timeout=timeout,
                         max_bytes=max_bytes, token=token)


def uri_ok(connector: Connector, uri: Any) -> bool:
    """`uri` is `<scheme>:<rest>` with `scheme` one of the connector's OWN
    schemes that declares forms, and `rest` matches one of them (`fullmatch`).
    A scheme without forms vets nothing, so it is never enough here."""
    if not isinstance(uri, str) or not uri or len(uri) > MAX_ID:
        return False
    scheme, sep, rest = uri.partition(":")
    if not sep or not rest:
        return False
    sch = next((s for s in connector.schemes if s.name == scheme.lower()), None)
    return bool(sch is not None and sch.forms
                and any(f.matches(rest) for f in sch.forms))


def vet_rows(connector: Connector, rows: Any) -> list[dict]:
    """The polled rows whose `chat_uri` (required) and `sender_uri` (when
    present) are the connector's own URIs, and whose `chat_uri` is exactly
    `<scheme>:<chat_id>`. Every other row is dropped and
    logged — without its values: a sender id is personal data, and a log line
    is not the place to keep it."""
    kept: list[dict] = []
    dropped = 0
    for row in rows if isinstance(rows, list) else ():
        if len(kept) >= MAX_ROWS:
            dropped += 1
            continue
        if not isinstance(row, dict):
            dropped += 1
            continue
        chat_uri = row.get("chat_uri")
        chat_ok = uri_ok(connector, chat_uri)
        # The chat the relay will reply to (`chat_id`) and the chat it is
        # vetted as (`chat_uri`) must be the same chat: otherwise a row could
        # be vetted as one chat of the room and answered into another.
        chat_id = row.get("chat_id")
        chat_id = str(chat_id) if isinstance(chat_id, (str, int)) \
            and not isinstance(chat_id, bool) else ""
        same_chat = chat_ok and bool(chat_id) and chat_uri == \
            f"{chat_uri.partition(':')[0].lower()}:{chat_id}"
        sender = row.get("sender_uri")
        sender_ok = sender is None or uri_ok(connector, sender)
        if chat_ok and same_chat and sender_ok:
            kept.append(row)
            continue
        dropped += 1
        LOG.warning("channels %s: relayed row dropped (%s)", connector.id,
                    "chat_uri outside the connector's schemes and forms"
                    if not chat_ok else
                    "chat_uri is not <scheme>:<chat_id>" if not same_chat else
                    "sender_uri outside the connector's schemes and forms")
    if not isinstance(rows, list) and rows is not None:
        LOG.warning("channels %s: poll answer 'messages' is not a list",
                    connector.id)
    if dropped:
        LOG.warning("channels %s: %d relayed row(s) dropped", connector.id, dropped)
    return kept


def cursor_ok(value: Any) -> bool:
    """A poll cursor / ack: an opaque string, bounded like an id, printable."""
    return isinstance(value, str) and 0 < len(value) <= MAX_ID \
        and all(c.isprintable() for c in value)


async def relay_poll(connector: Connector, timeout: int,
                     ack: str | None = None) -> tuple[list[dict], str | None]:
    """`POST <base>/poll {timeout, ack?}` → `(vetted rows, cursor)`.

    `ack` is the cursor of the previous poll: the service drops what it covers.
    The cursor comes back whatever `vet_rows` keeps — a row dropped here is
    still delivered-and-refused, and losing the cursor would make the service
    send the same rows forever.
    """
    body: dict = {"timeout": timeout}
    if ack is not None:
        body["ack"] = ack
    out = await _call(connector, "poll", body,
                      timeout=timeout + POLL_MARGIN, max_bytes=MAX_POLL_BYTES)
    cursor = out.get("cursor")
    if cursor is not None and not cursor_ok(cursor):
        LOG.warning("channels %s: poll cursor refused (not a short printable "
                    "string)", connector.id)
        cursor = None
    return vet_rows(connector, out.get("messages")), cursor


async def relay_send(connector: Connector, chat_id: str, text: str,
                     thread_id: Any = None) -> dict:
    """`POST <base>/send`. Shared with `channel.deliver` (`channel.relay_send`),
    which reaches it only after the egress decision on `<scheme>:<chat_id>`."""
    body: dict = {"chat_id": chat_id, "text": text}
    if thread_id is not None:
        body["thread_id"] = thread_id
    out = await _call(connector, "send", body, timeout=SEND_TIMEOUT,
                      max_bytes=MAX_SEND_BYTES)
    mid = out.get("message_id")
    if not isinstance(mid, (str, int)) or isinstance(mid, bool):
        mid = None
    elif isinstance(mid, str):
        mid = mid[:MAX_ID]
    return {"ok": out.get("ok") is True, "message_id": mid}


async def relay_download(connector: Connector, file_id: str) -> dict:
    if not connector.relay.attachments:
        raise RelayRefused(f"connector '{connector.id}' declares no attachments")
    out = await _call(connector, "download", {"file_id": file_id},
                      timeout=DOWNLOAD_TIMEOUT, max_bytes=MAX_DOWNLOAD_BYTES)
    content = out.get("content_b64")
    if not isinstance(content, str):
        raise RelayFailed("download answer carries no content_b64")
    size = out.get("size")
    mime = out.get("mime")
    return {"content_b64": content,
            "size": size if isinstance(size, int) and not isinstance(size, bool) else None,
            "mime": mime[:128] if isinstance(mime, str) else ""}


# --------------------------------------------------------------------------
# routes
# --------------------------------------------------------------------------

def _authorize(request: Request):
    """The rule of every internal relay route (`telegram_api._authorize`)."""
    payload, err = internal_auth.authorize(request, log=LOG)
    return (str(payload.get("agent")) if payload else None), err


def _error(e: Exception) -> JSONResponse:
    if isinstance(e, RelayRefused):
        return JSONResponse({"error": str(e)[:200]}, status_code=404)
    if isinstance(e, RelayUnavailable):
        return JSONResponse({"error": str(e)[:200]}, status_code=503)
    return JSONResponse({"error": str(e)[:200]}, status_code=502)


async def _body(request: Request) -> dict:
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001
        return {}
    return body if isinstance(body, dict) else {}


async def poll(request: Request):
    _agent, err = _authorize(request)
    if err:
        return err
    body = await _body(request)
    try:
        timeout = int(body.get("timeout", POLL_DEFAULT))
    except (TypeError, ValueError):
        timeout = POLL_DEFAULT
    timeout = max(POLL_MIN, min(POLL_MAX, timeout))
    ack = body.get("ack")
    if ack is not None and not cursor_ok(ack):
        return JSONResponse({"error": "ack must be a short printable string"},
                            status_code=400)
    try:
        connector = relay_connector(request.path_params["connector"])
        msgs, cursor = await relay_poll(connector, timeout, ack)
    except (RelayRefused, RelayUnavailable, RelayFailed) as e:
        if not isinstance(e, RelayRefused):
            LOG.warning("channels %s poll: %s", request.path_params["connector"], e)
        return _error(e)
    out: dict = {"messages": msgs, "count": len(msgs)}
    if cursor is not None:
        out["cursor"] = cursor
    return JSONResponse(out)


async def send(request: Request):
    _agent, err = _authorize(request)
    if err:
        return err
    body = await _body(request)
    chat_id = body.get("chat_id")
    chat_id = str(chat_id).strip() if isinstance(chat_id, (str, int)) \
        and not isinstance(chat_id, bool) else ""
    text = body.get("text")
    if not chat_id or len(chat_id) > MAX_ID:
        return JSONResponse({"error": "chat_id required"}, status_code=400)
    if not isinstance(text, str) or len(text) > MAX_TEXT:
        return JSONResponse({"error": "text required (a string)"}, status_code=400)
    thread_id = body.get("thread_id")
    if thread_id is not None and (isinstance(thread_id, bool)
                                  or not isinstance(thread_id, (str, int))):
        return JSONResponse({"error": "thread_id must be a string or an integer"},
                            status_code=400)
    try:
        connector = relay_connector(request.path_params["connector"])
        out = await relay_send(connector, chat_id, text, thread_id)
    except (RelayRefused, RelayUnavailable, RelayFailed) as e:
        if not isinstance(e, RelayRefused):
            LOG.warning("channels %s send: %s", request.path_params["connector"], e)
        return _error(e)
    return JSONResponse(out)


async def download(request: Request):
    _agent, err = _authorize(request)
    if err:
        return err
    body = await _body(request)
    file_id = body.get("file_id")
    file_id = file_id.strip() if isinstance(file_id, str) else ""
    try:
        connector = relay_connector(request.path_params["connector"])
        if not connector.relay.attachments:
            raise RelayRefused(f"connector '{connector.id}' declares no attachments")
        if not file_id or len(file_id) > MAX_ID:
            return JSONResponse({"error": "file_id required"}, status_code=400)
        out = await relay_download(connector, file_id)
    except (RelayRefused, RelayUnavailable, RelayFailed) as e:
        if not isinstance(e, RelayRefused):
            LOG.warning("channels %s download: %s", request.path_params["connector"], e)
        return _error(e)
    return JSONResponse(out)


routes = [
    Route("/internal/channels/{connector}/poll", poll, methods=["POST"]),
    Route("/internal/channels/{connector}/send", send, methods=["POST"]),
    Route("/internal/channels/{connector}/download", download, methods=["POST"]),
]

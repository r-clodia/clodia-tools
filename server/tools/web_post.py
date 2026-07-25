"""Gated HTTP POST tool.

Authorization is enforced by the gateway's M-gate before this module is called.
This layer provides protocol limits, redirect refusal, bounded responses and an
append-only audit record. Private-network targets are intentionally supported:
the per-invocation human gate is the SSRF control selected by the owner.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
from urllib.parse import urlsplit, urlunsplit

import httpx


MAX_REQUEST_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 256 * 1024
DEFAULT_TIMEOUT_SECONDS = 10.0
_FORBIDDEN_HEADERS = {
    "host", "content-length", "transfer-encoding", "connection",
    "proxy-authorization", "proxy-authenticate",
}


def _audit_path() -> Path:
    root = Path(os.environ.get("CLODIA_VAULT_DIR") or (Path.home() / ".clodia"))
    return root / "web-post-audit.log"


def _safe_url(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(str(url or "").strip())
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("url deve usare http o https")
    if not parsed.hostname:
        raise ValueError("url privo di host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("credenziali nell'URL non consentite; usa headers")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    # Query e fragment possono contenere segreti: il gate/audit mostra solo la
    # destinazione operativa. La richiesta usa comunque l'URL originale.
    display = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
    return display, parsed.hostname, port


def _payload(arguments: dict) -> tuple[bytes, str]:
    has_json = "json" in arguments
    has_body = "body" in arguments
    if has_json and has_body:
        raise ValueError("specifica solo uno tra json e body")
    if has_json:
        raw = json.dumps(arguments["json"], ensure_ascii=False, separators=(",", ":")).encode()
        content_type = "application/json"
    else:
        body = arguments.get("body", "")
        if not isinstance(body, str):
            raise ValueError("body deve essere una stringa")
        raw = body.encode("utf-8")
        content_type = "text/plain; charset=utf-8"
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError(f"payload oltre il limite di {MAX_REQUEST_BYTES} byte")
    return raw, content_type


def _headers(arguments: dict, default_content_type: str) -> dict[str, str]:
    supplied = arguments.get("headers") or {}
    if not isinstance(supplied, dict):
        raise ValueError("headers deve essere un oggetto")
    headers: dict[str, str] = {}
    for key, value in supplied.items():
        name = str(key).strip()
        if name.lower() in _FORBIDDEN_HEADERS:
            raise ValueError(f"header non consentito: {name}")
        if "\r" in name or "\n" in name or "\r" in str(value) or "\n" in str(value):
            raise ValueError("newline negli header non consentita")
        headers[name] = str(value)
    if not any(key.lower() == "content-type" for key in headers):
        headers["Content-Type"] = default_content_type
    return headers


def _resolved_ips(host: str, port: int) -> list[str]:
    return sorted({
        row[4][0] for row in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    })


def gate_summary(arguments: dict) -> str:
    """Validate the request and provide non-secret context for the human gate."""
    display, host, port = _safe_url(arguments.get("url", ""))
    raw, content_type = _payload(arguments)
    headers = _headers(arguments, content_type)
    header_names = sorted(headers)
    effective_content_type = next(
        (value for key, value in headers.items() if key.lower() == "content-type"),
        content_type,
    )
    return (
        f"POST {display} (host={host}, port={port}); "
        f"payload={len(raw)} bytes, content-type={effective_content_type}; "
        f"headers={','.join(header_names)}"
    )


def _audit(agent: str, target: str, result: str, **extra) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "agent": agent,
        "action": "web.post",
        "target": target,
        "result": result,
        **extra,
    }
    try:
        path = _audit_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


def post(arguments: dict, *, agent: str) -> dict:
    url = str(arguments.get("url") or "").strip()
    display, host, port = _safe_url(url)
    raw, content_type = _payload(arguments)
    headers = _headers(arguments, content_type)
    ips: list[str] = []
    timeout = min(
        max(float(arguments.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)), 0.1),
        DEFAULT_TIMEOUT_SECONDS,
    )
    try:
        ips = _resolved_ips(host, port)
        with httpx.Client(follow_redirects=False, timeout=timeout) as client:
            with client.stream("POST", url, content=raw, headers=headers) as response:
                chunks: list[bytes] = []
                captured = 0
                truncated = False
                for chunk in response.iter_bytes():
                    remaining = MAX_RESPONSE_BYTES - captured
                    if len(chunk) > remaining:
                        chunks.append(chunk[:remaining])
                        captured += remaining
                        truncated = True
                        break
                    chunks.append(chunk)
                    captured += len(chunk)
                status = response.status_code
                response_headers = dict(response.headers)
        text = b"".join(chunks).decode("utf-8", errors="replace")
        _audit(agent, display, "OK", status=status,
               request_bytes=len(raw), response_bytes=captured,
               response_truncated=truncated, resolved_ips=ips)
        return {
            "ok": 200 <= status < 300,
            "status": status,
            "url": display,
            "resolved_ips": ips,
            "headers": {
                key: value for key, value in response_headers.items()
                if key.lower() in {"content-type", "content-length", "date"}
            },
            "body": text,
            "truncated": truncated,
            "response_bytes": captured,
        }
    except Exception as exc:
        _audit(agent, display, "ERROR", error=type(exc).__name__,
               request_bytes=len(raw), resolved_ips=ips)
        raise

"""The forms an «Add MCP server» input can take (clodia-platform#632).

Besides an `mcp.json` (`{"mcpServers": {…}}`), two forms are accepted and
turned into the same `http` backend entry:

- **a bare URL** (`https://mcp.clickup.com/mcp`): most remote MCP servers are
  published that way. The name comes from the host (`clickup`) unless given.
- **`mcp-remote`**: an entry whose command is `npx [-y] mcp-remote <url>` (or
  `mcp-remote <url>`) is the stdio wrapper many install docs give for a remote
  server. Run inside the gateway it starts its own OAuth client, prints the
  consent link to a log nobody reads and waits on a localhost callback a
  browser cannot reach (observed 29 Oct 2026). It is translated to the `http`
  backend on `<url>` instead, which the platform's own OAuth flow serves.
  What does not map is refused with a message, never dropped silently.

What happens after — OAuth detection, credentials, ownership — is the mount's
job (`tools_api.register_mcp_core`), the same for every form.
"""
from __future__ import annotations

import ipaddress
import json
import re
from urllib.parse import urlsplit


class McpInputError(ValueError):
    """The input cannot be turned into an `mcpServers` config."""


#: Labels that say «this is an API host», not whose it is.
_GENERIC_LABELS = {"mcp", "api", "www", "app", "server", "remote", "sse"}
_PLACEHOLDER = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}")
_MCP_REMOTE = re.compile(r"^mcp-remote(@[\w.\-]+)?$")


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_url(url: str) -> str:
    """An MCP endpoint the gateway may call: `https://`, or `http://` on a
    loopback host (development). Returns it stripped."""
    u = str(url or "").strip()
    p = urlsplit(u)
    host = (p.hostname or "").lower()
    if not host:
        raise McpInputError(f"URL non valido: {u!r}")
    if p.scheme == "https":
        return u
    if p.scheme == "http" and _is_loopback(host):
        return u
    raise McpInputError(f"serve un URL https:// (http solo in locale): {u!r}")


def name_from_url(url: str) -> str:
    """`https://mcp.clickup.com/mcp` → `clickup`; `https://example.org` →
    `example`. The first label of the host that is not a generic API word,
    the TLD excluded."""
    host = (urlsplit(url).hostname or "").lower()
    labels = [x for x in host.split(".") if x]
    if len(labels) > 1:
        labels = labels[:-1]          # the TLD names nobody
    for label in labels:
        if label not in _GENERIC_LABELS:
            return label
    return labels[0] if labels else "mcp"


def _from_mcp_remote(name: str, spec: dict) -> tuple[dict, str] | None:
    """The `http` entry for an `mcp-remote` wrapper, or None if `spec` is not
    one. Refuses what does not map."""
    cmd = str(spec.get("command") or "").strip()
    args = [str(a) for a in (spec.get("args") or [])]
    base = cmd.rsplit("/", 1)[-1]
    if base == "npx":
        rest = [a for a in args if a not in ("-y", "--yes")]
        if not rest or not _MCP_REMOTE.match(rest[0]):
            return None
        rest = rest[1:]
    elif _MCP_REMOTE.match(base):
        rest = args
    else:
        return None
    if not rest:
        raise McpInputError(f"server '{name}': mcp-remote senza URL")
    url = check_url(rest[0])
    headers: dict[str, str] = {}
    i = 1
    while i < len(rest):
        flag = rest[i]
        if flag == "--header" and i + 1 < len(rest):
            key, sep, value = rest[i + 1].partition(":")
            if not sep or not key.strip():
                raise McpInputError(f"server '{name}': header non valido {rest[i + 1]!r}")
            value = value.strip()
            if not _PLACEHOLDER.search(value):
                # A literal credential in a config would end up in the
                # gateway's config file: the mcp.json form with a `${NAME}`
                # placeholder sends it to the vault instead.
                raise McpInputError(
                    f"server '{name}': l'header {key.strip()!r} contiene un valore "
                    f"letterale; usa un segnaposto (es. \"{key.strip()}: Bearer "
                    f"${{TOKEN}}\") così il segreto va nel vault")
            headers[key.strip()] = value
            i += 2
            continue
        raise McpInputError(
            f"server '{name}': l'opzione di mcp-remote {flag!r} non ha un "
            f"equivalente nel backend http; monta il server per URL")
    if spec.get("env"):
        raise McpInputError(
            f"server '{name}': mcp-remote con 'env' non si traduce; monta il "
            f"server per URL (le credenziali col «Connetti»)")
    entry: dict = {"url": url}
    if headers:
        entry["headers"] = headers
    if spec.get("auth") is not None:
        entry["auth"] = spec["auth"]
    return entry, f"{name}: mcp-remote tradotto nel backend http {url} (nessun processo avviato)"


def normalize(config, name: str | None = None) -> tuple[dict, list[str]]:
    """Any accepted input → `({"mcpServers": {…}}, notes)`.

    `config`: an `mcp.json` (dict or JSON text) or a bare URL. `name`: the
    server's name for a URL (default: from the host). `notes` says what was
    translated, for the dialog. An `mcp.json` without wrappers comes back
    unchanged, so the existing forms behave as before."""
    notes: list[str] = []
    cfg = config
    if isinstance(cfg, str):
        text = cfg.strip()
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", text):
            url = check_url(text)
            server = (str(name).strip() if name else "") or name_from_url(url)
            notes.append(f"{server}: registrato dal suo URL come backend http")
            return {"mcpServers": {server: {"url": url}}}, notes
        try:
            cfg = json.loads(text)
        except Exception:
            raise McpInputError("serve un mcp.json o un URL https://")
    servers = cfg.get("mcpServers") if isinstance(cfg, dict) else None
    if not isinstance(servers, dict) or not servers:
        raise McpInputError("manca l'oggetto mcpServers nel config")
    out: dict = {}
    for server, spec in servers.items():
        if isinstance(spec, dict) and spec.get("command"):
            translated = _from_mcp_remote(str(server), spec)
            if translated is not None:
                out[server], note = translated
                notes.append(note)
                continue
        out[server] = spec
    return {**cfg, "mcpServers": out}, notes

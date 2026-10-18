"""The value transforms a verb mapping may name, implemented by the GATEWAY.

A `template:` builds a URI out of a value; these three do the part a template
cannot — lowercase a host, drop a port, resolve a repository shorthand. They are
a closed list (`manifest.NORMALISERS`) and they live here rather than in the
manifest grammar for one reason: a pack that could supply the transform would be
deciding what a URL means on this instance, which is exactly the authority the
schema refuses it for `https:` (clodia-platform#516, «known gaps», answered by
#518 with the tables in front of us).

Each takes the raw value of the mapping's argument plus the whole argument dict,
and returns the values the URI template is then applied to. Returning an empty
list means «no destination readable from the arguments», which upstream turns
into UNKNOWN and denies the call — never into «no destination».
"""
from __future__ import annotations

from typing import Callable
from urllib.parse import urlsplit


def url_origin(value: str, arguments: dict) -> list[str]:
    """`https://Example.IT:443/a?q=1` → `https://example.it/`.

    The destination of an HTTP call reduced to scheme and host. On TLS the path
    is not visible to a proxy anyway, and a whitelist promising a granularity it
    does not have is worse than one that states its own.
    """
    url = (value or "").strip()
    if not url:
        return []
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    return [f"{parts.scheme or 'https'}://{host}/"] if host else []


def repo_url(value: str, arguments: dict) -> list[str]:
    """A repository as the gateway's own verbs pass it: one whole URL.

    `github.pull_request` sends `repo` already shaped as a URL and `github.push`
    does not send it at all — the caller resolves the remote and adds it. What
    «the shape of a repository» is, `normalize_repo` decides, and it decides
    alone: a second definition here would drift from it at the first change, and
    it already did once with the `owner/repo` shorthand (accepted by the verb,
    dropped before reaching the check, denied as «destination unreadable»).

    `file://` is not an exit, it is the gateway's own filesystem:
    `normalize_repo` refuses it already, but only while `ALLOW_LOCAL_REPOS`
    stays shut, and «unreadable ⇒ denied» must not depend on a test seam.
    """
    raw = (value or "").strip()
    if not raw:
        return []
    try:
        from ..tools.github_repo import normalize_repo
        dest = normalize_repo(raw).lower()
    except Exception:  # noqa: BLE001 — not a repository: unreadable
        return []
    return [dest] if dest.startswith(("http://", "https://")) else []


def repo_pair(value: str, arguments: dict) -> list[str]:
    """`owner` + `repo`, the way the GitHub MCP backend passes them."""
    owner = str((arguments or {}).get("owner") or "").strip()
    repo = str(value or "").strip()
    if not (owner and repo):
        return []
    return [f"https://github.com/{owner}/{repo}".lower()]


def address_of(header: str) -> str:
    """`Nome <a@b.it>` → `a@b.it`. A pure function, so the parsing is testable
    without a mailbox.

    The FIRST address of the header, parsed as RFC 5322 (`getaddresses`), and
    nothing else: it is the same rule the mail client uses to pick the reply
    recipient, so the PDP judges exactly the address the reply goes to
    (clodia-platform#559 — «evil@x.com, Ok <ok@vetted.it>» was judged as
    ok@vetted.it and sent to evil@x.com)."""
    from email.utils import getaddresses
    for _name, addr in getaddresses([header or ""]):
        addr = addr.strip().strip('"').strip("'").lower()
        if "@" in addr:
            return addr
    return ""


def email_from(value: str, data: dict) -> list[str]:
    """The sender of a mail that was read, out of the ANSWER of the call.

    Two shapes, because two verbs answer differently (`{"from": …}` and
    `{"message": {"from": …}}`), and a header that carries a display name is
    reduced to the address. Nothing readable ⇒ no source ⇒ the read is treated
    as unvetted, which is the prudent direction: a read whose provenance we do
    not know is not a trusted read.
    """
    raw = str(value or "")
    if not raw:
        raw = str(((data or {}).get("message") or {}).get("from") or "")
    addr = address_of(raw)
    return [addr] if addr else []


_BY_NAME: dict[str, Callable[[str, dict], list[str]]] = {
    "url_origin": url_origin,
    "repo_url": repo_url,
    "repo_pair": repo_pair,
    "email_from": email_from,
}


def apply(name: str, value: str, arguments: dict) -> list[str]:
    """Run the named transform. An unknown name yields no destination.

    Unknown cannot happen through the grammar — `NORMALISERS` is checked at load
    — and if it ever did, the safe answer is «unreadable», i.e. denied.
    """
    fn = _BY_NAME.get(name)
    return fn(value, arguments or {}) if fn else []

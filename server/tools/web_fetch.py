"""HTTP GET tool — reading the open web THROUGH the gateway.

Why this exists. The runtime's own `WebFetch`/`WebSearch` do not pass here: the
provider executes them inside the conversation with the API, so no rule of ours
is consulted and no taint is lit (measured 12 Aug 2026, archseed). An agent that
reads the web that way has the capability without the control that makes it
acceptable. This verb is the arbitrated way in: the URL is an argument, so
`_source_vetted` can weigh it against `ingress`, and `taint.py` already lists
`web.fetch` among the prefixes that contaminate a channel.

Not gated, and deliberately so: reading does not cross a boundary outwards. The
control on the way in is the SOURCE list — a vetted source does not contaminate,
an unknown one does, and the gate then falls on whatever tries to LEAVE.

Two limits are load-bearing rather than prudent:

1. **Redirects are refused, not followed.** The taint is decided on the URL that
   was asked for. A vetted host that bounces to an unvetted one would be judged
   on the first and read from the second — the source list would say "trusted"
   about bytes nobody vetted. The redirect comes back as a result, with its
   Location, so the caller can ask for the new URL explicitly and have it
   weighed on its own merits.
2. **Private destinations are refused.** `web.post` can allow them because a
   human approves each invocation and IS the SSRF control. Nothing approves a
   fetch, so the check has to live in the code: loopback, RFC1918, link-local
   (169.254.169.254 is the cloud metadata endpoint) and the other reserved
   ranges are denied on every resolved address.

Known limit, stated rather than papered over: the addresses are resolved here
and resolved again by the HTTP client, so a name that answers differently
between the two calls (DNS rebinding) is not covered. Closing it means pinning
the connection to the address already vetted, which is a change to the transport
and not to this check.
"""
from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import socket
from urllib.parse import urlsplit, urlunsplit

import httpx


#: Quanto entra nel CONTESTO per default. Non è «quanto è grande una pagina» —
#: quello era il criterio con cui l'avevo scelto, ed era sbagliato. Un risultato
#: di tool entra nella conversazione della sessione e ci RESTA: costa una volta
#: per essere prodotto e N volte per essere riletto, una per ogni round trip
#: successivo del turno. 512 KB sono ~130.000 token riletti a ogni azione: per un
#: digest che legge venticinque fonti il conto è la ragione per cui un turno
#: prende minuti (clodia-platform#228).
#:
#: 64 KB (~16.000 token) bastano per un feed e per la parte utile di quasi ogni
#: pagina. Chi ha bisogno del resto lo chiede con `max_bytes`, e allora è una
#: decisione visibile invece del default.
DEFAULT_RESPONSE_BYTES = 64 * 1024
#: Tetto fisico: oltre questo non si va nemmeno chiedendolo. Resta il valore di
#: prima, così `max_bytes` copre i casi che prima funzionavano.
MAX_RESPONSE_BYTES = 512 * 1024
DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_TIMEOUT_SECONDS = 30.0

#: Types whose body is text an agent can read. A feed, a page, an API answer.
#: Anything else (an archive, an image, a binary) would arrive as replacement
#: characters and spend the response budget saying nothing.
_ALLOWED_CONTENT = ("text/", "application/json", "application/xml",
                    "application/xhtml+xml", "application/rss+xml",
                    "application/atom+xml", "application/ld+json")

#: Content-type binari ammessi per `download()`. Whitelist esplicita e stretta
#: di proposito: qui i byte non finiscono nel contesto (vanno su scratch), ma
#: restano scaricabili solo formati che un agente ha un motivo legittimo per
#: raccogliere — non un octet-stream generico o un archivio che potrebbe
#: portare un eseguibile.
_ALLOWED_BINARY_CONTENT = ("application/pdf", "image/png", "image/jpeg",
                           "image/gif", "image/webp")

#: Tetto fisico per `download()`: qui non c'è il costo di rilettura nel
#: contesto che limita `fetch()` a 512 KB (i byte vanno su scratch, non nel
#: turno), ma resta un tetto — coerente con `_MAX_DOC_BYTES` di `memory.py` e
#: con il limite di `content_b64` in main.py, entrambi 25 MB.
DOWNLOAD_MAX_BYTES = 25 * 1024 * 1024

#: Headers worth returning: enough to judge the answer, nothing that carries
#: session state. `Set-Cookie` in particular never comes back — an agent has no
#: use for it and repeating it into the context is how it would leak onwards.
_KEPT_HEADERS = {"content-type", "content-length", "date", "last-modified",
                 "etag", "location"}

_FORBIDDEN_HEADERS = {
    "host", "content-length", "transfer-encoding", "connection",
    "proxy-authorization", "proxy-authenticate", "cookie", "authorization",
}


def _audit_path() -> Path:
    root = Path(os.environ.get("CLODIA_VAULT_DIR") or (Path.home() / ".clodia"))
    return root / "web-fetch-audit.log"


def _safe_url(url: str) -> tuple[str, str, int, str]:
    parsed = urlsplit(str(url or "").strip())
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("url deve usare http o https")
    if not parsed.hostname:
        raise ValueError("url privo di host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("credenziali nell'URL non consentite; usa headers")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    # Il display tiene il path ma non query/fragment: l'audit non deve diventare
    # un registro di parametri, che è dove finiscono i token.
    display = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
    return display, parsed.hostname, port, parsed.scheme


def _public_ips(host: str, port: int) -> list[str]:
    """Indirizzi risolti, rifiutando tutto ciò che non è instradabile su Internet.

    Fail-closed su UN SOLO indirizzo privato, non sulla maggioranza: un nome che
    risolve a un pubblico e a un privato è esattamente la forma dell'attacco, e
    accettarlo perché «uno dei due va bene» lo renderebbe una scelta del
    resolver.
    """
    try:
        rows = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise ValueError(f"host non risolvibile: {host}") from e
    ips = sorted({row[4][0] for row in rows})
    if not ips:
        raise ValueError(f"host senza indirizzi: {host}")
    for raw in ips:
        addr = ipaddress.ip_address(raw)
        if (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified):
            raise PermissionError(
                f"destinazione non pubblica ({raw}): web.fetch legge il web aperto, "
                "non la rete interna del gateway")
    return ips


def _headers(arguments: dict) -> dict[str, str]:
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
    headers.setdefault("Accept", "text/html, application/xhtml+xml, "
                                 "application/xml;q=0.9, application/json;q=0.9, */*;q=0.1")
    return headers


def _readable(content_type: str) -> bool:
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    if not ct:
        # Nessun content-type: lo si legge come testo. Un server che non lo
        # dichiara è comune fra i feed, e rifiutare sarebbe più severo del
        # rischio (il body resta comunque limitato e decodificato in modo
        # tollerante).
        return True
    return ct.startswith("text/") or ct in _ALLOWED_CONTENT or ct.endswith("+xml")


def _downloadable(content_type: str) -> bool:
    """A differenza di `_readable`, nessun default permissivo: un binario
    senza content-type dichiarato non ha modo di essere vagliato prima di
    scrivere byte su disco, quindi va rifiutato invece di essere assunto."""
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    return ct in _ALLOWED_BINARY_CONTENT


def _audit(agent: str, target: str, result: str, *, action: str = "web.fetch",
           **extra) -> None:
    record = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "agent": agent,
        "action": action,
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


def _limite(arguments: dict) -> int:
    """Byte da tenere: `max_bytes` se chiesto, entro il tetto fisico."""
    grezzo = arguments.get("max_bytes")
    if grezzo in (None, ""):
        return DEFAULT_RESPONSE_BYTES
    try:
        n = int(grezzo)
    except (TypeError, ValueError):
        raise ValueError("max_bytes deve essere un intero di byte") from None
    if n <= 0:
        raise ValueError("max_bytes deve essere positivo")
    return min(n, MAX_RESPONSE_BYTES)


def fetch(arguments: dict, *, agent: str) -> dict:
    url = str(arguments.get("url") or "").strip()
    display, host, port, _scheme = _safe_url(url)
    headers = _headers(arguments)
    limite = _limite(arguments)
    timeout = min(
        max(float(arguments.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)), 0.1),
        MAX_TIMEOUT_SECONDS,
    )
    ips: list[str] = []
    try:
        ips = _public_ips(host, port)
        with httpx.Client(follow_redirects=False, timeout=timeout) as client:
            with client.stream("GET", url, headers=headers) as response:
                status = response.status_code
                response_headers = dict(response.headers)
                content_type = response_headers.get("content-type", "")
                if not _readable(content_type):
                    response.close()
                    _audit(agent, display, "REFUSED", status=status,
                           content_type=content_type, resolved_ips=ips)
                    raise ValueError(
                        f"content-type non testuale ({content_type or 'assente'}): "
                        "web.fetch legge testo, feed e JSON")
                chunks: list[bytes] = []
                captured = 0
                truncated = False
                for chunk in response.iter_bytes():
                    remaining = limite - captured
                    if len(chunk) > remaining:
                        chunks.append(chunk[:remaining])
                        captured += remaining
                        truncated = True
                        break
                    chunks.append(chunk)
                    captured += len(chunk)
        text = b"".join(chunks).decode("utf-8", errors="replace")
        kept = {k: v for k, v in response_headers.items()
                if k.lower() in _KEPT_HEADERS}
        redirected = 300 <= status < 400
        _audit(agent, display, "OK", status=status, response_bytes=captured,
               response_truncated=truncated, resolved_ips=ips,
               content_type=content_type)
        out = {
            "ok": 200 <= status < 300,
            "status": status,
            "url": display,
            "resolved_ips": ips,
            "headers": kept,
            "body": text,
            "truncated": truncated,
            "response_bytes": captured,
        }
        if truncated:
            # Un troncamento silenzioso fa concludere all'agente che la pagina
            # finisce lì. Qui gli si dice che è tagliata E come chiedere il
            # resto, che è l'unica forma in cui un limite non diventa un errore
            # di lettura.
            out["note"] = (
                f"corpo tagliato a {captured} byte (default {DEFAULT_RESPONSE_BYTES}): "
                f"rilancia con max_bytes fino a {MAX_RESPONSE_BYTES} se serve il resto")
        if redirected:
            # Il redirect NON è seguito: dirlo esplicitamente, altrimenti un
            # corpo vuoto con status 301 si legge come «la pagina è vuota».
            out["redirect_to"] = kept.get("location", "")
            out["note"] = ("redirect non seguito: la fonte va vagliata sull'URL "
                           "che si legge davvero — richiedi esplicitamente la "
                           "destinazione se la ritieni attendibile")
        return out
    except PermissionError as exc:
        _audit(agent, display, "DENIED", error=str(exc), resolved_ips=ips)
        raise
    except ValueError:
        raise
    except Exception as exc:
        _audit(agent, display, "ERROR", error=type(exc).__name__, resolved_ips=ips)
        raise


def download(arguments: dict, *, agent: str, dest: str) -> dict:
    """Scarica un binario (PDF, immagine — vedi `_ALLOWED_BINARY_CONTENT`) da
    un URL pubblico direttamente su `dest`, un path scratch dell'agente già
    validato dal dispatch (come `gdrive.download`).

    Perché un verbo separato invece di allargare `fetch()`: qui il body non
    finisce MAI nella risposta al tool-call. `fetch()` decodifica il corpo
    come testo (`errors="replace"`) perché quel testo è ciò che il modello
    legge — su un binario produrrebbe solo caratteri di sostituzione, uno
    spreco di budget di contesto che dice nulla. Qui invece i byte vanno su
    disco e il risultato riporta solo un path e una dimensione, esattamente
    il pattern di `gdrive.download`.

    Stessi controlli di `fetch()` per la parte di rete (SSRF-guard, redirect
    rifiutati, timeout): il rischio di destinazione non cambia scaricando un
    binario invece di un testo. Cambia invece la whitelist di content-type
    (binaria e stretta, non testuale) e il tetto dimensione (25 MB fisici,
    non il 512 KB pensato per un risultato che rientra nel turno).
    """
    url = str(arguments.get("url") or "").strip()
    display, host, port, _scheme = _safe_url(url)
    headers = _headers(arguments)
    timeout = min(
        max(float(arguments.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)), 0.1),
        MAX_TIMEOUT_SECONDS,
    )
    ips: list[str] = []
    written = 0
    try:
        ips = _public_ips(host, port)
        with httpx.Client(follow_redirects=False, timeout=timeout) as client:
            with client.stream("GET", url, headers=headers) as response:
                status = response.status_code
                response_headers = dict(response.headers)
                content_type = response_headers.get("content-type", "")
                if not _downloadable(content_type):
                    response.close()
                    _audit(agent, display, "REFUSED", action="web.download",
                           status=status, content_type=content_type, resolved_ips=ips)
                    raise ValueError(
                        f"content-type non scaricabile ({content_type or 'assente'}): "
                        f"web.download accetta solo {', '.join(_ALLOWED_BINARY_CONTENT)}")
                if not (200 <= status < 300):
                    response.close()
                    _audit(agent, display, "REFUSED", action="web.download",
                           status=status, content_type=content_type, resolved_ips=ips)
                    raise ValueError(f"risposta non 2xx ({status}): nessun file scritto")
                with open(dest, "wb") as fh:
                    for chunk in response.iter_bytes():
                        written += len(chunk)
                        if written > DOWNLOAD_MAX_BYTES:
                            fh.close()
                            Path(dest).unlink(missing_ok=True)
                            _audit(agent, display, "REFUSED", action="web.download",
                                   status=status, content_type=content_type,
                                   resolved_ips=ips, at_bytes=written)
                            raise ValueError(
                                f"file oltre il tetto ({DOWNLOAD_MAX_BYTES} byte): "
                                "scaricamento interrotto, nessun file parziale lasciato")
                        fh.write(chunk)
        _audit(agent, display, "OK", action="web.download", status=status,
               content_type=content_type, resolved_ips=ips, response_bytes=written)
        return {
            "ok": True,
            "status": status,
            "url": display,
            "resolved_ips": ips,
            "content_type": content_type,
            "local_path": dest,
            "size": written,
        }
    except PermissionError as exc:
        _audit(agent, display, "DENIED", action="web.download", error=str(exc),
               resolved_ips=ips)
        raise
    except ValueError:
        raise
    except Exception as exc:
        Path(dest).unlink(missing_ok=True)
        _audit(agent, display, "ERROR", action="web.download",
               error=type(exc).__name__, resolved_ips=ips)
        raise

"""eu_corpus — retrieval sul corpus normativo UE (RAG documentale).

Proxy leggero verso il micro-servizio `eu-rag-search` (host minipc), che tiene
il modello di embedding residente e interroga pgvector. Il gateway resta
leggero (niente torch). Ritorna passaggi citabili (documento+versione+pagina).

URL del servizio da env `EU_RAG_SEARCH_URL` (default host LAN del minipc).
"""
import json
import os
import time
import urllib.parse
import urllib.request
import uuid

_BASE = os.environ.get("EU_RAG_SEARCH_URL", "http://192.168.1.45:7900").rstrip("/")
_TIMEOUT = float(os.environ.get("EU_RAG_SEARCH_TIMEOUT", "15"))
DEFAULT_COLLECTION = "eu-normativa"
# L'ingest può essere lento (estrazione+embedding di un PDF grande).
_INGEST_TIMEOUT = float(os.environ.get("EU_RAG_INGEST_TIMEOUT", "300"))
_TOKEN_FILE = os.environ.get("EU_RAG_INGEST_TOKEN_FILE", "/datadir/eu-rag-ingest-token")


def _ingest_token() -> str:
    tok = os.environ.get("EU_RAG_INGEST_TOKEN")
    if not tok and os.path.isfile(_TOKEN_FILE):
        with open(_TOKEN_FILE) as f:
            tok = f.read().strip()
    if not tok:
        raise RuntimeError("token di ingest non disponibile (EU_RAG_INGEST_TOKEN[_FILE])")
    return tok


def search(query: str, k: int = 5, doc: str | None = None,
           collection: str = DEFAULT_COLLECTION) -> dict:
    """Cerca in una collection del corpus RAG (semantico, multilingue IT/EN).

    Returns {"query", "results": [{name, version, section, page, score, text}]}.
    Ogni risultato è una citazione: cita documento+versione+pagina e leggi il
    testo per intero prima di affermare una regola (retrieval ≠ verità).
    """
    params = {"q": query, "k": max(1, min(int(k), 20)), "collection": collection}
    if doc:
        params["doc"] = doc
    url = f"{_BASE}/search?" + urllib.parse.urlencode(params)
    try:
        with urllib.request.urlopen(url, timeout=_TIMEOUT) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"eu-rag-search HTTP {e.code}: {e.read().decode('utf-8', 'ignore')[:200]}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"eu-rag-search irraggiungibile ({_BASE}): {e.reason}")


def list_documents(collection: str = DEFAULT_COLLECTION) -> dict:
    """Elenca i documenti di una collection (nome, versione, status, n. chunk)."""
    url = f"{_BASE}/documents?" + urllib.parse.urlencode({"collection": collection})
    try:
        with urllib.request.urlopen(url, timeout=_TIMEOUT) as resp:
            return json.load(resp)
    except urllib.error.URLError as e:
        raise RuntimeError(f"eu-rag-search irraggiungibile ({_BASE}): {getattr(e, 'reason', e)}")


def collections() -> dict:
    """Elenca le collection con tier e conteggi."""
    try:
        with urllib.request.urlopen(f"{_BASE}/collections", timeout=_TIMEOUT) as resp:
            return json.load(resp)
    except urllib.error.URLError as e:
        raise RuntimeError(f"eu-rag-search irraggiungibile ({_BASE}): {getattr(e, 'reason', e)}")


_tier_cache: dict = {"at": 0.0, "map": {}}


def collection_tier(collection: str) -> str:
    """Tier (SEAL-N) di una collection, con cache 30s. Default SEAL-0 se ignota
    (fail-safe verso il tier più basso: l'ACL read/write resta comunque il gate)."""
    now = time.time()
    if now - _tier_cache["at"] > 30:
        try:
            m = {c["collection"]: c.get("tier", "SEAL-0")
                 for c in collections().get("collections", [])}
            _tier_cache.update(at=now, map=m)
        except Exception:  # noqa: BLE001 — su errore infra riusa la cache
            pass
    return _tier_cache["map"].get(collection, "SEAL-0")


def remove(doc_name: str, version: str | None = None,
           collection: str = DEFAULT_COLLECTION) -> dict:
    """Rimuove un documento da una collection (o una sua versione). Distruttivo."""
    fields = {"name": doc_name, "collection": collection}
    if version:
        fields["version"] = version
    data = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        f"{_BASE}/remove", data=data, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Authorization": f"Bearer {_ingest_token()}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"eu-rag remove HTTP {e.code}: {e.read().decode('utf-8', 'ignore')[:200]}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"eu-rag remove irraggiungibile ({_BASE}): {e.reason}")


def _multipart(fields: dict, file_field: str, filename: str, content: bytes) -> tuple[bytes, str]:
    """Costruisce un body multipart/form-data (solo stdlib)."""
    boundary = "----eucorpus" + uuid.uuid4().hex
    crlf = b"\r\n"
    buf = []
    for k, v in fields.items():
        if v is None:
            continue
        buf.append(b"--" + boundary.encode())
        buf.append(f'Content-Disposition: form-data; name="{k}"'.encode())
        buf.append(b"")
        buf.append(str(v).encode())
    buf.append(b"--" + boundary.encode())
    buf.append(f'Content-Disposition: form-data; name="{file_field}"; filename="{filename}"'.encode())
    buf.append(b"Content-Type: application/pdf")
    buf.append(b"")
    buf.append(content)
    buf.append(b"--" + boundary.encode() + b"--")
    buf.append(b"")
    return crlf.join(buf), boundary


def ingest_bytes(content: bytes, filename: str, doc_name: str, version: str,
                 url: str | None = None, supersede: bool = False,
                 collection: str = DEFAULT_COLLECTION) -> dict:
    """Invia un PDF (byte) al micro-servizio per l'ingest in una collection.

    Chiamato server-side dal gateway dopo aver letto il file dal topic (i byte
    NON passano dal modello). Ritorna {status, collection, name, version, chunks}.
    """
    body, boundary = _multipart(
        {"name": doc_name, "version": version, "url": url, "collection": collection,
         "supersede": "true" if supersede else "false"},
        "file", filename, content,
    )
    req = urllib.request.Request(
        f"{_BASE}/ingest", data=body, method="POST",
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Authorization": f"Bearer {_ingest_token()}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=_INGEST_TIMEOUT) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"eu-rag ingest HTTP {e.code}: {e.read().decode('utf-8', 'ignore')[:200]}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"eu-rag ingest irraggiungibile ({_BASE}): {e.reason}")

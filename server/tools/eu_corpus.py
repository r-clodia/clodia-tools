"""eu_corpus — retrieval sul corpus normativo UE (RAG documentale).

Proxy leggero verso il micro-servizio `eu-rag-search` (host minipc), che tiene
il modello di embedding residente e interroga pgvector. Il gateway resta
leggero (niente torch). Ritorna passaggi citabili (documento+versione+pagina).

URL del servizio da env `EU_RAG_SEARCH_URL` (default host LAN del minipc).
"""
import json
import os
import urllib.parse
import urllib.request
import uuid

_BASE = os.environ.get("EU_RAG_SEARCH_URL", "http://192.168.1.45:7900").rstrip("/")
_TIMEOUT = float(os.environ.get("EU_RAG_SEARCH_TIMEOUT", "15"))
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


def search(query: str, k: int = 5, doc: str | None = None) -> dict:
    """Cerca nel corpus normativo UE (semantico, multilingue IT/EN).

    Args:
        query: domanda in linguaggio naturale (es. "i costi di un co.co.co.
               pagato a tempo sono personnel o subcontracting?").
        k: numero di passaggi da ritornare (1-20, default 5).
        doc: filtro opzionale per nome documento (es. "AGA",
             "HE-Programme-Guide", "HE-General-Annexes").

    Returns:
        {"query", "results": [{name, version, section, page, score, text}]}.
        Ogni risultato è una citazione: cita documento+versione+pagina e leggi
        il testo per intero prima di affermare una regola (retrieval ≠ verità).
    """
    params = {"q": query, "k": max(1, min(int(k), 20))}
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


def list_documents() -> dict:
    """Elenca i documenti indicizzati nel corpus (nome, versione, status, n. chunk)."""
    try:
        with urllib.request.urlopen(f"{_BASE}/documents", timeout=_TIMEOUT) as resp:
            return json.load(resp)
    except urllib.error.URLError as e:
        raise RuntimeError(f"eu-rag-search irraggiungibile ({_BASE}): {getattr(e, 'reason', e)}")


def remove(doc_name: str, version: str | None = None) -> dict:
    """Rimuove un documento dal corpus (o una sua versione). Distruttivo, token-gated."""
    fields = {"name": doc_name}
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
                 url: str | None = None, supersede: bool = False) -> dict:
    """Invia un PDF (byte) al micro-servizio per l'ingest nel corpus.

    Chiamato server-side dal gateway dopo aver letto il file dal topic (i byte
    NON passano dal modello). Ritorna {status, name, version, chunks, doc_id}.
    """
    body, boundary = _multipart(
        {"name": doc_name, "version": version, "url": url,
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

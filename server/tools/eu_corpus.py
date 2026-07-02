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

_BASE = os.environ.get("EU_RAG_SEARCH_URL", "http://192.168.1.45:7900").rstrip("/")
_TIMEOUT = float(os.environ.get("EU_RAG_SEARCH_TIMEOUT", "15"))


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

"""Backend interno del gateway per l'inventario delle collection RAG.

A differenza del verbo MCP `rag.collections` — che filtra per i grant
dell'agente chiamante (`_dispatch_rag` in `main.py`) — questa rotta serve la
pagina "Databases" della webui: un admin che deve vedere TUTTE le collection
esistenti (comprese quelle orfane, il cui pack è stato disinstallato), non
solo quelle a cui il proprio agente ha grant. Stessa distinzione già fatta per
i provider (`providers_api.py`): il consumatore è il runner di clodia-logic,
non un modello, quindi l'autorizzazione è il principal privilegiato di questa
rotta, non un grant per-risorsa.

  GET /internal/rag/collections   → {"collections": [...]}  (eu_corpus.collections(), non filtrato)
  GET /internal/rag/documents?collection=X → {"documents": [...]} (eu_corpus.list_documents)

La seconda è il contenuto della prima: una collection con «12 documenti» e
nessun modo di sapere QUALI non si può amministrare — si vede il conteggio di
ciò che è stato iniettato, non ciò che è stato iniettato (clodia-platform#342).

Sola lettura: non esiste ancora un modo di cancellare una collection (il
servizio `eu-rag-search` non espone l'endpoint — clodia-platform, decisione
9 set 2026). Aggiungere qui un DELETE quando quel servizio lo supporterà.
"""
from __future__ import annotations

import logging

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from . import internal_auth
from .tools import eu_corpus

LOG = logging.getLogger("clodia-tools.rag_api")


def _authorize(request: Request) -> tuple[str | None, JSONResponse | None]:
    payload, err = internal_auth.authorize(request, log=LOG)
    return (str(payload.get("agent") or "") if payload else None), err


async def list_collections(request: Request):
    agent, err = _authorize(request)
    if err:
        return err
    try:
        data = eu_corpus.collections()
    except RuntimeError as e:
        # Servizio eu-rag-search irraggiungibile: un errore infra, non
        # un'assenza di dati — la UI deve poterli distinguere.
        return JSONResponse({"error": str(e)}, status_code=502)
    return JSONResponse(data)


async def list_documents(request: Request):
    agent, err = _authorize(request)
    if err:
        return err
    collection = (request.query_params.get("collection") or "").strip()
    if not collection:
        # `eu_corpus.list_documents` ha un default (`eu-normativa`): senza
        # questo controllo una richiesta senza `collection` risponderebbe 200
        # con i documenti di un'ALTRA collection — un errore del chiamante
        # travestito da risposta valida, che è il modo peggiore di sbagliare.
        return JSONResponse({"error": "parametro 'collection' richiesto"},
                            status_code=400)
    try:
        data = eu_corpus.list_documents(collection)
    except RuntimeError as e:
        return JSONResponse({"error": str(e)}, status_code=502)
    return JSONResponse(data)


routes = [
    Route("/internal/rag/collections", list_collections, methods=["GET"]),
    Route("/internal/rag/documents", list_documents, methods=["GET"]),
]

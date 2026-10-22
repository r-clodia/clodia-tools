# rag-search

The RAG micro-service (pgvector + local MiniLM embeddings) behind the gateway's `rag.*` and `eu_corpus.*` verbs. Its source used to live in a topic's files on the minipc; it is versioned here since clodia-platform#600.

- `ingest.py`: PDF and text ingest, documents with provenance, collections. It is also a CLI (`python3 ingest.py --help`).
- `search_service.py`: the HTTP service (FastAPI). Embeddings are computed locally, and no text leaves the host.

## Endpoints

| route | auth |
|---|---|
| `GET /health`, `/embed`, `/embed_route` | open |
| `GET /search`, `/documents` | open, except `topic-*` collections (token) |
| `GET /collections` | open; `topic-*` collections listed only with the token |
| `POST /ingest` (PDF), `/ingest_text`, `/remove`, `/collections`, `/collections/drop` | token |

The token is `EU_RAG_INGEST_TOKEN` (service env) and `/datadir/eu-rag-ingest-token` on the gateway side.

`topic-*` collections hold a topic's conversations and files (#599). They are private because the service listens on the LAN.

Provenance (`trusted` | `untrusted` | `agent`) is stored per document and returned with every hit. The gateway turns an `untrusted` hit into taint (#602).

## Deploy (minipc)

```
cp ingest.py search_service.py ~/eu-rag/        # keep a backup of the old files
systemctl --user restart eu-rag-search
curl -s localhost:7900/health
```

The schema change is additive (`documents.provenance`, `documents.source`) and is applied on first use.

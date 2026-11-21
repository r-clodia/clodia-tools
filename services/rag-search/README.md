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
| `GET /chunks` (one document's chunks, paginated), `/export` (JSONL of a collection) | token |

The token is `EU_RAG_INGEST_TOKEN` (service env) and, on the gateway side, the file named by `EU_RAG_INGEST_TOKEN_FILE`. The platform compose sets it to `/gateway-state/eu-rag-ingest-token`, the gateway's own state directory, and its `setup.sh` generates both copies: the code default `/datadir/eu-rag-ingest-token` would sit in the datadir the agent-server also mounts.

`topic-*` collections hold a topic's conversations and files (#599). They are private because the service is reachable from the agent-server's network.

Provenance (`trusted` | `untrusted` | `agent`) is stored per document and returned with every hit. The gateway turns an `untrusted` hit into taint (#602).

## Deploy

Two services of the platform compose (clodia-platform#603), both on the internal network only, no published port:

- `rag-pg`: `pgvector/pgvector:pg16`, named volume `clodia-rag-pg`; `schema.sql` is applied on the first start (empty volume).
- `rag-search`: built from this directory (`Dockerfile`, models baked in at build time, so no internet at run time), env `EU_RAG_PG_HOST=rag-pg`, `EU_RAG_PG_PORT=5432`, `EU_RAG_PG_DB=eu_corpus`, `EU_RAG_PG_USER=clodia`, `EU_RAG_PG_PASSWORD`, `EU_RAG_INGEST_TOKEN`.

Gateway and agent-server reach it as `EU_RAG_SEARCH_URL=http://rag-search:7900`, which is also the code default.

The schema change is additive (`documents.provenance`, `documents.source`) and is applied on first use.

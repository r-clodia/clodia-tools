-- rag-search schema (clodia-platform#603). Idempotent: applied by the
-- pgvector container at first start (docker-entrypoint-initdb.d).
-- Recovered from the database that ran on the minipc (created by hand).
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS collections (
    name        text PRIMARY KEY,
    tier        text NOT NULL DEFAULT 'SEAL-0',
    created_at  timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS documents (
    id          serial PRIMARY KEY,
    name        text NOT NULL,
    version     text NOT NULL,
    source_url  text,
    hash        text,
    status      text NOT NULL DEFAULT 'active',
    ingested_at timestamptz NOT NULL DEFAULT now(),
    collection  text NOT NULL DEFAULT 'eu-normativa',
    provenance  text NOT NULL DEFAULT 'trusted',
    source      text
);
CREATE UNIQUE INDEX IF NOT EXISTS documents_collection_nv ON documents (collection, name, version);
CREATE INDEX IF NOT EXISTS documents_collection_idx ON documents (collection);

CREATE TABLE IF NOT EXISTS chunks (
    id          serial PRIMARY KEY,
    document_id integer NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    section     text,
    page        integer,
    ordinal     integer,
    text        text NOT NULL,
    embedding   vector(384) NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    collection  text NOT NULL DEFAULT 'eu-normativa'
);
CREATE INDEX IF NOT EXISTS chunks_collection_idx ON chunks (collection);
CREATE INDEX IF NOT EXISTS chunks_document_idx ON chunks (document_id);
CREATE INDEX IF NOT EXISTS chunks_embedding_idx ON chunks USING hnsw (embedding vector_cosine_ops);

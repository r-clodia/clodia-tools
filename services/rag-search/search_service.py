#!/usr/bin/env python3
"""eu-rag-search — micro-servizio HTTP di retrieval sul corpus normativo UE.

Tiene il modello MiniLM residente (una volta), embedda la query e fa cosine su
pgvector. Il gateway (container) lo chiama via GET; così torch NON deve stare
nell'immagine del gateway. Ritorna solo testo normativo pubblico + citazioni.

Avvio (systemd --user, vedi eu-rag-search.service):
  EU_RAG_PG_PASSWORD=... uvicorn search_service:app --host 0.0.0.0 --port 7900

Endpoint:
  GET /health                      → {"status":"ok","docs":N,"chunks":M}
  GET /search?q=...&k=5&doc=AGA    → {"query":..,"results":[{name,version,section,page,score,
                                      text,provenance,source}]}
  POST /ingest_text, /collections, /collections/drop   (token)

Collections named `topic-*` (a topic's own, clodia-platform#599) are private:
search and documents need the token; their names are hidden from /collections.
"""
import os
import tempfile

import psycopg
from fastapi import Body, FastAPI, File, Form, Header, HTTPException, Query, UploadFile
from sentence_transformers import SentenceTransformer

import ingest as ingest_mod

MODEL_NAME = "paraphrase-multilingual-MiniLM-L12-v2"
# Modello DEDICATO al routing del risponditore (disaccoppiato dal corpus RAG che
# resta su MiniLM). Retrieval-tuned multilingue, leggero (~0.5GB). Prefissi e5.
ROUTE_MODEL_NAME = "intfloat/multilingual-e5-small"
# Token per /ingest (scrittura sul corpus). Se non impostato, /ingest è disabilitato
# (fail-closed): l'ingest modifica la knowledge base, non va lasciato aperto.
_INGEST_TOKEN = os.environ.get("EU_RAG_INGEST_TOKEN")
_MAX_INGEST_BYTES = 100 * 1024 * 1024  # 100 MB

app = FastAPI(title="eu-rag-search", version="0.4.0")


def _authorized(authorization: str | None) -> bool:
    return bool(_INGEST_TOKEN) and authorization == f"Bearer {_INGEST_TOKEN}"


def _require_token(authorization: str | None) -> None:
    if not _INGEST_TOKEN:
        raise HTTPException(503, "scrittura disabilitata (EU_RAG_INGEST_TOKEN non impostato)")
    if not _authorized(authorization):
        raise HTTPException(401, "token non valido")


def _guard_read(collection: str, authorization: str | None) -> None:
    """A topic's collection (#599) is private: read only with the token the
    gateway holds. The service listens on the LAN; the EU corpus stays open."""
    if ingest_mod.is_private(collection) and not _authorized(authorization):
        raise HTTPException(401, "collection privata: token richiesto")
_model: SentenceTransformer | None = None
_route_model: SentenceTransformer | None = None


def _db():
    pw = os.environ.get("EU_RAG_PG_PASSWORD")
    if not pw:
        raise RuntimeError("EU_RAG_PG_PASSWORD non impostata")
    return psycopg.connect(
        host="127.0.0.1", port=5433, dbname="eu_corpus", user="clodia", password=pw
    )


@app.on_event("startup")
def _load():
    global _model, _route_model
    _model = SentenceTransformer(MODEL_NAME)
    _route_model = SentenceTransformer(ROUTE_MODEL_NAME)


def _embed(text: str) -> str:
    v = _model.encode([text], normalize_embeddings=True)[0]
    return "[" + ",".join(f"{x:.6f}" for x in v) + "]"


@app.get("/health")
def health():
    try:
        with _db() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM documents WHERE status='active'")
            docs = cur.fetchone()[0]
            cur.execute(
                "SELECT count(*) FROM chunks c JOIN documents d ON d.id=c.document_id"
                " WHERE d.status='active'"
            )
            chunks = cur.fetchone()[0]
        return {"status": "ok", "model_loaded": _model is not None, "docs": docs, "chunks": chunks}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=503, detail=str(e))


@app.get("/embed")
def embed(text: str = Query(..., min_length=1, description="testo da vettorizzare")):
    """Ritorna l embedding MiniLM (normalizzato) del testo. Usato dal router
    del risponditore: cosine == dot product perche i vettori sono unitari."""
    if _model is None:
        raise HTTPException(status_code=503, detail="modello non ancora caricato")
    v = _model.encode([text], normalize_embeddings=True)[0]
    return {"vector": [round(float(x), 6) for x in v], "dim": int(len(v))}


@app.get("/embed_route")
def embed_route(
    text: str = Query(..., min_length=1, description="testo da vettorizzare (routing)"),
    role: str = Query("query", description="query (messaggio) | passage (profilo agente)"),
):
    """Embedding per il ROUTING del risponditore con multilingual-e5-small.
    e5 richiede i prefissi: 'query:' per il messaggio, 'passage:' per i pezzi di
    profilo. Vettori normalizzati (cosine == dot)."""
    if _route_model is None:
        raise HTTPException(status_code=503, detail="modello routing non ancora caricato")
    prefix = "query: " if (role or "query").lower().startswith("q") else "passage: "
    v = _route_model.encode([prefix + text], normalize_embeddings=True)[0]
    return {"vector": [round(float(x), 6) for x in v], "dim": int(len(v)), "model": "e5-small"}


@app.get("/search")
def search(
    q: str = Query(..., min_length=2, description="query in linguaggio naturale (IT/EN)"),
    k: int = Query(5, ge=1, le=20),
    doc: str | None = Query(None, description="filtro opzionale per name del documento"),
    collection: str = Query("eu-normativa", description="collection su cui cercare"),
    authorization: str | None = Header(None),
):
    _guard_read(collection, authorization)
    if _model is None:
        raise HTTPException(status_code=503, detail="modello non ancora caricato")
    emb = _embed(q)
    with _db() as conn, conn.cursor() as cur:
        ingest_mod.ensure_schema(cur)
        conn.commit()
    sql = (
        "SELECT d.name, d.version, c.section, c.page, "
        "1 - (c.embedding <=> %s::vector) AS score, c.text, d.provenance, d.source "
        "FROM chunks c JOIN documents d ON d.id=c.document_id "
        "WHERE d.status='active' AND c.collection = %s"
    )
    params: list = [emb, collection]
    if doc:
        sql += " AND d.name = %s"
        params.append(doc)
    sql += " ORDER BY c.embedding <=> %s::vector LIMIT %s"
    params += [emb, k]
    with _db() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
    return {
        "query": q,
        "results": [
            {
                "name": name,
                "version": version,
                "section": section,
                "page": page,
                "score": round(float(score), 4),
                "text": text,
                "provenance": prov,
                "source": src,
            }
            for name, version, section, page, score, text, prov, src in rows
        ],
    }


@app.get("/documents")
def documents(collection: str = Query("eu-normativa"),
              authorization: str | None = Header(None)):
    """Elenco dei documenti di una collection (nome, versione, status, n. chunk)."""
    _guard_read(collection, authorization)
    return {"collection": collection, "documents": ingest_mod.list_documents(collection)}


@app.get("/collections")
def collections(authorization: str | None = Header(None)):
    """Elenco delle collection con tier e conteggi. Senza token, le collection
    private dei topic non compaiono (i loro nomi non sono di tutti)."""
    rows = ingest_mod.list_collections()
    if not _authorized(authorization):
        rows = [r for r in rows if not ingest_mod.is_private(r["collection"])]
    return {"collections": rows}


@app.post("/collections")
def create_collection(body: dict = Body(...), authorization: str | None = Header(None)):
    """Crea una collection o ne aggiorna il tier: {collection, tier}. Token-gated."""
    _require_token(authorization)
    name = str((body or {}).get("collection") or "").strip()
    tier = str((body or {}).get("tier") or "").strip()
    if not name or not tier:
        raise HTTPException(422, "collection e tier richiesti")
    return {"status": "ok", **ingest_mod.set_collection(name, tier)}


@app.post("/collections/drop")
def drop_collection(body: dict = Body(...), authorization: str | None = Header(None)):
    """Elimina una collection con tutti i suoi documenti: {collection}. Token-gated."""
    _require_token(authorization)
    name = str((body or {}).get("collection") or "").strip()
    if not name:
        raise HTTPException(422, "collection richiesta")
    return {"status": "ok", **ingest_mod.drop_collection(name)}


@app.post("/ingest_text")
def ingest_text(body: dict = Body(...), authorization: str | None = Header(None)):
    """Testo (o chunk già pronti) → una collection, con la provenienza del
    documento (#600): {collection, name, version, text | chunks, source?,
    provenance, tier?, supersede?}. Token-gated."""
    _require_token(authorization)
    if _model is None:
        raise HTTPException(503, "modello non ancora caricato")
    b = body or {}
    text = b.get("text")
    if text is not None and len(str(text)) > _MAX_INGEST_BYTES:
        raise HTTPException(413, "testo troppo grande")
    try:
        res = ingest_mod.ingest_text(
            str(b.get("collection") or ""), str(b.get("name") or ""),
            str(b.get("version") or "1"), text=text, chunks=b.get("chunks"),
            source=b.get("source"), provenance=str(b.get("provenance") or "trusted"),
            tier=b.get("tier"), supersede=bool(b.get("supersede")), model=_model)
    except ValueError as e:
        raise HTTPException(422, str(e))
    return {"status": "ok", **res}


@app.post("/remove")
def remove(
    name: str = Form(...),
    version: str | None = Form(None),
    collection: str = Form("eu-normativa"),
    authorization: str | None = Header(None),
):
    """Rimuove un documento (o una sua versione) da una collection. Token-gated."""
    if not _INGEST_TOKEN:
        raise HTTPException(503, "remove disabilitato (EU_RAG_INGEST_TOKEN non impostato)")
    if authorization != f"Bearer {_INGEST_TOKEN}":
        raise HTTPException(401, "token non valido")
    res = ingest_mod.remove_document(name, version, collection)
    return {"status": "ok", **res}


@app.post("/ingest")
async def ingest(
    file: UploadFile = File(...),
    name: str = Form(..., description="nome del documento (es. AGA)"),
    version: str = Form(..., description="versione (es. '2.0 (2025-04-01)')"),
    url: str | None = Form(None),
    supersede: bool = Form(False),
    collection: str = Form("eu-normativa"),
    authorization: str | None = Header(None),
):
    """Ingerisce un PDF nel corpus (embedding col modello residente + insert su
    pgvector). Protetto da bearer token: scrive sulla knowledge base."""
    if not _INGEST_TOKEN:
        raise HTTPException(503, "ingest disabilitato (EU_RAG_INGEST_TOKEN non impostato)")
    if authorization != f"Bearer {_INGEST_TOKEN}":
        raise HTTPException(401, "token di ingest non valido")
    if _model is None:
        raise HTTPException(503, "modello non ancora caricato")
    # scrive lo stream su file temporaneo (con limite di size)
    tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
    written = 0
    try:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break
            written += len(chunk)
            if written > _MAX_INGEST_BYTES:
                raise HTTPException(413, "file troppo grande (>100 MB)")
            tmp.write(chunk)
        tmp.close()
        try:
            res = ingest_mod.ingest_file(
                tmp.name, name, version, url=url, supersede=supersede,
                model=_model, log=lambda *_: None, collection=collection,
            )
        except ValueError as e:
            raise HTTPException(422, str(e))
        return {"status": "ok", **res}
    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass

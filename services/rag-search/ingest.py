#!/usr/bin/env python3
"""EU corpus ingest — PDF → section-aware chunks → MiniLM embeddings → pgvector.

Corpus normativo UE stabile (AGA, Programme Guide, General Annexes, …) per il
RAG documentale dell'agente progettazione europea.

Uso:
  EU_RAG_PG_PASSWORD=... python3 ingest.py add <pdf> \
      --name AGA --version "2.0 (2025-04-01)" --url https://... [--supersede]

  python3 ingest.py list          # elenca documenti + n. chunk
  python3 ingest.py search "..."  # test retrieval (embed query + cosine)

Idempotente: ri-ingerire la stessa (name, version) cancella e ricrea i suoi chunk.
Versionamento: con --supersede le altre versioni dello stesso `name` passano a
status='superseded' (restano nel DB, escluse di default dalla ricerca).
"""
import argparse
import hashlib
import os
import re
import sys

import psycopg
from pypdf import PdfReader
from sentence_transformers import SentenceTransformer

MODEL_NAME = "paraphrase-multilingual-MiniLM-L12-v2"  # 384-dim, come cc_index

# Target dimensione chunk (caratteri). Un chunk = pezzo di testo semanticamente
# coeso sotto una sezione; abbastanza grande da avere contesto, abbastanza
# piccolo da essere un "ago" recuperabile.
CHUNK_TARGET = 1200
CHUNK_MAX = 1800

# Euristica header di sezione. Cattura:
#   - "ARTICLE 6", "ARTICLE 6a"
#   - numerazioni "6", "6.2", "6.2.A", "6.2.A.2"
#   - "ANNEX 5", "SECTION 3"
# Il match deve stare a inizio riga ed essere seguito da spazio + testo (titolo).
HEADER_RE = re.compile(
    r"^\s*("
    r"ARTICLE\s+\d+[a-z]?"
    r"|ANNEX\s+[0-9IVX]+"
    r"|SECTION\s+\d+"
    r"|\d+(?:\.\d+){0,4}(?:\.[A-Z](?:\.\d+)?)?"
    r")\s+(?=\S)"
)


def _db():
    pw = os.environ.get("EU_RAG_PG_PASSWORD")
    if not pw:
        sys.exit("EU_RAG_PG_PASSWORD non impostata")
    return psycopg.connect(
        host="127.0.0.1", port=5433, dbname="eu_corpus", user="clodia", password=pw
    )


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def _iter_pages(path):
    reader = PdfReader(path)
    for i, page in enumerate(reader.pages, start=1):
        yield i, (page.extract_text() or "")


def _clean_section(raw):
    # normalizza il match dell'header a un id compatto (es. "6.2.A.2", "ARTICLE 6")
    return re.sub(r"\s+", " ", raw).strip()


def chunk_pdf(path):
    """Ritorna lista di dict {section, page, ordinal, text}."""
    chunks = []
    current_section = None
    buf = []
    buf_len = 0
    buf_page = 1
    buf_section = None
    ordinal = 0

    def flush():
        nonlocal buf, buf_len, ordinal
        text = " ".join(buf).strip()
        buf = []
        buf_len = 0
        if not text:
            return
        chunks.append(
            {
                "section": buf_section,
                "page": buf_page,
                "ordinal": ordinal,
                "text": text,
            }
        )
        ordinal += 1

    for page_no, page_text in _iter_pages(path):
        for line in page_text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            m = HEADER_RE.match(stripped)
            if m and len(stripped) < 120:
                # nuova sezione: chiudi il buffer corrente prima di cambiare
                flush()
                current_section = _clean_section(m.group(1))
            if not buf:
                buf_page = page_no
                buf_section = current_section
            buf.append(stripped)
            buf_len += len(stripped) + 1
            if buf_len >= CHUNK_TARGET:
                # chiudi al raggiungimento del target (salvo header appena aperto)
                flush()
                buf_page = page_no
                buf_section = current_section
    flush()

    # merge di chunk minuscoli col precedente (rumore da estrazione PDF)
    merged = []
    for c in chunks:
        if merged and len(c["text"]) < 120 and merged[-1]["section"] == c["section"]:
            if len(merged[-1]["text"]) + len(c["text"]) < CHUNK_MAX:
                merged[-1]["text"] += " " + c["text"]
                continue
        merged.append(c)
    for i, c in enumerate(merged):
        c["ordinal"] = i
    return merged


DEFAULT_COLLECTION = "eu-normativa"

#: Provenance of a document (clodia-platform#600): what reading it means for the
#: taint of the session that retrieves it. Same labels as the topic files.
PROVENANCES = ("trusted", "untrusted", "agent")

#: Collections whose content is private to a topic (#599): read only with the
#: service token. The EU corpus stays public on the LAN, as before.
PRIVATE_PREFIX = "topic-"


def is_private(collection):
    return str(collection or "").startswith(PRIVATE_PREFIX)


_SCHEMA_DONE = False


def ensure_schema(cur):
    """Additive migration, idempotent: provenance and source per document."""
    global _SCHEMA_DONE
    if _SCHEMA_DONE:
        return
    cur.execute("ALTER TABLE documents ADD COLUMN IF NOT EXISTS provenance text "
                "NOT NULL DEFAULT 'trusted'")
    cur.execute("ALTER TABLE documents ADD COLUMN IF NOT EXISTS source text")
    cur.connection.commit()
    _SCHEMA_DONE = True


def _ensure_collection(cur, collection, tier="SEAL-0"):
    cur.execute(
        "INSERT INTO collections (name, tier) VALUES (%s,%s) ON CONFLICT (name) DO NOTHING",
        (collection, tier),
    )


def create_collection(collection, tier):
    """Create a collection; an existing one keeps its tier (create-only)."""
    with _db() as conn, conn.cursor() as cur:
        cur.execute("INSERT INTO collections (name, tier) VALUES (%s,%s) "
                    "ON CONFLICT (name) DO NOTHING", (collection, tier))
        cur.execute("SELECT tier FROM collections WHERE name=%s", (collection,))
        current = cur.fetchone()[0]
        conn.commit()
    return {"collection": collection, "tier": current}


def set_collection_tier(collection, tier):
    """Set a collection's tier, creating it if needed: a topic's collection
    follows its topic's re-tiering (#599). A separate call from creation."""
    with _db() as conn, conn.cursor() as cur:
        cur.execute(
            "INSERT INTO collections (name, tier) VALUES (%s,%s) "
            "ON CONFLICT (name) DO UPDATE SET tier=EXCLUDED.tier",
            (collection, tier),
        )
        conn.commit()
    return {"collection": collection, "tier": tier}


def drop_collection(collection):
    """Every document of a collection (chunks by cascade), then the collection."""
    with _db() as conn, conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM documents WHERE collection=%s", (collection,))
        n = cur.fetchone()[0]
        cur.execute("DELETE FROM documents WHERE collection=%s", (collection,))
        cur.execute("DELETE FROM collections WHERE name=%s", (collection,))
        conn.commit()
    return {"collection": collection, "documents_removed": n}


def chunk_text(text, target=CHUNK_TARGET, hard=CHUNK_MAX):
    """Plain text → chunks of about `target` characters, cut at paragraph,
    then line, then sentence boundaries; never longer than `hard`."""
    paras = [p.strip() for p in re.split(r"\n\s*\n", text or "") if p.strip()]
    pieces = []
    for p in paras:
        if len(p) <= hard:
            pieces.append(p)
            continue
        for part in re.split(r"(?<=[.!?])\s+|\n", p):
            part = part.strip()
            while len(part) > hard:
                pieces.append(part[:hard])
                part = part[hard:]
            if part:
                pieces.append(part)
    chunks, buf = [], ""
    for piece in pieces:
        if buf and len(buf) + 1 + len(piece) > target:
            chunks.append(buf)
            buf = piece
        else:
            buf = f"{buf}\n{piece}" if buf else piece
    if buf:
        chunks.append(buf)
    return [{"section": None, "page": None, "ordinal": i, "text": c}
            for i, c in enumerate(chunks)]


def ingest_text(collection, name, version, text=None, chunks=None, source=None,
                provenance="trusted", tier=None, supersede=False, model=None):
    """Text (or ready chunks [{text, section?}]) → embeddings → pgvector, as one
    document with its provenance (#600). Idempotent per (collection, name,
    version). Returns {collection, name, version, chunks, doc_id}."""
    if provenance not in PROVENANCES:
        raise ValueError(f"provenance: {', '.join(PROVENANCES)}")
    if chunks:
        items = [{"section": c.get("section"), "page": None, "ordinal": i,
                  "text": str(c.get("text") or "").strip()}
                 for i, c in enumerate(chunks) if str(c.get("text") or "").strip()]
    else:
        items = chunk_text(text or "")
    if not items:
        raise ValueError("nessun testo da indicizzare")
    digest = hashlib.sha256("\n\x00".join(c["text"] for c in items).encode()).hexdigest()
    if model is None:
        model = SentenceTransformer(MODEL_NAME)
    vecs = model.encode([c["text"] for c in items], normalize_embeddings=True, batch_size=32)
    with _db() as conn, conn.cursor() as cur:
        ensure_schema(cur)
        _ensure_collection(cur, collection, tier or "SEAL-4")
        if supersede:
            cur.execute("UPDATE documents SET status='superseded' "
                        "WHERE collection=%s AND name=%s AND version<>%s",
                        (collection, name, version))
        cur.execute(
            """INSERT INTO documents (collection, name, version, source_url, hash, status,
                                      provenance, source)
               VALUES (%s,%s,%s,NULL,%s,'active',%s,%s)
               ON CONFLICT (collection, name, version)
               DO UPDATE SET hash=EXCLUDED.hash, status='active', ingested_at=now(),
                             provenance=EXCLUDED.provenance, source=EXCLUDED.source
               RETURNING id""",
            (collection, name, version, digest, provenance, source))
        doc_id = cur.fetchone()[0]
        cur.execute("DELETE FROM chunks WHERE document_id=%s", (doc_id,))
        for c, v in zip(items, vecs):
            emb = "[" + ",".join(f"{x:.6f}" for x in v) + "]"
            cur.execute(
                """INSERT INTO chunks (document_id, collection, section, page, ordinal, text, embedding)
                   VALUES (%s,%s,%s,%s,%s,%s,%s::vector)""",
                (doc_id, collection, c["section"], c["page"], c["ordinal"], c["text"], emb))
        conn.commit()
    return {"collection": collection, "name": name, "version": version,
            "chunks": len(items), "doc_id": doc_id}


def ingest_file(path, name, version, url=None, supersede=False, model=None,
                log=print, collection=DEFAULT_COLLECTION, provenance="trusted"):
    """Ingerisce un PDF in una collection del corpus. Riusabile da CLI e dal
    micro-servizio (che passa il proprio `model` residente). Ritorna
    {collection, name, version, chunks, doc_id}. ValueError se il PDF è vuoto."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"file non trovato: {path}")
    log(f"[1/4] hash + estrazione: {os.path.basename(path)}")
    digest = _sha256(path)
    chunks = chunk_pdf(path)
    if not chunks:
        raise ValueError("nessun chunk estratto (PDF vuoto o non testuale?)")
    log(f"      {len(chunks)} chunk estratti")

    if model is None:
        log(f"[2/4] carico modello {MODEL_NAME} …")
        model = SentenceTransformer(MODEL_NAME)
    log("[3/4] embedding …")
    vecs = model.encode(
        [c["text"] for c in chunks], normalize_embeddings=True, batch_size=32
    )

    if provenance not in PROVENANCES:
        raise ValueError(f"provenance: {', '.join(PROVENANCES)}")
    log("[4/4] scrittura su pgvector …")
    with _db() as conn, conn.cursor() as cur:
        ensure_schema(cur)
        _ensure_collection(cur, collection)
        if supersede:
            cur.execute(
                "UPDATE documents SET status='superseded' "
                "WHERE collection=%s AND name=%s AND version<>%s",
                (collection, name, version),
            )
        cur.execute(
            """INSERT INTO documents (collection, name, version, source_url, hash, status,
                                      provenance)
               VALUES (%s,%s,%s,%s,%s,'active',%s)
               ON CONFLICT (collection, name, version)
               DO UPDATE SET source_url=EXCLUDED.source_url, hash=EXCLUDED.hash,
                             status='active', ingested_at=now(),
                             provenance=EXCLUDED.provenance
               RETURNING id""",
            (collection, name, version, url, digest, provenance),
        )
        doc_id = cur.fetchone()[0]
        cur.execute("DELETE FROM chunks WHERE document_id=%s", (doc_id,))
        for c, v in zip(chunks, vecs):
            emb = "[" + ",".join(f"{x:.6f}" for x in v) + "]"
            cur.execute(
                """INSERT INTO chunks (document_id, collection, section, page, ordinal, text, embedding)
                   VALUES (%s,%s,%s,%s,%s,%s,%s::vector)""",
                (doc_id, collection, c["section"], c["page"], c["ordinal"], c["text"], emb),
            )
        conn.commit()
    return {"collection": collection, "name": name, "version": version,
            "chunks": len(chunks), "doc_id": doc_id}


def cmd_add(args):
    res = ingest_file(args.pdf, args.name, args.version, url=args.url,
                      supersede=args.supersede, collection=args.collection)
    print(f"OK — [{res['collection']}] {res['name']} {res['version']}: "
          f"{res['chunks']} chunk (doc_id={res['doc_id']})")


def list_documents(collection=DEFAULT_COLLECTION):
    """Documenti di una collection: [{name, version, status, chunks,
    source_url, ingested_at}]. Riusabile da CLI e micro-servizio."""
    with _db() as conn, conn.cursor() as cur:
        ensure_schema(cur)
        cur.execute(
            """SELECT d.name, d.version, d.status, count(c.id), d.source_url, d.ingested_at,
                      d.provenance, d.source
               FROM documents d LEFT JOIN chunks c ON c.document_id=d.id
               WHERE d.collection=%s
               GROUP BY d.id ORDER BY d.name, d.version""",
            (collection,),
        )
        rows = cur.fetchall()
    return [
        {"name": n, "version": v, "status": s, "chunks": cnt,
         "source_url": url, "ingested_at": ts.isoformat() if ts else None,
         "provenance": prov, "source": src}
        for n, v, s, cnt, url, ts, prov, src in rows
    ]


def list_collections():
    """Elenco collection: [{collection, tier, documents, chunks}]."""
    with _db() as conn, conn.cursor() as cur:
        cur.execute(
            """SELECT col.name, col.tier,
                      count(DISTINCT d.id) AS docs, count(c.id) AS chunks
               FROM collections col
               LEFT JOIN documents d ON d.collection=col.name
               LEFT JOIN chunks c ON c.document_id=d.id
               GROUP BY col.name, col.tier ORDER BY col.name"""
        )
        return [{"collection": n, "tier": t, "documents": docs, "chunks": ch}
                for n, t, docs, ch in cur.fetchall()]


def remove_document(name, version=None, collection=DEFAULT_COLLECTION):
    """Rimuove un documento da una collection (cascade sui chunk). Se version è
    None, rimuove TUTTE le versioni di `name` in quella collection.
    Ritorna {removed: [{collection, name, version, chunks}]}."""
    with _db() as conn, conn.cursor() as cur:
        if version is None:
            cur.execute(
                """SELECT d.version, count(c.id) FROM documents d
                   LEFT JOIN chunks c ON c.document_id=d.id
                   WHERE d.collection=%s AND d.name=%s GROUP BY d.version""",
                (collection, name))
            victims = [{"collection": collection, "name": name, "version": v, "chunks": cnt}
                       for v, cnt in cur.fetchall()]
            cur.execute("DELETE FROM documents WHERE collection=%s AND name=%s",
                        (collection, name))
        else:
            cur.execute(
                """SELECT count(c.id) FROM documents d
                   LEFT JOIN chunks c ON c.document_id=d.id
                   WHERE d.collection=%s AND d.name=%s AND d.version=%s GROUP BY d.id""",
                (collection, name, version))
            row = cur.fetchone()
            victims = ([{"collection": collection, "name": name, "version": version,
                         "chunks": row[0]}] if row else [])
            cur.execute("DELETE FROM documents WHERE collection=%s AND name=%s AND version=%s",
                        (collection, name, version))
        conn.commit()
    return {"removed": victims}


def cmd_list(args):
    docs = list_documents(args.collection)
    if not docs:
        print(f"(collection '{args.collection}' vuota)")
        return
    for d in docs:
        flag = "" if d["status"] == "active" else f" [{d['status']}]"
        ts = (d["ingested_at"] or "")[:10]
        print(f"{d['name']:20} {d['version']:22} {d['chunks']:5} chunk  {ts}{flag}")


def cmd_collections(args):
    for c in list_collections():
        print(f"{c['collection']:22} {c['tier']:8} {c['documents']:3} doc  {c['chunks']:6} chunk")


def cmd_remove(args):
    res = remove_document(args.name, args.version, args.collection)
    if not res["removed"]:
        print(f"nessun documento '{args.name}' in '{args.collection}'")
        return
    for r in res["removed"]:
        print(f"rimosso [{r['collection']}]: {r['name']} {r['version']} ({r['chunks']} chunk)")


def cmd_search(args):
    model = SentenceTransformer(MODEL_NAME)
    q = model.encode([args.query], normalize_embeddings=True)[0]
    emb = "[" + ",".join(f"{x:.6f}" for x in q) + "]"
    with _db() as conn, conn.cursor() as cur:
        cur.execute(
            """SELECT d.name, d.version, c.section, c.page,
                      1 - (c.embedding <=> %s::vector) AS score, c.text
               FROM chunks c JOIN documents d ON d.id=c.document_id
               WHERE d.status='active' AND c.collection=%s
               ORDER BY c.embedding <=> %s::vector
               LIMIT %s""",
            (emb, args.collection, emb, args.k),
        )
        rows = cur.fetchall()
    for name, version, section, page, score, text in rows:
        print(f"\n── {name} {version} · §{section or '?'} · p.{page} · score={score:.3f}")
        print(text[:400] + ("…" if len(text) > 400 else ""))


def main():
    ap = argparse.ArgumentParser(description="EU corpus ingest → pgvector")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("add", help="ingerisci un PDF")
    a.add_argument("pdf")
    a.add_argument("--name", required=True)
    a.add_argument("--version", required=True)
    a.add_argument("--url", default=None)
    a.add_argument("--collection", default=DEFAULT_COLLECTION)
    a.add_argument("--supersede", action="store_true",
                   help="marca superseded le altre versioni dello stesso name")
    a.set_defaults(func=cmd_add)

    l = sub.add_parser("list", help="elenca documenti di una collection")
    l.add_argument("--collection", default=DEFAULT_COLLECTION)
    l.set_defaults(func=cmd_list)

    cl = sub.add_parser("collections", help="elenca le collection")
    cl.set_defaults(func=cmd_collections)

    rm = sub.add_parser("remove", help="rimuovi un documento")
    rm.add_argument("--name", required=True)
    rm.add_argument("--version", default=None, help="se omesso, rimuove tutte le versioni")
    rm.add_argument("--collection", default=DEFAULT_COLLECTION)
    rm.set_defaults(func=cmd_remove)

    s = sub.add_parser("search", help="test retrieval")
    s.add_argument("query")
    s.add_argument("-k", type=int, default=5)
    s.add_argument("--collection", default=DEFAULT_COLLECTION)
    s.set_defaults(func=cmd_search)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

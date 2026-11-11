"""rag-search unit tests that need neither torch nor pgvector: the heavy
modules are stubbed before import. Run: python -m unittest test_rag_search"""
from __future__ import annotations

import sys
import types
import unittest

for mod in ("psycopg", "pypdf", "sentence_transformers"):
    if mod not in sys.modules:
        m = types.ModuleType(mod)
        m.PdfReader = object
        m.SentenceTransformer = object
        sys.modules[mod] = m

import ingest  # noqa: E402


class ChunkTextTests(unittest.TestCase):
    def test_paragraphs_grouped_up_to_the_target(self):
        text = "\n\n".join(f"paragrafo {i} " + "x" * 300 for i in range(10))
        chunks = ingest.chunk_text(text, target=1000, hard=1500)
        self.assertTrue(all(len(c["text"]) <= 1500 for c in chunks))
        self.assertEqual("".join(c["text"].replace("\n", "") for c in chunks).count("paragrafo"), 10)
        self.assertEqual([c["ordinal"] for c in chunks], list(range(len(chunks))))

    def test_a_huge_paragraph_is_cut(self):
        chunks = ingest.chunk_text("y" * 5000, target=1000, hard=1500)
        self.assertTrue(all(len(c["text"]) <= 1500 for c in chunks))
        self.assertEqual(sum(len(c["text"]) for c in chunks), 5000)

    def test_nul_bytes_removed(self):
        chunks = ingest.chunk_text("prima\x00riga\n\nseconda")
        self.assertNotIn("\x00", "".join(c["text"] for c in chunks))

    def test_empty(self):
        self.assertEqual(ingest.chunk_text("  \n\n "), [])


class PrivacyTests(unittest.TestCase):
    def test_topic_collections_are_private(self):
        self.assertTrue(ingest.is_private("topic-ab12cd34"))
        self.assertFalse(ingest.is_private("eu-normativa"))

    def test_bad_provenance_refused(self):
        with self.assertRaises(ValueError):
            ingest.ingest_text("topic-x", "a", "1", text="ciao", provenance="boh")


class _FakeCursor:
    """A cursor that answers each SQL from a list of (substring, rows) rules
    and records what it was asked: enough to test the SQL-free logic around
    the queries without pgvector."""

    def __init__(self, rules):
        self.rules, self.calls, self._rows = rules, [], []
        self.connection = self

    def commit(self):
        pass

    def execute(self, sql, params=()):
        flat = " ".join(sql.split())
        self.calls.append((flat, params))
        for needle, rows in self.rules:
            if needle in flat:
                self._rows = list(rows(params) if callable(rows) else rows)
                return
        self._rows = []

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        rows, self._rows = self._rows, []
        return rows

    def fetchmany(self, n):
        rows, self._rows = self._rows[:n], self._rows[n:]
        return rows

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeConn:
    def __init__(self, cur):
        self.cur = cur

    def cursor(self):
        return self.cur

    def commit(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class ChunkListingTests(unittest.TestCase):
    """#671: the chunks of one document, without a database."""

    def setUp(self):
        self.saved = ingest._db
        self.addCleanup(setattr, ingest, "_db", self.saved)

    def _db(self, rules):
        cur = _FakeCursor(rules)
        ingest._db = lambda: _FakeConn(cur)
        return cur

    def test_the_active_version_in_reading_order(self):
        cur = self._db([
            ("FROM documents WHERE collection=%s AND name=%s ORDER BY", [(7, "2")]),
            ("SELECT count(*) FROM chunks", [(3,)]),
            ("SELECT ordinal, section, page, text FROM chunks",
             [(0, "Art. 1", 1, "uno"), (1, None, 2, "due")]),
        ])
        out = ingest.list_chunks("manuali", "guida", limit=2)
        self.assertEqual((out["version"], out["total"], out["limit"], out["offset"]),
                         ("2", 3, 2, 0))
        self.assertEqual([c["text"] for c in out["chunks"]], ["uno", "due"])
        self.assertEqual(out["chunks"][0], {"ordinal": 0, "section": "Art. 1", "page": 1,
                                            "text": "uno"})
        sql, params = cur.calls[-1]
        self.assertIn("ORDER BY ordinal", sql)
        self.assertEqual(params, (7, 2, 0))

    def test_a_given_version_and_the_page_ceiling(self):
        cur = self._db([("AND version=%s", [(9, "1")]),
                        ("SELECT count(*) FROM chunks", [(0,)])])
        out = ingest.list_chunks("manuali", "guida", version="1", limit=10_000, offset=-5)
        self.assertEqual((out["limit"], out["offset"]), (ingest.MAX_CHUNKS_PAGE, 0))
        self.assertEqual(cur.calls[0][1], ("manuali", "guida", "1"))

    def test_an_unknown_document(self):
        self._db([])
        with self.assertRaises(LookupError):
            ingest.list_chunks("manuali", "nessuno")

    def test_export_yields_collection_documents_then_chunks(self):
        import datetime
        ts = datetime.datetime(2026, 11, 11, 10, 0)
        ingest._SCHEMA_DONE = True
        self.addCleanup(setattr, ingest, "_SCHEMA_DONE", False)
        self._db([
            ("FROM collections WHERE name=%s", [("manuali", "SEAL-1", ts)]),
            ("FROM documents WHERE collection=%s ORDER BY id",
             [(1, "guida", "1", None, "h", "active", ts, "untrusted", "upload:davide")]),
            ("FROM chunks WHERE collection=%s",
             [(10, 1, None, None, 0, "testo", "[0.1,0.2]")]),
        ])
        rows = list(ingest.export_collection("manuali"))
        self.assertEqual([r["type"] for r in rows], ["collection", "document", "chunk"])
        self.assertEqual(rows[0]["tier"], "SEAL-1")
        self.assertEqual(rows[2]["embedding"], "[0.1,0.2]")


try:
    import fastapi  # noqa: F401
    from fastapi.testclient import TestClient
except ImportError:  # the gateway's venv may not have FastAPI
    TestClient = None


@unittest.skipIf(TestClient is None, "fastapi not installed")
class AuthTests(unittest.TestCase):
    def setUp(self):
        import importlib
        import os
        os.environ["EU_RAG_INGEST_TOKEN"] = "t0k"
        import search_service
        self.s = importlib.reload(search_service)
        self.s.ingest_mod.list_collections = lambda: [
            {"collection": "eu-normativa", "tier": "SEAL-0", "documents": 1, "chunks": 1},
            {"collection": "topic-abc", "tier": "SEAL-3", "documents": 1, "chunks": 1}]
        self.s.ingest_mod.list_documents = lambda c: []
        self.c = TestClient(self.s.app)

    def test_private_collections_need_the_token(self):
        self.assertEqual(self.c.get("/documents", params={"collection": "topic-abc"}).status_code, 401)
        self.assertEqual(self.c.get("/search", params={"q": "ciao", "collection": "topic-abc"}).status_code, 401)
        self.assertEqual(self.c.get("/documents", params={"collection": "topic-abc"},
                                    headers={"Authorization": "Bearer t0k"}).status_code, 200)
        self.assertEqual(self.c.get("/documents", params={"collection": "eu-normativa"}).status_code, 200)

    def test_private_names_hidden_without_token(self):
        names = [r["collection"] for r in self.c.get("/collections").json()["collections"]]
        self.assertEqual(names, ["eu-normativa"])
        names = [r["collection"] for r in self.c.get(
            "/collections", headers={"Authorization": "Bearer t0k"}).json()["collections"]]
        self.assertEqual(names, ["eu-normativa", "topic-abc"])

    def test_the_guard_lets_the_public_corpus_and_the_token_through(self):
        self.s._guard_read("eu-normativa", None)
        self.s._guard_read("topic-abc", "Bearer t0k")
        from fastapi import HTTPException
        with self.assertRaises(HTTPException):
            self.s._guard_read("topic-abc", "Bearer sbagliato")

    def test_chunks_and_export_need_the_token(self):
        from unittest.mock import patch
        for attr, fake in (("list_chunks", lambda c, n, v, l, o: {"chunks": [], "name": n}),
                           ("export_collection", lambda c: iter([{"type": "collection", "name": c}]))):
            p = patch.object(self.s.ingest_mod, attr, fake)
            p.start()
            self.addCleanup(p.stop)
        self.assertEqual(self.c.get("/chunks", params={"collection": "eu-normativa",
                                                       "name": "AGA"}).status_code, 401)
        self.assertEqual(self.c.get("/export", params={"collection": "eu-normativa"}).status_code, 401)
        ok = {"Authorization": "Bearer t0k"}
        r = self.c.get("/chunks", params={"collection": "eu-normativa", "name": "AGA"}, headers=ok)
        self.assertEqual((r.status_code, r.json()["name"]), (200, "AGA"))
        r = self.c.get("/export", params={"collection": "x"}, headers=ok)
        self.assertEqual(r.text.strip(), '{"type": "collection", "name": "x"}')

    def test_ingest_text_keeps_the_url_and_the_supersede_choice(self):
        from unittest.mock import patch
        seen = {}
        self.s._model = object()
        self.addCleanup(setattr, self.s, "_model", None)
        p = patch.object(self.s.ingest_mod, "ingest_text",
                         lambda *a, **k: seen.update(k) or {"chunks": 1})
        p.start()
        self.addCleanup(p.stop)
        r = self.c.post("/ingest_text", headers={"Authorization": "Bearer t0k"},
                        json={"collection": "c", "name": "d", "text": "x", "url": "https://x/d",
                              "supersede": False, "provenance": "untrusted"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual((seen["url"], seen["supersede"]), ("https://x/d", False))

    def test_an_unknown_document_is_404(self):
        from unittest.mock import patch

        def missing(*a):
            raise LookupError("no")
        p = patch.object(self.s.ingest_mod, "list_chunks", missing)
        p.start()
        self.addCleanup(p.stop)
        r = self.c.get("/chunks", params={"collection": "c", "name": "d"},
                       headers={"Authorization": "Bearer t0k"})
        self.assertEqual(r.status_code, 404)

    def test_writes_need_the_token(self):
        for path, body in (("/ingest_text", {"collection": "topic-abc", "name": "a", "text": "x"}),
                           ("/collections", {"collection": "topic-abc", "tier": "SEAL-3"}),
                           ("/collections/tier", {"collection": "topic-abc", "tier": "SEAL-3"}),
                           ("/collections/drop", {"collection": "topic-abc"})):
            with self.subTest(path=path):
                self.assertEqual(self.c.post(path, json=body).status_code, 401)


if __name__ == "__main__":
    unittest.main()

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

    def test_writes_need_the_token(self):
        for path, body in (("/ingest_text", {"collection": "topic-abc", "name": "a", "text": "x"}),
                           ("/collections", {"collection": "topic-abc", "tier": "SEAL-3"}),
                           ("/collections/tier", {"collection": "topic-abc", "tier": "SEAL-3"}),
                           ("/collections/drop", {"collection": "topic-abc"})):
            with self.subTest(path=path):
                self.assertEqual(self.c.post(path, json=body).status_code, 401)


if __name__ == "__main__":
    unittest.main()

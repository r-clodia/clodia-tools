"""clodia-platform#499 — whether the RAG ingest token is there, without its value.

`rag.ingest` failed because neither EU_RAG_INGEST_TOKEN nor its file was
provisioned, and nothing could tell. Now `runtime.health` reports the token
present or missing and from where (environment or file), never the value; and
the error of a missing token says what to do.
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from server.tools import eu_corpus, health

SECRET = "tok~s3cr3t~value"


class TokenStatusTests(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.file = self.d / "eu-rag-ingest-token"
        p = mock.patch.object(eu_corpus, "_TOKEN_FILE", str(self.file))
        p.start()
        self.addCleanup(p.stop)
        e = mock.patch.dict(os.environ, {}, clear=False)
        e.start()
        self.addCleanup(e.stop)
        os.environ.pop("EU_RAG_INGEST_TOKEN", None)

    def test_missing(self):
        st = eu_corpus.ingest_token_status()
        self.assertEqual((st["present"], st["source"]), (False, None))
        with self.assertRaises(RuntimeError) as ctx:
            eu_corpus._ingest_token()
        msg = str(ctx.exception)
        self.assertIn("EU_RAG_INGEST_TOKEN", msg)
        self.assertIn(str(self.file), msg)

    def test_from_the_environment(self):
        os.environ["EU_RAG_INGEST_TOKEN"] = SECRET
        self.assertEqual(eu_corpus.ingest_token_status()["source"], "env")

    def test_from_the_file_without_a_restart(self):
        self.file.write_text(SECRET + "\n")
        self.assertEqual(eu_corpus.ingest_token_status()["source"], "file")
        self.assertEqual(eu_corpus._ingest_token(), SECRET)

    def test_an_empty_file_is_missing(self):
        self.file.write_text("  \n")
        self.assertFalse(eu_corpus.ingest_token_status()["present"])

    def test_health_reports_it_never_the_value(self):
        self.file.write_text(SECRET)
        part = health._rag_ingest()
        self.assertEqual((part["token"], part["source"]), ("present", "file"))
        self.assertNotIn(SECRET, json.dumps(part))

    def test_health_carries_the_part_and_it_does_not_decide_ok(self):
        async def run():
            with mock.patch.object(health, "_agent_server", return_value={"ok": True}), \
                    mock.patch.object(health, "_courier", return_value={"ok": True}), \
                    mock.patch.object(health, "_gateway_errors", return_value={"lines": []}), \
                    mock.patch.object(health, "_gateway", return_value={"version": "x"}):
                return await health._run(backends=False)
        out = asyncio.run(run())
        self.assertEqual(out["rag_ingest"]["token"], "missing")
        self.assertTrue(out["ok"])
        self.assertNotIn(SECRET, json.dumps(out))


if __name__ == "__main__":
    unittest.main()

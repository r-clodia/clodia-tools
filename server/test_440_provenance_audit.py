"""clodia-platform#440 — provenance records the content hash of what was read.

Topic v2 has no git: a file read at 06:10 can be rewritten at 06:20, and
"what was the decision based on?" had no answer. Every read with a source now
emits `data.read` with `ref`, `content_hash` and `read_at`: for a topic file
the hash of the whole file at read time (even when a window was returned), for
a RAG search one source per returned chunk.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from . import main
from .claims import ClaimsContext
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicService

TOKEN = {"agent": "clodia", "execution_id": "clodia-320", "principal": "davide",
         "chat": "chan:SEAL-1:ch:clodia", "clearance": "SEAL-3"}


class ProvenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        (base / "data").mkdir()
        self.root = base / "audit"
        env = patch.dict(os.environ, {"CLODIA_AUDIT_DIR": str(self.root),
                                      "CLODIA_AUDIT_KEY_DIR": str(base / "k"),
                                      "CLODIA_DATA": str(base / "data")})
        env.start()
        self.addCleanup(env.stop)
        self.svc = TopicService(LocalFsStorage(base / "store"))
        self.svc.new("SEAL-1", "ch", {"title": "ch", "owner": "davide",
                                      "participants": ["davide", "clodia"]})

    def reads(self) -> list[dict]:
        out = []
        for seg in sorted(self.root.glob("events-*.jsonl")):
            out += [json.loads(x) for x in seg.read_text().splitlines() if x.strip()]
        return [e for e in out if e["event"]["type"] == "data.read"]

    def call(self, name: str, args: dict, **patches):
        async def go():
            with ClaimsContext(TOKEN, "t"):
                ps = [patch.object(main, "_topics", lambda: self.svc),
                      patch.object(main, "_source_vetted", lambda *a, **k: True),
                      patch.object(main, "_require_gate_consent", AsyncMock(return_value={}))]
                ps += [patch.object(*p) for p in patches.values()]
                for p in ps:
                    p.start()
                try:
                    return await main.call_tool(name, args)
                finally:
                    for p in ps:
                        p.stop()
        return asyncio.run(go())

    def test_the_version_of_the_file_read_is_recorded_and_survives_a_rewrite(self) -> None:
        r = self.svc.put_file("SEAL-1", "ch", "nota.md", b"version one", "trusted", by="davide")
        path = r.get("path") or f"files/{r['name']}"
        self.call("topic.read_file", {"tier": "SEAL-1", "name": "ch", "path": path})
        self.svc.put_file("SEAL-1", "ch", "nota.md", b"version two", "trusted", by="davide")
        self.call("topic.read_file", {"tier": "SEAL-1", "name": "ch", "path": path})
        first, second = (e["provenance"]["sources"][0] for e in self.reads())
        self.assertEqual(first["ref"], f"topic:SEAL-1/ch/{path}")
        self.assertEqual(first["content_hash"],
                         "sha256:" + hashlib.sha256(b"version one").hexdigest())
        self.assertEqual(second["content_hash"],
                         "sha256:" + hashlib.sha256(b"version two").hexdigest())
        self.assertEqual(first["hash_of"], "file")
        self.assertIn("read_at", first)

    def test_a_window_is_marked_partial_but_hashes_the_whole_file(self) -> None:
        r = self.svc.put_file("SEAL-1", "ch", "big.md", b"x" * 1000, "trusted", by="davide")
        path = r.get("path") or f"files/{r['name']}"
        self.call("topic.read_file", {"tier": "SEAL-1", "name": "ch", "path": path,
                                      "offset": 10, "max_bytes": 5})
        src = self.reads()[0]["provenance"]["sources"][0]
        self.assertTrue(src["partial"])
        self.assertEqual(src["content_hash"], "sha256:" + hashlib.sha256(b"x" * 1000).hexdigest())

    def test_a_rag_answer_cites_every_chunk_it_returned(self) -> None:
        res = {"query": "q", "results": [
            {"name": "NIS2", "version": "2022/2555", "page": 12, "section": "Art. 21",
             "text": "measures"},
            {"name": "DORA", "version": "2022/2554", "page": 3, "text": "ict risk"}]}
        self.call("rag.search", {"collection": "eu-normativa", "query": "q"},
                  rag=(main, "_dispatch_rag", lambda n, a: res))
        refs = [s["ref"] for s in self.reads()[0]["provenance"]["sources"]]
        self.assertEqual(refs, ["rag:eu-normativa/NIS2@2022/2555#p12",
                                "rag:eu-normativa/DORA@2022/2554#p3"])
        self.assertEqual(self.reads()[0]["provenance"]["sources"][1]["content_hash"],
                         "sha256:" + hashlib.sha256(b"ict risk").hexdigest())
        raw = "".join(p.read_text() for p in self.root.glob("events-*.jsonl"))
        self.assertNotIn("ict risk", raw)

    def test_a_listing_is_not_a_read_of_something(self) -> None:
        self.call("topic.files", {"tier": "SEAL-1", "name": "ch"})
        self.assertEqual(self.reads(), [])


if __name__ == "__main__":
    unittest.main()

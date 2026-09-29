"""clodia-platform#444 — human reads of topics ≥ SEAL-2 are on the trail.

Confidentiality is shown by reads, not only by writes. These tests hold the
topics API to: one `human.view` per person and topic per window (the webui
polls, and one event per poll would bury the trail), a `human.download` with
the hash of the file served, every `human.export`, and nothing for SEAL-0/1
views or for the runner's own system reads.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.testclient import TestClient

from . import topics_api
from .audit import reads
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicService

HUMAN = {"agent": "clodia", "principal": "davide", "on_behalf": True, "human_role": "owner"}
RUNNER = {"agent": "clodia", "principal": "clodia"}


class HumanReadsTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        self.root = base / "audit"
        env = patch.dict(os.environ, {"CLODIA_AUDIT_DIR": str(self.root),
                                      "CLODIA_AUDIT_KEY_DIR": str(base / "k"),
                                      "CLODIA_DATA": str(base / "data")})
        env.start()
        self.addCleanup(env.stop)
        reads._seen.clear()
        self.svc = TopicService(LocalFsStorage(base / "store"))
        for tier, name in (("SEAL-2", "titulon-tech"), ("SEAL-1", "blog")):
            self.svc.new(tier, name, {"title": name, "owner": "davide", "participants": ["davide"]})
        r = self.svc.put_file("SEAL-2", "titulon-tech", "offerta.pdf", b"%PDF riservato",
                              "trusted", by="davide")
        self.path = r.get("path") or f"files/{r['name']}"
        self.payload = HUMAN
        for target, attr, val in (
                (topics_api, "_service", lambda: self.svc),
                (topics_api.internal_auth, "authorize", lambda *a, **k: (self.payload, None)),
                (topics_api.human_mcp, "principal_kind_of", lambda p: "human")):
            p = patch.object(target, attr, val)
            p.start()
            self.addCleanup(p.stop)
        self.c = TestClient(Starlette(routes=topics_api.routes))

    def events(self, prefix: str = "human.") -> list[dict]:
        out = []
        for seg in sorted(self.root.glob("events-*.jsonl")):
            out += [json.loads(x) for x in seg.read_text().splitlines() if x.strip()]
        return [e for e in out if e["event"]["type"].startswith(prefix)]

    def test_polling_a_seal2_topic_is_one_view_per_window(self) -> None:
        for _ in range(5):
            self.assertEqual(self.c.get("/internal/topics/SEAL-2/titulon-tech").status_code, 200)
            self.c.get("/internal/topics/SEAL-2/titulon-tech/messages")
        (ev,) = self.events()
        self.assertEqual(ev["event"]["type"], "human.view")
        self.assertEqual(ev["actor"], {"type": "human", "id": "davide", "role": "owner",
                                       "via": "clodia", "source": "claims"})
        self.assertEqual(ev["scope"], {"tier": "SEAL-2", "topic": "titulon-tech"})

    def test_a_seal1_view_is_not_recorded(self) -> None:
        self.c.get("/internal/topics/SEAL-1/blog")
        self.assertEqual(self.events(), [])

    def test_the_runners_system_reads_are_not_human_reads(self) -> None:
        self.payload = RUNNER
        self.c.get("/internal/topics/SEAL-2/titulon-tech")
        self.assertEqual(self.events(), [])

    def test_a_download_records_the_hash_of_the_file_served(self) -> None:
        r = self.c.get("/internal/topics/SEAL-2/titulon-tech/file", params={"path": self.path})
        self.assertEqual(r.content, b"%PDF riservato")
        (ev,) = self.events("human.download")
        src = ev["provenance"]["sources"][0]
        self.assertEqual(src["content_hash"],
                         "sha256:" + hashlib.sha256(b"%PDF riservato").hexdigest())

    def test_every_export_is_recorded(self) -> None:
        r = self.c.get("/internal/topics/export", params={"topics": "SEAL-2/titulon-tech"})
        self.assertEqual(r.status_code, 200, r.text[:200])
        (ev,) = self.events("human.export")
        self.assertEqual(ev["result"]["topics"], ["SEAL-2/titulon-tech"])
        self.assertEqual(ev["result"]["bytes"], len(r.content))


if __name__ == "__main__":
    unittest.main()

"""`https:*` — the open web as a source of ONE topic without confidential
data (owner, 23 Oct 2026)."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import data_catalog as cat, topic_data as td, whitelist
from . import egress, main  # noqa: F401 — main: patched below
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicService


class OpenWebTests(unittest.TestCase):
    def setUp(self):
        d = Path(tempfile.mkdtemp(prefix="ow-"))
        self.svc = TopicService(LocalFsStorage(tempfile.mkdtemp(prefix="topics-")))
        self.cfg = {"data_access": "legacy", "agents": {"fact-checker": {}}}
        for p in [patch.object(whitelist, "CONFIG", self.cfg),
                  patch.object(whitelist, "save_config", lambda: None),
                  patch.object(cat, "_path", lambda: d / "cat.json"),
                  patch.object(td, "_svc", lambda: self.svc),
                  patch("server.main._topics", lambda: self.svc),
                  patch("server.datastores.declared", lambda: [
                      {"pack": "p", "name": "clienti", "clearance": "SEAL-1", "seeds": []}]),
                  patch("server.tools.eu_corpus.collections",
                        lambda: {"collections": [{"collection": "eu-normativa", "tier": "SEAL-0"}]}),
                  patch("server.tools.eu_corpus.collection_tier", lambda c: "SEAL-0")]:
            p.start()
            self.addCleanup(p.stop)
        cat.sync()
        self.svc.new("SEAL-1", "blog", {"owner": "davide", "participants": ["davide"]})
        self.svc.new("SEAL-2", "clienti", {"owner": "davide", "participants": ["davide"]})

    def test_any_https_page_is_a_source_of_that_topic_only(self):
        egress.scope_allow("ingress", "SEAL-1/blog", "https:*")
        self.assertTrue(egress.is_vetted_source("https://www.uni.com/x", scope="SEAL-1/blog"))
        self.assertFalse(egress.is_vetted_source("https://www.uni.com/x", scope="SEAL-2/clienti"))
        self.assertFalse(egress.is_vetted_source("http://www.uni.com/x", scope="SEAL-1/blog"))
        self.assertFalse(egress.is_vetted_source("mailfrom:a@b.it", scope="SEAL-1/blog"))

    def test_never_global_never_egress(self):
        with self.assertRaises(ValueError):
            egress.allow("ingress", "https:*")
        with self.assertRaises(ValueError):
            egress.scope_allow("egress", "SEAL-1/blog", "https:*")

    def test_not_on_a_confidential_topic(self):
        with self.assertRaises(ValueError):
            egress.scope_allow("ingress", "SEAL-2/clienti", "https:*")

    def test_not_with_confidential_data_imported(self):
        td.import_resource("SEAL-1", "blog", "datastore", "p/clienti", principal="davide",
                           is_admin=True, clearance="SEAL-4")
        with self.assertRaises(ValueError):
            egress.scope_allow("ingress", "SEAL-1/blog", "https:*")

    def test_public_data_is_fine_and_confidential_imports_are_refused_after(self):
        td.import_resource("SEAL-1", "blog", "rag", "eu-normativa", principal="davide",
                           is_admin=True, clearance="SEAL-4")
        egress.scope_allow("ingress", "SEAL-1/blog", "https:*")
        with self.assertRaises(PermissionError):
            td.import_resource("SEAL-1", "blog", "datastore", "p/clienti", principal="davide",
                               is_admin=True, clearance="SEAL-4")

    def test_no_retier_above_seal_1_while_open(self):
        egress.scope_allow("ingress", "SEAL-1/blog", "https:*")
        meta = self.svc._read_meta("SEAL-1", "blog")[0]
        with self.assertRaises(ValueError):
            egress.open_web_allowed("SEAL-1/blog", tier="SEAL-2", meta=meta)
        egress.open_web_allowed("SEAL-1/blog", tier="SEAL-0", meta=meta)


if __name__ == "__main__":
    unittest.main()

"""#599/#601/#602 — every topic indexed in its own collection; a hit from
untrusted content taints."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import data_catalog as cat, topic_data as td, topic_index as ti, whitelist
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicService


class FakeRag:
    def __init__(self):
        self.docs, self.tiers, self.dropped = {}, {}, []

    def set_collection(self, c, t):
        self.tiers[c] = t

    def ingest_text(self, c, name, text, *, version="1", source="", provenance="untrusted", tier=None):
        self.docs[(c, name)] = {"text": text, "provenance": provenance}

    def remove(self, name, version, c):
        self.docs.pop((c, name), None)

    def drop_collection(self, c):
        self.dropped.append(c)
        self.docs = {k: v for k, v in self.docs.items() if k[0] != c}


class _Base(unittest.TestCase):
    def setUp(self):
        d = Path(tempfile.mkdtemp(prefix="ix-"))
        self.svc = TopicService(LocalFsStorage(tempfile.mkdtemp(prefix="topics-")))
        self.rag = FakeRag()
        for p in [patch.object(cat, "_path", lambda: d / "cat.json"),
                  patch.object(ti, "_state_path", lambda c: d / f"{c}.json"),
                  patch.object(ti, "_svc", lambda: self.svc),
                  patch.object(td, "_svc", lambda: self.svc),
                  patch.object(ti, "_rag", lambda: self.rag),
                  patch("server.tools.eu_corpus.collection_tier", lambda c: "SEAL-0"),
                  patch.object(whitelist, "CONFIG", {"agents": {"clodia": {}, "ophelia": {}}})]:
            p.start()
            self.addCleanup(p.stop)
        self.svc.new("SEAL-2", "vendite", {"owner": "davide",
                                           "participants": ["davide", "clodia", "ophelia"]})

    def meta(self):
        return self.svc._read_meta("SEAL-2", "vendite")[0]

    def coll(self):
        return self.meta()["index"]["collection"]


class CollectionTests(_Base):
    def test_the_topic_gets_its_collection_imported_and_read_by_participants(self):
        out = ti.ensure("SEAL-2", "vendite")
        self.assertTrue(out["collection"].startswith("topic-"))
        self.assertEqual(self.rag.tiers[out["collection"]], "SEAL-2")
        self.assertEqual(cat.get("rag", out["collection"])["tier"], "SEAL-2")
        (imp,) = td.imports(self.meta())
        self.assertEqual(imp["grants"], {"clodia": "read", "ophelia": "read"})   # agents, not davide

    def test_a_revoked_grant_stays_revoked(self):
        ti.ensure("SEAL-2", "vendite")
        td.grant("SEAL-2", "vendite", "rag", self.coll(), "ophelia", None)
        ti.ensure("SEAL-2", "vendite")
        self.assertNotIn("ophelia", td.imports(self.meta())[0]["grants"])

    def test_the_collection_follows_the_topic_tier(self):
        ti.ensure("SEAL-2", "vendite")
        meta, ver = self.svc._read_meta("SEAL-2", "vendite")
        meta["tier"] = "SEAL-3"
        self.svc._write_meta("SEAL-2", "vendite", meta, ver)
        ti.ensure("SEAL-2", "vendite")
        self.assertEqual(self.rag.tiers[self.coll()], "SEAL-3")

    def test_opt_out_drops_and_stops(self):
        ti.ensure("SEAL-2", "vendite")
        c = self.coll()
        ti.set_enabled("SEAL-2", "vendite", False)
        self.assertEqual(self.rag.dropped, [c])
        self.assertEqual(ti.sync("SEAL-2", "vendite"), {"skipped": "indicizzazione spenta"})
        self.assertEqual(ti.topics(), [])


class SyncTests(_Base):
    def test_messages_summary_and_files_with_provenance(self):
        self.svc.post_message("SEAL-2", "vendite", "davide", "ciao a tutti", kind="human")
        self.svc.post_message("SEAL-2", "vendite", "posta", "busta di una mail", kind="proxy")
        out = ti.sync("SEAL-2", "vendite")
        c = out["collection"]
        days = [k for k in self.rag.docs if k[1].startswith("msg/")]
        self.assertEqual(len(days), 1)
        self.assertEqual(self.rag.docs[days[0]]["provenance"], "untrusted")   # a proxy spoke
        self.assertIn("busta di una mail", self.rag.docs[days[0]]["text"])
        again = ti.sync("SEAL-2", "vendite")
        self.assertEqual((again["days"], again["files"]), (0, 0))              # nothing new

    def test_files_in_and_out(self):
        files = [{"kind": "file", "path": "files/a.md", "size": 5, "mtime_iso": "1"},
                 {"kind": "file", "path": "files/b.png", "size": 5, "mtime_iso": "1"}]
        with patch.object(self.svc, "list_files",
                          lambda t, n, root: files if root == "files" else []), \
                patch.object(self.svc, "read_file", lambda t, n, p: b"testo del file"), \
                patch.object(self.svc, "provenance_of", lambda t, n, p: None):
            out = ti.sync("SEAL-2", "vendite")
            c = out["collection"]
            self.assertEqual(self.rag.docs[(c, "file/files/a.md")]["provenance"], "untrusted")
            self.assertNotIn((c, "file/files/b.png"), self.rag.docs)
            files.pop(0)
            out = ti.sync("SEAL-2", "vendite")
        self.assertEqual(out["removed"], 1)
        self.assertNotIn((c, "file/files/a.md"), self.rag.docs)


class TaintTests(unittest.TestCase):
    def test_an_untrusted_hit_taints(self):
        from . import main
        marks = []
        with patch.object(main._taint, "mark", lambda *a, **k: marks.append(a)), \
                patch.object(main, "current_chat", lambda: "chan:SEAL-2:vendite:clodia"), \
                patch.object(main, "agent_name_safe", lambda: "clodia"):
            main._taint_from_hits("topic-ab", {"results": [{"name": "summary", "provenance": "agent"}]})
            self.assertEqual(marks, [])
            main._taint_from_hits("topic-ab", {"results": [{"name": "msg/2026-10-22",
                                                            "provenance": "untrusted"}]})
            self.assertEqual(len(marks), 1)
            main._taint_from_hits("topic-ab", {"results": [{"name": "old"}]})   # unlabelled
            main._taint_from_hits("eu-normativa", {"results": [{"name": "AGA"}]})
        self.assertEqual(len(marks), 2)


class LegacyTopicCollectionTests(_Base):
    def test_topic_collections_follow_topic_rules_in_legacy(self):
        from . import main
        ti.ensure("SEAL-2", "vendite")
        c = self.coll()
        with patch.object(whitelist, "CONFIG", {"data_access": "legacy",
                                                "agents": {"clodia": {}, "ophelia": {}}}), \
                patch.object(main, "agent_name", lambda: "clodia"), \
                patch.object(main, "current_clearance", lambda: "SEAL-2"), \
                patch("server.egress._scope_of_call", lambda: "SEAL-2/vendite"), \
                patch.object(main.instance_profile, "rag_check_collection", lambda x: None), \
                patch("server.tools.eu_corpus.collection_tier", lambda x: "SEAL-2"):
            main._rag_authorize(c, write=False)
            with patch("server.egress._scope_of_call", lambda: "SEAL-2/altro"):
                with self.assertRaises(PermissionError):
                    main._rag_authorize(c, write=False)
            with self.assertRaises(PermissionError):
                main._rag_authorize(c, write=True)


if __name__ == "__main__":
    unittest.main()

"""#616 — the A·V·R·Q migration plan: a dry run read from the audit."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from . import authz_migration as M


def _ev(t, **kw):
    return {"event": {"type": t, **kw.pop("event", {})}, **kw}


class _Audit(unittest.TestCase):
    def setUp(self):
        from .connectors import first_party_fixture
        first_party_fixture.install(); self.addCleanup(first_party_fixture.uninstall)
        self.dir = tempfile.mkdtemp(prefix="audit616-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        p = patch.dict(os.environ, {"CLODIA_AUDIT_DIR": self.dir})
        p.start(); self.addCleanup(p.stop)
        day = datetime.now(timezone.utc).strftime("%Y%m%d")
        ev = [
            _ev("turn.start", span_id="T1", event={"resource": "chan:SEAL-1:fatture:clodia"}),
            _ev("tool.call", event_id="C1", parent_span_id="T1",
                agent={"seed": "clodia"}, event={"resource": "email.send"}),
            _ev("tool.result", parent_span_id="C1", result={"status": "ok"}),
            _ev("flow.egress", parent_span_id="C1", tool={"destination": ["mailto:anna@foo.bar"]}),
            _ev("turn.start", span_id="T2", event={"resource": "chan:SEAL-1:fatture:officer"}),
            _ev("tool.call", event_id="C2", parent_span_id="T2",
                agent={"seed": "officer"}, event={"resource": "email.search"}),
            _ev("turn.start", span_id="T3", event={"resource": "20261025-dm"}),
            _ev("tool.call", event_id="C3", parent_span_id="T3",
                agent={"seed": "clodia"}, event={"resource": "copybrain.call"}),
            _ev("tool.call", event_id="C4", parent_span_id="T1",
                agent={"seed": "clodia"}, event={"resource": "rag.search"}),
        ]
        with open(os.path.join(self.dir, f"events-{day}.jsonl"), "w") as fh:
            for e in ev:
                fh.write(json.dumps(e) + "\n")


class UsageTests(_Audit):
    def test_calls_are_tied_to_their_room_and_targets(self):
        u = M.usage(30)
        self.assertEqual(u[("SEAL-1/fatture", "clodia", "email.send")]["targets"],
                         {"mailto:anna@foo.bar": "egress"})
        self.assertIn((None, "clodia", "copybrain.call"), u)


class PlanTests(_Audit):
    def _plan(self):
        meta = {"owner": "davide", "participants": ["clodia", "officer"],
                "data": [{"kind": "rag", "name": "topic-abc",
                          "grants": {"clodia": "read", "officer": "read"}}]}
        with patch.object(M, "_agents", lambda: ["clodia", "officer"]), \
                patch.object(M, "_seed_verbs", lambda a: {"email.send", "email.search",
                                                          "packs.list", "web.post"}), \
                patch.object(M, "_topics", lambda: [("SEAL-1", "fatture", meta)]), \
                patch.object(M, "_list_entries", lambda d, s: []):
            return M.plan(30)

    def test_a_write_stays_with_who_used_it_a_read_goes_to_everyone(self):
        rows = {(t["agent"], t["verb"]) for t in self._plan()["topics"]["SEAL-1/fatture"]}
        self.assertIn(("clodia", "email.send"), rows)
        self.assertNotIn(("*", "email.send"), rows)
        self.assertIn(("*", "email.search"), rows)

    def test_own_tools_and_governance_are_global_data_by_grant(self):
        p = self._plan()
        glob = {(t["agent"], t["verb"]) for t in p["global"]}
        self.assertIn(("clodia", "copybrain.call"), glob)
        self.assertIn(("clodia", "packs.list"), glob)
        # Data grants are read as tuples at runtime (authz_runtime): the plan
        # writes none, and a generic `rag.search` used in the room is not one.
        topic = p["topics"]["SEAL-1/fatture"]
        self.assertFalse([t for t in topic if t["verb"].startswith("rag.")])

    def test_unused_seed_verbs_are_listed_as_dropped(self):
        self.assertIn("web.post", self._plan()["dropped"]["clodia"])

    def test_the_markdown_names_every_tuple(self):
        md = M.markdown(self._plan())
        self.assertIn("| clodia | `email.send` |", md)
        self.assertIn("## SEAL-1/fatture", md)


if __name__ == "__main__":
    unittest.main()

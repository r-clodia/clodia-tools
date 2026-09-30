"""clodia-platform#466 — an agent-server event replayed from its outbox is
recorded once.

clodia-logic #491 attaches its own `event_id` (uuid) to the PKI events it keeps
in an outbox, and re-sends one whose answer it did not see. The gateway admits
each id once — also across a restart, since the window is persisted in the
audit state dir — and answers a repeat with 200 `{"duplicate": true}`.
"""
from __future__ import annotations

import json
import time
import uuid

from .audit import dedupe
from .test_433_450_trace_and_mint import SPAN, TRACE, _AuditEnv


def _revoke(eid: str | None) -> dict:
    ev = {"type": "control.pki", "action": "revoke", "resource": "minerva",
          "actor": {"type": "human", "id": "davide"}}
    if eid is not None:
        ev["event_id"] = eid
    return ev


class IngestDedupeTests(_AuditEnv):
    def setUp(self) -> None:
        super().setUp()
        dedupe._window = None

    def post(self, body: dict) -> dict:
        r = self.c.post("/internal/audit/event", headers=self.h, json=body)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def pki_events(self) -> list[dict]:
        return [e for e in self.events() if e["event"]["type"] == "control.pki"]

    def test_a_replay_is_answered_and_not_appended(self) -> None:
        eid = str(uuid.uuid4())
        first = self.post(_revoke(eid))
        again = self.post(_revoke(eid))
        self.assertTrue(first["recorded"])
        self.assertNotIn("duplicate", first)
        self.assertEqual(again, {"recorded": True, "duplicate": True,
                                 "event_id": first["event_id"]})
        self.assertEqual(len(self.pki_events()), 1)
        # the dashed and undashed spelling are the same id
        self.assertTrue(self.post(_revoke(eid.replace("-", "").upper()))["duplicate"])
        self.assertEqual(len(self.pki_events()), 1)

    def test_a_restart_does_not_re_admit_a_replay(self) -> None:
        eid = uuid.uuid4().hex
        self.post(_revoke(eid))
        dedupe._window = None                      # the gateway restarts
        self.assertTrue(self.post(_revoke(eid))["duplicate"])
        self.assertEqual(len(self.pki_events()), 1)

    def test_without_an_id_every_post_is_recorded(self) -> None:
        self.post(_revoke(None))
        self.post(_revoke(None))
        self.post(_revoke("not-a-uuid"))
        self.assertEqual(len(self.pki_events()), 3)

    def test_a_replayed_turn_start_does_not_touch_the_trace(self) -> None:
        from .audit import trace
        eid = str(uuid.uuid4())
        start = {"type": "turn.start", "action": "start", "trace_id": TRACE, "span_id": SPAN,
                 "agent": {"seed": "clodia", "spawn": "clodia-320"}, "event_id": eid}
        self.post(start)
        trace.end("clodia-320")
        self.assertTrue(self.post(start)["duplicate"])
        self.assertIsNone(trace.current("clodia-320"))

    def test_the_window_is_bounded_by_count_and_age(self) -> None:
        w = dedupe.Window(self.root / "w.jsonl", max_ids=3, max_age_s=60)
        ids = [uuid.uuid4().hex for _ in range(5)]
        for i in ids:
            w.admit(i, lambda: {"event_id": "e"})
        self.assertEqual(list(w._ids), ids[2:])
        self.assertFalse(w.seen(ids[0])[0])
        w._ids[ids[2]] = (time.time() - 120, "e")  # older than the window
        w._ids.move_to_end(ids[2], last=False)
        self.assertFalse(w.seen(ids[2])[0])
        # the file is compacted, not grown forever
        for _ in range(10):
            w.admit(uuid.uuid4().hex, lambda: {"event_id": "e"})
        lines = (self.root / "w.jsonl").read_text().splitlines()
        self.assertLessEqual(len(lines), 2 * 3)
        self.assertTrue(all(json.loads(x)["id"] for x in lines))

    def test_an_event_that_failed_to_record_can_be_resent(self) -> None:
        w = dedupe.Window(self.root / "w2.jsonl")
        eid = uuid.uuid4().hex
        self.assertEqual(w.admit(eid, lambda: None), (False, None, None))
        dup, rec, _ = w.admit(eid, lambda: {"event_id": "e2"})
        self.assertFalse(dup)
        self.assertEqual(rec, {"event_id": "e2"})


if __name__ == "__main__":
    import unittest
    unittest.main()

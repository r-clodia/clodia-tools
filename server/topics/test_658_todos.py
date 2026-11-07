"""The room's to-do list and the derived deadline (clodia-platform#658).

What must hold:
  - `deadline` is the earliest `due` among OPEN items: empty list → null, all
    done → null, overdue still counts, ties are one date;
  - every `todo_*` write requires `base_version`, and a stale one raises
    VersionConflict instead of overwriting a list the caller has not seen;
  - the read path drops malformed items without making the topic unopenable;
  - a pre-#658 manual deadline survives as an item, and the migration is
    dry-run by default and idempotent;
  - `set_deadline` and its route refuse: the deadline is derived.
"""
from __future__ import annotations

import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import date, timedelta
from pathlib import Path

from .local_fs import LocalFsStorage
from .service import (DEADLINE_DERIVED, LEGACY_DEADLINE_TODO_ID, TopicError,
                      TopicService, derive_deadline, normalize_meta_v2,
                      todos_version)
from .storage import VersionConflict
from . import migrate_todos


def _item(i, due=None, status="open"):
    return {"id": f"t-{i}", "text": f"item {i}", "due": due, "status": status}


class Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="todos-"))
        self.svc = TopicService(LocalFsStorage(str(self.root)))
        self.svc.new("SEAL-1", "room", {"title": "Room", "owner": "davide"})

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _ver(self, name="room"):
        return self.svc.open("SEAL-1", name)["todos_version"]

    def _raw_meta(self, name="room"):
        return json.loads(self.svc.s.read(self.svc._meta_p("SEAL-1", name)).data.decode())

    def _write_raw_meta(self, raw, name="room"):
        self.svc.s.write(self.svc._meta_p("SEAL-1", name), json.dumps(raw).encode())


class DerivationTests(unittest.TestCase):
    def test_empty_list_has_no_deadline(self):
        self.assertIsNone(derive_deadline([]))
        self.assertIsNone(derive_deadline(None))

    def test_items_without_due_have_no_deadline(self):
        self.assertIsNone(derive_deadline([_item(1), _item(2)]))

    def test_all_done_has_no_deadline(self):
        self.assertIsNone(derive_deadline([_item(1, "2026-11-20", "done"),
                                           _item(2, "2026-11-10", "done")]))

    def test_earliest_open_due_wins_and_done_items_are_ignored(self):
        todos = [_item(1, "2026-12-01"), _item(2, "2026-11-05", "done"),
                 _item(3, "2026-11-20"), _item(4)]
        self.assertEqual(derive_deadline(todos), "2026-11-20")

    def test_overdue_item_is_still_the_deadline(self):
        past = (date.today() - timedelta(days=30)).isoformat()
        future = (date.today() + timedelta(days=30)).isoformat()
        self.assertEqual(derive_deadline([_item(1, future), _item(2, past)]), past)

    def test_ties_give_that_date(self):
        self.assertEqual(derive_deadline([_item(1, "2026-11-20"),
                                          _item(2, "2026-11-20")]), "2026-11-20")

    def test_normalize_ignores_a_written_deadline_and_derives_it(self):
        out = normalize_meta_v2({"deadline": "2030-01-01",
                                 "todos": [_item(1, "2026-11-20")]}, "SEAL-1")
        self.assertEqual(out["deadline"], "2026-11-20")
        out = normalize_meta_v2({"deadline": "2030-01-01", "todos": []}, "SEAL-1")
        self.assertIsNone(out["deadline"])


class NormalizeTests(unittest.TestCase):
    def test_malformed_items_are_dropped_not_raised(self):
        out = normalize_meta_v2({"todos": [
            "a string", 42, None,
            {"text": "no id"},
            {"id": "bad id with spaces", "text": "x"},
            {"id": "t-1", "text": "   "},
            {"id": "t-ok", "text": " keep me ", "due": "20/11/2026",
             "status": "weird", "assignee": 7},
            {"id": "t-ok", "text": "duplicate id"},
        ]}, "SEAL-1")
        self.assertEqual(len(out["todos"]), 1)
        t = out["todos"][0]
        self.assertEqual(t["id"], "t-ok")
        self.assertEqual(t["text"], "keep me")
        self.assertIsNone(t["due"])            # non-ISO date → null
        self.assertEqual(t["status"], "open")  # unknown status → open
        self.assertIsNone(t["assignee"])

    def test_todos_not_a_list_becomes_empty(self):
        out = normalize_meta_v2({"todos": {"id": "t-1"}}, "SEAL-1")
        self.assertEqual(out["todos"], [])
        self.assertIsNone(out["deadline"])

    def test_legacy_manual_deadline_becomes_an_item(self):
        out = normalize_meta_v2({"deadline": "2026-12-24"}, "SEAL-1")
        self.assertEqual(out["deadline"], "2026-12-24")
        self.assertEqual([t["id"] for t in out["todos"]], [LEGACY_DEADLINE_TODO_ID])
        self.assertEqual(out["todos"][0]["text"], "Topic deadline")

    def test_legacy_invalid_deadline_gives_no_item(self):
        out = normalize_meta_v2({"deadline": "fine agosto"}, "SEAL-1")
        self.assertEqual(out["todos"], [])
        self.assertIsNone(out["deadline"])

    def test_a_malformed_topic_stays_openable(self):
        root = Path(tempfile.mkdtemp(prefix="todos-"))
        try:
            svc = TopicService(LocalFsStorage(str(root)))
            svc.new("SEAL-1", "x", {"title": "X"})
            mp = svc._meta_p("SEAL-1", "x")
            raw = json.loads(svc.s.read(mp).data.decode())
            raw["todos"] = [{"broken": True}, "nope"]
            svc.s.write(mp, json.dumps(raw).encode())
            self.assertEqual(svc.open("SEAL-1", "x")["meta"]["todos"], [])
            self.assertIn("x", {r["name"] for r in svc.list()})
        finally:
            shutil.rmtree(root, ignore_errors=True)


class VerbTests(Base):
    def test_add_update_remove_and_deadline_follows(self):
        r = self.svc.todo_add("SEAL-1", "room", "Send the LOI", due="2026-11-20",
                              assignee="segretario", base_version=self._ver(), by="davide")
        tid = r["todo"]["id"]
        self.assertRegex(tid, r"^t-[0-9a-f]{4}$")
        self.assertEqual(r["deadline"], "2026-11-20")
        self.assertEqual(r["todo"]["updated_by"], "davide")
        self.assertTrue(r["todo"]["updated_at"])
        self.assertEqual(r["todos_version"], self._ver())

        r = self.svc.todo_add("SEAL-1", "room", "Earlier one", due="2026-11-10",
                              base_version=r["todos_version"], by="segretario")
        early = r["todo"]["id"]
        self.assertEqual(r["deadline"], "2026-11-10")

        r = self.svc.todo_update("SEAL-1", "room", early, status="done",
                                 base_version=r["todos_version"], by="segretario")
        self.assertEqual(r["deadline"], "2026-11-20")
        self.assertEqual(r["todo"]["status"], "done")

        r = self.svc.todo_update("SEAL-1", "room", tid, due=None,
                                 base_version=r["todos_version"])
        self.assertIsNone(r["deadline"])
        self.assertEqual(r["todo"]["assignee"], "segretario")   # untouched

        r = self.svc.todo_remove("SEAL-1", "room", tid, base_version=r["todos_version"])
        self.assertEqual([t["id"] for t in r["todos"]], [early])
        opened = self.svc.open("SEAL-1", "room")
        self.assertIsNone(opened["meta"]["deadline"])
        self.assertEqual(self.svc.list()[0]["next_deadline"], opened["meta"]["deadline"])

    def test_base_version_is_mandatory(self):
        for bv in (None, "", "  "):
            with self.assertRaises(TopicError):
                self.svc.todo_add("SEAL-1", "room", "x", base_version=bv)
        tid = self.svc.todo_add("SEAL-1", "room", "x", base_version=self._ver())["todo"]["id"]
        with self.assertRaises(TopicError):
            self.svc.todo_update("SEAL-1", "room", tid, status="done", base_version=None)
        with self.assertRaises(TopicError):
            self.svc.todo_remove("SEAL-1", "room", tid, base_version=None)
        self.assertEqual(len(self.svc.open("SEAL-1", "room")["meta"]["todos"]), 1)

    def test_concurrent_writes_conflict_instead_of_overwriting(self):
        v0 = self._ver()
        self.svc.todo_add("SEAL-1", "room", "first writer", base_version=v0)
        with self.assertRaises(VersionConflict):
            self.svc.todo_add("SEAL-1", "room", "second writer, stale", base_version=v0)
        texts = [t["text"] for t in self.svc.open("SEAL-1", "room")["meta"]["todos"]]
        self.assertEqual(texts, ["first writer"])

    def test_unrelated_meta_write_does_not_invalidate_the_todo_lock(self):
        v = self._ver()
        self.svc.set_status("SEAL-1", "room", "on-hold")
        r = self.svc.todo_add("SEAL-1", "room", "still fine", base_version=v)
        self.assertEqual(len(r["todos"]), 1)

    def test_strict_validation_on_write(self):
        v = self._ver()
        bad = [dict(text=""), dict(text="x" * 501), dict(text="x", due="20/11/2026"),
               dict(text="x", due="2026-02-30"), dict(text="x", assignee="a" * 65)]
        for kw in bad:
            text = kw.pop("text")
            with self.assertRaises(TopicError, msg=repr(kw)):
                self.svc.todo_add("SEAL-1", "room", text, base_version=v, **kw)
        tid = self.svc.todo_add("SEAL-1", "room", "ok", base_version=v)["todo"]["id"]
        v = self._ver()
        for kw in (dict(status="closed"), dict(owner="x"), {}):
            with self.assertRaises(TopicError, msg=repr(kw)):
                self.svc.todo_update("SEAL-1", "room", tid, base_version=v, **kw)
        with self.assertRaises(TopicError):
            self.svc.todo_update("SEAL-1", "room", "t-nope", status="done", base_version=v)

    def test_set_deadline_is_refused(self):
        with self.assertRaises(TopicError) as cm:
            self.svc.set_deadline("SEAL-1", "room", "2026-11-20")
        self.assertIn("deadline is derived from todo items", str(cm.exception))
        self.assertEqual(str(cm.exception), DEADLINE_DERIVED)

    def test_editing_a_legacy_topic_keeps_its_manual_deadline(self):
        raw = self._raw_meta()
        raw.pop("todos", None)
        raw["deadline"] = "2026-12-24"
        self._write_raw_meta(raw)
        r = self.svc.todo_add("SEAL-1", "room", "later", due="2027-01-10",
                              base_version=self._ver())
        self.assertEqual(r["deadline"], "2026-12-24")
        self.assertEqual(r["todos"][0]["id"], LEGACY_DEADLINE_TODO_ID)

    def test_version_is_of_the_list(self):
        self.assertEqual(todos_version([]), todos_version(None))
        self.assertNotEqual(todos_version([]), todos_version([_item(1)]))


class MigrationTests(Base):
    def setUp(self):
        super().setUp()
        self.svc.new("SEAL-1", "legacy", {"title": "Legacy"})
        raw = self._raw_meta("legacy")
        raw.pop("todos", None)
        raw["deadline"] = "2026-12-24"
        self._write_raw_meta(raw, "legacy")
        self.svc.s.write(self.svc._summary_p("SEAL-1", "legacy"),
                         b"Legacy\n\n## Prossimi passi\n- send LOI by 2026-11-30\n- call\n")
        raw = self._raw_meta("room")
        raw.pop("todos", None)
        raw["deadline"] = None
        self._write_raw_meta(raw, "room")

    def test_dry_run_writes_nothing_and_reports(self):
        before = self._raw_meta("legacy")
        rep = migrate_todos.migrate(self.svc, apply=False)
        self.assertEqual(rep["migrated"], [{"topic": "SEAL-1/legacy", "deadline": "2026-12-24"}])
        self.assertEqual(self._raw_meta("legacy"), before)
        self.assertNotIn("todos", self._raw_meta("legacy"))
        self.assertEqual(rep["dated_bullets"],
                         [{"topic": "SEAL-1/legacy", "bullets": ["send LOI by 2026-11-30"]}])
        self.assertEqual(rep["no_deadline"], 1)

    def test_apply_is_idempotent_and_keeps_the_deadline(self):
        rep = migrate_todos.migrate(self.svc, apply=True)
        self.assertEqual(len(rep["migrated"]), 1)
        raw = self._raw_meta("legacy")
        self.assertEqual([t["id"] for t in raw["todos"]], [LEGACY_DEADLINE_TODO_ID])
        self.assertEqual(raw["todos"][0]["due"], "2026-12-24")
        self.assertEqual(self.svc.open("SEAL-1", "legacy")["meta"]["deadline"], "2026-12-24")
        after_first = self._raw_meta("legacy")

        rep2 = migrate_todos.migrate(self.svc, apply=True)
        self.assertEqual(rep2["migrated"], [])
        self.assertIn("SEAL-1/legacy", rep2["already"])
        self.assertEqual(self._raw_meta("legacy"), after_first)

    def test_cli_defaults_to_dry_run(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = migrate_todos.main(["--root", str(self.root)])
        self.assertEqual(rc, 0)
        self.assertIn("DRY-RUN", buf.getvalue())
        self.assertNotIn("todos", self._raw_meta("legacy"))


class RouteTests(Base):
    """The internal routes: deadline refused, todos with version handling."""

    def setUp(self):
        super().setUp()
        from unittest import mock
        from starlette.applications import Starlette
        from starlette.testclient import TestClient
        from .. import topics_api
        self._patches = [mock.patch.object(topics_api, "_service", return_value=self.svc),
                         mock.patch.object(topics_api, "_authorize", return_value=("clodia", None))]
        for p in self._patches:
            p.start()
        self.client = TestClient(Starlette(routes=topics_api.routes))

    def tearDown(self):
        for p in self._patches:
            p.stop()
        super().tearDown()

    def test_deadline_route_refuses(self):
        r = self.client.post("/internal/topics/SEAL-1/room/deadline", json={"deadline": "2026-11-20"})
        self.assertEqual(r.status_code, 400)
        self.assertIn("deadline is derived from todo items", r.json()["error"])

    def test_todo_routes(self):
        v = self._ver()
        r = self.client.post("/internal/topics/SEAL-1/room/todos",
                             json={"text": "a", "due": "2026-11-20", "base_version": v, "by": "davide"})
        self.assertEqual(r.status_code, 200, r.text)
        body = r.json()
        tid = body["todo"]["id"]
        self.assertEqual(body["deadline"], "2026-11-20")
        self.assertEqual(body["todo"]["updated_by"], "davide")
        # stale version → 409
        r = self.client.post("/internal/topics/SEAL-1/room/todos",
                             json={"text": "b", "base_version": v})
        self.assertEqual(r.status_code, 409)
        # missing version → 400
        r = self.client.post(f"/internal/topics/SEAL-1/room/todos/{tid}", json={"status": "done"})
        self.assertEqual(r.status_code, 400)
        r = self.client.post(f"/internal/topics/SEAL-1/room/todos/{tid}",
                             json={"status": "done", "base_version": body["todos_version"]})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertIsNone(r.json()["deadline"])
        r = self.client.delete(f"/internal/topics/SEAL-1/room/todos/{tid}",
                               params={"base_version": r.json()["todos_version"]})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["todos"], [])


if __name__ == "__main__":
    unittest.main()

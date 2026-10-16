"""Google connector behaviour, pinned before it moves (clodia-platform#524, step 1).

#524 moves the HTTP transport of the 24 `gdrive/gsheets/gdocs/gcalendar` verbs
out of `googleapiclient` and, later, into google-pack. Everything that decides
— the PDP tables, the folder/calendar perimeter of `gdrive_root`, the custody of
the `google_<acct>` credential — stays in the gateway. This file fixes that
behaviour so the move can be shown to change nothing:

1. **PDP parity** for the 24 verbs: destinations (`egress.spec_for`), the one
   source of a declared read, taint, `check_grantable` on `gdrive:`/`gsheets:`/
   `gcal:` including the canonical form of URLs copied from a browser, and the
   shape of the folder labels. The expected values are literal tables written
   here, not derived from the code under test.
2. **The perimeter on a fake Google service**: the parent walk inside/outside
   the root, the refusal of shortcuts, list filtering, the writable parent,
   adoption after create, the calendar allowlist — once for an account root and
   once for a topic `drive_folders` perimeter. The fake records every API call
   with its arguments, so the same table also pins WHAT each verb asks Google.
3. **Credential custody**: the shape of the `google_<acct>` bundle written by
   `/tools/google/connect`, and `UNIFIED_SCOPE` (changing either means a
   re-consent for every connected account).

The fake has the shape of a `googleapiclient` service (`svc.files().get(...)
.execute()`), because that is the reference semantics: it is what the verbs
called before #524. `_install` puts it at the lowest seam available — the
service builders before step 2, the `google_io` transport after it — so the
assertions below are the same ones on both sides of the change.

Not pinned here: the bytes of `gdrive.download`. Before step 2 a download runs
through `MediaIoBaseDownload`, which needs a real HTTP request object; the
transport's download/upload framing is pinned in `test_524_google_io.py`.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from . import egress
from . import google_oauth as go
from . import taint
from . import tools_api
from . import vault
from . import whitelist as wl
from .connectors import resolved
from .tools import gcalendar, gdocs, gdrive, gsheets
from .tools import gdrive_labels
from .tools import gdrive_root as gr

ACCT = "conto"

# ---------------------------------------------------------------------------
# 1. PDP parity
# ---------------------------------------------------------------------------

#: One set of arguments carrying every id a Google verb can name.
ARGS = {"folder_id": "F", "parent_id": "P", "email": "X@Y.it", "file_id": "FI",
        "document_id": "D", "spreadsheet_id": "S", "calendar_id": "c@x.it"}

_DRIVE_DESTS = ("drive", ["mailto:x@y.it", "gdrive:folder/F", "gdrive:folder/P"])

#: verb → (spec_for(verb) applied to ARGS, source_uri(verb, ARGS), taints(verb))
PDP = {
    "gdrive.list":              (None, None, False),
    "gdrive.search":            (None, None, False),
    "gdrive.mkdir":             (_DRIVE_DESTS, None, False),
    "gdrive.upload":            (_DRIVE_DESTS, None, False),
    "gdrive.update":            (_DRIVE_DESTS, None, False),
    "gdrive.download":          (None, "gdrive:file/FI", True),
    "gdrive.share":             (_DRIVE_DESTS, None, False),
    "gdrive.rename":            (None, None, False),
    "gdrive.move":              (_DRIVE_DESTS, None, False),
    "gcalendar.list_calendars": (None, None, False),
    "gcalendar.list_events":    (None, None, True),
    "gcalendar.create_event":   (None, None, False),
    "gcalendar.update_event":   (None, None, False),
    "gcalendar.delete_event":   (None, None, False),
    "gcalendar.freebusy":       (None, None, False),
    "gdocs.create":             (None, None, False),
    "gdocs.read":               (None, "gdrive:doc/D", True),
    "gdocs.append_text":        (None, None, False),
    "gdocs.replace_text":       (None, None, False),
    "gsheets.list_tabs":        (None, "gsheets:S", True),
    "gsheets.read":             (None, "gsheets:S", True),
    "gsheets.add_tab":          (("gsheets", ["gsheets:S"]), None, False),
    "gsheets.append_rows":      (("gsheets", ["gsheets:S"]), None, False),
    "gsheets.write_range":      (("gsheets", ["gsheets:S"]), None, False),
}

#: Declared reads (`direction: source`) — the verbs whose source can be vetted.
DECLARED_READS = {"gdrive.download", "gdocs.read", "gsheets.list_tabs",
                  "gsheets.read"}

#: raw URI → canonical form, for what a human pastes into a list.
CANONICAL = [
    ("https://drive.google.com/drive/folders/ABC", "gdrive:folder/ABC"),
    ("https://drive.google.com/drive/u/1/folders/ABC?usp=sharing", "gdrive:folder/ABC"),
    ("https://docs.google.com/document/d/D1/edit?tab=t.0", "gdrive:doc/D1"),
    ("https://drive.google.com/file/d/F1/view?usp=drive_link", "gdrive:file/F1"),
    ("https://docs.google.com/spreadsheets/d/S1/edit#gid=0", "gsheets:S1"),
    ("gdrive://ABC", "gdrive:folder/ABC"),
    ("gdrive://folder/ABC/", "gdrive:folder/ABC"),
    ("gsheets://S1/", "gsheets:S1"),
    ("gdrive:file/F", "gdrive:file/F"),
    ("gdrive:doc/D", "gdrive:doc/D"),
    ("gcal:a@b.it", "gcal:a@b.it"),
    ("gcal:primary", "gcal:primary"),
    ("gcal:*@tomato.blue", "gcal:*@tomato.blue"),
    # Oddity carried across on purpose: the scheme is lowercased, the
    # calendar id is not (matching is case-insensitive in `_matches`).
    ("GCAL:A@B.IT", "gcal:A@B.IT"),
]

#: (direction, uri) → canonical uri returned, or None when refused.
GRANTABLE = [
    ("egress", "gdrive:folder/ABC", "gdrive:folder/ABC"),
    ("egress", "gdrive:file/F", "gdrive:file/F"),
    ("egress", "gdrive:doc/D", "gdrive:doc/D"),
    ("egress", "gsheets:S1", "gsheets:S1"),
    ("egress", "gcal:a@b.it", "gcal:a@b.it"),
    ("egress", "gcal:primary", "gcal:primary"),
    ("egress", "gcal:*@x.it", "gcal:*@x.it"),
    ("egress", "https://drive.google.com/drive/folders/ABC", "gdrive:folder/ABC"),
    ("egress", "https://docs.google.com/spreadsheets/d/S1/edit", "gsheets:S1"),
    ("ingress", "gdrive:folder/ABC", "gdrive:folder/ABC"),
    ("ingress", "gdrive:file/F", "gdrive:file/F"),
    ("ingress", "gdrive:doc/D", "gdrive:doc/D"),
    ("ingress", "gsheets:S1", "gsheets:S1"),
    ("ingress", "https://drive.google.com/drive/folders/ABC", "gdrive:folder/ABC"),
    ("ingress", "https://docs.google.com/spreadsheets/d/S1/edit", "gsheets:S1"),
    # Oddity carried across: the `gdrive` forms are documentation for the
    # widget, not a filter — an unknown segment is still grantable.
    ("egress", "gdrive:bogus/x", "gdrive:bogus/x"),
    ("ingress", "gdrive:bogus/x", "gdrive:bogus/x"),
    # Refused.
    ("egress", "gcal:*", None),
    ("egress", "gcal:", None),
    ("egress", "gdrive:folder/", None),
    ("egress", "gsheets:", None),
    ("ingress", "gdrive:folder/", None),
    ("ingress", "gsheets:", None),
    ("ingress", "gcal:a@b.it", None),       # authority over a resource, not a source
    ("ingress", "gcal:primary", None),
    ("ingress", "gcal:*@x.it", None),
]


class PdpParityTests(unittest.TestCase):
    def test_the_table_covers_the_24_verbs(self):
        by_ns: dict[str, int] = {}
        for v in PDP:
            by_ns[v.split(".")[0]] = by_ns.get(v.split(".")[0], 0) + 1
        self.assertEqual(by_ns, {"gdrive": 9, "gcalendar": 6, "gdocs": 4, "gsheets": 5})

    def test_destinations(self):
        for verb, (spec, _src, _t) in PDP.items():
            with self.subTest(verb=verb):
                got = egress.spec_for(verb)
                if spec is None:
                    self.assertIsNone(got)
                else:
                    self.assertIsNotNone(got)
                    self.assertEqual((got[0], got[1](dict(ARGS))), spec)

    def test_destinations_with_one_argument(self):
        """The common case: a write naming only its folder or spreadsheet."""
        for verb, args, want in [
            ("gdrive.upload", {"folder_id": "F"}, ["gdrive:folder/F"]),
            ("gdrive.mkdir", {"parent_id": "P"}, ["gdrive:folder/P"]),
            ("gdrive.share", {"file_id": "FI", "email": "a@B.it"}, ["mailto:a@b.it"]),
            ("gdrive.update", {"file_id": "FI"}, []),
            ("gdrive.move", {"file_id": "FI", "folder_id": "F"}, ["gdrive:folder/F"]),
            ("gsheets.append_rows", {"spreadsheet_id": "S", "tab": "T"}, ["gsheets:S"]),
        ]:
            with self.subTest(verb=verb, args=args):
                self.assertEqual(egress.spec_for(verb)[1](args), want)

    def test_sources(self):
        for verb, (_spec, src, _t) in PDP.items():
            with self.subTest(verb=verb):
                self.assertEqual(resolved.source_uri(verb, dict(ARGS)), src)

    def test_declared_reads(self):
        got = {v for v in PDP if resolved.is_declared_read(v)}
        self.assertEqual(got, DECLARED_READS)

    def test_taint(self):
        for verb, (_spec, _src, t) in PDP.items():
            with self.subTest(verb=verb):
                self.assertEqual(taint.taints(verb), t)

    def test_schemes(self):
        self.assertIn("gcal", egress.egress_schemes())
        self.assertNotIn("gcal", egress.source_schemes())
        for s in ("gdrive", "gsheets"):
            self.assertIn(s, egress.egress_schemes())
            self.assertIn(s, egress.source_schemes())
        self.assertTrue(egress.hierarchical("gdrive"))
        self.assertFalse(egress.hierarchical("gsheets"))
        self.assertFalse(egress.hierarchical("gcal"))

    def test_canonical(self):
        for raw, want in CANONICAL:
            with self.subTest(uri=raw):
                self.assertEqual(egress.canonical(raw), want)

    def test_grantable(self):
        for direction, uri, want in GRANTABLE:
            with self.subTest(direction=direction, uri=uri):
                if want is None:
                    with self.assertRaises(ValueError):
                        egress.check_grantable(direction, uri)
                else:
                    self.assertEqual(egress.check_grantable(direction, uri), want)

    def test_calendar_matching(self):
        cfg = {"agents": {}, "egress_allow": ["gcal:*@tomato.blue", "gcal:Cal@X.it"]}
        with patch.object(wl, "CONFIG", cfg):
            self.assertEqual(egress.approved_calendars(), ["*@tomato.blue", "Cal@X.it"])
            self.assertTrue(egress.calendar_allowed("anna@tomato.blue"))
            self.assertTrue(egress.calendar_allowed("cal@x.it"))
            self.assertFalse(egress.calendar_allowed("primary"))
            self.assertFalse(egress.calendar_allowed("anna@tomato.blue.evil"))
            self.assertFalse(egress.calendar_allowed(""))


class FolderLabelShapeTests(unittest.TestCase):
    """`{uri: {"url", "name"}}`, only for `gdrive:folder/` entries."""

    def setUp(self):
        gdrive_labels._cache.clear()
        gdrive_labels._inflight.clear()
        self.addCleanup(gdrive_labels._cache.clear)
        self.fake = FakeGoogle({"1FolderAbcdEF": ["MYDRIVE"]},
                               names={"1FolderAbcdEF": "Progetto"})
        _install(self, self.fake)

    def test_shape(self):
        out = gdrive_labels.labels(["gdrive:folder/1FolderAbcdEF", "gsheets:S1",
                                    "gdrive:file/F1", "gdrive:folder/"])
        self.assertEqual(out, {"gdrive:folder/1FolderAbcdEF": {
            "url": "https://drive.google.com/drive/folders/1FolderAbcdEF",
            "name": "Progetto"}})
        self.assertEqual(self.fake.calls, [("files.get", {
            "fileId": "1FolderAbcdEF", "fields": "id,name,mimeType",
            "supportsAllDrives": True})])

    def test_an_unreadable_folder_keeps_the_link(self):
        out = gdrive_labels.labels(["gdrive:folder/1MissingFolderX"])
        self.assertEqual(out, {"gdrive:folder/1MissingFolderX": {
            "url": "https://drive.google.com/drive/folders/1MissingFolderX",
            "name": None}})


# ---------------------------------------------------------------------------
# 2. A fake Google service with the shape of googleapiclient
# ---------------------------------------------------------------------------

class _Request:
    def __init__(self, fn):
        self._fn = fn

    def execute(self, **_kw):
        return self._fn()


class _Resource:
    """`svc.files()`, `svc.spreadsheets().values()`, … — every method call is
    recorded as `(resource.method, kwargs)` and answered by the owner."""

    _CHILDREN = {"spreadsheets": ("values",)}

    def __init__(self, owner, name):
        self._o, self._n = owner, name

    def __getattr__(self, method):
        if method.startswith("_"):
            raise AttributeError(method)
        if method in self._CHILDREN.get(self._n, ()):
            return lambda: _Resource(self._o, f"{self._n}.{method}")
        op = f"{self._n}.{method}"

        def call(**kw):
            kw = {k: v for k, v in kw.items() if v is not None}
            if "media_body" in kw:
                kw["media_body"] = kw["media_body"].mimetype()
            self._o.calls.append((op, kw))
            return _Request(lambda: self._o.answer(op, kw))
        return call


class FakeGoogle:
    """Drive, Docs, Sheets and Calendar answered from a parents table."""

    def __init__(self, tree, *, shortcuts=(), names=None, mimes=None, rows=None,
                 calendars=None):
        self.tree = {k: list(v) for k, v in tree.items()}
        self.shortcuts = set(shortcuts)
        self.names = dict(names or {})
        self.mimes = dict(mimes or {})
        self.rows = list(rows or [])
        self.calendars = list(calendars if calendars is not None else [
            {"id": "cal@x.it", "summary": "Mine", "primary": True, "accessRole": "owner"},
            {"id": "other@x.it", "summary": "Theirs", "accessRole": "reader"}])
        self.calls: list[tuple[str, dict]] = []

    def __getattr__(self, resource):
        if resource.startswith("_"):
            raise AttributeError(resource)
        return lambda: _Resource(self, resource)

    def ops(self):
        return [op for op, _ in self.calls]

    def _file(self, fid):
        if fid not in self.tree:
            raise RuntimeError(f"404 File not found: {fid}")
        out = {"id": fid, "name": self.names.get(fid, f"name-{fid}"),
               "mimeType": self.mimes.get(fid, "text/plain"),
               "parents": list(self.tree[fid])}
        if fid in self.shortcuts:
            out["shortcutDetails"] = {"targetId": "elsewhere"}
            out["mimeType"] = gr.SHORTCUT_MIME
        return out

    def answer(self, op, kw):  # noqa: C901 — one branch per API method
        if op == "files.get":
            return self._file(kw["fileId"])
        if op == "files.list":
            return {"files": [dict(r) for r in self.rows]}
        if op == "files.create":
            body = kw.get("body") or {}
            return {"id": "NEW", "name": body.get("name"),
                    "mimeType": body.get("mimeType", "text/plain"),
                    "parents": body.get("parents", [])}
        if op == "files.update":
            f = self._file(kw["fileId"])
            if (kw.get("body") or {}).get("name"):
                f["name"] = kw["body"]["name"]
            if kw.get("addParents"):
                f["parents"] = [kw["addParents"]]
            return f
        if op == "permissions.create":
            return {"id": "PERM1"}
        if op == "documents.create":
            return {"documentId": "DOC1", "title": kw["body"]["title"]}
        if op == "documents.get":
            return {"title": "Doc", "body": {"content": [
                {"endIndex": 1, "sectionBreak": {}},
                {"endIndex": 6, "paragraph": {"elements": [
                    {"textRun": {"content": "ciao\n"}}]}}]}}
        if op == "documents.batchUpdate":
            return {"replies": [{"replaceAllText": {"occurrencesChanged": 2}}]}
        if op == "spreadsheets.get":
            return {"properties": {"title": "Budget"}, "sheets": [
                {"properties": {"title": "T1", "sheetId": 1, "index": 0,
                                "gridProperties": {"rowCount": 5, "columnCount": 3}}}]}
        if op == "spreadsheets.batchUpdate":
            p = kw["body"]["requests"][0]["addSheet"]["properties"]
            return {"replies": [{"addSheet": {"properties": {
                "title": p["title"], "sheetId": 9, "index": p.get("index", 1)}}}]}
        if op == "spreadsheets.values.get":
            return {"range": f"{kw['range']}!A1:B2", "values": [["a", "b"], ["1", "2"]]}
        if op == "spreadsheets.values.append":
            return {"updates": {"updatedRange": f"{kw['range']}!A6:B6",
                                "updatedRows": len(kw["body"]["values"])}}
        if op == "spreadsheets.values.update":
            return {"updatedRange": kw["range"], "updatedCells": 2}
        if op == "calendarList.list":
            return {"items": [dict(c) for c in self.calendars]}
        if op == "events.list":
            return {"items": [{"id": "E1", "summary": "Call", "etag": "x",
                               "start": {"dateTime": "2026-10-20T10:00:00+02:00"},
                               "end": {"dateTime": "2026-10-20T11:00:00+02:00"}}]}
        if op == "events.insert":
            return {"id": "E2", **kw["body"]}
        if op == "events.get":
            return {"id": kw["eventId"], "summary": "Old",
                    "start": {"date": "2026-10-20"}, "end": {"date": "2026-10-21"}}
        if op == "events.update":
            return dict(kw["body"])
        if op == "events.delete":
            return ""
        if op == "freebusy.query":
            return {"calendars": {kw["body"]["items"][0]["id"]: {"busy": [
                {"start": "2026-10-20T10:00:00Z", "end": "2026-10-20T11:00:00Z"}]}}}
        raise AssertionError(f"unexpected Google call {op} {kw}")


def _install(test: unittest.TestCase, fake: FakeGoogle) -> None:
    """Answer every Google call of the gateway from `fake`, at the lowest seam
    that exists: the `google_io` transport once it exists (#524 step 2), the
    service builders before it."""
    try:
        from .tools import google_io
    except ImportError:
        google_io = None
    patches = [patch.object(gdrive, "gworkspace_accounts", lambda: [ACCT]),
               patch.object(gdrive, "tool_allowed", lambda *_a, **_k: None)]
    if google_io is not None:
        from .tools._google_fake import ServiceTransport
        patches.append(patch.object(google_io, "_transport", ServiceTransport(fake)))
    else:  # pragma: no cover — main before #524 step 2
        def svc(account=None):
            return fake, gdrive._resolve_account(account)

        def build(api, version, account=None):
            return fake, gdrive._resolve_account(account)
        patches += [patch.object(gdrive, "_service", svc)]
        patches += [patch.object(m, "build_service", build)
                    for m in (gdocs, gsheets, gcalendar)]
    for p in patches:
        p.start()
        test.addCleanup(p.stop)


# ---------------------------------------------------------------------------
# What each verb asks Google, unconfined
# ---------------------------------------------------------------------------

_FIELDS = ("id, name, mimeType, modifiedTime, size, webViewLink, parents, "
           "md5Checksum, shortcutDetails")
_ALL = {"supportsAllDrives": True, "includeItemsFromAllDrives": True,
        "corpora": "allDrives"}


class _Base(unittest.TestCase):
    TREE = {
        "ROOT": ["MYDRIVE"], "MYDRIVE": [],
        "in": ["ROOT"], "sub": ["ROOT"], "deep": ["sub"],
        "SC": ["ROOT"],                       # a shortcut INSIDE the root
        "out": ["ELSE"], "ELSE": [],
        "TOPIC": ["MYDRIVE"], "in-topic": ["TOPIC"],
        "DOC1": ["MYDRIVE"],                  # where the Docs API creates
        "SHEET": ["ROOT"], "SHEET-OUT": ["ELSE"],
    }

    def setUp(self):
        gr.reset_cache()
        gr.reset_topic_cache()
        self.addCleanup(gr.reset_cache)
        self.addCleanup(gr.reset_topic_cache)
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.src = os.path.join(self.dir, "note.txt")
        with open(self.src, "wb") as fh:
            fh.write(b"hello\n")
        self.fake = FakeGoogle(self.TREE, shortcuts={"SC"},
                               mimes={"DOC1": "application/vnd.google-apps.document"},
                               rows=[{"id": "in", "name": "a", "parents": ["ROOT"],
                                      "mimeType": "text/plain"},
                                     {"id": "deep", "name": "b", "parents": ["sub"],
                                      "mimeType": "text/plain"},
                                     {"id": "out", "name": "c", "parents": ["ELSE"],
                                      "mimeType": "text/plain"},
                                     {"id": "SC", "name": "d", "parents": ["ROOT"],
                                      "mimeType": gr.SHORTCUT_MIME,
                                      "shortcutDetails": {"targetId": "out"}}])
        _install(self, self.fake)

    def cfg(self, **kw):
        c = {"agents": {}, **kw}
        p = patch.object(wl, "CONFIG", c)
        p.start()
        self.addCleanup(p.stop)


class UnconfinedCallsTests(_Base):
    """Every verb, no perimeter: the exact Google calls and the result."""

    def setUp(self):
        super().setUp()
        self.cfg()

    def test_drive_list_and_search(self):
        out = gdrive.list_files(folder_id="ROOT", query="name contains 'x'", limit=5)
        self.assertEqual(self.fake.calls, [("files.list", {
            "q": "trashed = false and 'ROOT' in parents and (name contains 'x')",
            "pageSize": 5, "fields": f"files({_FIELDS})", "orderBy": "folder,name",
            **_ALL})])
        self.assertEqual([f["id"] for f in out["files"]], ["in", "deep", "out", "SC"])
        self.assertEqual(out["account"], ACCT)
        self.fake.calls.clear()
        out = gdrive.search("o'k", limit=2000)
        self.assertEqual(self.fake.calls, [("files.list", {
            "q": "name contains 'o\\'k' and trashed = false", "pageSize": 1000,
            "fields": f"files({_FIELDS})", "orderBy": "folder,name", **_ALL})])

    def test_drive_mkdir(self):
        out = gdrive.mkdir("New", parent_id="ROOT")
        self.assertEqual(out["reused"], True)               # the fake lists rows
        self.assertEqual(out["id"], "in")
        self.fake.calls.clear()
        self.fake.rows = []
        out = gdrive.mkdir("New", parent_id="ROOT")
        q = ("name = 'New' and mimeType = 'application/vnd.google-apps.folder' "
             "and trashed = false and 'ROOT' in parents")
        self.assertEqual(self.fake.calls, [
            ("files.list", {"q": q, "fields": f"files({_FIELDS})", **_ALL}),
            ("files.create", {"body": {"name": "New",
                                       "mimeType": "application/vnd.google-apps.folder",
                                       "parents": ["ROOT"]},
                              "fields": _FIELDS, "supportsAllDrives": True})])
        self.assertEqual(out["reused"], False)

    def test_drive_upload(self):
        out = gdrive.upload(self.src, folder_id="ROOT")
        self.assertEqual(self.fake.calls, [("files.create", {
            "body": {"name": "note.txt", "parents": ["ROOT"]},
            "media_body": "text/plain", "fields": _FIELDS,
            "supportsAllDrives": True})])
        self.assertEqual(out["uploaded"], True)
        self.assertEqual(out["id"], "NEW")

    def test_drive_update(self):
        out = gdrive.update("in", self.src)
        self.assertEqual(self.fake.calls, [
            ("files.get", {"fileId": "in", "fields": "id, name, mimeType",
                           "supportsAllDrives": True}),
            ("files.update", {"fileId": "in", "media_body": "text/plain",
                              "fields": _FIELDS, "supportsAllDrives": True})])
        self.assertTrue(out["same_file"])

    def test_drive_share(self):
        out = gdrive.share("in", "a@b.it", role="reader")
        self.assertEqual(self.fake.calls, [
            ("permissions.create", {"fileId": "in", "sendNotificationEmail": True,
                                    "supportsAllDrives": True,
                                    "body": {"type": "user", "role": "reader",
                                             "emailAddress": "a@b.it"},
                                    "fields": "id"}),
            ("files.get", {"fileId": "in", "fields": "id, name, webViewLink",
                           "supportsAllDrives": True})])
        self.assertEqual(out["permission_id"], "PERM1")

    def test_drive_rename_and_move(self):
        gdrive.rename("in", " Nuovo ")
        self.assertEqual(self.fake.calls, [("files.update", {
            "fileId": "in", "body": {"name": "Nuovo"}, "fields": _FIELDS,
            "supportsAllDrives": True})])
        self.fake.calls.clear()
        out = gdrive.move("in", " sub ")
        self.assertEqual(self.fake.calls, [
            ("files.get", {"fileId": "in", "fields": "parents", "supportsAllDrives": True}),
            ("files.update", {"fileId": "in", "addParents": "sub", "removeParents": "ROOT",
                              "fields": _FIELDS, "supportsAllDrives": True})])
        self.assertEqual((out["from"], out["to"]), ("ROOT", "sub"))

    def test_docs(self):
        out = gdocs.create("Titolo", text="ciao")
        self.assertEqual(self.fake.calls, [
            ("documents.create", {"body": {"title": "Titolo"}}),
            ("documents.batchUpdate", {"documentId": "DOC1", "body": {"requests": [
                {"insertText": {"location": {"index": 1}, "text": "ciao"}}]}})])
        self.assertIsNone(out["folder_id"])
        self.fake.calls.clear()
        self.assertEqual(gdocs.read("DOC1")["text"], "ciao\n")
        self.assertEqual(self.fake.calls, [("documents.get", {"documentId": "DOC1"})])
        self.fake.calls.clear()
        gdocs.append_text("DOC1", "!")
        self.assertEqual(self.fake.calls[-1], ("documents.batchUpdate", {
            "documentId": "DOC1", "body": {"requests": [
                {"insertText": {"location": {"index": 5}, "text": "!"}}]}}))
        self.fake.calls.clear()
        self.assertEqual(gdocs.replace_text("DOC1", "a", "b", match_case=False)
                         ["occurrences"], 2)
        self.assertEqual(self.fake.calls, [("documents.batchUpdate", {
            "documentId": "DOC1", "body": {"requests": [{"replaceAllText": {
                "containsText": {"text": "a", "matchCase": False},
                "replaceText": "b"}}]}})])

    def test_sheets(self):
        out = gsheets.list_tabs("SHEET")
        self.assertEqual(self.fake.calls, [
            ("spreadsheets.get", {"spreadsheetId": "SHEET", "fields": "properties.title"}),
            ("spreadsheets.get", {"spreadsheetId": "SHEET", "fields":
                                  "sheets.properties(title,sheetId,index,gridProperties)"})])
        self.assertEqual(out["tabs"], [{"title": "T1", "sheet_id": 1, "index": 0,
                                        "rows": 5, "cols": 3}])
        self.fake.calls.clear()
        out = gsheets.read("SHEET", tab="T1", formulas=True)
        self.assertEqual(self.fake.calls, [("spreadsheets.values.get", {
            "spreadsheetId": "SHEET", "range": "T1", "valueRenderOption": "FORMULA"})])
        self.assertEqual(out["rows"], 2)
        self.fake.calls.clear()
        gsheets.append_rows("SHEET", "T1", [["x", 1]])
        self.assertEqual(self.fake.calls, [("spreadsheets.values.append", {
            "spreadsheetId": "SHEET", "range": "T1", "valueInputOption": "USER_ENTERED",
            "insertDataOption": "INSERT_ROWS", "body": {"values": [["x", 1]]}})])
        self.fake.calls.clear()
        gsheets.write_range("SHEET", "T1!A1:B1", [["x", "y"]])
        self.assertEqual(self.fake.calls, [("spreadsheets.values.update", {
            "spreadsheetId": "SHEET", "range": "T1!A1:B1",
            "valueInputOption": "USER_ENTERED", "body": {"values": [["x", "y"]]}})])
        self.fake.calls.clear()
        out = gsheets.add_tab("SHEET", "T2", index=1)
        self.assertEqual(self.fake.ops(), ["spreadsheets.get", "spreadsheets.batchUpdate"])
        self.assertEqual(self.fake.calls[1][1], {"spreadsheetId": "SHEET", "body": {
            "requests": [{"addSheet": {"properties": {"title": "T2", "index": 1}}}]}})
        self.assertEqual(out["kept_tabs"], ["T1"])

    def test_calendar(self):
        out = gcalendar.list_calendars()
        self.assertEqual(self.fake.calls, [("calendarList.list", {})])
        self.assertEqual([c["id"] for c in out["calendars"]], ["cal@x.it", "other@x.it"])
        self.fake.calls.clear()
        out = gcalendar.list_events("cal@x.it", time_min="A", time_max="B",
                                    query="q", limit=999)
        self.assertEqual(self.fake.calls, [("events.list", {
            "calendarId": "cal@x.it", "singleEvents": True, "orderBy": "startTime",
            "maxResults": 250, "timeMin": "A", "timeMax": "B", "q": "q"})])
        self.assertNotIn("etag", out["events"][0])
        self.fake.calls.clear()
        gcalendar.create_event("S", "2026-10-20", "2026-10-21", all_day=True,
                               attendees=["a@b.it"])
        self.assertEqual(self.fake.calls, [("events.insert", {
            "calendarId": "primary", "body": {
                "summary": "S", "start": {"date": "2026-10-20"},
                "end": {"date": "2026-10-21"}, "attendees": [{"email": "a@b.it"}]}})])
        self.fake.calls.clear()
        gcalendar.update_event("E1", start="2026-10-22")
        self.assertEqual(self.fake.calls, [
            ("events.get", {"calendarId": "primary", "eventId": "E1"}),
            ("events.update", {"calendarId": "primary", "eventId": "E1", "body": {
                "id": "E1", "summary": "Old", "start": {"date": "2026-10-22"},
                "end": {"date": "2026-10-21"}}})])
        self.fake.calls.clear()
        self.assertTrue(gcalendar.delete_event("E1")["ok"])
        self.assertEqual(self.fake.calls, [("events.delete", {
            "calendarId": "primary", "eventId": "E1"})])
        self.fake.calls.clear()
        out = gcalendar.freebusy("A", "B")
        self.assertEqual(self.fake.calls, [("freebusy.query", {"body": {
            "timeMin": "A", "timeMax": "B", "items": [{"id": "primary"}]}})])
        self.assertEqual(len(out["busy"]), 1)


# ---------------------------------------------------------------------------
# The perimeter: an account root, then a topic's drive_folders
# ---------------------------------------------------------------------------

class _PerimeterCases:
    """The same perimeter, whatever declares it. `ROOT_ID` is the folder."""

    ROOT_ID = "ROOT"
    INSIDE = "in"
    DEEP = "deep"

    def test_parent_walk(self):
        self.assertTrue(gr.confined(ACCT))
        gdrive.rename(self.DEEP, "x")                      # walks deep → sub → ROOT
        self.assertEqual(self.fake.ops()[-1], "files.update")
        self.fake.calls.clear()
        with self.assertRaises(gr.OutsideRoot):
            gdrive.rename("out", "x")
        self.assertNotIn("files.update", self.fake.ops())

    def test_an_api_error_is_outside(self):
        with self.assertRaises(gr.OutsideRoot):
            gdrive.share("missing", "a@b.it")
        self.assertNotIn("permissions.create", self.fake.ops())

    def test_a_shortcut_is_refused(self):
        with self.assertRaises(gr.OutsideRoot):
            gdrive.rename("SC", "x")
        with self.assertRaises(gr.OutsideRoot):
            gdrive.download("SC", os.path.join(self.dir, "x"))
        self.assertNotIn("files.update", self.fake.ops())

    def test_list_filtering(self):
        out = gdrive.list_files(query="anything")
        self.assertEqual([f["id"] for f in out["files"]], [self.INSIDE, self.DEEP])
        out = gdrive.search("a")
        self.assertEqual([f["id"] for f in out["files"]], [self.INSIDE, self.DEEP])

    def test_writable_parent(self):
        out = gdrive.upload(self.src)                       # default parent = the root
        create = [kw for op, kw in self.fake.calls if op == "files.create"][0]
        self.assertEqual(create["body"]["parents"], [self.ROOT_ID])
        self.assertEqual(out["uploaded"], True)
        with self.assertRaises(gr.OutsideRoot):
            gdrive.upload(self.src, folder_id="ELSE")
        with self.assertRaises(gr.OutsideRoot):
            gdrive.mkdir("x", parent_id="ELSE")
        n = len([op for op in self.fake.ops() if op == "files.create"])
        self.assertEqual(n, 1)

    def test_move_checks_both_ends(self):
        with self.assertRaises(gr.OutsideRoot) as ctx:
            gdrive.move(self.INSIDE, "ELSE")
        self.assertIn("destinazione", str(ctx.exception))
        self.assertNotIn("files.update", self.fake.ops())

    def test_adopt_after_create(self):
        out = gdocs.create("T")
        self.assertEqual(out["folder_id"], self.ROOT_ID)
        self.assertEqual(self.fake.calls[-2:], [
            ("files.get", {"fileId": "DOC1", "fields": "parents",
                           "supportsAllDrives": True}),
            ("files.update", {"fileId": "DOC1", "addParents": self.ROOT_ID,
                              "removeParents": "MYDRIVE", "fields": "id",
                              "supportsAllDrives": True})])

    def test_docs_and_sheets_ids_are_guarded(self):
        with self.assertRaises(gr.OutsideRoot):
            gsheets.read("SHEET-OUT")
        with self.assertRaises(gr.OutsideRoot):
            gdocs.read("DOC1")                              # in My Drive, not the root
        self.assertNotIn("spreadsheets.values.get", self.fake.ops())
        self.assertNotIn("documents.get", self.fake.ops())

    def test_calendar_without_approval_is_closed(self):
        self.approve_calendars([])
        with self.assertRaises(gr.OutsideRoot):
            gcalendar.list_calendars()
        with self.assertRaises(gr.OutsideRoot):
            gcalendar.list_events("cal@x.it")
        self.assertEqual(self.fake.calls, [])

    def test_calendar_with_approved_gcal(self):
        self.approve_calendars(["gcal:cal@x.it"])
        out = gcalendar.list_calendars()
        self.assertEqual([c["id"] for c in out["calendars"]], ["cal@x.it"])
        self.assertEqual(gcalendar.list_events("cal@x.it")["calendar_id"], "cal@x.it")
        with self.assertRaises(gr.OutsideRoot):
            gcalendar.list_events("other@x.it")
        with self.assertRaises(gr.OutsideRoot):
            gcalendar.create_event("S", "a", "b", calendar_id="other@x.it")
        self.assertNotIn("events.insert", self.fake.ops())


class AccountRootTests(_PerimeterCases, _Base):
    def setUp(self):
        super().setUp()
        self.approve_calendars([])

    def approve_calendars(self, uris):
        self.cfg(gdrive_roots={ACCT: ["ROOT"]}, egress_allow=list(uris))


class TopicPerimeterTests(_PerimeterCases, _Base):
    """The topic's `drive_folders` is the root inside its channel."""

    ROOT_ID = "TOPIC"
    INSIDE = "in-topic"
    DEEP = "deep-topic"
    CHAN = "chan:SEAL-1:acme:messaggero"

    def setUp(self):
        super().setUp()
        self.fake.tree.update({"sub-topic": ["TOPIC"], "deep-topic": ["sub-topic"]})
        self.fake.rows = [{"id": "in-topic", "name": "a", "parents": ["TOPIC"],
                           "mimeType": "text/plain"},
                          {"id": "in", "name": "b", "parents": ["ROOT"],
                           "mimeType": "text/plain"},
                          {"id": "deep-topic", "name": "e", "parents": ["sub-topic"],
                           "mimeType": "text/plain"},
                          {"id": "SC", "name": "d", "parents": ["TOPIC"],
                           "mimeType": gr.SHORTCUT_MIME,
                           "shortcutDetails": {"targetId": "out"}}]
        self.fake.tree["SC"] = ["TOPIC"]
        self.fake.tree["SHEET"] = ["TOPIC"]
        meta = {"drive_folders": [{"folder": "TOPIC"}]}
        topics = type("T", (), {"open": lambda _s, tier, name: {"meta": meta}})()
        from . import main as _main
        p = patch.object(_main, "_topics", lambda: topics)
        p.start()
        self.addCleanup(p.stop)
        tok = wl.set_current_chat(self.CHAN)
        self.addCleanup(wl.reset_current_chat, tok)
        self.approve_calendars([])

    def approve_calendars(self, uris):
        self.cfg(scope_egress_allow={"SEAL-1/acme": list(uris)})

    def test_the_perimeter_comes_from_the_topic(self):
        self.assertEqual(gr.roots_for_call(ACCT), (["TOPIC"], "topic"))

    def test_a_folder_of_the_account_is_not_the_topic(self):
        with self.assertRaises(gr.OutsideRoot):
            gdrive.rename("in", "x")


# ---------------------------------------------------------------------------
# 3. Credential custody
# ---------------------------------------------------------------------------

class _JsonRequest:
    def __init__(self, body):
        self._body = body

    async def json(self):
        return self._body


class CredentialCustodyTests(unittest.TestCase):
    def test_unified_scope_is_unchanged(self):
        self.assertEqual(go.UNIFIED_SCOPE, " ".join([
            "https://mail.google.com/",
            "https://www.googleapis.com/auth/drive",
            "https://www.googleapis.com/auth/documents",
            "https://www.googleapis.com/auth/calendar",
            "https://www.googleapis.com/auth/userinfo.email",
            "openid"]))
        self.assertEqual(go.TOKEN_URL, "https://oauth2.googleapis.com/token")

    def test_connect_deposits_the_bundle(self):
        deposits = []
        app = {"client_id": "CID", "client_secret": "CSECRET",
               "redirect_uri": "http://127.0.0.1"}
        with patch.object(tools_api, "_connector_guard", lambda _c: None), \
                patch.object(tools_api, "_authorized", lambda _r: True), \
                patch.object(vault, "read_internal",
                             lambda n: app if n == go.APP_CREDENTIAL else {}), \
                patch.object(go, "exchange_code",
                             lambda *a: {"refresh_token": "RT", "access_token": "AT"}), \
                patch.object(go, "get_profile_email", lambda _t: "Mario.Rossi@x.it"), \
                patch.object(vault, "deposit",
                             lambda name, bundle, **kw: deposits.append((name, bundle, kw))):
            resp = asyncio.run(tools_api.google_connect(_JsonRequest({"code": "C"})))
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(deposits, [(
            "google_Mario_Rossi",
            {"client_id": "CID", "client_secret": "CSECRET", "refresh_token": "RT",
             "email": "Mario.Rossi@x.it", "account": "Mario_Rossi",
             "scope": go.UNIFIED_SCOPE},
            {"cred_type": "oauth2_google", "grant_agents": ["clodia"]})])

    def test_the_verbs_read_that_bundle(self):
        """`google_<acct>` wins over the legacy `gworkspace_<acct>`."""
        with patch.object(vault, "has_credential", lambda n: n == "google_conto"):
            self.assertEqual(gdrive._drive_cred("conto"), "google_conto")
        with patch.object(vault, "has_credential", lambda n: False):
            self.assertEqual(gdrive._drive_cred("conto"), "gworkspace_conto")
        with patch.object(vault, "store_names",
                          lambda: ["google_b", "gworkspace_a", "gmail_c", "other"]):
            self.assertEqual(gdrive.gworkspace_accounts(), ["a", "b"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

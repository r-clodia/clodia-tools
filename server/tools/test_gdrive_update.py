"""`gdrive.update`: correggere un file Drive senza farne una copia (clodia-platform#427)."""
from __future__ import annotations

import contextlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import gdrive
from . import google_io
from ._google_fake import ServiceTransport


@contextlib.contextmanager
def _drive(svc, error=None):
    """Answer the Google calls from the fake `svc`, or fail them with `error`
    (#524: the calls go through `google_io`, the fake keeps its old shape)."""
    def boom(_account, _req):
        raise error
    with patch.object(google_io, "_transport", boom if error else ServiceTransport(svc)), \
            patch.object(gdrive, "gworkspace_accounts", lambda: ["davide"]):
        yield


class _Req:
    def __init__(self, v):
        self.v = v

    def execute(self, **_k):
        return self.v


class _Files:
    def __init__(self, mime):
        self.mime, self.updated = mime, []

    def get(self, fileId, fields="", supportsAllDrives=True):
        return _Req({"id": fileId, "name": "Offerta", "mimeType": self.mime, "parents": ["F1"]})

    def update(self, fileId, media_body=None, fields="", supportsAllDrives=True, **_k):
        self.updated.append((fileId, media_body.mimetype()))
        return _Req({"id": fileId, "name": "Offerta", "mimeType": self.mime,
                     "webViewLink": f"https://docs.google.com/document/d/{fileId}"})


class _Svc:
    def __init__(self, mime):
        self._f = _Files(mime)

    def files(self):
        return self._f


def _src(ext: str) -> str:
    d = Path(tempfile.mkdtemp())
    p = d / f"offerta{ext}"
    p.write_bytes(b"contenuto")
    return str(p)


class UpdateTests(unittest.TestCase):
    def _run(self, mime, ext):
        svc = _Svc(mime)
        with patch.object(gdrive, "tool_allowed", lambda v: None), \
                _drive(svc), \
                patch.object(gdrive.gdrive_root, "assert_inside") as inside:
            out = gdrive.update("DOC1", _src(ext))
        return out, svc, inside

    def test_the_same_file_is_updated_not_copied(self):
        out, svc, inside = self._run("application/vnd.openxmlformats-officedocument.wordprocessingml.document", ".docx")
        self.assertTrue(out["updated"] and out["same_file"])
        self.assertEqual(svc.files().updated[0][0], "DOC1")
        inside.assert_called_once()

    def test_a_docx_goes_into_a_native_google_doc(self):
        out, svc, _ = self._run("application/vnd.google-apps.document", ".docx")
        self.assertTrue(out["same_file"])
        self.assertIn("wordprocessingml", svc.files().updated[0][1])

    def test_markdown_goes_into_a_native_google_doc(self):
        _out, svc, _ = self._run("application/vnd.google-apps.document", ".md")
        self.assertEqual(svc.files().updated[0][1], "text/markdown")

    def test_a_pdf_cannot_become_a_google_doc(self):
        with self.assertRaises(ValueError):
            self._run("application/vnd.google-apps.document", ".pdf")

    def test_a_folder_is_not_a_file(self):
        with self.assertRaises(ValueError):
            self._run("application/vnd.google-apps.folder", ".docx")

    def test_outside_the_perimeter_nothing_is_written(self):
        svc = _Svc("application/vnd.google-apps.document")
        with patch.object(gdrive, "tool_allowed", lambda v: None), \
                _drive(svc), \
                patch.object(gdrive.gdrive_root, "assert_inside",
                             side_effect=gdrive.gdrive_root.OutsideRoot("fuori")):
            with self.assertRaises(gdrive.gdrive_root.OutsideRoot):
                gdrive.update("DOC1", _src(".docx"))
        self.assertEqual(svc.files().updated, [])


class EgressTests(unittest.TestCase):
    def test_the_destination_is_the_folder_of_the_file(self):
        from .. import egress, main
        self.assertIsNotNone(egress.spec_for("gdrive.update"))
        with _drive(_Svc("x")):
            self.assertEqual(main._drive_parent_of({"file_id": "DOC1"}), "F1")
        self.assertEqual(
            egress.spec_for("gdrive.update")[1]({"file_id": "DOC1",
                                                 "folder_id": "F1"}),
            ["gdrive:folder/F1"])

    def test_an_unresolvable_parent_is_an_unknown_destination(self):
        from .. import main
        with _drive(None, RuntimeError("drive giù")):
            self.assertEqual(main._drive_parent_of({"file_id": "DOC1"}), "")


if __name__ == "__main__":
    unittest.main()

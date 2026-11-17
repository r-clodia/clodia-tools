"""#698 — a `.zip` uploaded to a RAG collection: unpacked in memory, every
supported member indexed as its own document, safety limits first."""
from __future__ import annotations

import io
import unittest
import zipfile
from unittest.mock import patch

from . import databases, main
from .test_671_databases import RouteTests, _Base


def _docx(text: str) -> bytes:
    from docx import Document
    d = Document()
    d.add_paragraph(text)
    buf = io.BytesIO()
    d.save(buf)
    return buf.getvalue()


def _pdf(text: str) -> bytes:
    stream = b"BT /F1 24 Tf 72 720 Td (" + text.encode() + b") Tj ET"
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
            b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"]
    out, offs = b"%PDF-1.4\n", []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    out += b"".join(b"%010d 00000 n \n" % x for x in offs)
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objs) + 1, xref)
    return out


def _zip(members: dict[str, bytes], dirs=(), method=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", method) as z:
        for d in dirs:
            z.writestr(zipfile.ZipInfo(d), b"")
        for n, b in members.items():
            z.writestr(n, b)
    return buf.getvalue()


def _up(data, **kw):
    return databases.upload("manuali", "pacco.zip", data, who="davide",
                            clearance="SEAL-4", **kw)


class ZipUploadTests(_Base):
    def test_mixed_archive(self):
        data = _zip({
            "docs/contratto.pdf": _pdf("Hello PDF"),
            "docs/offerta.docx": _docx("Offerta di prova"),
            "README.md": b"# Leggimi",
            "note/appunti.txt": b"appunti",
            "img/logo.png": b"\x89PNG....",
            ".DS_Store": b"x",
            "docs/.nascosto.md": b"segreto",
            "__MACOSX/docs/._contratto.pdf": b"x",
            "inner.zip": _zip({"a.txt": b"a"}),
            "vuoto.txt": b"   ",
        }, dirs=("docs/",))
        out = _up(data)
        self.assertTrue(out["archive"])
        by = {m["path"]: m for m in out["members"]}
        self.assertNotIn("docs/", by)                      # directories are not members
        for p, doc in (("docs/contratto.pdf", "docs/contratto"),
                       ("docs/offerta.docx", "docs/offerta"),
                       ("README.md", "README"), ("note/appunti.txt", "note/appunti")):
            self.assertEqual((by[p]["status"], by[p]["document"], by[p]["chunks"]),
                             ("indexed", doc, 1), p)
        reasons = {p: by[p]["reason"] for p in by if by[p]["status"] == "skipped"}
        self.assertEqual(reasons, {
            "img/logo.png": "unsupported format", ".DS_Store": "hidden file",
            "docs/.nascosto.md": "hidden file",
            "__MACOSX/docs/._contratto.pdf": "macOS metadata (__MACOSX)",
            "inner.zip": "nested archive (not expanded)", "vuoto.txt": "no extractable text"})
        self.assertEqual((out["indexed"], out["skipped"], out["errors"], out["bytes"]),
                         (4, 6, 0, len(data)))
        texts = {n: t for _c, n, t, _k in self.rag.ingested}
        self.assertIn("Hello PDF", texts["docs/contratto"])
        self.assertIn("Offerta di prova", texts["docs/offerta"])
        kw = self.rag.ingested[0][3]
        self.assertEqual(kw["provenance"], "untrusted")
        self.assertTrue(kw["source"].startswith("upload:davide:pacco.zip!"))

    def test_a_member_error_does_not_abort_the_others(self):
        out = _up(_zip({"rotto.docx": b"not a docx", "ok.txt": b"ciao"}))
        st = {m["path"]: m["status"] for m in out["members"]}
        self.assertEqual(st, {"rotto.docx": "error", "ok.txt": "indexed"})
        self.assertEqual((out["indexed"], out["errors"]), (1, 1))
        self.assertTrue(out["members"][0]["reason"])

    def test_zip_bomb_refused_before_indexing(self):
        bomb = _zip({"a.txt": b"hello", "bomb.txt": b"\0" * (5 * 1024 * 1024)})
        with self.assertRaisesRegex(ValueError, "zip bomb"):
            _up(bomb)
        with patch.object(main, "ZIP_MAX_TOTAL", 100):
            with self.assertRaisesRegex(ValueError, "zip bomb"):
                _up(_zip({"a.txt": b"x" * 60, "b.txt": b"y" * 60}, method=zipfile.ZIP_STORED))
        self.assertEqual(self.rag.ingested, [])

    def test_too_many_entries_refused(self):
        with patch.object(databases, "ARCHIVE_MAX_MEMBERS", 3):
            with self.assertRaisesRegex(ValueError, "max 3"):
                _up(_zip({f"f{i}.txt": b"x" for i in range(4)}, dirs=("d/",)))
            out = _up(_zip({f"f{i}.txt": b"x" for i in range(3)}, dirs=("d/", "e/")))
        self.assertEqual(out["indexed"], 3)

    def test_member_over_the_single_file_limit_is_skipped(self):
        with patch.object(databases, "_upload_max", lambda: 1000):
            out = _up(_zip({"big.txt": b"a b " * 400, "small.txt": b"ok"}))
        by = {m["path"]: m for m in out["members"]}
        self.assertEqual(by["big.txt"]["status"], "skipped")
        self.assertIn("too large", by["big.txt"]["reason"])
        self.assertEqual(by["small.txt"]["status"], "indexed")

    def test_doc_name_collisions(self):
        out = _up(_zip({"a/guida.md": b"1", "a/guida.txt": b"2", "a/guida.pdf": b"3"}))
        docs = [m["document"] for m in out["members"] if m["status"] == "indexed"]
        self.assertEqual(docs[:2], ["a/guida", "a/guida.txt"])
        self.assertEqual(len(set(docs)), len(docs))
        names = databases._archive_doc_name
        used = set()
        self.assertEqual([names(p, used) for p in ("x.md", "x.md", "x.md", "x")],
                         ["x", "x.md", "x.md (2)", "x (2)"])

    def test_doc_name_is_a_prefix_for_an_archive(self):
        out = _up(_zip({"a.txt": b"x"}), doc_name="lotto")
        self.assertEqual(out["members"][0]["document"], "lotto/a")

    def test_invalid_zip_and_tier(self):
        with self.assertRaisesRegex(ValueError, "not a valid ZIP"):
            _up(b"PK\x03\x04garbage")
        with self.assertRaises(PermissionError):
            databases.upload("manuali", "p.zip", _zip({"a.txt": b"x"}), who="mario",
                             clearance="SEAL-1")
        self.assertEqual(self.rag.ingested, [])

    def test_upload_formats_list_zip(self):
        self.assertIn(".zip", databases.catalogue(who="davide", is_admin=True,
                                                  clearance="SEAL-4")["upload_formats"])


class ZipRouteTests(_Base):
    client, person = RouteTests.client, RouteTests.person

    def test_zip_route_contract_and_audit(self):
        from . import databases_api
        seen = []
        p = patch.object(databases_api, "_audit", lambda *a, **k: seen.append((a, k)))
        p.start()
        self.addCleanup(p.stop)
        a = self.person("davide", role="admin", clearance="SEAL-4")
        url = "/internal/databases/collection/manuali/upload"
        r = a.post(url, params={"filename": "p.zip"},
                   content=_zip({"a.md": b"x", "b.png": b"y"}))
        self.assertEqual(r.status_code, 200, r.text)
        j = r.json()
        for k in ("archive", "members", "indexed", "skipped", "errors", "bytes"):
            self.assertIn(k, j)
        self.assertEqual(j["members"][0], {"path": "a.md", "document": "a", "chunks": 1,
                                           "status": "indexed"})
        self.assertEqual(j["members"][1]["reason"], "unsupported format")
        self.assertEqual(len(seen), 1)
        self.assertTrue(seen[0][1]["archive"])
        self.assertEqual([m["status"] for m in seen[0][1]["members"]], ["indexed", "skipped"])
        r = a.post(url, params={"filename": "p.zip"}, content=b"not a zip")
        self.assertEqual(r.status_code, 400)
        self.assertIn("ZIP", r.json()["error"])
        # A non-zip upload's response is unchanged.
        r = a.post(url, params={"filename": "a.txt"}, content=b"ciao")
        self.assertEqual(set(r.json()), {"ok", "collection", "document", "version", "chunks",
                                         "bytes", "characters"})


if __name__ == "__main__":
    unittest.main()

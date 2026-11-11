"""#671 — the Databases page's backend: catalogue, containers (create, delete
with pre-delete export, tombstones), content (rows, schema, documents,
chunks, upload) and who may do what."""
from __future__ import annotations

import io
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import data_catalog as cat, databases, datastores, topic_data as td, whitelist
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicService
from .tools import datastore_sql, eu_corpus as _eu

#: The real client functions, before any fixture replaces them with fakes.
_REAL_EU = {n: getattr(_eu, n) for n in ("ingest_text", "ingest_bytes", "create_collection",
                                         "set_collection_tier")}


class FakeRag:
    """The RAG service, in memory: collections, documents, chunks."""

    def __init__(self):
        self.cols = {"eu-normativa": "SEAL-0", "manuali": "SEAL-2", "topic-abc123": "SEAL-2"}
        self.docs = {"manuali": [{"name": "guida", "version": "1", "status": "active",
                                  "chunks": 2}]}
        self.ingested, self.dropped = [], []

    def collections(self):
        return {"collections": [{"collection": c, "tier": t,
                                 "documents": len(self.docs.get(c, [])),
                                 "chunks": sum(d["chunks"] for d in self.docs.get(c, [])),
                                 "updated_at": "2026-11-11T10:00:00+00:00"}
                                for c, t in self.cols.items()]}

    def collection_tier(self, c):
        return self.cols.get(c, "SEAL-0")

    def list_documents(self, c):
        return {"collection": c, "documents": list(self.docs.get(c, []))}

    def export_rows(self, c):
        yield {"type": "collection", "name": c, "tier": self.cols.get(c)}
        for i, d in enumerate(self.docs.get(c, [])):
            yield {"type": "document", "id": i, **d}
            for o in range(d["chunks"]):
                yield {"type": "chunk", "document_id": i, "ordinal": o, "text": f"t{o}",
                       "embedding": "[0.1]"}

    def drop_collection(self, c):
        self.dropped.append(c)
        self.cols.pop(c, None)
        self.docs.pop(c, None)
        return {"collection": c}

    def create_collection(self, c, tier="SEAL-1", description=None):
        self.cols.setdefault(c, tier)
        return {"collection": c, "tier": self.cols[c]}

    def ingest_text(self, c, name, text, **kw):
        self.ingested.append((c, name, text, kw))
        return {"chunks": 1}


class _Base(unittest.TestCase):
    def setUp(self):
        from . import authz_runtime as _azr
        _azr.invalidate()
        self.addCleanup(_azr.invalidate)
        self.root = Path(tempfile.mkdtemp(prefix="db671-"))
        state = self.root / "state"
        state.mkdir()
        # A pack datastore with one table.
        packdir = self.root / "plugins" / "tomato-pack"
        packdir.mkdir(parents=True)
        (packdir / "plugin.yaml").write_text(
            "datastores:\n  - name: clienti\n    path: clienti.db\n    clearance: SEAL-2\n"
            "rag_collections:\n  - name: manuali\n", encoding="utf-8")
        conn = sqlite3.connect(packdir / "clienti.db")
        conn.execute("CREATE TABLE persone (id INTEGER PRIMARY KEY, nome TEXT)")
        conn.execute("INSERT INTO persone (nome) VALUES ('Ada'), ('Bruno')")
        conn.commit()
        conn.close()
        self.rag = FakeRag()
        self.svc = TopicService(LocalFsStorage(tempfile.mkdtemp(prefix="topics-")))
        from .tools import eu_corpus
        for p in [
            patch.object(datastores, "DATADIR", str(self.root)),
            patch.object(cat, "_path", lambda: state / "data-catalog.json"),
            patch.object(cat, "_tomb_path", lambda: state / "data-tombstones.json"),
            patch.object(td, "_svc", lambda: self.svc),
            patch.object(whitelist, "CONFIG", {"data_access": "topic"}),
            *[patch.object(eu_corpus, n, getattr(self.rag, n)) for n in (
                "collections", "collection_tier", "list_documents", "export_rows",
                "drop_collection", "create_collection", "ingest_text")],
        ]:
            p.start()
            self.addCleanup(p.stop)
        cat._LAST_SYNC[0] = 0.0
        cat.sync()
        self.svc.new("SEAL-2", "commerciale", {"owner": "davide",
                                               "participants": ["davide", "mario", "clodia"]})
        self.svc.new("SEAL-2", "altro", {"owner": "davide", "participants": ["davide"]})
        td.import_resource("SEAL-2", "commerciale", "datastore", "tomato-pack/clienti",
                           principal="davide", is_admin=True, clearance="SEAL-4")
        td.import_resource("SEAL-2", "commerciale", "rag", "manuali",
                           principal="davide", is_admin=True, clearance="SEAL-4")

    def entry(self):
        return datastores.find("tomato-pack", "clienti")


class ExtractionTests(unittest.TestCase):
    """PPTX (new), DOCX, MD, TXT and PDF through the one extractor."""

    def test_pptx_slides_tables_and_notes(self):
        from pptx import Presentation
        from pptx.util import Inches
        prs = Presentation()
        s = prs.slides.add_slide(prs.slide_layouts[1])
        s.shapes.title.text = "Titolo della slide"
        s.placeholders[1].text = "Primo punto"
        tbl = s.shapes.add_table(2, 2, Inches(1), Inches(4), Inches(4), Inches(1)).table
        tbl.cell(0, 0).text, tbl.cell(1, 1).text = "colA", "valore"
        s.notes_slide.notes_text_frame.text = "Nota per il relatore"
        prs.slides.add_slide(prs.slide_layouts[5]).shapes.title.text = "Seconda"
        buf = io.BytesIO()
        prs.save(buf)
        text = databases.extract_text("deck.pptx", buf.getvalue())
        for want in ("## Slide 1", "Titolo della slide", "Primo punto", "colA", "valore",
                     "Note: Nota per il relatore", "## Slide 2", "Seconda"):
            self.assertIn(want, text)

    def test_docx(self):
        from docx import Document
        d = Document()
        d.add_paragraph("Contratto di prova")
        buf = io.BytesIO()
        d.save(buf)
        self.assertIn("Contratto di prova", databases.extract_text("a.docx", buf.getvalue()))

    def test_md_and_txt(self):
        self.assertEqual(databases.extract_text("a.md", "# Titolo\nè".encode()), "# Titolo\nè")
        self.assertEqual(databases.extract_text("a.TXT", b"ciao"), "ciao")

    def test_pdf(self):
        stream = b"BT /F1 24 Tf 72 720 Td (Hello PDF) Tj ET"
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
        self.assertIn("Hello PDF", databases.extract_text("a.pdf", out))

    def test_other_formats_refused(self):
        with self.assertRaises(ValueError):
            databases.extract_text("a.xlsx", b"x")
        with self.assertRaises(ValueError):
            databases.extract_text("a.exe", b"x")

    def test_the_topic_indexer_reads_pptx_too(self):
        from . import topic_index
        self.assertIn(".pptx", topic_index.DOC_EXT)


class UploadTests(_Base):
    def test_size_format_and_empty_limits(self):
        with patch.object(databases, "_upload_max", lambda: 10):
            with self.assertRaisesRegex(ValueError, "troppo grande"):
                databases.upload("manuali", "a.txt", b"x" * 11, who="davide", clearance="SEAL-4")
        with self.assertRaisesRegex(ValueError, "formato"):
            databases.upload("manuali", "a.exe", b"MZ", who="davide", clearance="SEAL-4")
        with self.assertRaisesRegex(ValueError, "vuoto"):
            databases.upload("manuali", "a.txt", b"", who="davide", clearance="SEAL-4")
        with self.assertRaisesRegex(ValueError, "testo"):
            databases.upload("manuali", "a.txt", b"   ", who="davide", clearance="SEAL-4")
        self.assertEqual(self.rag.ingested, [])

    def test_the_uploader_clearance_covers_the_collection_tier(self):
        with self.assertRaisesRegex(PermissionError, "tier"):
            databases.upload("manuali", "a.txt", b"ciao", who="mario", clearance="SEAL-1")
        out = databases.upload("manuali", "../../x/Guida Rapida.md", b"# ciao", who="mario",
                               clearance="SEAL-2")
        self.assertEqual((out["document"], out["chunks"]), ("Guida Rapida", 1))
        c, name, text, kw = self.rag.ingested[-1]
        self.assertEqual((c, name, text, kw["provenance"]), ("manuali", "Guida Rapida",
                                                             "# ciao", "untrusted"))
        self.assertEqual(kw["source"], "upload:mario:Guida Rapida.md")

    def test_an_unknown_collection_is_not_created_by_an_upload(self):
        with self.assertRaises(databases.NotFound):
            databases.upload("nuova", "a.txt", b"ciao", who="davide", clearance="SEAL-4")


class AccessTests(_Base):
    def auth(self, who, write=False, admin=False, clearance="SEAL-2", scope=None,
             kind="datastore", name="tomato-pack/clienti"):
        databases.authorize_person(kind, name, write=write, who=who, is_admin=admin,
                                   clearance=clearance, scope=scope)

    def test_row_crud_refused_outside_a_scope(self):
        for scope in (None, "SEAL-2/altro"):
            with self.subTest(scope=scope), self.assertRaises(PermissionError):
                self.auth("mario", write=True, scope=scope)
        with self.assertRaises(PermissionError):                 # not a participant
            self.auth("estraneo", write=True, scope="SEAL-2/commerciale")
        self.auth("mario", write=True, scope="SEAL-2/commerciale")

    def test_admins_reach_everything_within_their_clearance(self):
        self.auth("davide", write=True, admin=True, clearance="SEAL-2")
        with self.assertRaises(PermissionError):
            self.auth("davide", admin=True, clearance="SEAL-1")

    def test_topic_indexes_and_deleted_resources_are_out(self):
        with self.assertRaises(PermissionError):
            self.auth("davide", admin=True, clearance="SEAL-4", kind="rag", name="topic-abc123")
        cat.tombstone("rag", "eu-normativa", by="davide")
        with self.assertRaises(PermissionError):
            self.auth("davide", admin=True, clearance="SEAL-4", kind="rag", name="eu-normativa")

    def test_ddl_is_refused_to_agents(self):
        for stmt in ("CREATE TABLE x (a)", "DROP TABLE persone", "ALTER TABLE persone ADD b",
                     "ATTACH DATABASE '/tmp/x' AS y"):
            with self.subTest(stmt=stmt), self.assertRaises(ValueError):
                datastore_sql.write(self.entry(), {"statement": stmt}, agent="clodia")


class ContentTests(_Base):
    def test_rows_insert_update_delete(self):
        e = self.entry()
        t = datastore_sql.tables(e, agent="human:davide")["tables"]
        self.assertEqual([(x["name"], x["rows"], x["editable"]) for x in t], [("persone", 2, True)])
        out = datastore_sql.row_op(e, "insert", "persone", values={"nome": "Carla"}, agent="h")
        rid = out["rowid"]
        datastore_sql.row_op(e, "update", "persone", rowid=rid, values={"nome": "Carla B"},
                             agent="h")
        page = datastore_sql.rows(e, "persone", q="carla", agent="h")
        self.assertEqual([(r["__rowid__"], r["nome"]) for r in page["rows"]], [(rid, "Carla B")])
        self.assertEqual(page["total"], 1)
        datastore_sql.row_op(e, "delete", "persone", rowid=rid, agent="h")
        self.assertEqual(datastore_sql.rows(e, "persone", agent="h")["total"], 2)

    def test_identifiers_are_checked_not_trusted(self):
        e = self.entry()
        with self.assertRaises(ValueError):
            datastore_sql.row_op(e, "insert", 'persone"; DROP TABLE persone; --',
                                 values={"nome": "x"}, agent="h")
        with self.assertRaises(ValueError):
            datastore_sql.row_op(e, "insert", "persone", values={"nome) --": "x"}, agent="h")
        with self.assertRaises(ValueError):
            datastore_sql.rows(e, "nessuna", agent="h")

    def test_schema_editor(self):
        e = self.entry()
        datastore_sql.ddl(e, {"op": "create_table", "table": "note",
                              "columns": [{"name": "id", "type": "INTEGER", "pk": True},
                                          {"name": "testo", "type": "TEXT"}]}, agent="h")
        datastore_sql.ddl(e, {"op": "add_column", "table": "note",
                              "column": {"name": "data", "type": "TEXT"}}, agent="h")
        cols = [c["name"] for c in datastore_sql.rows(e, "note", agent="h")["columns"]]
        self.assertEqual(cols, ["id", "testo", "data"])
        with self.assertRaises(ValueError):
            datastore_sql.ddl(e, {"op": "add_column", "table": "note",
                                  "column": {"name": "x", "type": "VARCHAR(10); DROP"}}, agent="h")
        with self.assertRaises(ValueError):
            datastore_sql.ddl(e, {"op": "statement", "statement": "DELETE FROM note"}, agent="h")
        datastore_sql.ddl(e, {"op": "drop_table", "table": "note"}, agent="h")
        self.assertEqual([t["name"] for t in datastore_sql.tables(e, agent="h")["tables"]],
                         ["persone"])


class ContainerTests(_Base):
    def test_create_a_platform_datastore(self):
        out = databases.create_datastore("note-interne", purpose="appunti", tier="SEAL-1",
                                         pii=False, by="davide", clearance="SEAL-4")
        self.assertEqual(out["created"]["name"], "platform/note-interne")
        e = datastores.find("platform", "note-interne")
        self.assertTrue(Path(e["abs_path"]).is_file())
        self.assertEqual(cat.get("datastore", "platform/note-interne")["tier"], "SEAL-1")
        with self.assertRaises(ValueError):
            databases.create_datastore("note-interne", purpose="", tier="SEAL-1", pii=False,
                                       by="davide", clearance="SEAL-4")
        for bad in ("Note", "../x", "", "a" * 70):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                databases.create_datastore(bad, purpose="", tier="SEAL-1", pii=False, by="d",
                                           clearance="SEAL-4")

    def test_delete_datastore_exports_then_removes_everything(self):
        path = Path(self.entry()["abs_path"])
        out = databases.delete("datastore", "tomato-pack/clienti", by="davide", clearance="SEAL-4")
        export = Path(datastores.DATADIR) / out["export_dir"]
        self.assertTrue(out["export_dir"].startswith("deleted/datastore-tomato-pack__clienti-"))
        conn = sqlite3.connect(export / "clienti.db")
        self.assertEqual(conn.execute("SELECT count(*) FROM persone").fetchone()[0], 2)
        conn.close()
        meta = json.loads((export / "meta.json").read_text())
        self.assertEqual(meta["imported_by_scopes"], ["SEAL-2/commerciale"])
        self.assertFalse(path.exists())                                   # data
        self.assertIsNone(cat.get("datastore", "tomato-pack/clienti"))    # catalogue
        self.assertEqual(out["imports_removed"], ["SEAL-2/commerciale"])  # scope imports
        meta_t = self.svc._read_meta("SEAL-2", "commerciale")[0]
        self.assertEqual([e["name"] for e in td.imports(meta_t)], ["manuali"])

    def test_delete_collection_exports_jsonl_then_drops(self):
        out = databases.delete("rag", "manuali", by="davide", clearance="SEAL-4")
        export = Path(datastores.DATADIR) / out["export_dir"]
        docs = [json.loads(x) for x in (export / "documents.jsonl").read_text().splitlines()]
        chunks = (export / "chunks.jsonl").read_text().splitlines()
        self.assertEqual([d["type"] for d in docs], ["collection", "document"])
        self.assertEqual(len(chunks), 2)
        self.assertEqual(out["export"], {"documents": 1, "chunks": 2})
        self.assertEqual(self.rag.dropped, ["manuali"])
        self.assertIsNone(cat.get("rag", "manuali"))

    def test_an_incomplete_export_stops_the_delete(self):
        self.rag.export_rows = lambda c: iter([{"type": "collection", "name": c}])
        from .tools import eu_corpus
        with patch.object(eu_corpus, "export_rows", self.rag.export_rows):
            with self.assertRaisesRegex(RuntimeError, "incompleto"):
                databases.delete("rag", "manuali", by="davide", clearance="SEAL-4")
        self.assertEqual(self.rag.dropped, [])
        self.assertIsNotNone(cat.get("rag", "manuali"))
        self.assertIsNone(cat.tombstoned("rag", "manuali"))
        self.assertFalse(any((Path(datastores.DATADIR) / "deleted").iterdir()))

    def test_topic_indexes_cannot_be_deleted_from_here(self):
        with self.assertRaises(PermissionError):
            databases.delete("rag", "topic-abc123", by="davide", clearance="SEAL-4")

    def test_the_tombstone_stops_a_silent_recreation(self):
        databases.delete("datastore", "tomato-pack/clienti", by="davide", clearance="SEAL-4")
        databases.delete("rag", "manuali", by="davide", clearance="SEAL-4")
        # The pack update brings the file back and the service the collection:
        conn = sqlite3.connect(Path(datastores.DATADIR) / "plugins/tomato-pack/clienti.db")
        conn.close()
        self.rag.cols["manuali"] = "SEAL-2"
        cat._LAST_SYNC[0] = 0.0
        cat.sync()
        self.assertIsNone(cat.get("datastore", "tomato-pack/clienti"))
        self.assertIsNone(cat.get("rag", "manuali"))
        self.assertIsNone(datastores.find("tomato-pack", "clienti"))
        from . import main
        with self.assertRaisesRegex(PermissionError, "eliminata"):
            main._refuse_tombstoned("manuali")
        # Only an explicit action brings them back.
        databases.restore("datastore", "tomato-pack/clienti", by="davide", clearance="SEAL-4")
        self.assertIsNotNone(datastores.find("tomato-pack", "clienti"))
        self.assertIsNotNone(cat.get("datastore", "tomato-pack/clienti"))
        self.rag.cols.pop("manuali")
        databases.create_collection("manuali", tier="SEAL-2", by="davide", clearance="SEAL-4")
        self.assertIsNone(cat.tombstoned("rag", "manuali"))
        main._refuse_tombstoned("manuali")

    def test_create_collection_refuses_topic_names_and_duplicates(self):
        with self.assertRaises(ValueError):
            databases.create_collection("topic-x", tier="SEAL-1", by="davide", clearance="SEAL-4")
        with self.assertRaises(ValueError):
            databases.create_collection("manuali", tier="SEAL-1", by="davide", clearance="SEAL-4")
        out = databases.create_collection("procedure", tier="SEAL-1", by="davide", clearance="SEAL-4")
        self.assertEqual(out["created"], {"kind": "rag", "name": "procedure", "tier": "SEAL-1"})


class ReviewFixTests(_Base):
    """The independent review of #671 (should-fix 1-5, minor 10-11)."""

    def test_1_every_eu_corpus_write_path_refuses_a_tombstone(self):
        from .tools import eu_corpus
        cat.tombstone("rag", "manuali", by="davide")
        sent = []
        euc = type("RealClient", (), {k: staticmethod(v) for k, v in _REAL_EU.items()})
        p = patch.object(eu_corpus, "_post_json", lambda *a, **k: sent.append(a) or {})
        p.start()
        self.addCleanup(p.stop)
        for call in (lambda: euc.ingest_text("manuali", "d", "testo"),
                     lambda: euc.ingest_bytes(b"%PDF", "a.pdf", "d", "1", collection="manuali"),
                     lambda: euc.create_collection("manuali", tier="SEAL-0"),
                     lambda: euc.set_collection_tier("manuali", "SEAL-0")):
            with self.assertRaisesRegex(PermissionError, "eliminat"):
                call()
        with self.assertRaisesRegex(PermissionError, "eliminat"):
            # eu_corpus.ingest's own default collection, the reviewed bypass
            cat.tombstone("rag", "eu-normativa", by="davide")
            euc.ingest_bytes(b"%PDF", "a.pdf", "d", "1")
        self.assertEqual(sent, [])
        euc.ingest_text("eu-altro", "d", "testo")
        self.assertEqual(len(sent), 1)

    def test_3_the_tombstone_freezes_before_the_export(self):
        seen = {}
        real = databases._export_datastore

        def export(ds, name, d):
            seen["declared"] = datastores.find("tomato-pack", "clienti")
            seen["tomb"] = cat.tombstoned("datastore", "tomato-pack/clienti")
            return real(ds, name, d)
        with patch.object(databases, "_export_datastore", export):
            databases.delete("datastore", "tomato-pack/clienti", by="davide", clearance="SEAL-4")
        self.assertIsNone(seen["declared"])           # datastore.* refuse it during the export
        self.assertIsNotNone(seen["tomb"])
        t = cat.tombstoned("datastore", "tomato-pack/clienti")
        self.assertTrue(t["export"].startswith("deleted/"))
        self.assertEqual(t["tier"], "SEAL-2")

    def test_3_an_export_failure_lifts_the_tombstone(self):
        with patch.object(databases, "_export_datastore",
                          lambda *a: (_ for _ in ()).throw(RuntimeError("disco pieno"))):
            with self.assertRaises(RuntimeError):
                databases.delete("datastore", "tomato-pack/clienti", by="davide",
                                 clearance="SEAL-4")
        self.assertIsNone(cat.tombstoned("datastore", "tomato-pack/clienti"))
        self.assertIsNotNone(datastores.find("tomato-pack", "clienti"))
        self.assertTrue(Path(self.entry()["abs_path"]).is_file())

    def test_3_the_chunk_count_is_checked_too(self):
        real = self.rag.export_rows

        def short(c):
            rows = list(real(c))
            return iter(rows[:-1])                     # every document, one chunk missing
        from .tools import eu_corpus
        with patch.object(eu_corpus, "export_rows", short):
            with self.assertRaisesRegex(RuntimeError, "1 chunk su 2"):
                databases.delete("rag", "manuali", by="davide", clearance="SEAL-4")
        self.assertEqual(self.rag.dropped, [])
        self.assertIsNone(cat.tombstoned("rag", "manuali"))

    def test_2_job_scopes_are_recorded_and_returned(self):
        out = databases.delete("rag", "manuali", by="davide", clearance="SEAL-4",
                               job_scopes=["job:7"])
        meta = json.loads((Path(datastores.DATADIR) / out["export_dir"] / "meta.json").read_text())
        self.assertEqual(meta["imported_by_scopes"], ["SEAL-2/commerciale", "job:7"])
        self.assertEqual(out["job_scopes"], ["job:7"])

    def test_4_container_actions_need_the_clearance(self):
        with self.assertRaisesRegex(PermissionError, "clearance"):
            databases.delete("datastore", "tomato-pack/clienti", by="davide", clearance="SEAL-1")
        self.assertIsNone(cat.tombstoned("datastore", "tomato-pack/clienti"))
        with self.assertRaisesRegex(PermissionError, "clearance"):
            databases.create_datastore("alto", purpose="", tier="SEAL-3", pii=False,
                                       by="davide", clearance="SEAL-2")
        with self.assertRaisesRegex(PermissionError, "clearance"):
            databases.create_collection("alta", tier="SEAL-3", by="davide", clearance="SEAL-2")
        databases.delete("datastore", "tomato-pack/clienti", by="davide", clearance="SEAL-2")
        with self.assertRaisesRegex(PermissionError, "clearance"):
            databases.restore("datastore", "tomato-pack/clienti", by="davide", clearance="SEAL-1")
        databases.restore("datastore", "tomato-pack/clienti", by="davide", clearance="SEAL-2")

    def _zip(self, entries):
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for n, data in entries:
                z.writestr(n, data)
        return buf.getvalue()

    def test_5_zip_bombs_are_refused_before_parsing(self):
        from . import main
        bomb = self._zip([("word/document.xml", b"\0" * (5 * 1024 * 1024))])
        for fn in ("a.docx", "a.pptx"):
            with self.subTest(fn=fn), self.assertRaisesRegex(ValueError, "zip bomb"):
                databases.extract_text(fn, bomb)
        with self.assertRaisesRegex(ValueError, "zip bomb"):     # agents' rag.ingest path
            databases.extract_text("a.xlsx", bomb, formats=databases.AGENT_INGEST_EXT)
        with patch.object(main, "ZIP_MAX_TOTAL", 1000):
            with self.assertRaisesRegex(ValueError, "decompresso"):
                databases.extract_text("a.docx", self._zip([("a", b"x" * 600), ("b", b"y" * 600)]))
        with self.assertRaisesRegex(ValueError, "non è un file Office"):
            databases.extract_text("a.docx", b"not a zip")

    def test_10_agent_ingest_of_a_non_pdf_keeps_supersede_url_and_xlsx(self):
        from . import main
        from .tools import eu_corpus
        from openpyxl import Workbook
        wb = Workbook()
        wb.active["A1"] = "cella"
        buf = io.BytesIO()
        wb.save(buf)
        files = {"files/t.xlsx": buf.getvalue(), "files/n.md": b"# nota"}
        sent = []

        class Svc:
            def read_file(self, t, n, path):
                return files[path]

            def provenance_of(self, *a):
                return "trusted"
        with patch.object(main, "_rag_authorize", lambda *a, **k: None), \
                patch.object(main, "_topics", lambda: Svc()), \
                patch.object(main, "_require_topic_member", lambda *a: None), \
                patch.object(main, "_ingest_source_ok", lambda *a: None), \
                patch.object(eu_corpus, "ingest_text", lambda *a, **k: sent.append((a, k)) or {}):
            main._dispatch_rag("rag.ingest", {"collection": "manuali", "tier": "SEAL-2",
                                              "name": "commerciale", "path": "files/t.xlsx",
                                              "doc_name": "T", "version": "1"})
            main._dispatch_rag("rag.ingest", {"collection": "manuali", "tier": "SEAL-2",
                                              "name": "commerciale", "path": "files/n.md",
                                              "doc_name": "N", "version": "2", "supersede": True,
                                              "url": "https://x/n"})
        (a1, k1), (a2, k2) = sent
        self.assertIn("cella", a1[2])
        self.assertEqual((k1["supersede"], k1["url"]), (False, None))
        self.assertEqual((k2["supersede"], k2["url"]), (True, "https://x/n"))


class CatalogueTests(_Base):
    def test_uniform_rows_without_topic_indexes(self):
        cat.register("rag", "topic-abc123", tier="SEAL-2")
        out = databases.catalogue(who="davide", is_admin=True, clearance="SEAL-4")
        rows = {r["key"]: r for r in out["entries"]}
        self.assertNotIn("rag:topic-abc123", rows)
        ds = rows["datastore:tomato-pack/clienti"]
        self.assertEqual((ds["kind"], ds["pack"], ds["tier"], ds["status"]),
                         ("datastore", "tomato-pack", "SEAL-2", "active"))
        self.assertEqual((ds["size"]["tables"], ds["size"]["rows"]), (1, 2))
        self.assertEqual(ds["imported_by_scopes"], ["SEAL-2/commerciale"])
        self.assertTrue(ds["updated_at"])
        rag = rows["rag:manuali"]
        self.assertEqual((rag["pack"], rag["size"], rag["updated_at"]),
                         ("tomato-pack", {"documents": 1, "chunks": 2},
                          "2026-11-11T10:00:00+00:00"))
        self.assertIsNone(rows["rag:eu-normativa"]["pack"])
        self.assertIn("tombstones", out)

    def test_a_non_admin_sees_only_what_their_scopes_import(self):
        out = databases.catalogue(who="mario", is_admin=False, clearance="SEAL-2")
        self.assertEqual(sorted(r["key"] for r in out["entries"]),
                         ["datastore:tomato-pack/clienti", "rag:manuali"])
        self.assertNotIn("tombstones", out)
        self.assertEqual(databases.catalogue(who="estraneo", is_admin=False,
                                             clearance="SEAL-4")["entries"], [])


class RouteTests(_Base):
    def client(self, payload):
        from starlette.applications import Starlette
        from starlette.testclient import TestClient
        from . import databases_api

        def fake(request, **kw):
            return payload, None
        p = patch.object(databases_api.internal_auth, "authorize", fake)
        p.start()
        self.addCleanup(p.stop)
        return TestClient(Starlette(routes=databases_api.routes))

    def person(self, who, role="user", clearance="SEAL-2"):
        return self.client({"agent": "clodia", "principal": who, "on_behalf": True,
                            "human_role": role, "clearance": clearance})

    def test_agents_do_not_pass(self):
        c = self.client({"agent": "clodia"})
        self.assertEqual(c.get("/internal/databases").status_code, 403)

    def test_rows_need_a_scope_for_a_non_admin(self):
        c = self.person("mario")
        base = "/internal/databases/datastore/tomato-pack/clienti/rows"
        self.assertEqual(c.get(base, params={"table": "persone"}).status_code, 403)
        r = c.get(base, params={"table": "persone", "scope": "SEAL-2/commerciale"})
        self.assertEqual((r.status_code, r.json()["total"]), (200, 2))
        r = c.post(base, json={"op": "insert", "table": "persone", "values": {"nome": "Dino"}})
        self.assertEqual(r.status_code, 403)
        r = c.post(base, json={"op": "insert", "table": "persone", "values": {"nome": "Dino"},
                               "scope": "SEAL-2/commerciale"})
        self.assertEqual(r.status_code, 200, r.text)

    def test_schema_and_containers_are_admin_only(self):
        c = self.person("mario")
        r = c.post("/internal/databases/datastore/tomato-pack/clienti/schema",
                   json={"op": "drop_table", "table": "persone"})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(c.post("/internal/databases", json={
            "action": "delete", "kind": "rag", "name": "manuali",
            "confirm": "manuali"}).status_code, 403)
        a = self.person("davide", role="admin", clearance="SEAL-4")
        r = a.post("/internal/databases", json={"action": "delete", "kind": "rag",
                                                "name": "manuali", "confirm": "manual"})
        self.assertEqual(r.status_code, 400)                   # typed name must match
        r = a.post("/internal/databases", json={"action": "delete", "kind": "rag",
                                                "name": "manuali", "confirm": "manuali"})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertTrue(r.json()["export_dir"].startswith("deleted/rag-manuali-"))

    def test_11_refused_and_failed_container_actions_are_audited(self):
        from . import databases_api
        seen = []
        p = patch.object(databases_api, "_audit", lambda *a, **k: seen.append((a, k)))
        p.start()
        self.addCleanup(p.stop)
        self.person("mario").post("/internal/databases", json={
            "action": "delete", "kind": "rag", "name": "manuali", "confirm": "manuali"})
        a = self.person("davide", role="admin", clearance="SEAL-1")
        a.post("/internal/databases", json={"action": "delete", "kind": "rag",
                                            "name": "manuali", "confirm": "manuali"})
        with patch.object(databases, "delete", lambda *x, **k: (_ for _ in ()).throw(
                RuntimeError("servizio giù"))):
            self.person("davide", role="admin", clearance="SEAL-4").post(
                "/internal/databases", json={"action": "delete", "kind": "rag",
                                             "name": "manuali", "confirm": "manuali"})
        self.assertEqual([(x[0][0], x[0][2], x[1]["result"]) for x in seen],
                         [("delete", "mario", "refused"), ("delete", "davide", "refused"),
                          ("delete", "davide", "failed")])

    def test_upload_route_limits(self):
        a = self.person("davide", role="admin", clearance="SEAL-4")
        url = "/internal/databases/collection/manuali/upload"
        with patch.object(databases, "_upload_max", lambda: 8):
            r = a.post(url, params={"filename": "a.txt"}, content=b"x" * 9)
            self.assertEqual(r.status_code, 400)
        r = a.post(url, params={"filename": "a.zip"}, content=b"PK")
        self.assertEqual(r.status_code, 400)
        r = a.post(url, params={"filename": "a.txt", "doc_name": "Nota"}, content=b"ciao")
        self.assertEqual((r.status_code, r.json()["document"]), (200, "Nota"))
        low = self.person("davide", role="admin", clearance="SEAL-1")
        self.assertEqual(low.post(url, params={"filename": "a.txt"}, content=b"x").status_code,
                         403)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from .tools import datastore_sql


def _entry(db_path: str) -> dict:
    return {"pack": "base-pack", "name": "contacts", "path": "data/contacts.db",
            "abs_path": db_path, "purpose": "", "pii": True, "backup": True,
            "clearance": "SEAL-1", "seeds": ["messaggero", "clodia"]}


def _seeded_db(tmp: str) -> str:
    path = str(Path(tmp) / "contacts.db")
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE contacts (id INTEGER PRIMARY KEY, name TEXT)")
    conn.execute("INSERT INTO contacts (name) VALUES ('Ada Lovelace')")
    conn.commit()
    conn.close()
    return path


class ReadTests(unittest.TestCase):
    def test_select_returns_rows(self) -> None:
        with TemporaryDirectory() as tmp:
            db = _seeded_db(tmp)
            out = datastore_sql.read(
                _entry(db), {"query": "SELECT id, name FROM contacts"}, agent="messaggero")
        self.assertEqual(out["rows"], [{"id": 1, "name": "Ada Lovelace"}])
        self.assertFalse(out["truncated"])

    def test_params_are_bound_not_interpolated(self) -> None:
        with TemporaryDirectory() as tmp:
            db = _seeded_db(tmp)
            out = datastore_sql.read(
                _entry(db),
                {"query": "SELECT name FROM contacts WHERE name = ?", "params": ["Ada Lovelace"]},
                agent="messaggero")
        self.assertEqual(out["rows"], [{"name": "Ada Lovelace"}])

    def test_pragma_table_info_is_allowed(self) -> None:
        with TemporaryDirectory() as tmp:
            db = _seeded_db(tmp)
            out = datastore_sql.read(
                _entry(db), {"query": "PRAGMA table_info(contacts)"}, agent="messaggero")
        self.assertTrue(out["ok"])

    def test_non_select_is_refused(self) -> None:
        with TemporaryDirectory() as tmp:
            db = _seeded_db(tmp)
            with self.assertRaises(ValueError):
                datastore_sql.read(
                    _entry(db), {"query": "DELETE FROM contacts"}, agent="messaggero")

    def test_a_write_disguised_as_read_fails_at_the_connection_too(self) -> None:
        """Difesa in profondità: anche aggirando `_READ_RE` a mano, la
        connessione read-only rifiuta comunque la scrittura."""
        with TemporaryDirectory() as tmp:
            db = _seeded_db(tmp)
            entry = _entry(db)
            with patch.object(datastore_sql, "_READ_RE") as fake_re:
                fake_re.match.return_value = True
                with self.assertRaises(ValueError):
                    datastore_sql.read(
                        entry, {"query": "DELETE FROM contacts"}, agent="messaggero")

    def test_ddl_is_refused(self) -> None:
        with TemporaryDirectory() as tmp:
            db = _seeded_db(tmp)
            with self.assertRaises(ValueError):
                datastore_sql.read(
                    _entry(db), {"query": "DROP TABLE contacts"}, agent="messaggero")

    def test_stacked_statements_are_refused(self) -> None:
        with TemporaryDirectory() as tmp:
            db = _seeded_db(tmp)
            with self.assertRaises(ValueError):
                datastore_sql.read(
                    _entry(db),
                    {"query": "SELECT 1; DROP TABLE contacts"}, agent="messaggero")

    def test_result_is_capped_and_truncation_is_reported(self) -> None:
        with TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "contacts.db")
            conn = sqlite3.connect(path)
            conn.execute("CREATE TABLE contacts (id INTEGER PRIMARY KEY, note TEXT)")
            for i in range(2000):
                conn.execute("INSERT INTO contacts (note) VALUES (?)", (f"nota numero {i}" * 5,))
            conn.commit()
            conn.close()
            out = datastore_sql.read(
                _entry(path), {"query": "SELECT * FROM contacts", "max_bytes": 2048},
                agent="messaggero")
        self.assertTrue(out["truncated"])
        self.assertIn("note", out)
        self.assertLess(len(out["rows"]), 2000)


class WriteTests(unittest.TestCase):
    def test_insert_is_committed(self) -> None:
        with TemporaryDirectory() as tmp:
            db = _seeded_db(tmp)
            out = datastore_sql.write(
                _entry(db),
                {"statement": "INSERT INTO contacts (name) VALUES (?)", "params": ["Grace Hopper"]},
                agent="messaggero")
            self.assertEqual(out["rowcount"], 1)
            conn = sqlite3.connect(db)
            names = [r[0] for r in conn.execute("SELECT name FROM contacts ORDER BY id")]
            conn.close()
        self.assertEqual(names, ["Ada Lovelace", "Grace Hopper"])

    def test_update_and_delete_are_allowed(self) -> None:
        with TemporaryDirectory() as tmp:
            db = _seeded_db(tmp)
            out = datastore_sql.write(
                _entry(db),
                {"statement": "UPDATE contacts SET name = ? WHERE id = 1", "params": ["A. Lovelace"]},
                agent="messaggero")
            self.assertEqual(out["rowcount"], 1)
            out = datastore_sql.write(
                _entry(db), {"statement": "DELETE FROM contacts WHERE id = 1"},
                agent="messaggero")
            self.assertEqual(out["rowcount"], 1)

    def test_ddl_is_refused(self) -> None:
        with TemporaryDirectory() as tmp:
            db = _seeded_db(tmp)
            with self.assertRaises(ValueError):
                datastore_sql.write(
                    _entry(db), {"statement": "DROP TABLE contacts"}, agent="messaggero")

    def test_attach_is_refused(self) -> None:
        with TemporaryDirectory() as tmp:
            db = _seeded_db(tmp)
            with self.assertRaises(ValueError):
                datastore_sql.write(
                    _entry(db), {"statement": "ATTACH DATABASE '/etc/passwd' AS x"},
                    agent="messaggero")

    def test_select_is_refused_on_the_write_verb(self) -> None:
        with TemporaryDirectory() as tmp:
            db = _seeded_db(tmp)
            with self.assertRaises(ValueError):
                datastore_sql.write(
                    _entry(db), {"statement": "SELECT * FROM contacts"}, agent="messaggero")

    def test_stacked_statements_are_refused(self) -> None:
        with TemporaryDirectory() as tmp:
            db = _seeded_db(tmp)
            with self.assertRaises(ValueError):
                datastore_sql.write(
                    _entry(db),
                    {"statement": "INSERT INTO contacts (name) VALUES ('x'); DROP TABLE contacts"},
                    agent="messaggero")

    def test_a_failed_statement_rolls_back(self) -> None:
        with TemporaryDirectory() as tmp:
            db = _seeded_db(tmp)
            with self.assertRaises(ValueError):
                datastore_sql.write(
                    _entry(db),
                    {"statement": "INSERT INTO contacts (nonexistent_column) VALUES (1)"},
                    agent="messaggero")
            conn = sqlite3.connect(db)
            n = conn.execute("SELECT COUNT(*) FROM contacts").fetchone()[0]
            conn.close()
        self.assertEqual(n, 1)


class AuditTests(unittest.TestCase):
    def test_refusal_is_audited(self) -> None:
        with TemporaryDirectory() as tmp:
            db = _seeded_db(tmp)
            with patch.dict("os.environ", {"CLODIA_VAULT_DIR": tmp}):
                with self.assertRaises(ValueError):
                    datastore_sql.read(
                        _entry(db), {"query": "DROP TABLE contacts"}, agent="messaggero")
            righe = [json.loads(x) for x in
                     (Path(tmp) / "datastore-audit.log").read_text().splitlines()]
        self.assertEqual(righe[-1]["result"], "REFUSED")
        self.assertEqual(righe[-1]["action"], "datastore.read")
        self.assertEqual(righe[-1]["target"], "base-pack/contacts")


if __name__ == "__main__":
    unittest.main()

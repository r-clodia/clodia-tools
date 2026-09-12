"""#342 — un datastore è navigabile in forma tabellare da chi ne ha diritto.

Il test precedente (`test_datastore_authorize`) interroga il reference monitor;
questo percorre la STRADA vera: `call_tool`, cioè ciò che esegue
`/internal/tool` quando la webui inoltra al PDP. Le due cose si rompono
separatamente — una decisione corretta dietro un dispatch che non ci arriva è
muta — e una correzione applicata solo al monitor sarebbe restata invisibile
proprio sul percorso che la issue nomina.

Le due chiamate qui sono esattamente quelle di cui una tabella ha bisogno:
l'elenco delle tabelle e una pagina di righe.
"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from . import main, whitelist


def _db(path: str) -> None:
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE contacts (id INTEGER PRIMARY KEY, nome TEXT)")
    conn.execute("INSERT INTO contacts (nome) VALUES ('Giovanni'), ('Anna')")
    conn.commit()
    conn.close()


class _Sessione:
    """I contextvar di una richiesta on-behalf, come li imposta `tool_api._Ctx`."""

    def __init__(self, *, role: str, clearance: str):
        self.role, self.clearance = role, clearance

    def __enter__(self):
        self._t = [
            whitelist.set_current_agent("clodia"),
            whitelist.set_current_on_behalf(True),
            whitelist.set_current_human_role(self.role),
            whitelist.set_current_principal("davide"),
            whitelist.set_current_clearance(self.clearance),
        ]
        return self

    def __exit__(self, *exc):
        for reset, tok in zip(
            (whitelist.reset_current_clearance, whitelist.reset_current_principal,
             whitelist.reset_current_human_role, whitelist.reset_current_on_behalf,
             whitelist.reset_current_agent), reversed(self._t)):
            reset(tok)
        return False


class DatastoreNavigabileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        db = os.path.join(self.tmp.name, "contacts.db")
        _db(db)
        self.entry = {
            "pack": "base-pack", "name": "contacts", "path": "data/contacts.db",
            "abs_path": db, "purpose": "CRM", "pii": True, "backup": True,
            # Il carrier `clodia` NON è nei seeds: la lettura deve passare
            # sull'asse umano, non per un permesso dell'agente che trasporta.
            "clearance": "SEAL-1", "seeds": ["messaggero"],
        }
        # L'audit dei verbi datastore scrive su disco: fuori dalla home del
        # runner, dentro la tmpdir del test.
        vault = patch.dict(os.environ, {"CLODIA_VAULT_DIR": self.tmp.name})
        vault.start()
        self.addCleanup(vault.stop)

    def _text(self, tool: str, args: dict, *, role="admin", clearance="SEAL-2") -> str:
        """Il testo grezzo: `call_tool` NON solleva, traduce il rifiuto in
        `DENIED: …` (main.py, fondo di `call_tool`). Un test che aspettasse
        un'eccezione passerebbe soltanto quando il tool esplode davvero."""
        with _Sessione(role=role, clearance=clearance), \
                patch.object(main.datastores, "find", return_value=self.entry):
            res = asyncio.run(main.call_tool(tool, args))
        return res[0].text

    def _call(self, tool: str, args: dict, **kw) -> dict:
        testo = self._text(tool, args, **kw)
        self.assertFalse(testo.startswith(("DENIED:", "ERROR:")), testo[:200])
        return json.loads(testo)

    def test_admin_lists_tables_and_reads_a_page_of_rows(self) -> None:
        tabelle = self._call("datastore.read", {
            "datastore": "base-pack/contacts", "query": "PRAGMA table_list"})
        self.assertIn("contacts", [r.get("name") for r in tabelle["rows"]])

        righe = self._call("datastore.read", {
            "datastore": "base-pack/contacts",
            "query": "SELECT id, nome FROM contacts ORDER BY id LIMIT ? OFFSET ?",
            "params": [1, 1]})
        self.assertEqual(["id", "nome"], righe["columns"])
        self.assertEqual([{"id": 2, "nome": "Anna"}], righe["rows"])

    # Il ramo «umano non admin» sta in `test_datastore_authorize` e non qui:
    # per una sessione non-admin `call_tool` passa dal M-gate, che ASPETTA la
    # decisione di una persona. Un test che attende un consenso umano non è un
    # test, è un blocco — e il rifiuto che interessa lo dà comunque il monitor,
    # dopo il gate.

    def test_admin_cannot_write_from_the_ui(self) -> None:
        self.assertTrue(
            self._text("datastore.write", {
                "datastore": "base-pack/contacts",
                "statement": "DELETE FROM contacts"}).startswith("DENIED:"))
        conn = sqlite3.connect(self.entry["abs_path"])
        restanti = conn.execute("SELECT count(*) FROM contacts").fetchone()[0]
        conn.close()
        self.assertEqual(2, restanti, "il rifiuto deve precedere l'esecuzione")


if __name__ == "__main__":
    unittest.main()

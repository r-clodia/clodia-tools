"""#684 — pack datastore structures, always multi-instance.

- #685: manifest structures, create (verb + route), list, catalogue, delete
  through the #671 flow, uninstall archives, one-off migration of the legacy
  pack datastore files (dry run, apply, idempotent, imports rewritten);
- #686: the instance a call works on comes from the scope's imports (1 → it,
  several → named, none → refused), the pack MCP gets its file in
  `CLODIA_DATASTORE_<STRUCTURE>`, one process per instance;
- #687: pack update migrates every instance, backup first, one transaction
  per instance, a failure rolls back that instance only.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import sqlite3
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

from . import (data_catalog as cat, databases, datastore_instances as di, datastores,
               migrate_legacy_datastores as mig, proxy, topic_data as td, whitelist)
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicService

SCHEMA = "CREATE TABLE fatture (id TEXT PRIMARY KEY, totale REAL);\n" \
         "CREATE TABLE movimenti (id INTEGER PRIMARY KEY, importo REAL);\n"


def _manifest(datastores_decl, mcp=None) -> str:
    import yaml
    return yaml.safe_dump({"name": "assetti-contabili", "datastores": datastores_decl,
                           "mcp_servers": mcp or {}})


class _Base(unittest.TestCase):
    def setUp(self):
        from . import authz_runtime as _azr
        _azr.invalidate()
        self.addCleanup(_azr.invalidate)
        self.root = Path(tempfile.mkdtemp(prefix="ds684-"))
        self.state = self.root / "state"
        self.state.mkdir()
        self.plugin = self.root / "plugins" / "assetti-contabili"
        (self.plugin / "mcp").mkdir(parents=True)
        (self.plugin / "mcp" / "schema.sql").write_text(SCHEMA, encoding="utf-8")
        self.write_manifest()
        self.svc = TopicService(LocalFsStorage(tempfile.mkdtemp(prefix="topics684-")))
        from . import state_paths
        for p in [
            patch.object(datastores, "DATADIR", str(self.root)),
            patch.object(state_paths, "state_path", lambda name: self.state / name),
            patch.object(cat, "_path", lambda: self.state / "data-catalog.json"),
            patch.object(cat, "_tomb_path", lambda: self.state / "data-tombstones.json"),
            patch.object(td, "_svc", lambda: self.svc),
            patch("server.tools.eu_corpus.collections", lambda: {"collections": []}),
        ]:
            p.start()
            self.addCleanup(p.stop)
        cat._LAST_SYNC[0] = 0.0
        self.svc.new("SEAL-2", "tomato", {"owner": "davide",
                                          "participants": ["davide", "commercialista"]})
        self.svc.new("SEAL-2", "uncommon", {"owner": "davide",
                                            "participants": ["davide", "commercialista"]})

    def write_manifest(self, decl=None, mcp=None):
        if decl is None:
            decl = [{"name": "contabilita", "schema": "mcp/schema.sql",
                     "purpose": "Contabilità", "pii": True, "backup": True,
                     "tier_hint": "SEAL-2"}]
        if mcp is None:
            mcp = {"contabilita": {"command": "python3", "args": ["x.py"]}}
        (self.plugin / "plugin.yaml").write_text(_manifest(decl, mcp), encoding="utf-8")

    def create(self, name="tomato", tier="SEAL-2", clearance="SEAL-4", **kw):
        return di.create("assetti-contabili/contabilita", name, tier=tier, by="davide",
                         clearance=clearance, **kw)

    def imp(self, topic, iid):
        td.import_resource("SEAL-2", topic, "datastore", iid, principal="davide",
                           is_admin=True, clearance="SEAL-4")


# ── #685 ─────────────────────────────────────────────────────────────────────

class StructureTests(_Base):
    def test_manifest_structure_is_listed_with_schema_and_version(self):
        st = datastores.structure("assetti-contabili/contabilita")
        self.assertFalse(st["legacy"])
        self.assertTrue(st["schema"].endswith("mcp/schema.sql"))
        self.assertEqual(0, st["latest_version"])
        self.assertEqual("SEAL-2", st["tier_hint"])

    def test_the_plugin_folder_itself_is_never_a_schema_or_migrations_dir(self):
        for bad in (".", "./", "mcp/.."):
            with self.subTest(bad=bad):
                self.write_manifest([{"name": "contabilita", "schema": "mcp/schema.sql",
                                      "migrations": bad}])
                self.assertIsNone(datastores.structure("assetti-contabili/contabilita")
                                  ["migrations"])

    def test_structures_whose_env_names_collide_are_refused(self):
        self.write_manifest([{"name": "a-b", "schema": "mcp/schema.sql"},
                             {"name": "a_b", "schema": "mcp/schema.sql"}])
        self.assertEqual(["assetti-contabili/a-b"], sorted(datastores.structures()))

    def test_schema_outside_the_plugin_is_not_a_schema(self):
        self.write_manifest([{"name": "contabilita", "schema": "../../etc/passwd"}])
        self.assertIsNone(datastores.structure("assetti-contabili/contabilita")["schema"])
        with self.assertRaises(ValueError):
            self.create()

    def test_installing_a_pack_creates_no_instance(self):
        self.assertEqual([], datastores.instances())
        self.assertEqual([], [d for d in datastores.declared() if d["pack"] == "assetti-contabili"])
        view = di.structures_view()
        self.assertEqual(["assetti-contabili/contabilita"], [s["id"] for s in view["structures"]])
        self.assertEqual([], view["structures"][0]["instances"])
        self.assertTrue(view["structures"][0]["creatable"])


class CreateTests(_Base):
    def test_imported_by_scopes_is_the_list(self):
        out = self.create()
        self.imp("tomato", out["id"])
        [row] = di.structures_view()["structures"][0]["instances"]
        self.assertEqual(["SEAL-2/tomato"], row["imported_by_scopes"])
        self.assertEqual(1, row["imported_count"])

    def test_registry_writes_take_a_file_lock(self):
        import fcntl
        self.create()
        lock = self.state / "datastore-instances.lock"
        self.assertTrue(lock.exists())
        with open(lock, "a+") as fh:          # free once the write is done
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fh, fcntl.LOCK_UN)

    def test_create_builds_the_file_from_the_schema_and_catalogues_it(self):
        out = self.create(purpose="Libri di Tomato")
        self.assertEqual("assetti-contabili/contabilita:tomato", out["id"])
        self.assertEqual("SEAL-2", out["tier"])
        self.assertEqual("Libri di Tomato", out["purpose"])
        self.assertTrue(out["pii"])                         # inherited
        f = self.root / "datastores" / "assetti-contabili" / "contabilita" / "tomato.db"
        self.assertTrue(f.is_file())
        conn = sqlite3.connect(f)
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        conn.close()
        self.assertEqual({"fatture", "movimenti"}, tables)
        self.assertIsNotNone(cat.get("datastore", out["id"]))
        entry = datastores.find_instance(out["id"])
        self.assertEqual("SEAL-2", entry["clearance"])
        self.assertEqual("datastores/assetti-contabili/contabilita/tomato.db", entry["path"])
        # no scope import
        self.assertEqual({}, {k: v for k, v in td.importing_topics().items()
                              if out["id"] in k})

    def test_any_number_of_instances(self):
        self.create("tomato")
        self.create("uncommon", tier="SEAL-1")
        ids = [i["id"] for i in di.structures_view()["structures"][0]["instances"]]
        self.assertEqual(["assetti-contabili/contabilita:tomato",
                          "assetti-contabili/contabilita:uncommon"], ids)

    def test_duplicate_is_refused(self):
        self.create()
        with self.assertRaises(ValueError):
            self.create()

    def test_bad_names_are_refused(self):
        for bad in ("", "Tomato", "-x", "a_b", "a" * 42, "x:y", "../x"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.create(bad)

    def test_tier_is_required_and_valid(self):
        for bad in ("", "SEAL-9", "top"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.create(tier=bad)

    def test_tier_above_clearance_is_refused(self):
        with self.assertRaises(PermissionError):
            self.create(tier="SEAL-3", clearance="SEAL-2")
        with self.assertRaises(PermissionError):
            self.create(tier="SEAL-0", clearance=None)

    def test_unknown_or_legacy_structure_is_refused(self):
        with self.assertRaises(LookupError):
            di.create("assetti-contabili/nope", "x", tier="SEAL-1", by="d", clearance="SEAL-4")
        self.write_manifest([{"path": "data/contabilita.db", "name": "contabilita"}])
        with self.assertRaises(ValueError):
            self.create()

    def test_a_deleted_name_is_not_created_again(self):
        out = self.create()
        self.imp("tomato", out["id"])
        res = databases.delete("datastore", out["id"], by="davide", clearance="SEAL-4")
        self.assertEqual(["SEAL-2/tomato"], res["imports_removed"])
        self.assertTrue((self.root / res["export_dir"] / "contabilita__tomato.db").is_file())
        self.assertFalse((self.root / "datastores/assetti-contabili/contabilita/tomato.db").exists())
        self.assertNotIn(out["id"], datastores.instance_registry())
        with self.assertRaises(PermissionError):
            self.create()

    def test_uninstall_archives_the_instance(self):
        out = self.create()
        # clodia-logic moves plugins/<pack>/ and datastores/<pack>/ to the archive
        import shutil
        shutil.move(str(self.plugin), str(self.root / "plugins-archive" / "a"))
        shutil.move(str(self.root / "datastores" / "assetti-contabili"),
                    str(self.root / "plugins-archive" / "a" / "datastores"))
        self.assertEqual([], datastores.instances())
        self.assertIsNone(datastores.find_instance(out["id"]))
        archived = datastores.instances(include_archived=True)
        self.assertTrue(archived[0]["archived_at"])
        self.assertIsNotNone(cat.get("datastore", out["id"]))   # the catalogue keeps it
        # reinstall: the name stays the archived instance's, with a clear message …
        shutil.copytree(str(self.root / "plugins-archive" / "a"), str(self.plugin),
                        ignore=shutil.ignore_patterns("datastores"))
        with self.assertRaises(ValueError) as c:
            self.create()
        self.assertIn("archiviata", str(c.exception))
        # … and putting its file back makes it usable again
        shutil.move(str(self.root / "plugins-archive" / "a" / "datastores"),
                    str(self.root / "datastores" / "assetti-contabili"))
        self.assertEqual(out["id"], datastores.find_instance(out["id"])["pack"] + "/"
                         + datastores.find_instance(out["id"])["name"])
        self.assertIsNone(datastores.instances()[0]["archived_at"])


class RouteTests(_Base):
    def _call(self, method, path, body=None, *, admin=True, clearance="SEAL-4"):
        from starlette.testclient import TestClient
        from starlette.applications import Starlette
        from . import databases_api
        payload = {"agent": "clodia", "on_behalf": True, "principal": "davide",
                   "human_role": "admin" if admin else "user", "clearance": clearance}
        app = Starlette(routes=databases_api.routes)
        with patch.object(databases_api.internal_auth, "authorize",
                          lambda req, **kw: (payload, None)), \
                patch.object(databases_api.human_mcp, "principal_kind_of", lambda p: "human"):
            c = TestClient(app)
            return c.request(method, path, json=body)

    def test_create_instance_route(self):
        r = self._call("POST", "/internal/databases",
                       {"action": "create_instance", "structure": "assetti-contabili/contabilita",
                        "name": "uncommon", "tier": "SEAL-1", "pii": False})
        self.assertEqual(200, r.status_code, r.text)
        self.assertEqual("assetti-contabili/contabilita:uncommon", r.json()["id"])
        self.assertFalse(r.json()["pii"])

    def test_create_instance_is_for_admins(self):
        r = self._call("POST", "/internal/databases",
                       {"action": "create_instance", "structure": "assetti-contabili/contabilita",
                        "name": "uncommon", "tier": "SEAL-1"}, admin=False)
        self.assertEqual(403, r.status_code)

    def test_create_instance_tier_above_clearance(self):
        r = self._call("POST", "/internal/databases",
                       {"action": "create_instance", "structure": "assetti-contabili/contabilita",
                        "name": "uncommon", "tier": "SEAL-3"}, clearance="SEAL-2")
        self.assertEqual(403, r.status_code)

    def test_structures_route_carries_the_callers_clearance(self):
        self.create()
        r = self._call("GET", "/internal/databases/structures", clearance="SEAL-3")
        self.assertEqual(200, r.status_code, r.text)
        out = r.json()
        self.assertEqual("SEAL-3", out["caller_clearance"])
        self.assertTrue(out["is_admin"])
        self.assertEqual("assetti-contabili/contabilita:tomato",
                         out["structures"][0]["instances"][0]["id"])

    def test_structures_route_non_admin_sees_only_its_scopes_instances(self):
        self.create("tomato")
        self.create("uncommon")
        self.imp("tomato", "assetti-contabili/contabilita:tomato")
        with patch.object(cat, "sync_due", lambda: False):
            r = self._call("GET", "/internal/databases/structures", admin=False,
                           clearance="SEAL-2")
        self.assertEqual(200, r.status_code, r.text)
        self.assertFalse(r.json()["is_admin"])
        payload_ids = [i["id"] for i in r.json()["structures"][0]["instances"]]
        self.assertEqual(["assetti-contabili/contabilita:tomato"], payload_ids)

    def test_instance_key_works_in_the_existing_datastore_routes(self):
        self.create()
        r = self._call("GET", "/internal/databases/datastore/assetti-contabili/"
                              "contabilita%3Atomato/tables")
        self.assertEqual(200, r.status_code, r.text)

    def test_migrate_route_needs_a_service_token(self):
        from starlette.testclient import TestClient
        from starlette.applications import Starlette
        from . import databases_api
        app = Starlette(routes=databases_api.routes)
        r = TestClient(app).post("/internal/datastores/migrate", json={})
        self.assertEqual(401, r.status_code)


class VerbTests(_Base):
    def test_verbs_exist_and_kinds(self):
        from . import authz_shadow, gate, main as M
        names = M.all_native_verb_names()
        self.assertIn("packs.create_datastore", names)
        self.assertIn("packs.datastore_structures", names)
        self.assertEqual("read", authz_shadow.facts("packs.datastore_structures", {})["kind"])
        self.assertEqual("write", authz_shadow.facts("packs.create_datastore", {})["kind"])
        self.assertFalse(gate.is_gated("packs.datastore_structures"))

    def test_create_verb_uses_the_agents_clearance(self):
        from . import main as M
        with patch.object(M, "agent_name", lambda: "sysadmin"), \
                patch.object(M, "is_on_behalf", lambda: False), \
                patch.object(M, "current_clearance", lambda: "SEAL-1"):
            out = M._dispatch_packs("packs.create_datastore", {
                "structure": "assetti-contabili/contabilita", "name": "uncommon",
                "tier": "SEAL-1"})
            self.assertEqual("sysadmin", out["created_by"])
            with self.assertRaises(PermissionError):
                M._dispatch_packs("packs.create_datastore", {
                    "structure": "assetti-contabili/contabilita", "name": "other",
                    "tier": "SEAL-2"})
            listed = M._dispatch_packs("packs.datastore_structures", {})
        [row] = listed["structures"][0]["instances"]
        self.assertNotIn("created_by", row)                 # not for agents
        self.create("alto", tier="SEAL-3")
        with patch.object(M, "current_clearance", lambda: "SEAL-1"):
            listed = M._dispatch_packs("packs.datastore_structures", {})
        self.assertEqual(["assetti-contabili/contabilita:uncommon"],
                         [i["id"] for i in listed["structures"][0]["instances"]])


class LegacyMigrationTests(_Base):
    """Today's `plugins/assetti-contabili/data/contabilita.db` →
    `assetti-contabili/contabilita:tomato`, same bytes, imports rewritten."""

    def setUp(self):
        super().setUp()
        (self.plugin / "data").mkdir()
        self.legacy = self.plugin / "data" / "contabilita.db"
        conn = sqlite3.connect(self.legacy)
        conn.executescript(SCHEMA + "INSERT INTO fatture VALUES ('f1', 100.0);")
        conn.commit()
        conn.close()
        # the old manifest, a legacy key in the catalogue and two scope imports
        self.write_manifest([{"path": "data/contabilita.db", "pii": True, "clearance": "SEAL-4"}])
        cat.sync()
        cat.update("datastore", "assetti-contabili/contabilita", tier="SEAL-1")
        self.svc.new("SEAL-1", "bilancio", {"owner": "davide",
                                            "participants": ["davide", "commercialista"]})
        td.import_resource("SEAL-1", "bilancio", "datastore", "assetti-contabili/contabilita",
                           principal="davide", is_admin=True, clearance="SEAL-4")
        td.import_resource("SEAL-2", "tomato", "datastore", "assetti-contabili/contabilita",
                           principal="davide", is_admin=True, clearance="SEAL-4")

    def test_before_the_pack_update_the_declared_file_waits(self):
        rows = mig.candidates()
        self.assertEqual(1, len(rows))
        self.assertEqual("needs-pack-update", rows[0]["action"])
        mig.apply(rows)
        self.assertTrue(self.legacy.is_file())
        self.assertEqual({}, datastores.instance_registry())

    def test_dry_run_apply_and_idempotent(self):
        self.write_manifest()          # the pack updated: a structure, no `path:`
        rows = mig.candidates()
        self.assertEqual([("assetti-contabili/contabilita",
                           "assetti-contabili/contabilita:tomato", "migrate")],
                         [(r["from"], r["to"], r["action"]) for r in rows])
        self.assertTrue(self.legacy.is_file())                   # dry run: nothing moved
        before = self.legacy.read_bytes()
        mig.apply(rows)
        new = self.root / "datastores/assetti-contabili/contabilita/tomato.db"
        self.assertFalse(self.legacy.exists())
        self.assertEqual(before, new.read_bytes())               # same bytes
        iid = "assetti-contabili/contabilita:tomato"
        e = cat.get("datastore", iid)
        self.assertEqual("SEAL-1", cat.effective_tier(e))        # admin's level kept
        self.assertIsNone(cat.get("datastore", "assetti-contabili/contabilita"))
        for tier, topic in (("SEAL-1", "bilancio"), ("SEAL-2", "tomato")):
            names = [x["name"] for x in td.imports(self.svc._read_meta(tier, topic)[0])]
            self.assertEqual([iid], names)
        self.assertEqual(iid, datastores.find_instance(iid)["pack"] + "/"
                         + datastores.find_instance(iid)["name"])
        m = json.loads((self.root / "datastores" / mig.MAP_FILE).read_text())
        self.assertEqual({"datastore:assetti-contabili/contabilita": f"datastore:{iid}"},
                         m["map"])
        # idempotent
        again = mig.candidates()
        self.assertEqual([], [r for r in again if r["action"] == "migrate"])
        cat._LAST_SYNC[0] = 0.0
        cat.sync()
        self.assertIsNone(cat.get("datastore", "assetti-contabili/contabilita"))

    def test_authz_rules_follow_the_datastore(self):
        from . import authz_shadow
        gp = Path(authz_shadow._global_path())
        gp.write_text(json.dumps({"tuples": [
            {"id": "g1", "agent": "commercialista", "verb": "datastore.read",
             "resource": "datastore:assetti-contabili/contabilita",
             "rule": [{"effect": "allow", "match": "*"}]},
            {"id": "g2", "agent": "*", "verb": "web.fetch", "resource": "*",
             "rule": [{"effect": "ask", "match": "*"}]}]}))
        meta, ver = self.svc._read_meta("SEAL-1", "bilancio")
        meta["authz"] = [{"id": "r1", "agent": "*", "verb": "datastore.write",
                          "resource": "datastore:assetti-contabili/contabilita",
                          "rule": [{"effect": "deny", "match": "*"}]}]
        self.svc._write_meta("SEAL-1", "bilancio", meta, base_version=ver)
        self.write_manifest()
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            mig.main([])
        dry = json.loads(buf.getvalue())["candidates"][0]["authz_rules"]
        self.assertEqual(["global:g1", "SEAL-1/bilancio:r1"], dry)
        self.assertIn("datastore:assetti-contabili/contabilita\"", gp.read_text())  # untouched
        mig.apply(mig.candidates())
        iid = "datastore:assetti-contabili/contabilita:tomato"
        g = json.loads(gp.read_text())["tuples"]
        self.assertEqual([iid, "*"], [t["resource"] for t in g])
        self.assertEqual(iid, self.svc._read_meta("SEAL-1", "bilancio")[0]["authz"][0]["resource"])

    def test_an_interrupted_run_is_resumed(self):
        self.write_manifest()
        rows = mig.candidates()
        # crash right after the registry entry (step 1): nothing else done
        with patch.object(mig, "_move", side_effect=OSError("disk")):
            with self.assertRaises(OSError):
                mig.apply(rows)
        self.assertIn("assetti-contabili/contabilita:tomato", datastores.instance_registry())
        self.assertTrue(self.legacy.is_file())
        again = mig.candidates()
        self.assertEqual(["resume"], [r["action"] for r in again])
        mig.apply(again)
        self.assertFalse(self.legacy.exists())
        self.assertIsNone(cat.get("datastore", "assetti-contabili/contabilita"))
        self.assertEqual([], [r for r in mig.candidates() if r["action"] != "skip"])

    def test_a_file_already_in_place_is_adopted(self):
        self.write_manifest()
        dst = self.root / "datastores/assetti-contabili/contabilita/tomato.db"
        dst.parent.mkdir(parents=True)
        self.legacy.replace(dst)
        rows = mig.candidates()
        self.assertEqual(["adopt"], [r["action"] for r in rows])
        mig.apply(rows)
        self.assertIsNotNone(datastores.find_instance("assetti-contabili/contabilita:tomato"))
        self.assertIsNotNone(cat.get("datastore", "assetti-contabili/contabilita:tomato"))

    def test_name_override(self):
        self.write_manifest()
        rows = mig.candidates({"assetti-contabili/contabilita": "studio"})
        self.assertEqual("assetti-contabili/contabilita:studio", rows[0]["to"])

    def test_cli_is_a_dry_run_by_default(self):
        self.write_manifest()
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            mig.main([])
        out = json.loads(buf.getvalue())
        self.assertFalse(out["apply"])
        self.assertTrue(self.legacy.is_file())


# ── #686 ─────────────────────────────────────────────────────────────────────

class ResolveTests(_Base):
    def setUp(self):
        super().setUp()
        self.create("tomato")
        self.create("uncommon")
        self.imp("tomato", "assetti-contabili/contabilita:tomato")

    def resolve(self, scope="SEAL-2/tomato", instance=None, agent="commercialista"):
        return di.resolve("assetti-contabili/contabilita", scope=scope, agent=agent,
                          clearance="SEAL-2", instance=instance)

    def test_one_import_is_implicit(self):
        self.assertTrue(self.resolve()["abs_path"].endswith("contabilita/tomato.db"))

    def test_several_need_the_instance(self):
        self.imp("tomato", "assetti-contabili/contabilita:uncommon")
        with self.assertRaises(ValueError) as c:
            self.resolve()
        self.assertIn("assetti-contabili/contabilita:tomato", str(c.exception))
        self.assertIn("assetti-contabili/contabilita:uncommon", str(c.exception))
        self.assertTrue(self.resolve(instance="uncommon")["abs_path"].endswith("uncommon.db"))
        self.assertTrue(self.resolve(instance="assetti-contabili/contabilita:tomato")
                        ["abs_path"].endswith("tomato.db"))

    def test_none_is_refused(self):
        with self.assertRaises(PermissionError) as c:
            self.resolve(scope="SEAL-2/uncommon")
        self.assertIn("nessuna istanza", str(c.exception))
        with self.assertRaises(PermissionError):
            self.resolve(scope=None)

    def test_an_instance_not_imported_cannot_be_named(self):
        with self.assertRaises(PermissionError):
            self.resolve(instance="uncommon")

    def test_access_rules_apply(self):
        with self.assertRaises(PermissionError):
            self.resolve(agent="ophelia")                     # not a participant
        cat.update("datastore", "assetti-contabili/contabilita:tomato", tier="SEAL-3")
        with self.assertRaises(PermissionError):
            self.resolve()                                    # above the topic's tier

    def test_datastore_verbs_take_the_structure_id(self):
        from . import main as M
        with patch.object(whitelist, "current_chat", lambda: "chan:SEAL-2:tomato:commercialista"), \
                patch.object(whitelist, "current_channel", lambda: "SEAL-2/tomato"), \
                patch.object(M, "agent_name", lambda: "commercialista"), \
                patch.object(M, "is_on_behalf", lambda: False), \
                patch.object(M, "current_clearance", lambda: "SEAL-2"):
            e = M._datastore_authorize("assetti-contabili/contabilita", write=False)
            self.assertEqual("contabilita:tomato", e["name"])
            e = M._datastore_authorize("assetti-contabili/contabilita:tomato", write=True)
            self.assertEqual("contabilita:tomato", e["name"])
            with self.assertRaises(PermissionError):
                M._datastore_authorize("assetti-contabili/contabilita:uncommon", write=False)

    def _bind(self, scope, args):
        b = {"name": "contabilita", "command": "python3", "args": [], "env": {"X": "1"}}
        with patch.object(whitelist, "current_channel", lambda: scope), \
                patch.object(whitelist, "agent_name", lambda: "commercialista"), \
                patch.object(whitelist, "current_clearance", lambda: "SEAL-2"):
            return proxy.bind_instances("contabilita", b, args)

    def test_proxy_binds_the_instance_and_strips_the_argument(self):
        self.imp("uncommon", "assetti-contabili/contabilita:uncommon")
        b1, a1 = self._bind("SEAL-2/tomato", {"q": 1, "instance": "tomato"})
        b2, a2 = self._bind("SEAL-2/uncommon", {"q": 1})
        self.assertEqual({"q": 1}, a1)
        self.assertEqual({"q": 1}, a2)
        self.assertTrue(b1["env"]["CLODIA_DATASTORE_CONTABILITA"].endswith("tomato.db"))
        self.assertTrue(b2["env"]["CLODIA_DATASTORE_CONTABILITA"].endswith("uncommon.db"))
        self.assertEqual("1", b1["env"]["X"])

    def test_proxy_refuses_without_an_import(self):
        self.svc.new("SEAL-2", "vuoto", {"owner": "davide", "participants": ["commercialista"]})
        with self.assertRaises(PermissionError):
            self._bind("SEAL-2/vuoto", {})

    def test_a_bound_backend_over_http_is_refused(self):
        b = {"name": "contabilita", "transport": "http", "url": "https://x.example/mcp"}
        with patch.object(whitelist, "current_channel", lambda: "SEAL-2/tomato"), \
                patch.object(whitelist, "agent_name", lambda: "commercialista"), \
                patch.object(whitelist, "current_clearance", lambda: "SEAL-2"):
            with self.assertRaises(PermissionError) as c:
                proxy.bind_instances("contabilita", b, {})
        self.assertIn("non è stdio", str(c.exception))

    def test_other_backends_are_untouched(self):
        b = {"name": "normattiva", "command": "x"}
        self.assertEqual((b, {"instance": "y"}),
                         proxy.bind_instances("normattiva", b, {"instance": "y"}))

    def test_tool_schema_gets_the_instance_argument(self):
        s = proxy._with_instance_arg("contabilita", {"type": "object", "properties": {}})
        self.assertIn("instance", s["properties"])
        self.assertIsNone(proxy._with_instance_arg("normattiva", None))


_ECHO_MCP = textwrap.dedent('''
    import os, sqlite3, sys
    from mcp.server.fastmcp import FastMCP
    path = os.environ.get("CLODIA_DATASTORE_CONTABILITA")
    if not path:
        sys.exit("CLODIA_DATASTORE_CONTABILITA not set")
    mcp = FastMCP("contabilita")

    @mcp.tool()
    def where(tag: str = "") -> str:
        conn = sqlite3.connect(path)
        conn.execute("INSERT INTO movimenti (importo) VALUES (1)")
        conn.commit()
        n = conn.execute("SELECT count(*) FROM movimenti").fetchone()[0]
        conn.close()
        return f"{os.getpid()}|{path}|{n}|{tag}"

    mcp.run()
''')


class ProxyProcessTests(_Base):
    """A real stdio MCP: two scopes → two processes on two files."""

    def setUp(self):
        super().setUp()
        script = self.plugin / "mcp" / "echo.py"
        script.write_text(_ECHO_MCP, encoding="utf-8")
        backend = {"name": "contabilita", "transport": "stdio", "command": sys.executable,
                   "args": [str(script)], "pack": "studio-commercialista"}
        self.write_manifest(mcp={"contabilita": {"command": sys.executable,
                                                 "args": [str(script)]}})
        p = patch.object(proxy, "CONFIG", {"mcp_backends": [backend]})
        p.start()
        self.addCleanup(p.stop)
        proxy.clear_cache()
        self.addCleanup(proxy.clear_cache)
        self.create("tomato")
        self.create("uncommon")
        self.imp("tomato", "assetti-contabili/contabilita:tomato")
        self.imp("uncommon", "assetti-contabili/contabilita:uncommon")

    def call(self, scope, args):
        with patch.object(whitelist, "current_channel", lambda: scope), \
                patch.object(whitelist, "agent_name", lambda: "commercialista"), \
                patch.object(whitelist, "current_clearance", lambda: "SEAL-2"), \
                patch.object(proxy, "is_disabled", lambda n: False):
            return asyncio.run(proxy.call_proxied("contabilita.where", args))

    def test_two_scopes_two_processes_two_files(self):
        pid1, path1, n1, _ = self.call("SEAL-2/tomato", {"tag": "a"}).split("|")
        pid2, path2, n2, _ = self.call("SEAL-2/uncommon", {"tag": "b"}).split("|")
        self.assertNotEqual(pid1, pid2)
        self.assertTrue(path1.endswith("contabilita/tomato.db"))
        self.assertTrue(path2.endswith("contabilita/uncommon.db"))
        _, _, n1b, _ = self.call("SEAL-2/tomato", {}).split("|")
        self.assertEqual(("1", "1", "2"), (n1, n2, n1b))

    def test_instance_argument_is_not_forwarded(self):
        out = self.call("SEAL-2/tomato", {"tag": "x", "instance": "tomato"})
        self.assertTrue(out.endswith("|x"))

    def test_listing_starts_the_mcp_on_a_throwaway_database(self):
        with patch("server.whitelist.disabled_backend_tools", lambda b: set()), \
                patch.object(proxy, "_is_transport", lambda b: False):
            tools = asyncio.run(proxy.list_proxied_tools())
        where = next(t for t in tools if t.name == "contabilita.where")
        self.assertIn("instance", where.inputSchema["properties"])
        for name in ("tomato", "uncommon"):
            f = self.root / "datastores/assetti-contabili/contabilita" / f"{name}.db"
            conn = sqlite3.connect(f)
            self.assertEqual(0, conn.execute("SELECT count(*) FROM movimenti").fetchone()[0])
            conn.close()


# ── #687 ─────────────────────────────────────────────────────────────────────

class SchemaMigrationTests(_Base):
    def setUp(self):
        super().setUp()
        self.create("tomato")
        self.create("uncommon")
        self.mdir = self.plugin / "mcp" / "migrations"
        self.mdir.mkdir()
        self.write_manifest([{"name": "contabilita", "schema": "mcp/schema.sql",
                              "migrations": "mcp/migrations"}])

    def add(self, n, sql):
        (self.mdir / f"{n:03d}_step.sql").write_text(sql, encoding="utf-8")

    def cols(self, name):
        conn = sqlite3.connect(self.root / "datastores/assetti-contabili/contabilita" / f"{name}.db")
        try:
            return [r[1] for r in conn.execute("PRAGMA table_info(fatture)")]
        finally:
            conn.close()

    def test_every_instance_is_migrated_with_a_backup(self):
        self.add(1, "ALTER TABLE fatture ADD COLUMN valuta TEXT;")
        self.add(2, "ALTER TABLE fatture ADD COLUMN conto TEXT;\nCREATE INDEX i ON fatture(conto);")
        rep = di.migrate(["assetti-contabili"])
        self.assertEqual(2, len(rep["migrated"]), rep)
        self.assertEqual([], rep["failed"])
        for row in rep["migrated"]:
            self.assertEqual((0, 2), (row["from"], row["to"]))
            b = Path(row["backup"])
            self.assertTrue(b.is_file())
            self.assertEqual(self.root / "migrations", b.parent)
            conn = sqlite3.connect(b)
            self.assertNotIn("valuta", [r[1] for r in conn.execute("PRAGMA table_info(fatture)")])
            conn.close()
        for name in ("tomato", "uncommon"):
            self.assertIn("conto", self.cols(name))
        self.assertEqual({2}, {i["schema_version"] for i in datastores.instances()})
        # idempotent
        rep = di.migrate(["assetti-contabili"])
        self.assertEqual([], rep["migrated"])
        self.assertEqual(2, len(rep["current"]))

    def test_a_failure_rolls_back_only_that_instance(self):
        # uncommon already has the column the migration adds: it fails there
        conn = sqlite3.connect(self.root / "datastores/assetti-contabili/contabilita/uncommon.db")
        conn.execute("ALTER TABLE fatture ADD COLUMN valuta TEXT")
        conn.commit()
        conn.close()
        self.add(1, "CREATE TABLE extra (x);\nALTER TABLE fatture ADD COLUMN valuta TEXT;")
        rep = di.migrate()
        self.assertIn("Update", rep["retry"])
        self.assertEqual(["assetti-contabili/contabilita:tomato"],
                         [r["id"] for r in rep["migrated"]])
        self.assertEqual(["assetti-contabili/contabilita:uncommon"],
                         [r["id"] for r in rep["failed"]])
        self.assertTrue(Path(rep["failed"][0]["backup"]).is_file())
        conn = sqlite3.connect(self.root / "datastores/assetti-contabili/contabilita/uncommon.db")
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        conn.close()
        self.assertNotIn("extra", tables)                    # rolled back as a whole
        versions = {i["name"]: i["schema_version"] for i in datastores.instances()}
        self.assertEqual({"tomato": 1, "uncommon": 0}, versions)

    def test_a_stale_instance_is_refused_also_by_its_full_id(self):
        from . import main as M
        self.add(1, "ALTER TABLE fatture ADD COLUMN valuta TEXT;")
        self.imp("tomato", "assetti-contabili/contabilita:tomato")
        with patch.object(whitelist, "current_chat", lambda: "chan:SEAL-2:tomato:commercialista"), \
                patch.object(whitelist, "current_channel", lambda: "SEAL-2/tomato"), \
                patch.object(M, "agent_name", lambda: "commercialista"), \
                patch.object(M, "is_on_behalf", lambda: False), \
                patch.object(M, "current_clearance", lambda: "SEAL-2"):
            with self.assertRaises(PermissionError) as c:
                M._datastore_authorize("assetti-contabili/contabilita:tomato", write=False)
            self.assertIn("Riprova migrazione", str(c.exception))
            di.migrate(ids=["assetti-contabili/contabilita:tomato"])
            M._datastore_authorize("assetti-contabili/contabilita:tomato", write=False)

    def test_retry_one_instance(self):
        self.add(1, "ALTER TABLE fatture ADD COLUMN valuta TEXT;")
        rep = di.migrate(ids=["assetti-contabili/contabilita:uncommon"])
        self.assertEqual(["assetti-contabili/contabilita:uncommon"],
                         [r["id"] for r in rep["migrated"]])
        versions = {i["name"]: i["schema_version"] for i in datastores.instances()}
        self.assertEqual({"tomato": 0, "uncommon": 1}, versions)
        with self.assertRaises(ValueError):
            di.migrate(ids=["nonsense"])

    def test_an_instance_below_the_schema_is_not_served(self):
        self.add(1, "ALTER TABLE fatture ADD COLUMN valuta TEXT;")
        self.imp("tomato", "assetti-contabili/contabilita:tomato")
        with self.assertRaises(PermissionError) as c:
            di.resolve("assetti-contabili/contabilita", scope="SEAL-2/tomato",
                       agent="commercialista", clearance="SEAL-2")
        self.assertIn("va migrata", str(c.exception))
        di.migrate()
        di.resolve("assetti-contabili/contabilita", scope="SEAL-2/tomato",
                   agent="commercialista", clearance="SEAL-2")

    def test_new_instances_start_at_the_latest_version(self):
        self.add(1, "ALTER TABLE fatture ADD COLUMN valuta TEXT;")
        out = self.create("nuova")
        self.assertEqual(1, out["schema_version"])
        self.assertEqual([], di.migrate()["migrated"][2:])

    def test_uninstalled_packs_are_not_migrated(self):
        self.add(1, "ALTER TABLE fatture ADD COLUMN valuta TEXT;")
        (self.plugin / "plugin.yaml").unlink()
        rep = di.migrate()
        self.assertEqual({"migrated": [], "failed": [], "current": []}, rep)

    def test_duplicate_migration_numbers_are_reported(self):
        self.add(1, "SELECT 1;")
        (self.mdir / "001_other.sql").write_text("SELECT 2;", encoding="utf-8")
        rep = di.migrate()
        self.assertEqual("assetti-contabili/contabilita", rep["failed"][0]["structure"])


if __name__ == "__main__":
    unittest.main()

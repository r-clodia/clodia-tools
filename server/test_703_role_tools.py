"""#703 — sysadmin's role tools as global A·V·R·Q tuples: a plan the owner
applies, merged without touching the other tuples."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from . import authz as A
from . import authz_migration as MIG
from . import authz_roles as ROLES
from . import authz_runtime as R
from . import authz_shadow as S
from . import main, whitelist
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicService

GITHUB_LISTED = ["get_me", "list_issues", "issue_read", "issue_write",
                 "get_pull_request", "get_workflow_run", "run_workflow",
                 "create_pull_request", "delete_repository", "merge_pull_request"]


class _Env(unittest.TestCase):
    def setUp(self):
        R.invalidate()
        self.addCleanup(R.invalidate)
        self.dir = tempfile.mkdtemp(prefix="roles703-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        cfg = {"authz_mode": "enforce",
               "agents": {"sysadmin": {"gated_tools": ["runtime.restart_agent"]}}}
        for p in (patch.dict(os.environ, {"CLODIA_TOOLS_STATE_DIR": self.dir}),
                  patch.object(whitelist, "CONFIG", cfg),
                  patch.object(whitelist, "save_config", lambda: None),
                  patch.object(whitelist, "reload_config", lambda: None)):
            p.start(); self.addCleanup(p.stop)
        self.svc = TopicService(LocalFsStorage(tempfile.mkdtemp(prefix="topics703-")))
        p = patch.object(main, "_topics", lambda: self.svc)
        p.start(); self.addCleanup(p.stop)
        self.svc.new("SEAL-1", "blog", {"owner": "davide",
                                        "participants": ["clodia", "sysadmin"]})

    def plan(self):
        return ROLES.role_plan("sysadmin", github_tools=GITHUB_LISTED)

    def by_verb(self, p):
        return {t["verb"]: t for t in p["global"]}


class PlanTests(_Env):
    def test_the_three_groups_named_and_everywhere(self):
        p = self.plan()
        v = self.by_verb(p)
        for verb in ("runtime.health", "runtime.inspect_topic", "logs.tail",
                     "packs.list", "agents.show", "jobs.list", "rag.collections",
                     "rag.create_collection", "packs.create_datastore",
                     "github.list_issues", "github.issue_write"):
            self.assertIn(verb, v)
        for t in p["global"]:
            self.assertEqual(t["agent"], "sysadmin")
            self.assertEqual(t["where"], A.EVERYWHERE)
            self.assertEqual(t["resource"], "*")
            self.assertTrue(t["id"].startswith("role-sysadmin-"))
        self.assertEqual(p["topics"], {})
        self.assertEqual(p["github_source"], "backend")

    def test_reads_allow_writes_ask_own_gates_do_not_ask_twice(self):
        v = self.by_verb(self.plan())
        eff = lambda verb: v[verb]["rule"][0]["effect"]  # noqa: E731
        for read in ("runtime.health", "logs.tail", "packs.list", "github.get_me",
                     "github.issue_read", "runtime.agents", "github.get_pull_request",
                     "github.get_workflow_run"):
            self.assertEqual(eff(read), "allow", read)
        for write in ("github.issue_write", "github.create_pull_request", "github.run_workflow",
                      "packs.setup_done", "rag.create_collection"):
            self.assertEqual(eff(write), "ask", write)
        # Gated globally, gated by the seed, or asking inside: one card, not two.
        for own in ("packs.import_url", "agents.grant_tool", "jobs.set_enabled",
                    "runtime.restart_agent", "runtime.room_resource", "jobs.propose"):
            self.assertEqual(eff(own), "allow", own)

    def test_what_is_never_in_the_role(self):
        v = self.by_verb(self.plan())
        for never in ("github.delete_repository", "github.merge_pull_request",
                      "github.clone", "github.push", "github.pull_request",
                      "rag.search", "rag.list", "rag.ingest", "datastore.read",
                      "topic.read_file", "jobs.report_status", "github.*"):
            self.assertNotIn(never, v)

    def test_an_unknown_role_is_refused(self):
        with self.assertRaises(ValueError):
            ROLES.role_plan("clodia")

    def test_the_markdown_names_every_tuple(self):
        p = self.plan()
        md = ROLES.markdown(p)
        for t in p["global"]:
            self.assertIn(f"`{t['verb']}`", md)


class MergeTests(_Env):
    def test_merge_adds_without_touching_the_rest_and_rollback_undoes(self):
        existing = {"id": "g-0001", "agent": "*", "verb": "topic.*", "resource": "*",
                    "rule": [{"effect": "allow", "match": "*"}]}
        S._global_path().write_text(json.dumps({"tuples": [existing]}))
        meta, ver = self.svc._read_meta("SEAL-1", "blog")
        meta["authz"] = [{**existing, "id": "t-1", "verb": "notify.send"}]
        self.svc._write_meta("SEAL-1", "blog", meta, base_version=ver)
        p = self.plan()
        out = ROLES.merge(p, by="davide")
        self.assertTrue(out["ok"])
        self.assertEqual(out["added"], len(p["global"]))
        ids = [t.id for t in S.global_tuples()[0]]
        self.assertEqual(ids[0], "g-0001")
        self.assertEqual(len(ids), 1 + len(p["global"]))
        # The rooms' rules are untouched (apply would have replaced them).
        self.assertEqual(self.svc._read_meta("SEAL-1", "blog")[0]["authz"][0]["id"], "t-1")
        # Idempotent: merging again adds nothing.
        again = ROLES.merge(p, by="davide")
        self.assertEqual(again["added"], 0)
        MIG.rollback(out["backup"], by="davide")
        self.assertEqual([t.id for t in S.global_tuples()[0]], ["g-0001"])

    def test_an_owner_rule_for_the_same_verb_wins(self):
        mine = {"id": "gate-x", "agent": "sysadmin", "verb": "github.issue_write",
                "resource": "*", "rule": [{"effect": "deny", "match": "*"}]}
        S._global_path().write_text(json.dumps({"tuples": [mine]}))
        out = ROLES.merge(self.plan(), by="davide")
        self.assertIn("role-sysadmin-github.issue_write", out["skipped"])
        rows = [t for t in S.global_tuples()[0] if t.verb == "github.issue_write"]
        self.assertEqual([t.id for t in rows], ["gate-x"])

    def test_a_tampered_plan_writes_nothing(self):
        p = self.plan()
        bad = dict(p)
        bad["global"] = p["global"] + [{"id": "role-sysadmin-topic.read_file",
                                        "agent": "sysadmin", "verb": "topic.read_file",
                                        "resource": "*",
                                        "rule": [{"effect": "allow", "match": "*"}]}]
        with self.assertRaises(A.AuthzError):
            ROLES.merge(bad, by="davide")
        self.assertEqual(S.global_tuples()[0], [])
        with self.assertRaises(A.AuthzError):
            ROLES.merge({"global": [{"id": "g-1", "agent": "*", "verb": "*",
                                     "resource": "*",
                                     "rule": [{"effect": "allow", "match": "*"}]}]},
                        by="davide")
        with self.assertRaises(A.AuthzError):
            ROLES.merge({**p, "topics": {"SEAL-1/blog": p["global"]}}, by="davide")

    def test_after_merge_sysadmin_has_the_tools_everywhere_and_no_one_else(self):
        ROLES.merge(self.plan(), by="davide")
        self.assertTrue(R.available("sysadmin", "runtime.health", None))
        self.assertTrue(R.available("sysadmin", "runtime.health", "SEAL-1/blog"))
        self.assertTrue(R.available("sysadmin", "github.list_issues", "SEAL-1/blog"))
        self.assertFalse(R.available("clodia", "runtime.health", "SEAL-1/blog"))
        self.assertFalse(R.available("clodia", "github.list_issues", None))
        # A write asks an ADMIN outside a room (system card), per the gate key.
        d = R.check("sysadmin", "github.issue_write", {}, None, False)
        self.assertEqual(d.effect, "ask")
        self.assertTrue(R.gate_key(d, "github.issue_write").startswith("authz-global:"))


if __name__ == "__main__":
    unittest.main()

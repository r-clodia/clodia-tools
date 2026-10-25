"""#617 — A·V·R·Q enforced: availability from tuples, deny and ask per call,
the room's panels read as tuples, apply and rollback of an approved plan."""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from . import authz as A
from . import authz_migration as MIG
from . import authz_runtime as R
from . import authz_shadow as S
from . import gate, main, whitelist
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicService


class _Env(unittest.TestCase):
    def setUp(self):
        R.invalidate()
        self.addCleanup(R.invalidate)
        self.dir = tempfile.mkdtemp(prefix="authz617-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        for p in (patch.dict(os.environ, {"CLODIA_TOOLS_STATE_DIR": self.dir}),
                  patch.object(whitelist, "CONFIG", {"authz_mode": "enforce"}),
                  patch.object(whitelist, "save_config", lambda: None),
                  patch.object(whitelist, "reload_config", lambda: None)):
            p.start(); self.addCleanup(p.stop)
        self.svc = TopicService(LocalFsStorage(tempfile.mkdtemp(prefix="topics617-")))
        p = patch.object(main, "_topics", lambda: self.svc)
        p.start(); self.addCleanup(p.stop)
        self.svc.new("SEAL-1", "blog", {"owner": "davide", "participants": ["clodia", "officer"]})

    def glob(self, tuples):
        S._global_path().write_text(json.dumps({"tuples": tuples}))
        R.invalidate()

    def meta_set(self, **kw):
        meta, ver = self.svc._read_meta("SEAL-1", "blog")
        meta.update(kw)
        self.svc._write_meta("SEAL-1", "blog", meta, base_version=ver)
        R.invalidate()


def _t(id, agent="*", verb="email.send", rule=None, **kw):
    return {"id": id, "agent": agent, "verb": verb, "resource": "*",
            "rule": rule or [{"effect": "allow", "match": "*"}], **kw}


class AvailabilityTests(_Env):
    def test_the_seed_grants_nothing_the_tuples_decide(self):
        self.assertFalse(R.available("clodia", "email.send", "SEAL-1/blog"))
        self.meta_set(authz=[_t("t1", agent="clodia")])
        self.assertTrue(R.available("clodia", "email.send", "SEAL-1/blog"))
        self.assertFalse(R.available("officer", "email.send", "SEAL-1/blog"))
        self.assertFalse(R.available("clodia", "email.send", "SEAL-1/altro"))

    def test_outside_tuples_hold_only_outside_rooms(self):
        self.glob([_t("g1", agent="clodia", where="outside")])
        self.assertTrue(R.available("clodia", "email.send", None))
        self.assertFalse(R.available("clodia", "email.send", "SEAL-1/blog"))

    def test_the_panels_of_the_room_are_tuples(self):
        self.meta_set(tools={"enabled": ["web.*"], "except": {"officer": ["web.post"]}},
                      data=[{"kind": "rag", "name": "topic-x", "grants": {"officer": "read"}}],
                      drive_folders=[{"name": "drive", "folder": "FOLDER1"}])
        self.assertTrue(R.available("clodia", "web.post", "SEAL-1/blog"))
        self.assertFalse(R.available("officer", "web.post", "SEAL-1/blog"))
        self.assertTrue(R.available("officer", "rag.search", "SEAL-1/blog"))
        self.assertFalse(R.available("clodia", "rag.search", "SEAL-1/blog"))
        self.assertTrue(R.available("clodia", "gdrive.list", "SEAL-1/blog"))
        self.assertFalse(R.available("clodia", "gdrive.upload", "SEAL-1/blog"))

    def test_reachability_follows_the_mode(self):
        self.meta_set(authz=[_t("t1", agent="clodia")])
        with patch("server.egress._scope_of_call", lambda: "SEAL-1/blog"), \
                patch.object(main, "_declared_tools", lambda a: set()):
            self.assertTrue(main._agent_tool_reachable("email.send", "clodia"))
            whitelist.CONFIG["authz_mode"] = "shadow"
            self.assertFalse(main._agent_tool_reachable("email.send", "clodia"))

    def test_an_unreadable_global_file_fails_closed(self):
        S._global_path().write_text("{rotto")
        R.invalidate()
        self.assertFalse(R.available("clodia", "email.send", None))


class DispatchTests(_Env):
    async def _call(self, decision, unattended=False):
        gate_mock = AsyncMock(return_value=None)
        with patch.object(main, "agent_name", lambda: "clodia"), \
                patch.object(main, "is_on_behalf", lambda: False), \
                patch.object(main, "_agent_tool_reachable", lambda *a, **k: True), \
                patch.object(main, "agent_denies", lambda *a, **k: False), \
                patch.object(main, "_unattended_denial", lambda n: None), \
                patch.object(main, "is_unattended", lambda: unattended), \
                patch.object(main.origin, "evaluate", lambda c, n: {"action": "allow"}), \
                patch.object(main, "_origin_chain", lambda n: []), \
                patch.object(R, "check", lambda *a, **k: decision), \
                patch.object(main, "_require_gate_consent", gate_mock):
            out = await main._call_tool_unaudited("zz.verbo_finto", {})
        return out[0].text, gate_mock

    def test_deny_ask_and_unattended(self):
        import asyncio
        deny = A.Decision(A.DENY, True, [], "deny su mailto:x@y.it")
        text, g = asyncio.run(self._call(deny))
        self.assertIn("A·V·R·Q", text)
        self.assertFalse(g.await_count)
        ask = A.Decision(A.ASK, True, [A.TargetDecision("mailto:x@y.it", A.ASK, A.TOPIC)], "ask")
        text, g = asyncio.run(self._call(ask))
        self.assertEqual(g.await_count, 1)
        self.assertTrue(g.await_args.args[1].startswith("authz:zz.verbo_finto|mailto:x@y.it"))
        text, g = asyncio.run(self._call(ask, unattended=True))
        self.assertIn("non presidiato", text)
        self.assertFalse(g.await_count)


class GateAndStripTests(_Env):
    def test_who_answers_an_ask(self):
        self.assertEqual(gate.gate_class("authz:email.send|mailto:a@b.it"), gate.GATE_WALLS)
        self.assertEqual(gate.gate_class("authz-global:email.send|*"), gate.GATE_SYSTEM)

    def test_a_creator_never_brings_rules(self):
        self.svc.new("SEAL-1", "x", {"owner": "davide", "authz": [_t("t")]})
        self.assertNotIn("authz", self.svc._read_meta("SEAL-1", "x")[0])

    def test_where_outside_is_global_only(self):
        with self.assertRaises(A.AuthzError):
            A.parse_tuple(_t("t", where="outside"), level=A.TOPIC)


class ApplyTests(_Env):
    def test_apply_writes_everything_and_rollback_restores(self):
        self.meta_set(authz=[_t("vecchia")])
        plan = {"global": [_t("g1", agent="clodia", verb="packs.list")],
                "topics": {"SEAL-1/blog": [_t("t1", agent="clodia")]}}
        out = MIG.apply(plan, by="davide")
        self.assertTrue(out["ok"])
        self.assertEqual([t.id for t in S.global_tuples()[0]], ["g1"])
        self.assertEqual([r["id"] for r in self.svc._read_meta("SEAL-1", "blog")[0]["authz"]],
                         ["t1"])
        MIG.rollback(out["backup"], by="davide")
        self.assertEqual(S.global_tuples()[0], [])
        self.assertEqual([r["id"] for r in self.svc._read_meta("SEAL-1", "blog")[0]["authz"]],
                         ["vecchia"])

    def test_an_invalid_plan_writes_nothing(self):
        plan = {"global": [], "topics": {"SEAL-1/blog": [_t("t1", verb="packs.import_url")]}}
        with self.assertRaises(A.AuthzError):
            MIG.apply(plan, by="davide")
        self.assertNotIn("authz", self.svc._read_meta("SEAL-1", "blog")[0])

    def test_set_mode(self):
        MIG.set_mode("shadow")
        self.assertEqual(whitelist.CONFIG["authz_mode"], "shadow")
        with self.assertRaises(A.AuthzError):
            MIG.set_mode("tutto")


if __name__ == "__main__":
    unittest.main()

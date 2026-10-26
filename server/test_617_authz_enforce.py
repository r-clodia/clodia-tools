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
        self.meta_set(tools={"enabled": ["web.*"]},
                      data=[{"kind": "rag", "name": "topic-x", "grants": {"officer": "read"}}],
                      drive_folders=[{"name": "drive", "folder": "FOLDER1"}])
        self.assertTrue(R.available("clodia", "web.post", "SEAL-1/blog"))
        self.assertTrue(R.available("officer", "web.post", "SEAL-1/blog"))
        # A RAG imported in the room is read by every participant (26 Oct).
        self.assertTrue(R.available("officer", "rag.search", "SEAL-1/blog"))
        self.assertTrue(R.available("clodia", "rag.search", "SEAL-1/blog"))
        self.assertFalse(R.available("estraneo", "rag.search", "SEAL-1/blog"))
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

    def test_judged_targets_supersede_the_egress_whitelist(self):
        """A destination A·V·R·Q judged (and the owner approved) is not refused
        again by the legacy egress PDP, nor asked twice (gdrive.upload into a
        quote folder, 25 Oct). With no readable target the PDP still refuses."""
        import asyncio
        from . import egress
        refused = {"checked": True, "allowed": False, "action": "deny",
                   "destinations": [egress.UNKNOWN], "type": "drive",
                   "reason": "destinazione non leggibile dalla chiamata"}
        with patch.object(egress, "check", lambda *a, **k: dict(refused)), \
                patch.object(main, "_verb_implemented", lambda n: True):
            ask = A.Decision(A.ASK, True, [A.TargetDecision(
                "gdrive:folder/F1", A.ASK, A.TOPIC)], "ask")
            text, g = asyncio.run(self._call(ask))
            self.assertEqual(g.await_count, 1)          # A·V·R·Q's consent only
            self.assertNotIn("non leggibile", text)
            blind = A.Decision(A.ASK, True, [A.TargetDecision(None, A.ASK, A.TOPIC)], "ask")
            text, g = asyncio.run(self._call(blind))
            self.assertIn("non leggibile", text)

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


class ReviewOf435Tests(_Env):
    """Second-line promise: enforcing never opens what is closed today."""

    def test_a_creator_never_brings_drive_folders(self):
        self.svc.new("SEAL-1", "furbo", {"owner": "intruder", "participants": ["intruder"],
                                          "drive_folders": [{"name": "d", "folder": "X"}],
                                          "mounts": [{"type": "drive", "folder": "Y"}]})
        meta = self.svc._read_meta("SEAL-1", "furbo")[0]
        self.assertNotIn("drive_folders", meta)
        self.assertFalse(R.available("intruder", "gdrive.list", "SEAL-1/furbo"))

    def test_a_linked_folder_is_read_and_nothing_else(self):
        self.meta_set(drive_folders=[{"name": "drive", "folder": "F1"}])
        d = R.check("clodia", "gdrive.download", {"file_id": "ALTRO"}, "SEAL-1/blog", False)
        self.assertIn(d.effect, (A.DENY, A.ALLOW))
        g, t = R.tuples_for("clodia", "SEAL-1/blog")
        dec = A.decide(g, t, agent="clodia", verb="gdrive.list", resource="google:default",
                       targets=["gdrive:folder/ALTRA"], kind=A.READ)
        self.assertEqual(dec.effect, A.DENY)
        dec = A.decide(g, t, agent="clodia", verb="gdrive.list", resource="google:default",
                       targets=["gdrive:folder/F1"], kind=A.READ)
        self.assertEqual(dec.effect, A.ALLOW)
        # A file is left to the Drive perimeter (its parents), not refused here.
        dec = A.decide(g, t, agent="clodia", verb="gdrive.download", resource="google:default",
                       targets=["gdrive:file/DENTRO"], kind=A.READ)
        self.assertEqual(dec.effect, A.ALLOW)

    def test_the_room_gives_nothing_to_outsiders_or_once_archived(self):
        self.meta_set(tools={"enabled": ["web.*"]})
        self.assertFalse(R.available("estraneo", "web.fetch", "SEAL-1/blog"))
        self.meta_set(status="archived")
        self.assertFalse(R.available("clodia", "web.fetch", "SEAL-1/blog"))

    def test_the_toolbox_does_not_decide_targets(self):
        self.meta_set(tools={"enabled": ["email.*"]},
                      authz=[_t("t1", agent="clodia",
                                rule=[{"effect": "allow", "match": "mailto:a@foo.bar"}])])
        g, t = R.tuples_for("clodia", "SEAL-1/blog")
        dec = A.decide(g, t, agent="clodia", verb="email.send", resource="mail:default",
                       targets=["mailto:b@evil.com"], kind=A.WRITE)
        self.assertEqual(dec.effect, A.ASK)

    def test_one_consent_names_every_asked_recipient(self):
        d = A.Decision(A.ASK, True, [A.TargetDecision("mailto:b@x.it", A.ASK, A.GLOBAL),
                                     A.TargetDecision("mailto:evil@y.com", A.ASK, A.TOPIC)], "r")
        k = R.gate_key(d, "email.send")
        self.assertTrue(k.startswith("authz-global:email.send|"))
        self.assertIn("mailto:evil@y.com", k)
        self.assertIn("mailto:b@x.it", k)

    def test_an_unreadable_room_denies(self):
        d = R.check("clodia", "email.send", {}, "SEAL-1/inesistente", False)
        self.assertEqual(d.effect, A.DENY)


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

    def test_a_topic_outside_the_plan_loses_its_old_rules(self):
        self.svc.new("SEAL-1", "altro", {"owner": "davide"})
        meta, ver = self.svc._read_meta("SEAL-1", "altro")
        meta["authz"] = [_t("residuo")]
        self.svc._write_meta("SEAL-1", "altro", meta, base_version=ver)
        out = MIG.apply({"global": [_t("g1", agent="clodia", verb="packs.list")],
                         "topics": {"SEAL-1/blog": [_t("t1", agent="clodia")]}}, by="davide")
        self.assertTrue(out["ok"])
        self.assertNotIn("authz", self.svc._read_meta("SEAL-1", "altro")[0])
        MIG.rollback(out["backup"], by="davide")
        self.assertEqual(self.svc._read_meta("SEAL-1", "altro")[0]["authz"][0]["id"], "residuo")

    def test_a_failed_topic_puts_everything_back(self):
        orig = self.svc._write_meta

        def boom(tier, name, meta, base_version=None):
            if name == "blog":
                raise RuntimeError("disco pieno")
            return orig(tier, name, meta, base_version=base_version)
        with patch.object(self.svc, "_write_meta", boom):
            out = MIG.apply({"global": [_t("g1", agent="clodia", verb="packs.list")],
                             "topics": {"SEAL-1/blog": [_t("t1", agent="clodia")]}}, by="d")
        self.assertFalse(out["ok"])
        self.assertTrue(out["rolled_back"])
        self.assertEqual(S.global_tuples()[0], [])

    def test_enforce_needs_an_applied_plan(self):
        with self.assertRaises(A.AuthzError):
            MIG.set_mode("enforce")
        self.glob([_t("g1", agent="clodia", verb="packs.list")])
        MIG.set_mode("enforce")

    def test_set_mode(self):
        MIG.set_mode("shadow")
        self.assertEqual(whitelist.CONFIG["authz_mode"], "shadow")
        with self.assertRaises(A.AuthzError):
            MIG.set_mode("tutto")


if __name__ == "__main__":
    unittest.main()


class AdapterAndCopybrainTests(_Env):
    """25 Oct: the adapter-level gate read the seed and copybrain borrowed
    another seed's verbs to pass it."""

    def test_the_adapter_gate_answers_with_the_room(self):
        from . import whitelist as W
        self.meta_set(authz=[_t("t1", verb="email.list")])
        with patch("server.egress._scope_of_call", lambda: "SEAL-1/blog"), \
                patch.object(W, "agent_name", lambda: "clodia"), \
                patch.object(W, "agent_denies", lambda *a, **k: False), \
                patch.object(W, "effective_tools", lambda a: set()):
            W.tool_allowed("email.list")
            with self.assertRaises(PermissionError):
                W.tool_allowed("email.send")

    def test_copybrain_is_refused_when_enforcing(self):
        import asyncio
        with patch.object(main, "agent_name", lambda: "clodia"), \
                patch.object(main, "is_on_behalf", lambda: False), \
                patch.object(main, "_agent_tool_reachable", lambda *a, **k: True), \
                patch.object(main, "agent_denies", lambda *a, **k: False), \
                patch.object(main, "_unattended_denial", lambda n: None), \
                patch.object(main.origin, "evaluate", lambda c, n: {"action": "allow"}), \
                patch.object(main, "_origin_chain", lambda n: []), \
                patch.object(R, "check", lambda *a, **k: A.Decision(A.ALLOW, True, [], "ok")):
            out = asyncio.run(main._call_tool_unaudited("copybrain.assume",
                                                        {"seed": "officer", "reason": "x"}))
        self.assertIn("copybrain non è disponibile", out[0].text)


class NativeWebSearchTests(_Env):
    """Option C (owner, 26 Oct 2026): the model's WebSearch is governed by the
    room's `web.search` — authorised with «Web» in the Strumenti panel."""

    def _consent(self, agent="clodia"):
        import asyncio
        g = AsyncMock(return_value=None)
        with patch("server.egress._scope_of_call", lambda: "SEAL-1/blog"), \
                patch.object(main, "is_unattended", lambda: False), \
                patch.object(main, "current_chat", lambda: "chan:SEAL-1:blog:clodia"), \
                patch.object(main._taint, "mark", lambda *a, **k: None), \
                patch.object(main._taint, "status", lambda c: {"tainted": False}), \
                patch("server.audit.emit", lambda *a, **k: None), \
                patch.object(main, "_require_gate_consent", g):
            try:
                out = asyncio.run(main._native_consent({"tool": "WebSearch", "query": "q"}, agent))
            except PermissionError as e:
                out = e
        return out, g

    def test_not_authorised_in_the_room_is_refused(self):
        out, g = self._consent()
        self.assertIsInstance(out, PermissionError)
        self.assertIn("web.search", str(out))
        self.assertFalse(g.await_count)

    def test_web_authorised_searches_without_a_card(self):
        self.meta_set(tools={"enabled": ["web.*"]})
        out, g = self._consent()
        self.assertEqual(out, {"granted": True, "tool": "WebSearch"})
        self.assertFalse(g.await_count)

    def test_a_rule_that_asks_shows_the_card_and_a_deny_refuses(self):
        self.meta_set(tools={"enabled": ["web.*"]},
                      authz=[_t("t1", verb="web.search", rule=[{"effect": "ask", "match": "*"}])])
        out, g = self._consent()
        self.assertEqual(g.await_count, 1)
        self.meta_set(authz=[_t("t2", verb="web.search", rule=[{"effect": "deny", "match": "*"}])])
        out, g = self._consent()
        self.assertIsInstance(out, PermissionError)

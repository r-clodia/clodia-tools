"""#693 — the approval matrix of a gate: which cells a gate has, and the rule a
cell writes, judged through the real decision path (`authz_runtime.check`).

A rule written for a seed in a room must make THAT seed's identical call stop
asking — and nothing wider: another seed, another target, another room still
ask. A global rule the same at the instance level. The cells a gate does not
have are refused with their reason.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import asyncio
from unittest.mock import AsyncMock

from . import authz as A
from . import authz_runtime as R
from . import egress
from .claims import ClaimsContext
from . import authz_shadow as S
from . import gate_remember as G
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicService

URL = "https://api.example.com/x"
TARGET = "https://api.example.com/"
OTHER = "https://other.example.org/"

#: The room asks on every target of `web.post` (as a room whose owner wrote
#: «ask» — the shape of a toolbox row on a write).
ROOM_ASK = {"id": "t-ask", "agent": "*", "verb": "web.post", "resource": "*",
            "rule": [{"effect": "ask", "match": "*"}]}
GLOBAL_ASK = {"id": "g-ask", "agent": "*", "verb": "web.post", "resource": "*",
              "rule": [{"effect": "ask", "match": "*"}]}


class _Env(unittest.TestCase):
    def setUp(self):
        d = Path(tempfile.mkdtemp(prefix="g693-"))
        self.svc = TopicService(LocalFsStorage(tempfile.mkdtemp(prefix="topics-")))
        self.global_path = d / "authz.json"
        for p in (patch("server.main._topics", lambda: self.svc),
                  patch.object(S, "_global_path", lambda: self.global_path)):
            p.start()
            self.addCleanup(p.stop)
        R.invalidate()
        self.addCleanup(R.invalidate)
        for name in ("vendite", "acquisti"):
            self.svc.new("SEAL-1", name, {"owner": "davide",
                                          "participants": ["davide", "officer", "clodia"]})

    def room_rules(self, name, rows):
        meta, ver = self.svc._read_meta("SEAL-1", name)
        meta["authz"] = list(rows)
        self.svc._write_meta("SEAL-1", name, meta, ver)
        R.invalidate()

    def global_rules(self, rows):
        self.global_path.write_text(json.dumps({"tuples": list(rows)}))
        R.invalidate()

    def effect(self, agent, url=URL, scope="SEAL-1/vendite"):
        return R.check(agent, "web.post", {"url": url}, scope, False)


class CellsTests(unittest.TestCase):
    def test_a_room_ask_is_answered_in_the_room(self):
        c = G.cells(f"authz:web.post|{TARGET}")
        self.assertEqual((c["seed:chat"], c["all:chat"]), ("", ""))
        self.assertTrue(c["seed:global"] and c["all:global"])

    def test_a_global_ask_is_answered_globally(self):
        c = G.cells(f"authz-global:web.post|{TARGET}")
        self.assertEqual((c["seed:global"], c["all:global"]), ("", ""))
        self.assertTrue(c["seed:chat"] and c["all:chat"])

    def test_a_destination_has_every_cell(self):
        c = G.cells("egress:http:https://api.example.com/")
        self.assertEqual(set(c.values()), {""})

    def test_a_trusted_source_is_for_every_agent(self):
        """The taint is the channel's, not an agent's: «trusted for one seed»
        means nothing, and the seed row says why."""
        c = G.cells("ingress:web:https://api.example.com/|chan:SEAL-1:x:clodia")
        self.assertEqual((c["all:chat"], c["all:global"]), ("", ""))
        self.assertIn("canale", c["seed:chat"])
        self.assertIn("canale", c["seed:global"])

    def test_other_gates_have_no_rule(self):
        for key in ("native:shell|chan:x", "topic-access:SEAL-1/x", "copybrain:clodia",
                    "unattended:web.post"):
            with self.subTest(key=key):
                self.assertTrue(all(G.cells(key).values()))


class RoomRuleTests(_Env):
    def setUp(self):
        super().setUp()
        self.room_rules("vendite", [ROOM_ASK])
        self.room_rules("acquisti", [ROOM_ASK])

    def test_the_seed_s_identical_call_stops_asking_and_nothing_wider(self):
        d = self.effect("officer")
        self.assertEqual(d.effect, A.ASK)
        key = R.gate_key(d, "web.post")
        self.assertTrue(key.startswith("authz:"), key)
        out = G.remember(key, agent="officer", scope="SEAL-1/vendite", by="davide")
        self.assertEqual(out["kind"], "rule")
        self.assertEqual(self.effect("officer").effect, A.ALLOW)
        self.assertEqual(self.effect("clodia").effect, A.ASK)              # another seed
        self.assertEqual(self.effect("officer", "https://other.example.org/y").effect,
                         A.ASK)                                            # another target
        self.assertEqual(self.effect("officer", scope="SEAL-1/acquisti").effect,
                         A.ASK)                                            # another room

    def test_every_agent_in_the_room(self):
        key = R.gate_key(self.effect("officer"), "web.post")
        G.remember(key, agent="*", scope="SEAL-1/vendite", by="davide")
        for agent in ("officer", "clodia"):
            self.assertEqual(self.effect(agent).effect, A.ALLOW, agent)
        self.assertEqual(self.effect("officer", scope="SEAL-1/acquisti").effect, A.ASK)

    def test_the_rule_is_a_visible_room_rule_written_once(self):
        key = R.gate_key(self.effect("officer"), "web.post")
        G.remember(key, agent="officer", scope="SEAL-1/vendite", by="davide")
        again = G.remember(key, agent="officer", scope="SEAL-1/vendite", by="davide")
        self.assertFalse(again["new"])
        rows = self.svc._read_meta("SEAL-1", "vendite")[0]["authz"]
        mine = [r for r in rows if r.get("origin") == "gate"]
        self.assertEqual(len(mine), 1)
        self.assertEqual((mine[0]["agent"], mine[0]["verb"], mine[0]["rule"], mine[0]["by"]),
                         ("officer", "web.post", [{"effect": "allow", "match": TARGET}],
                          "davide"))

    def test_a_global_cell_is_refused_for_a_room_ask(self):
        key = R.gate_key(self.effect("officer"), "web.post")
        with self.assertRaises(G.RememberError):
            G.remember(key, agent="officer", scope="", by="davide")
        self.assertFalse(self.global_path.exists())


class GlobalRuleTests(_Env):
    def setUp(self):
        super().setUp()
        self.global_rules([GLOBAL_ASK])

    def test_the_seed_everywhere_and_nothing_wider(self):
        d = self.effect("officer", scope=None)
        self.assertEqual(d.effect, A.ASK)
        key = R.gate_key(d, "web.post")
        self.assertTrue(key.startswith("authz-global:"), key)
        G.remember(key, agent="officer", scope="", by="admin")
        for scope in (None, "SEAL-1/vendite", "SEAL-1/acquisti"):
            self.assertEqual(self.effect("officer", scope=scope).effect, A.ALLOW, scope)
        self.assertEqual(self.effect("clodia", scope=None).effect, A.ASK)
        self.assertEqual(self.effect("officer", OTHER + "z", scope=None).effect, A.ASK)
        # The admin's other rules are kept.
        ids = [t["id"] for t in json.loads(self.global_path.read_text())["tuples"]]
        self.assertIn("g-ask", ids)

    def test_a_room_cell_is_refused_for_a_global_ask(self):
        key = R.gate_key(self.effect("officer", scope=None), "web.post")
        with self.assertRaises(G.RememberError):
            G.remember(key, agent="officer", scope="SEAL-1/vendite", by="davide")


class PendingPayloadTests(unittest.TestCase):
    def test_a_pending_gate_carries_its_cells(self):
        from . import gate
        now = __import__("time").time()
        req = {"k": {"agent": "officer", "instance": "officer-28",
                     "verb": f"authz:web.post|{TARGET}", "at": now}}
        with patch.object(gate, "_load", return_value=req), \
                patch.object(gate, "_save"):
            (row,) = gate.list_requests()
        self.assertEqual(row["remember"], G.cells(f"authz:web.post|{TARGET}"))


class DestinationTests(_Env):
    """An `egress:` gate (the PDP's: A·V·R·Q did not judge the call — a
    delivery, a super agent, a person) remembered for ONE seed: the egress PDP
    accepts the address for that seed only, A·V·R·Q in the room too."""

    KEY = "egress:http:https://api.example.com/"

    def setUp(self):
        super().setUp()
        for p in (patch.dict("os.environ", {"CLODIA_EGRESS_ENFORCE": "gate"}),
                  patch.object(egress, "effective_uris", lambda *a, **k: [])):
            p.start()
            self.addCleanup(p.stop)

    def pdp(self, agent, url=URL, scope="SEAL-1/vendite"):
        with patch.object(egress, "_scope_of_call", lambda: scope):
            return egress.check(agent, {}, "web.post", {"url": url})["action"]

    def test_every_agent_goes_to_the_room_list(self):
        with patch("server.egress.scope_allow", return_value={"added": True}) as sa:
            out = G.remember(self.KEY, agent="*", scope="SEAL-1/vendite")
        sa.assert_called_once_with("egress", "SEAL-1/vendite", "https://api.example.com/")
        self.assertEqual(out["kind"], "list")

    def test_a_seed_in_this_room(self):
        self.assertEqual(self.pdp("officer"), "gate")
        out = G.remember(self.KEY, agent="officer", scope="SEAL-1/vendite", by="davide")
        self.assertEqual(out["kind"], "rule")
        self.assertIn("web.post", [r["verb"] for r in out["rules"]])
        self.assertEqual(self.pdp("officer"), "allow")                       # seed A
        self.assertEqual(self.pdp("clodia"), "gate")                         # seed B
        self.assertEqual(self.pdp("officer", "https://other.example.org/y"), "gate")
        self.assertEqual(self.pdp("officer", scope="SEAL-1/acquisti"), "gate")
        self.assertEqual(self.pdp("officer", scope=None), "gate")
        # A·V·R·Q in the room agrees: the seed's call is allowed, not another's.
        self.room_rules("vendite", self.svc._read_meta("SEAL-1", "vendite")[0]["authz"]
                        + [ROOM_ASK])
        self.assertEqual(self.effect("officer").effect, A.ALLOW)
        self.assertEqual(self.effect("clodia").effect, A.ASK)

    def test_a_seed_everywhere(self):
        G.remember(self.KEY, agent="officer", scope="", by="admin")
        for scope in (None, "SEAL-1/vendite", "SEAL-1/acquisti"):
            self.assertEqual(self.pdp("officer", scope=scope), "allow", scope)
        self.assertEqual(self.pdp("clodia", scope=None), "gate")
        self.assertEqual(self.pdp("officer", "https://other.example.org/y", scope=None), "gate")

    def test_the_pdp_honours_only_rules_a_gate_wrote(self):
        """A migrated per-agent allow (or a `*` clause) is not a gate's seed
        rule: the PDP keeps its lists for those."""
        self.global_rules([{"id": "plan-1", "agent": "officer", "verb": "web.post",
                            "resource": "*", "rule": [{"effect": "allow", "match": TARGET}]},
                           {"id": "gate-x", "agent": "officer", "verb": "web.post",
                            "resource": "*", "rule": [{"effect": "allow", "match": "*"}]}])
        self.assertEqual(self.pdp("officer", scope=None), "gate")

    def test_a_global_deny_still_wins(self):
        G.remember(self.KEY, agent="officer", scope="", by="admin")
        doc = json.loads(self.global_path.read_text())
        # A deny for the same seed: as specific as the gate's allow, so deny wins
        # (§4: a `*` deny loses to a named agent's allow at the same level).
        doc["tuples"].append({"id": "g-deny", "agent": "officer", "verb": "web.post",
                              "resource": "*", "rule": [{"effect": "deny", "match": TARGET}]})
        self.global_rules(doc["tuples"])
        self.assertEqual(self.pdp("officer", scope=None), "gate")

    def test_an_approval_for_one_seed_is_not_a_list_entry(self):
        """The PDP's gate used to remember the address in the room's list for
        EVERY agent after any approval. «Solo questo spawn» / «questo seed»
        must not."""
        from . import main
        verdict = {"checked": True, "allowed": False, "action": "gate", "type": "http",
                   "gate_key": self.KEY, "remember": [TARGET], "verb": "web.post",
                   "destinations": [TARGET], "mode": "gate"}
        for who, remembered in (("spawn", False), ("seed", False), ("all", True), (None, True)):
            with self.subTest(who=who):
                with patch.object(egress, "check", return_value=verdict), \
                        patch.object(egress, "remember") as rem, \
                        patch.object(main, "_require_gate_consent",
                                     AsyncMock(return_value={"who": who} if who else {})), \
                        patch.object(main, "_is_super", lambda a: True), \
                        patch.object(main.web_post if hasattr(main, "web_post") else main,
                                     "post", lambda *a, **k: {"ok": 1}, create=True), \
                        ClaimsContext({"agent": "clodia", "execution_id": "clodia-1",
                                       "principal": "davide",
                                       "chat": "chan:SEAL-1:vendite:clodia"}, "t"):
                    asyncio.run(main.call_tool("web.post", {"url": URL, "body": "x"}))
                self.assertEqual(rem.called, remembered)


class ShadowedTests(_Env):
    """«Chiedi batte consenti»: a room cell whose allow would lose to an
    explicit ask of the room is offered disabled, never written dead."""

    def test_an_explicit_ask_for_the_seed_disables_the_room_cells(self):
        self.room_rules("vendite", [ROOM_ASK, {
            "id": "t-officer", "agent": "officer", "verb": "web.post", "resource": "*",
            "rule": [{"effect": "ask", "match": TARGET}]}])
        key = f"authz:web.post|{TARGET}"
        c = G.cells(key, "officer", "SEAL-1/vendite")
        self.assertIn("non avrebbe effetto", c["seed:chat"])
        self.assertEqual(c["all:chat"], "")       # officer's ask does not cover the others
        with self.assertRaises(G.RememberError):
            G.remember(key, agent="officer", scope="SEAL-1/vendite")

    def test_a_global_deny_disables_the_global_cell(self):
        self.global_rules([{"id": "g-deny", "agent": "officer", "verb": "web.post",
                            "resource": "*", "rule": [{"effect": "deny", "match": TARGET}]}])
        c = G.cells("egress:http:https://api.example.com/", "officer", "SEAL-1/vendite")
        self.assertIn("non avrebbe effetto", c["seed:global"])


class RulesPanelTests(_Env):
    def test_list_and_remove_room_and_global_rules(self):
        self.room_rules("vendite", [ROOM_ASK])
        key = R.gate_key(self.effect("officer"), "web.post")
        G.remember(key, agent="officer", scope="SEAL-1/vendite", by="davide")
        rows = G.list_room("SEAL-1/vendite")
        mine = [r for r in rows if r["origin"] == "gate"]
        self.assertEqual((mine[0]["agent"], mine[0]["by"]), ("officer", "davide"))
        self.assertIn("t-ask", [r["id"] for r in rows])          # every explicit rule
        self.assertTrue(G.remove_room("SEAL-1/vendite", mine[0]["id"], by="davide"))
        self.assertEqual(self.effect("officer").effect, A.ASK)   # cache invalidated
        self.assertFalse(G.remove_room("SEAL-1/vendite", mine[0]["id"]))
        G.remember("egress:http:https://api.example.com/", agent="officer", scope="")
        rows = G.list_global()
        self.assertTrue(rows and all(r["origin"] == "gate" and r["agent"] == "officer"
                                     for r in rows))
        for r in rows:
            self.assertTrue(G.remove_global(r["id"]))
        self.assertEqual(G.list_global(), [])


if __name__ == "__main__":
    unittest.main()


class RulesRoutesTests(_Env):
    def test_room_routes_list_and_remove(self):
        from types import SimpleNamespace as NS
        from . import topics_api
        self.room_rules("vendite", [ROOM_ASK])

        class Req:
            def __init__(self, method, body=None):
                self.method = method
                self.path_params = {"tier": "SEAL-1", "name": "vendite"}
                self._b = body or {}
                self.state = NS(auth_payload={})

            async def json(self):
                return self._b

        with patch.object(topics_api, "_authorize", lambda r: ("agent-server", None)):
            r = asyncio.run(topics_api.room_rules_route(Req("GET")))
            self.assertEqual([x["id"] for x in json.loads(r.body)["rules"]], ["t-ask"])
            r = asyncio.run(topics_api.room_rules_route(Req("DELETE", {"id": "t-ask"})))
            self.assertTrue(json.loads(r.body)["removed"])
            r = asyncio.run(topics_api.room_rules_route(Req("GET")))
            self.assertEqual(json.loads(r.body)["rules"], [])
            # The global list is an admin's: a plain caller is refused.
            r = asyncio.run(topics_api.global_rules_route(Req("GET")))
            self.assertEqual(r.status_code, 403)

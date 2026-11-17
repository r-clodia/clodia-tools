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

from . import authz as A
from . import authz_runtime as R
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

    def test_a_destination_of_the_lists_is_for_every_agent(self):
        c = G.cells("egress:http:https://api.example.com/")
        self.assertEqual((c["all:chat"], c["all:global"]), ("", ""))
        self.assertTrue(c["seed:chat"] and c["seed:global"])

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
    def test_every_agent_goes_to_the_room_list(self):
        with patch("server.egress.scope_allow", return_value={"added": True}) as sa:
            out = G.remember("egress:http:https://api.example.com/", agent="*",
                             scope="SEAL-1/vendite")
        sa.assert_called_once_with("egress", "SEAL-1/vendite", "https://api.example.com/")
        self.assertEqual(out["kind"], "list")

    def test_a_seed_is_refused(self):
        with self.assertRaises(G.RememberError):
            G.remember("egress:http:https://api.example.com/", agent="officer",
                       scope="SEAL-1/vendite")


if __name__ == "__main__":
    unittest.main()

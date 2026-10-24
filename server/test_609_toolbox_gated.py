"""#609 R5 — the panel must say WHICH of the verbs it offers stay gated.

Decision 3 of the epic #604 is «included ≠ ungated»: a verb enabled in a room
still asks for confirmation. The owner reads that sentence where the verb is
enabled, or discovers it at the first card.

The one invariant worth a test: what the panel offers (`enablable`) and what it
marks (`gated`) are DERIVED FROM THE SAME PLACE — the gate. A second list,
compiled by hand here or in the webui, is what goes stale the day a verb enters
`gate._DEFAULT_GATED_EXACT`.
"""
from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from . import gate, main, room_tools as rt, topics_api
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicService


class GatedMarkingTests(unittest.TestCase):
    def test_marked_is_exactly_what_the_gate_says_of_what_is_offered(self):
        offered = {v for verbs in rt.enablable().values() for v in verbs}
        self.assertEqual(set(rt.gated()),
                         {v for v in offered if gate.is_gated(v)})

    def test_a_verb_that_will_ask_is_marked_and_a_quiet_one_is_not(self):
        marked = set(rt.gated())
        self.assertIn("web.post", marked)
        self.assertNotIn("web.fetch", marked)

    def test_a_backend_that_does_not_name_its_verbs_adds_nothing(self):
        """A mounted MCP backend (and a packaged connector whose component is
        not loaded) appears with an EMPTY verb set: the panel offers `ns.*` and
        this list has nothing to say about it. It must not guess."""
        with patch.object(rt, "_catalogue",
                          lambda: {"web": {"web.fetch", "web.post"}, "cartografo": set()}):
            self.assertEqual(rt.gated(), ["web.post"])

    def test_nothing_is_marked_that_the_panel_cannot_offer(self):
        """`jobs.set_enabled` is gated and is NOT enablable: marking it would
        show the owner a verb they cannot enable from here."""
        self.assertTrue(gate.is_gated("jobs.set_enabled"))
        self.assertNotIn("jobs.set_enabled", rt.gated())

    def test_the_list_follows_the_gate_and_is_not_a_copy_of_it(self):
        with patch.object(gate, "_configured", lambda: ((), frozenset({"web.fetch"}))):
            self.assertEqual(rt.gated(), ["web.fetch"])


class RouteTests(unittest.TestCase):
    """Both doors of the panel carry the marking: the room's toolbox and the
    DM one are edited in two different screens, and `enablable` travels on
    both."""

    def setUp(self):
        self.svc = TopicService(LocalFsStorage(tempfile.mkdtemp(prefix="topics-")))
        for p in (patch.object(rt, "_svc", lambda: self.svc),
                  patch.object(main, "_topics", lambda: self.svc),
                  patch.object(topics_api, "_service", lambda: self.svc)):
            p.start()
            self.addCleanup(p.stop)
        self.svc.new("SEAL-1", "blog", {"owner": "davide", "participants": ["davide"]})

    def _client(self):
        from starlette.applications import Starlette
        from starlette.testclient import TestClient
        payload = {"principal": "davide", "on_behalf": True, "human_role": "admin"}

        def fake_authorize(request):
            request.state.auth_payload = payload
            return "davide", None
        p = patch.object(topics_api, "_authorize", fake_authorize)
        p.start()
        self.addCleanup(p.stop)
        return TestClient(Starlette(routes=topics_api.routes))

    def test_the_room_panel_receives_the_marking(self):
        body = self._client().get("/internal/topics/SEAL-1/blog/tools").json()
        self.assertEqual(body["gated"], rt.gated())
        self.assertIn("web.post", body["gated"])

    def test_the_dm_panel_receives_the_marking(self):
        body = self._client().get("/internal/dm-tools").json()
        self.assertEqual(body["gated"], rt.gated())


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

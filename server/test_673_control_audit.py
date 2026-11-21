"""clodia-platform#673 — data catalogue and room data changes reach the audit trail.

Both routes passed `kind=` (and the room route `resource=`) to
`control.emit(kind, action, resource, **details)`: the call raised
`TypeError`, `control.safe` logged «not recorded», and every catalogue change
(tier, importers, sync, retire) and room import/removal was missing.
"""
from __future__ import annotations

import ast
import unittest
from pathlib import Path
from unittest.mock import patch

from . import whitelist
from .audit import control


class _Recorder:
    def __init__(self):
        self.events = []

    def __call__(self, event_type, **fields):
        self.events.append((event_type, fields))


class EmitTests(unittest.TestCase):
    def test_details_may_share_the_names_of_the_event(self):
        rec = _Recorder()
        with patch("server.audit.emit", rec):
            control.emit("x", "update", "r", kind="rag", action="a", resource="b")
        self.assertEqual(rec.events, [("control.x", {
            "action": "update", "resource": "r",
            "result": {"kind": "rag", "action": "a", "resource": "b"}})])

    def test_no_caller_passes_the_events_names_as_keywords(self):
        """Statically: the positional-only names would now land in `result`
        under a confusing key. Callers say `resource_kind`, not `kind`."""
        root = Path(__file__).parent
        found = []
        for p in root.rglob("*.py"):
            if p.name.startswith("test_"):
                continue
            for n in ast.walk(ast.parse(p.read_text())):
                if not isinstance(n, ast.Call):
                    continue
                f = n.func
                target = n.args[0] if getattr(f, "attr", "") == "safe" and n.args else f
                if getattr(target, "attr", "") != "emit" or \
                        getattr(getattr(target, "value", None), "id", "") not in ("control", "_control"):
                    continue
                found += [f"{p.relative_to(root)}:{n.lineno} {k.arg}" for k in n.keywords
                          if k.arg in ("kind", "action", "resource")]
        self.assertEqual(found, [])


class RoutesAuditTests(unittest.TestCase):
    def _client(self, payload):
        from starlette.applications import Starlette
        from starlette.testclient import TestClient
        from . import topics_api

        def fake_authorize(request):
            request.state.auth_payload = payload
            return payload.get("principal") or payload.get("agent"), None
        self.addCleanup(patch.stopall)
        patch.object(topics_api, "_authorize", fake_authorize).start()
        patch.object(whitelist, "CONFIG", {}).start()
        self.rec = _Recorder()
        patch("server.audit.emit", self.rec).start()
        return TestClient(Starlette(routes=topics_api.routes))

    def test_a_catalogue_update_is_recorded(self):
        from . import data_catalog
        c = self._client({"agent": "clodia", "role": "agent-server"})
        patch.object(data_catalog, "update", lambda *a, **k: {"ok": True}).start()
        r = c.post("/internal/data-catalog", json={
            "action": "update", "kind": "rag", "resource": "eu-normativa", "tier": "SEAL-1"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.rec.events, [("control.data_catalog", {
            "action": "update", "resource": "eu-normativa",
            "result": {"resource_kind": "rag", "tier": "SEAL-1"}})])

    def test_a_room_import_is_recorded(self):
        from . import topics_api, topic_data
        c = self._client({"principal": "davide", "on_behalf": True, "human_role": "admin"})
        patch.object(topics_api, "_authorize_topic_owner", lambda r: ("davide", None)).start()
        patch.object(topic_data, "import_resource", lambda *a, **k: {"ok": True}).start()
        r = c.post("/internal/topics/SEAL-1/x/data", json={
            "action": "import", "kind": "rag", "resource": "c", "by": "davide"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.rec.events, [("control.topic_data", {
            "action": "import", "resource": "SEAL-1/x",
            "result": {"resource_kind": "rag", "data_resource": "c", "by": "davide"}})])


if __name__ == "__main__":
    unittest.main()

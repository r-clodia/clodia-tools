"""Every gateway call to the agent-server carries the paired secret (#705).

Since clodia-platform#705 the agent-server answers only a signed caller: a
session token, or the secret shared with the paired gateway. `runtime.*`,
`jobs.*` and `agents.*` proxies used to call it with no header at all
(`/api/agents`, `/clodia/jobs`, `restart-agent`, `inspect-topic`, the
`*/internal` job routes…): each would now be a 401.
"""
from __future__ import annotations

import os
import unittest
from unittest import mock

from .tools import agents_admin, runtime

SECRET = "s3cret-for-tests"


class _Resp:
    status_code = 200
    content = b"{}"
    text = "{}"
    is_success = True

    def json(self):
        return {"agents": [], "ok": True}


class _Client:
    calls: list = []

    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def get(self, url, headers=None, **k):
        _Client.calls.append(("GET", url, dict(headers or {})))
        return _Resp()

    def post(self, url, json=None, headers=None, **k):
        _Client.calls.append(("POST", url, dict(headers or {})))
        return _Resp()


class PairedSecretTests(unittest.TestCase):
    def setUp(self):
        _Client.calls = []
        for p in (mock.patch.dict(os.environ, {"CLODIA_ORCHESTRATOR_SECRET": SECRET}),
                  mock.patch.object(runtime.httpx, "Client", _Client),
                  mock.patch.object(agents_admin.httpx, "Client", _Client),
                  mock.patch.object(runtime, "raise_for_backend_error", lambda *a, **k: None),
                  mock.patch.object(runtime.whitelist, "current_token", return_value=None),
                  mock.patch.object(agents_admin.whitelist, "current_token",
                                    return_value=None)):
            p.start()
            self.addCleanup(p.stop)

    def _headers_of(self, fn):
        _Client.calls = []
        try:
            fn()
        except Exception:  # noqa: BLE001 — the shape of the answer is not under test
            pass
        self.assertTrue(_Client.calls, "no call made")
        return _Client.calls[-1][2]

    def test_every_proxy_sends_the_secret(self):
        for fn in (lambda: runtime._get("/api/agents"),
                   lambda: runtime.restart_agent("clodia"),
                   lambda: runtime.inspect_topic("SEAL-1", "t", "sysadmin"),
                   lambda: runtime.set_participant("SEAL-1", "t", "x", "clodia", True),
                   lambda: runtime.job_scope(3),
                   lambda: runtime.jobs(),
                   lambda: runtime.set_job_enabled(3, False, by="sysadmin"),
                   lambda: runtime.report_run_status(chat_id="c", status="success"),
                   lambda: runtime.note_run_refusal(chat_id="c", verb="v"),
                   lambda: runtime.suggest_team("SEAL-1", "x"),
                   lambda: agents_admin._get("/api/agents")):
            self.assertEqual(self._headers_of(fn).get("X-Orchestrator-Secret"), SECRET)

    def test_the_callers_token_still_travels_where_it_did(self):
        with mock.patch.object(runtime.whitelist, "current_token", return_value="ckt1.x"):
            h = self._headers_of(lambda: runtime.channel_trigger("SEAL-1", "t", "hi", "clodia"))
        self.assertEqual(h.get("Authorization"), "Bearer ckt1.x")
        self.assertEqual(h.get("X-Orchestrator-Secret"), SECRET)

    def test_no_secret_configured_no_header(self):
        with mock.patch.dict(os.environ, {"CLODIA_ORCHESTRATOR_SECRET": ""}):
            h = self._headers_of(lambda: runtime._get("/api/agents"))
        self.assertNotIn("X-Orchestrator-Secret", h)


if __name__ == "__main__":
    unittest.main()

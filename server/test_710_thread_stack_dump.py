"""Thread stack dump of the gateway, on demand and during a stall
(clodia-platform#710).

What is checked: the dump names the threads and their frames (including the
code that holds a blocked loop, sampled DURING the block); the route is
refused to agent tokens, the bare carrier and non-admin persons; every string
is redacted; SIGUSR1 writes the stacks to the state dir; `runtime.health`
carries the stall block for admins only.
"""
from __future__ import annotations

import asyncio
import json
import os
import signal
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from starlette.applications import Starlette
from starlette.testclient import TestClient

from . import internal_auth, stackdump, stackdump_api
from .pki_mint import ROLE_AGENT_SERVER

_H = {"Authorization": "Bearer ckt1.fake"}
_SERVICE = {"agent": "clodia", "role": ROLE_AGENT_SERVER}
_ADMIN = {"agent": "clodia", "principal": "davide", "principal_kind": "human",
          "on_behalf": True, "human_role": "admin"}
_MEMBER = {"agent": "clodia", "principal": "mario", "principal_kind": "human",
           "on_behalf": True, "human_role": "user"}
_CARRIER = {"agent": "clodia"}                 # the bare carrier token
_SPAWN = {"agent": "ophelia", "execution_id": "turn-1"}   # an agent's token

#: Secrets and a topic name, in the places a dump picks strings up from. The
#: fake token is assembled at runtime so the secret scanner of the repository
#: does not flag a literal.
_FAKE_PAT = "ghp" + "_" + "abcdefghij" + "1234567890"
_THREAD_NAME = f"worker token={_FAKE_PAT} SEAL-3/dossier-segreto"


def _session(payload: dict):
    return patch.object(internal_auth, "verify_session_token", lambda _t: payload)


def _parked_in_named_function(ev: threading.Event) -> None:
    ev.wait(30)  # password=hunter2-in-source mailto:someone@example.org


class _ParkedThread:
    def __enter__(self):
        self.ev = threading.Event()
        self.t = threading.Thread(target=_parked_in_named_function, args=(self.ev,),
                                  name=_THREAD_NAME, daemon=True)
        self.t.start()
        time.sleep(0.05)
        return self

    def __exit__(self, *a):
        self.ev.set()
        self.t.join(5)
        return False


class RouteTests(unittest.TestCase):
    def setUp(self) -> None:
        stackdump.reset()
        self.client = TestClient(Starlette(routes=stackdump_api.routes))

    def get(self, payload: dict | None):
        if payload is None:
            return self.client.get("/internal/diagnostics/stacks")
        with _session(payload):
            return self.client.get("/internal/diagnostics/stacks", headers=_H)

    def test_the_dump_names_threads_and_frames(self) -> None:
        with _ParkedThread():
            r = self.get(_SERVICE)
        self.assertEqual(200, r.status_code, r.text)
        data = r.json()
        names = [t["name"] for t in data["threads"]]
        self.assertTrue(any(n.startswith("worker") for n in names), names)
        self.assertIn("MainThread", names)
        parked = next(t for t in data["threads"] if t["name"].startswith("worker"))
        funcs = [f["func"] for f in parked["frames"]]
        self.assertIn("_parked_in_named_function", funcs)
        self.assertTrue(parked["idle"])        # waiting in Event.wait = parked
        frame = next(f for f in parked["frames"]
                     if f["func"] == "_parked_in_named_function")
        self.assertEqual("server/test_710_thread_stack_dump.py", frame["file"])
        self.assertIn("ev.wait(30)", frame["code"])
        # The asyncio tasks of the loop serving the request: at least this one.
        self.assertTrue(data["tasks"], data["tasks"])
        for key in ("inflight", "offload_pool", "last_stall", "signal_dump", "pid"):
            self.assertIn(key, data)

    def test_an_admin_person_may_read_it(self) -> None:
        self.assertEqual(200, self.get(_ADMIN).status_code)

    def test_refused_to_agents_the_carrier_and_members(self) -> None:
        for who, payload in (("spawn", _SPAWN), ("carrier", _CARRIER),
                             ("member", _MEMBER)):
            with self.subTest(who=who):
                r = self.get(payload)
                self.assertEqual(403, r.status_code, r.text)
                self.assertNotIn("threads", r.text)
        self.assertEqual(401, self.get(None).status_code)

    def test_a_scoped_token_is_refused_even_with_the_role_shape(self) -> None:
        r = self.get({**_CARRIER, "scoped_tools": ["topic.messages"]})
        self.assertEqual(403, r.status_code)

    def test_the_dump_is_redacted(self) -> None:
        with _ParkedThread():
            r = self.get(_SERVICE)
        text = r.text
        for leak in (_FAKE_PAT, "hunter2-in-source",
                     "someone@example.org", "dossier-segreto"):
            self.assertNotIn(leak, text)
        parked = next(t for t in r.json()["threads"] if t["name"].startswith("worker"))
        self.assertIn("SEAL-3/•••", parked["name"])     # the tier stays readable
        # No host path prefix of the interpreter in a frame.
        self.assertNotIn("/lib/python", text)


class StallSamplerTests(unittest.TestCase):
    def setUp(self) -> None:
        stackdump.reset()
        self.addCleanup(stackdump.reset)

    def test_the_stacks_are_sampled_while_the_loop_is_blocked(self) -> None:
        """A real loop blocked by a synchronous call: the sampler thread sees
        the blocking function on the loop thread, during the block."""
        def _hog_the_loop() -> None:
            time.sleep(1.2)

        async def main() -> None:
            stackdump.heartbeat()
            _hog_the_loop()

        sampler = stackdump.StallSampler(threshold_s=0.3, repeat_s=0, poll_s=0.05).start()
        self.addCleanup(sampler.stop)
        with self.assertLogs("clodia-tools.stacks", "WARNING") as logs:
            t = threading.Thread(target=lambda: asyncio.run(main()), name="loop-under-test")
            t.start()
            t.join(10)
        stall = stackdump.last_stall()
        self.assertIsNotNone(stall)
        self.assertGreaterEqual(stall["blocked_s"], 0.3)
        loop = [th for th in stall["threads"] if th["loop"]]
        self.assertEqual(1, len(loop), stall)
        self.assertEqual("loop-under-test", loop[0]["name"])
        self.assertTrue(any("_hog_the_loop" in f for f in loop[0]["frames"]), loop)
        self.assertIn("_hog_the_loop", "\n".join(logs.output))
        self.assertIn("(loop)", "\n".join(logs.output))

    def test_one_sample_per_stall_and_rate_limited(self) -> None:
        stackdump.heartbeat()
        beat = stackdump._BEAT
        s = stackdump.StallSampler(threshold_s=10, repeat_s=120)
        self.assertIsNone(s.check(now=beat + 5))            # under the threshold
        with self.assertLogs("clodia-tools.stacks", "WARNING"):
            self.assertIsNotNone(s.check(now=beat + 11))
        self.assertIsNone(s.check(now=beat + 12))           # same stall
        stackdump.heartbeat()                               # a new stall soon after
        self.assertIsNone(s.check(now=stackdump._BEAT + 11))   # rate-limited

    def test_no_heartbeat_no_sample(self) -> None:
        self.assertIsNone(stackdump.StallSampler(threshold_s=0.1).check())

    def test_the_compact_sample_is_redacted(self) -> None:
        stackdump.heartbeat()
        with _ParkedThread(), self.assertLogs("clodia-tools.stacks", "WARNING") as logs:
            stackdump.sample_stall(12.0)
        text = json.dumps(stackdump.last_stall()) + "\n".join(logs.output)
        self.assertNotIn(_FAKE_PAT, text)
        self.assertNotIn("dossier-segreto", text)

    def test_the_watchdog_beats_the_heartbeat(self) -> None:
        from . import inflight

        async def main() -> None:
            task = asyncio.create_task(inflight.watch(interval=0.01))
            await asyncio.sleep(0.05)
            task.cancel()

        asyncio.run(main())
        self.assertGreater(stackdump._BEAT, 0)


@unittest.skipUnless(hasattr(signal, "SIGUSR1"), "no SIGUSR1 on this platform")
class SignalDumpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(stackdump.uninstall_signal_dump)

    def test_sigusr1_writes_every_thread_to_the_state_dir(self) -> None:
        with patch.dict(os.environ, {"CLODIA_TOOLS_STATE_DIR": self.tmp.name}):
            path = stackdump.install_signal_dump()
        self.assertEqual(Path(self.tmp.name) / "diagnostics" / "thread-stacks.txt", path)
        self.assertEqual(0o600, path.stat().st_mode & 0o777)
        with _ParkedThread():
            os.kill(os.getpid(), signal.SIGUSR1)
            time.sleep(0.2)
        text = path.read_text()
        self.assertIn("_parked_in_named_function", text)
        self.assertIn("Thread 0x", text)
        tail = stackdump.signal_dump_tail()
        self.assertTrue(tail["installed"])
        self.assertTrue(any("_parked_in_named_function" in line for line in tail["lines"]))
        self.assertEqual([], stackdump.signal_dump_tail(lines=0)["lines"])

    def test_an_unwritable_dir_does_not_raise(self) -> None:
        blocker = Path(self.tmp.name) / "file"
        blocker.write_text("x")
        with self.assertLogs("clodia-tools.stacks", "WARNING"):
            self.assertIsNone(stackdump.install_signal_dump(blocker / "sub" / "f.txt"))


class HealthTests(unittest.TestCase):
    def setUp(self) -> None:
        from .tools import health
        self.health = health
        health.reset_cache()
        self.addCleanup(health.reset_cache)
        stackdump.reset()
        self.addCleanup(stackdump.reset)
        for name, value in (("_agent_server", {"ok": True}),
                            ("_courier", {"ok": True}),
                            ("_gateway_errors", {"count": 0, "lines": []})):
            p = patch.object(health, name, lambda v=value: v)
            p.start()
            self.addCleanup(p.stop)

    def run_health(self, admin: bool) -> dict:
        with patch.object(self.health, "_admin_reader", lambda: admin):
            return asyncio.run(self.health.health(backends=False))

    def test_admins_see_the_last_stall(self) -> None:
        stackdump.heartbeat()
        with self.assertLogs("clodia-tools.stacks", "WARNING"):
            stackdump.sample_stall(31.0)
        out = self.run_health(admin=True)
        self.assertEqual(31.0, out["stalls"]["last_stall"]["blocked_s"])
        self.assertIn("signal_dump", out["stalls"])

    def test_others_do_not_and_do_not_share_the_admin_cache(self) -> None:
        self.run_health(admin=True)
        self.assertNotIn("stalls", self.run_health(admin=False))


if __name__ == "__main__":
    unittest.main()

"""#704 — no tool sysadmin can reach returns what someone wrote.

sysadmin's charter is «never the contents» (epic #701). Before #704 it was a
prompt rule: `runtime.inspect_topic` returned a room's latest 40 messages to a
non-participant, and `logs.tail` returned the agent-server log with the first
80 characters of every prompt (`turno START <chat>: …`). These tests make it a
property: each content-carrying input is planted with a marker, and the
marker must not come out of any verb of the role.
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import authz_roles, whitelist
from .tools import health, logs, runtime

#: The text someone wrote. It must never come out.
SECRET = "il bilancio di Rossi chiude in perdita"


class _Datadir:
    def __enter__(self):
        self.d = tempfile.TemporaryDirectory()
        self.p = patch.dict(os.environ, {"CLODIA_DATA": self.d.name})
        self.p.start()
        (Path(self.d.name) / "logs").mkdir(parents=True, exist_ok=True)
        return self

    def __exit__(self, *a):
        self.p.stop()
        self.d.cleanup()
        return False

    def write(self, name: str, *lines: str) -> None:
        (Path(self.d.name) / "logs" / name).write_text("\n".join(lines) + "\n",
                                                       encoding="utf-8")


#: The lines a pre-#704 agent-server writes, plus the narrative-mention one.
AGENT_SERVER_LINES = (
    f"2026-11-18 10:00:00,001 INFO agent-server.sdk_runtime.session: "
    f"turno START chan:SEAL-1:fatture:clodia: {SECRET}",
    f"2026-11-18 10:00:01,001 INFO agent-server.sdk_runtime.session: "
    f"turno START 20261118-dm: {SECRET}",
    f"2026-11-18 10:00:02,001 WARNING agent-server.api.channels: delega da clodia "
    f"su SEAL-1/fatture: @officer convocato da una menzione che sembra narrativa "
    f"('{SECRET} @officer'): turno avviato comunque, ma la forma giusta per un "
    f"resoconto è il nome senza @ (#336)",
    "2026-11-18 10:00:03,001 INFO agent-server.sdk_runtime.session: "
    "turno START chan:SEAL-1:fatture:clodia (37 chars)",
)


class InspectTopicTests(unittest.TestCase):
    def _call(self, answer):
        seen = {}

        def fake_post(path, payload, **kw):
            seen.update(path=path, payload=payload, **kw)
            return answer
        with patch.object(runtime, "_post", fake_post):
            return runtime.inspect_topic("SEAL-1", "fatture", by="sysadmin"), seen

    def test_an_older_agent_server_answer_is_stripped_of_messages(self):
        """The agent-server before #704 returned `messages` with their text:
        the gateway's whitelist strips them, so the deploy order cannot leak."""
        out, seen = self._call({
            "ok": True, "tier": "SEAL-1", "name": "fatture",
            "meta": {"title": "Fatture", "status": "active", "owner": "davide",
                     "participants": ["davide", "clodia"], "agents": ["clodia"],
                     "summary": SECRET},
            "messages": [{"author": "davide", "kind": "human", "text": SECRET,
                          "ts": "2026-11-18T10:00:00Z"}],
            "message_count": 1})
        blob = json.dumps(out, ensure_ascii=False)
        self.assertNotIn(SECRET, blob)
        self.assertNotIn("messages", out)
        self.assertEqual(out["meta"]["participants"], ["davide", "clodia"])
        self.assertTrue(seen.get("auth"), "the signed caller must travel (#704)")

    def test_the_metadata_shape_passes(self):
        out, _ = self._call({
            "ok": True, "tier": "SEAL-1", "name": "fatture",
            "meta": {"title": "Fatture", "status": "active", "owner": "davide",
                     "participants": ["davide", "clodia"], "agents": ["clodia"]},
            "counts": {"messages": 12, "messages_window": 12, "human": 7, "agent": 5,
                       "files": 3, "text": SECRET},
            "last_activity": {"last_message_at": "2026-11-18T10:00:00Z",
                              "last_message_author": "davide", "preview": SECRET},
            "toolbox": {"enabled": ["github.clone"], "mcp": ["gdrive"],
                        "resources": [SECRET]},
            "imports": [{"kind": "datastore", "name": "contacts",
                         "grants": {"clodia": "read"}, "rows": [SECRET]}]})
        self.assertNotIn(SECRET, json.dumps(out, ensure_ascii=False))
        self.assertEqual(out["counts"]["messages"], 12)
        self.assertEqual(out["last_activity"]["last_message_author"], "davide")
        self.assertEqual(out["toolbox"], {"enabled": ["github.clone"], "mcp": ["gdrive"]})
        self.assertEqual(out["imports"][0], {"kind": "datastore", "name": "contacts",
                                             "grants": {"clodia": "read"}})


class LogsTailTests(unittest.TestCase):
    def test_no_prompt_or_reply_text_comes_out(self):
        with _Datadir() as d, patch.object(logs, "tool_allowed", lambda *_a, **_k: True):
            d.write("agent-server.log", *AGENT_SERVER_LINES)
            t = whitelist.set_current_clearance("SEAL-1")
            try:
                out = logs.tail(50, source="agent-server")["lines"]
            finally:
                whitelist.reset_current_clearance(t)
        self.assertEqual(len(out), 4)
        for line in out:
            self.assertNotIn(SECRET, line)
        # The technical part stays: who, where, when.
        self.assertIn("turno START chan:SEAL-1:fatture:clodia: [message text withheld]", out[0])
        self.assertIn("turno START 20261118-dm: [message text withheld]", out[1])
        self.assertIn("sembra narrativa ([withheld]): turno avviato", out[2])
        self.assertTrue(out[3].endswith("turno START chan:SEAL-1:fatture:clodia (37 chars)"))

    def test_the_level_filter_still_works_on_redacted_lines(self):
        with _Datadir() as d, patch.object(logs, "tool_allowed", lambda *_a, **_k: True):
            d.write("agent-server.log", *AGENT_SERVER_LINES)
            out = logs.tail(50, level="WARNING", source="agent-server")["lines"]
        self.assertEqual(len(out), 1)
        self.assertNotIn(SECRET, out[0])


class HealthTests(unittest.TestCase):
    def test_health_carries_no_content_and_no_secret(self):
        with _Datadir() as d, \
                patch.object(health, "_agent_server",
                             lambda: {"ok": True, "status": "ok", "version": "6.362.0"}), \
                patch.object(health, "_courier",
                             lambda: {"ok": True, "rows": 3, "tagged": 1, "untagged": 2}), \
                patch("server.proxy._backends", lambda: {}):
            d.write("clodia-tools.log",
                    "2026-11-18 09:00:00 INFO clodia-tools.refmon: avvio",
                    f"2026-11-18 09:00:01 ERROR clodia-tools.refmon: turno START x: {SECRET}",
                    "2026-11-18 09:00:02 CRITICAL clodia-tools.refmon: ISOLAMENTO ASSENTE "
                    "token=fake-credential-value")
            out = asyncio.run(health.health())
        blob = json.dumps(out, ensure_ascii=False)
        self.assertNotIn(SECRET, blob)
        self.assertNotIn("fake-credential-value", blob)
        self.assertEqual(out["gateway_errors"]["count"], 2)
        self.assertEqual(out["courier"], {"ok": True, "rows": 3, "tagged": 1, "untagged": 2})
        self.assertEqual(out["mcp_backends"]["count"], 0)
        self.assertTrue(out["ok"])

    def test_a_failing_backend_is_named_and_its_detail_redacted(self):
        async def fake_test(name):
            if name == "github":
                return {"ok": False, "detail": "401 Bad credentials token=ghp_LEAK"}
            return {"ok": True, "detail": "3 tool", "tools": [{"name": "x.a"}] * 3}
        with patch("server.proxy._backends", lambda: {"github": {}, "drawio": {}}), \
                patch("server.proxy._is_transport", lambda n: False), \
                patch("server.proxy.test_backend", fake_test):
            rows = asyncio.run(health._backends())
        by = {r["name"]: r for r in rows}
        self.assertEqual(by["drawio"], {"name": "drawio", "ok": True, "tools": 3})
        self.assertFalse(by["github"]["ok"])
        self.assertNotIn("ghp_LEAK", by["github"]["detail"])


class RolePlanHasNoContentVerbTests(unittest.TestCase):
    """The role plan built from the REAL catalogue: every verb sysadmin gets
    is one of the verbs above or carries no content."""

    def test_no_role_tool_is_content_bearing(self):
        p = authz_roles.role_plan("sysadmin", github_tools=None)
        verbs = [t["verb"] for t in p["global"]]
        self.assertTrue(verbs)
        for v in verbs:
            self.assertFalse(authz_roles.content_bearing(v), v)
            self.assertFalse(v.startswith(("topic.", "datastore.", "memory.", "web.",
                                           "email.", "channel.")), v)
        for v in ("rag.search", "rag.list", "rag.ingest", "datastore.read",
                  "topic.messages", "topic.read_file"):
            self.assertNotIn(v, verbs)

    def test_every_data_returning_runtime_verb_is_covered_here(self):
        """A runtime verb added tomorrow enters the role by namespace: this
        list must then be extended with a test that it returns no content."""
        checked = {"runtime.inspect_topic", "runtime.health", "runtime.agents",
                   "runtime.jobs", "runtime.skills", "runtime.chats", "runtime.topics",
                   "runtime.mcp_servers", "runtime.providers", "runtime.current_user",
                   "runtime.room_tools", "runtime.restart_agent",
                   "runtime.room_authorize_mcp", "runtime.room_resource"}
        p = authz_roles.role_plan("sysadmin", github_tools=None)
        runtime_verbs = {t["verb"] for t in p["global"] if t["verb"].startswith("runtime.")}
        self.assertEqual(runtime_verbs - checked, set(),
                         "new runtime verb in sysadmin's role: prove it returns no content")


if __name__ == "__main__":
    unittest.main()


class SecretRedactionTests(unittest.TestCase):
    """#703 review: the shapes credentials take in a log line."""

    CASES = (
        "Authorization: Bearer eyJhbGciOi.abc-def",
        '{"access_token": "ya29.A0Afake", "refresh_token":"1//0fake"}',
        "client_secret=shh-fake-value next",
        "oauth: id_token=abc123fake",
        "x-api-key: 12345fake",
        'password = "hunter2fake"',
        "ghp_ABCDEFGH12345678 and github_pat_11AAAAAA_bbbbbbbbcc",
        "sk-ant-abcdefgh12345 sk-proj-abcdefgh12345 ckt1.eyJfake.sigfake",
    )
    LEAKS = ("eyJhbGciOi", "ya29", "1//0fake", "shh-fake", "abc123fake", "12345fake",
             "hunter2fake", "ghp_ABCDEFGH", "github_pat_11", "sk-ant-abc",
             "sk-proj-abc", "ckt1.eyJ")

    def test_no_credential_survives(self):
        for line in self.CASES:
            out = logs.redact_secrets(line)
            for leak in self.LEAKS:
                self.assertNotIn(leak, out, f"{line!r} → {out!r}")

    def test_egress_destinations_lose_query_and_mailbox(self):
        out = logs.redact_secrets(
            "egress web.fetch → https://api.example.com/v1/items?key=abc&user=42 "
            "email.send → mailto:anna.rossi@foo.bar cc bob@example.org")
        self.assertIn("https://api.example.com/v1/items?•••", out)
        self.assertNotIn("user=42", out)
        self.assertIn("mailto:•••", out)
        self.assertNotIn("anna.rossi", out)
        self.assertIn("•••@example.org", out)

    def test_ordinary_words_are_left_alone(self):
        line = ("compartimento spawn · clodia tocca SEAL-1/blog (topic.read_file) "
                "da chan:SEAL-1:blog:clodia: monkey=banana keyboard: 3")
        self.assertEqual(logs.redact_secrets(line), line)


class HealthCacheTests(unittest.TestCase):
    def setUp(self):
        health.reset_cache()
        self.addCleanup(health.reset_cache)

    def test_concurrent_calls_share_one_run_and_later_ones_hit_the_cache(self):
        runs = []

        async def slow_run(*, backends=True):
            runs.append(1)
            await asyncio.sleep(0.05)
            return {"ok": True}

        async def go():
            with patch.object(health, "_run", slow_run):
                first = await asyncio.gather(*(health.health() for _ in range(5)))
                again = await health.health()
            return first, again
        first, again = asyncio.run(go())
        self.assertEqual(len(runs), 1)
        self.assertTrue(all(r == {"ok": True} for r in first))
        self.assertIn("cached_age_s", again)

    def test_the_cache_expires(self):
        runs = []

        async def run(*, backends=True):
            runs.append(1)
            return {"ok": True}
        with patch.object(health, "_run", run), patch.object(health, "CACHE_TTL_S", 0.0):
            asyncio.run(health.health())
            asyncio.run(health.health())
        self.assertEqual(len(runs), 2)


class DmGovernsRoomsTests(unittest.TestCase):
    """#701 widget: from an admin's DM, runtime.room_* names the room."""

    def setUp(self):
        from . import main
        from .topics.local_fs import LocalFsStorage
        from .topics.service import TopicService
        self.main = main
        self.svc = TopicService(LocalFsStorage(tempfile.mkdtemp(prefix="dm704-")))
        p = patch.object(main, "_topics", lambda: self.svc)
        p.start(); self.addCleanup(p.stop)
        self.svc.new("SEAL-0", "dm-davide--sysadmin", {"owner": "davide", "kind": "dm",
                                                       "participants": ["davide", "sysadmin"]})
        self.svc.new("SEAL-1", "blog", {"owner": "davide"})

    def _target(self, scope, args, admin):
        from . import authz_runtime
        with patch("server.egress._scope_of_call", lambda: scope), \
                patch.object(authz_runtime, "role_principal_ok", lambda: admin):
            return self.main._room_target(args)

    def test_an_admin_dm_acts_on_the_named_room_as_from_outside(self):
        out = self._target("SEAL-0/dm-davide--sysadmin",
                           {"tier": "SEAL-1", "name": "blog"}, admin=True)
        self.assertEqual(out, ("SEAL-1", "blog", False))   # False → admin card

    def test_a_non_admin_dm_stays_pinned(self):
        with self.assertRaises(PermissionError):
            self._target("SEAL-0/dm-davide--sysadmin",
                         {"tier": "SEAL-1", "name": "blog"}, admin=False)

    def test_a_room_stays_pinned_even_for_an_admin(self):
        with self.assertRaises(PermissionError):
            self._target("SEAL-1/blog", {"tier": "SEAL-0", "name": "dm-davide--sysadmin"},
                         admin=True)

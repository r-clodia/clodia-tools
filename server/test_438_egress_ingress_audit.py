"""clodia-platform#438 — what crossed the perimeter, where to, under which rule.

`flow.egress` is emitted only when data actually left (the verb succeeded after
the egress check), with the destinations, the rule and list that admitted each
one, and the hash and size of every file that went with it — never its name or
content. `flow.ingress` is emitted for a read from an identifiable source, with
the source, whether it is vetted, and the hash of what came in.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from . import egress, main
from .claims import ClaimsContext

TOKEN = {"agent": "clodia", "execution_id": "clodia-320", "principal": "davide",
         "chat": "chan:SEAL-2:titulon-tech:clodia"}


def _allow(dest: str, refused: bool = False) -> dict:
    return {"checked": True, "allowed": not refused, "action": "deny" if refused else "allow",
            "verb": "email.send", "type": "mailto", "destinations": [dest],
            "refused": [dest] if refused else None, "rules": [] if refused else [dest],
            "mode": "on", "applied_mode": "on"}


class _Env(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        (self.base / "data").mkdir()
        self.root = self.base / "audit"
        env = patch.dict(os.environ, {"CLODIA_AUDIT_DIR": str(self.root),
                                      "CLODIA_AUDIT_KEY_DIR": str(self.base / "k"),
                                      "CLODIA_DATA": str(self.base / "data")})
        env.start()
        self.addCleanup(env.stop)

    def events(self, type_: str) -> list[dict]:
        out = []
        for seg in sorted(self.root.glob("events-*.jsonl")):
            out += [json.loads(x) for x in seg.read_text().splitlines() if x.strip()]
        return [e for e in out if e["event"]["type"] == type_]

    def raw(self) -> str:
        return "".join(p.read_text() for p in self.root.glob("events-*.jsonl"))

    def run_call(self, name: str, args: dict, verdict: dict | None = None, **patches):
        async def go():
            with ClaimsContext(TOKEN, "t"), \
                    patch.object(main, "_require_gate_consent", AsyncMock(return_value={})):
                ctx = [patch.object(egress, "check", return_value=verdict)] if verdict else []
                ctx += [patch.object(*p) for p in patches.values()]
                for c in ctx:
                    c.start()
                try:
                    return await main.call_tool(name, args)
                finally:
                    for c in ctx:
                        c.stop()
        return asyncio.run(go())


class EgressTests(_Env):
    def scratch(self) -> Path:
        d = self.base / "spawns" / "clodia-320"
        d.mkdir(parents=True, exist_ok=True)
        p = patch.object(main, "_SPAWNS_ROOT", str(self.base / "spawns"))
        p.start()
        self.addCleanup(p.stop)
        return d

    def test_a_sent_email_records_destination_rule_and_attachment_hash(self) -> None:
        att = self.scratch() / "contratto_rossi.pdf"
        att.write_bytes(b"%PDF-1.4 riservato")
        out = self.run_call(
            "email.send", {"to": "mario.rossi@example.com", "subject": "s", "body": "b",
                           "attachments": [str(att)]},
            verdict=_allow("mailto:mario.rossi@example.com"),
            send=(main.email, "send", lambda *a, **k: {"ok": True}),
            account=(main, "_email_account", lambda a: "studio"))
        self.assertFalse(out[0].text.startswith(("DENIED", "ERROR")), out[0].text)
        (ev,) = self.events("flow.egress")
        self.assertEqual(ev["tool"]["destination"], ["mailto:mario.rossi@example.com"])
        self.assertEqual(ev["decision"]["rule"][0]["rule"], "mailto:mario.rossi@example.com")
        self.assertEqual(ev["result"]["files"], [{
            "kind": "attachment", "bytes": 18,
            "hash": "sha256:" + hashlib.sha256(b"%PDF-1.4 riservato").hexdigest()}])
        self.assertTrue(ev["tool"]["parameters_hash"].startswith("sha256:"))
        self.assertNotIn("contratto_rossi", self.raw())
        self.assertNotIn("riservato", self.raw())

    def _send_with(self, attachments: list[str]) -> list[dict]:
        out = self.run_call(
            "email.send", {"to": "x@example.com", "subject": "s", "body": "b",
                           "attachments": attachments},
            verdict=_allow("mailto:x@example.com"),
            send=(main.email, "send", lambda *a, **k: {"ok": True}),
            account=(main, "_email_account", lambda a: "studio"))
        self.assertFalse(out[0].text.startswith(("DENIED", "ERROR")), out[0].text)
        (ev,) = self.events("flow.egress")
        return ev["result"]["files"]

    def _within(self, seconds: float, fn):
        # The hash must never hang the gateway: run the call in a thread and
        # fail (instead of blocking the suite) if it does not return in time.
        import threading
        box: dict = {}
        t = threading.Thread(target=lambda: box.setdefault("v", fn()), daemon=True)
        t.start()
        t.join(seconds)
        self.assertFalse(t.is_alive(), "the crossing hash blocked")
        return box["v"]

    def test_dev_zero_as_attachment_does_not_hang(self) -> None:
        self.scratch()
        files = self._within(10, lambda: self._send_with(["/dev/zero"]))
        self.assertIsNone(files[0].get("hash"))
        self.assertIn(files[0]["error"], ("outside_scratch", "not_a_regular_file"))

    def test_a_device_or_fifo_inside_the_scratch_is_never_opened(self) -> None:
        d = self.scratch()
        fifo = d / "pipe"
        os.mkfifo(fifo)
        link = d / "zero"
        os.symlink("/dev/zero", link)
        files = self._within(10, lambda: self._send_with([str(fifo), str(link)]))
        self.assertEqual([f.get("hash") for f in files], [None, None])
        # the symlink resolves outside the scratch, the FIFO is not a regular file
        self.assertEqual(files[0]["error"], "not_a_regular_file")

    def test_a_file_over_the_cap_is_recorded_by_size_only(self) -> None:
        att = self.scratch() / "big.bin"
        att.write_bytes(b"x" * 2048)
        with patch.dict(os.environ, {"CLODIA_AUDIT_CROSSING_MAX_BYTES": "1024"}):
            files = self._send_with([str(att)])
        self.assertEqual(files, [{"kind": "attachment",
                                  "error": "too_large", "bytes": 2048}])

    def test_an_attachment_outside_the_scratch_is_not_opened(self) -> None:
        self.scratch()
        att = self.base / "elsewhere.pdf"
        att.write_bytes(b"x")
        files = self._send_with([str(att)])
        self.assertEqual(files, [{"kind": "attachment",
                                  "error": "outside_scratch"}])

    def test_nothing_is_recorded_as_sent_when_the_destination_is_refused(self) -> None:
        out = self.run_call(
            "email.send", {"to": "x@example.com", "subject": "s", "body": "b"},
            verdict=_allow("mailto:x@example.com", refused=True),
            send=(main.email, "send", lambda *a, **k: {"ok": True}))
        self.assertTrue(out[0].text.startswith("DENIED"))
        self.assertEqual(self.events("flow.egress"), [])

    def test_a_failed_send_is_not_a_crossing(self) -> None:
        def boom(*a, **k):
            raise RuntimeError("smtp down")
        self.run_call("email.send", {"to": "x@example.com", "subject": "s", "body": "b"},
                      verdict=_allow("mailto:x@example.com"),
                      send=(main.email, "send", boom),
                      account=(main, "_email_account", lambda a: "studio"))
        self.assertEqual(self.events("flow.egress"), [])


class IngressTests(_Env):
    def test_a_web_read_records_source_vetting_and_content_hash(self) -> None:
        page = {"status": 200, "text": "<html>third-party</html>"}
        self.run_call("web.fetch", {"url": "https://docs.ondo.finance/x"},
                      fetch=(main.web_fetch, "fetch", lambda a, agent="": page),
                      vet=(main, "_source_vetted", lambda *a, **k: False))
        (ev,) = self.events("flow.ingress")
        self.assertEqual(ev["tool"]["source"], "https://docs.ondo.finance/x")
        self.assertEqual(ev["tool"]["vetted"], "not_vetted")
        self.assertTrue(ev["input"]["hash"].startswith("sha256:"))
        self.assertNotIn("third-party", self.raw())

    def test_a_web_source_never_carries_credentials_query_or_fragment(self) -> None:
        self.run_call("web.fetch",
                      {"url": "https://alice:s3cr3t@Docs.Example.com:8443/a/B?token=XYZ&x=1#frag"},
                      fetch=(main.web_fetch, "fetch", lambda a, agent="": {"ok": 1}),
                      vet=(main, "_source_vetted", lambda *a, **k: None))
        (ev,) = self.events("flow.ingress")
        self.assertEqual(ev["tool"]["source"], "https://docs.example.com:8443/a/B")
        for leaked in ("alice", "s3cr3t", "XYZ", "token", "frag"):
            self.assertNotIn(leaked, self.raw())

    def test_source_url_forms(self) -> None:
        self.assertEqual(main._source_url("ftp://u:p@h.example/x?y=1"), "ftp://h.example/x")
        self.assertEqual(main._source_url("https://h:notaport/"), "url:unparseable")
        self.assertIsNone(main._source_url(""))

    def test_a_verb_with_no_identifiable_source_is_not_an_ingress(self) -> None:
        self.assertIsNone(main._ingress_source("email.list", {}))
        self.assertIsNone(main._ingress_source("topic.files", {}))
        self.assertEqual(main._ingress_source("gdrive.download", {"file_id": "F1"}),
                         "gdrive:file/F1")

    def test_an_audit_failure_never_breaks_the_read(self) -> None:
        with patch.object(main, "_ingress_source", side_effect=RuntimeError("bug")):
            out = self.run_call("web.fetch", {"url": "https://x.example"},
                                fetch=(main.web_fetch, "fetch", lambda a, agent="": {"ok": 1}))
        self.assertFalse(out[0].text.startswith("ERROR"), out[0].text)


if __name__ == "__main__":
    unittest.main()

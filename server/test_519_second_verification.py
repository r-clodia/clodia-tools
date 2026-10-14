"""Second verification of clodia-tools#359.

* the namespaces of the core connectors that are still to migrate (google,
  gmail, telegram, github, mailbox, openai, …) are reserved for EVERYONE, so
  no pack reaches their vault entries — `namespace: google` +
  `vault_entry: google_studio` used to load;
* a pack dropped by isolation does not leave its outbound verbs unmapped
  (= unchecked): they fail closed, and the other packs keep working.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import egress
from .connectors import resolved
from .connectors import validate as cv
from .connectors import manifest as M


def _connector(ns: str, entry: str, **extra) -> dict:
    return {"id": ns.replace("_", "-"), "manifest_version": 1, "namespace": ns,
            "schemes": [{"scheme": f"{ns.replace('_', '-')}x",
                         "direction": "egress"}],
            "providers": [{"id": "p", "label": "P", "credential": {
                "kind": "form", "vault_entry": entry,
                "fields": [{"name": "token", "secret": True}]}}],
            **extra}


class MigratingNamespacesTests(unittest.TestCase):
    def setUp(self):
        p = patch.object(resolved, "manifests", dict)
        p.start()
        self.addCleanup(p.stop)

    def test_the_verifier_case_is_refused(self):
        out = cv.validate("g-pack", [_connector("google", "google_studio")])
        self.assertFalse(out["ok"], out)

    def test_every_migrating_namespace_is_reserved(self):
        for ns in ("google", "gmail", "gworkspace", "telegram", "github",
                   "mailbox", "openai", "provider", "backup"):
            with self.subTest(ns=ns):
                self.assertIn(ns, getattr(M, "MIGRATING_NAMESPACES", frozenset()))
                out = cv.validate("x-pack", [_connector(ns, f"{ns}_key")])
                # Refused, or — for a namespace a builtin connector still
                # implements (telegram, github) — ignored, i.e. inactive.
                self.assertEqual(out["connectors"], [], out)
                self.assertTrue(out["errors"] or out["ignored"], out)


SENDER = _connector("sender", "sender_key", verbs=[
    {"verb": "sender.send", "direction": "egress", "scheme": "senderx",
     "arg": "to"}])
GOOD = _connector("sms", "sms_key", verbs=[
    {"verb": "sms.send", "direction": "egress", "scheme": "smsx", "arg": "to"}])


class DroppedPackFailsClosedTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.data = Path(tmp.name)
        p = patch.object(resolved, "_DATA", self.data)
        p.start()
        self.addCleanup(p.stop)
        resolved.invalidate()
        self.addCleanup(resolved.invalidate)

    def install(self, pack, *connectors):
        d = self.data / resolved.PACKS_DIR / pack
        d.mkdir(parents=True, exist_ok=True)
        (d / "pack.yaml").write_text(
            json.dumps({"name": pack, "connectors": list(connectors)}),
            encoding="utf-8")

    def test_only_the_offending_pack_is_dropped_and_its_sends_are_denied(self):
        self.install("good-pack", GOOD)
        self.install("bad-pack", {**SENDER, "manifest_version": 99})
        self.assertIsNotNone(egress.spec_for("sms.send"))
        v = egress.decide({}, "sender.send", {"to": "x"})
        self.assertTrue(v["checked"])
        self.assertFalse(v["allowed"])

    def test_a_clash_denies_both_sides_sends(self):
        a = {**SENDER, "schemes": [{"scheme": "contested", "direction": "egress"}],
             "verbs": [{"verb": "sender.send", "direction": "egress",
                        "scheme": "contested", "arg": "to"}]}
        b = {**_connector("other", "other_key"),
             "schemes": [{"scheme": "contested", "direction": "egress"}],
             "verbs": [{"verb": "other.send", "direction": "egress",
                        "scheme": "contested", "arg": "to"}]}
        self.install("good-pack", GOOD)
        self.install("a-pack", a)
        self.install("b-pack", b)
        for verb in ("sender.send", "other.send"):
            with self.subTest(verb=verb):
                self.assertFalse(egress.decide({}, verb, {"to": "x"})["allowed"])
        self.assertIsNotNone(egress.spec_for("sms.send"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

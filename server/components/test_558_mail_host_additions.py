"""clodia-platform#558, mail: what comms-pack's component needed from the host.

- `host.service(pack, name)`: another pack's component service, ONLY for the
  pairs `builtin.COMPONENT_SERVICES` grants (comms-pack → google-pack's
  `mail_accounts`, `mail_exec`), None when that component is not serving;
- `host.perimeter` mail facts: `mailbox_allowed`, `strict_scope`,
  `address_of`, `source_vetted`, `legacy_mail_accounts` — the gateway's own
  answers, read live;
- `host.topics.read_file(..., crossing=…)`: the crossing is recorded under
  the caller's kind, or by the caller itself (`None`);
- `host.audit_decision`: a decision record; `AuditUnavailable` when the trail
  cannot be written (fail-closed callers refuse on it);
- `host.tool_allowed`, `host.current_topic`;
- the `mailbox_` scope follows the `mail` switch, for comms-pack only.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from .. import egress, instance_profile, main
from .. import whitelist as w
from ..connectors import builtin, resolved
from . import loader, trust
from .grammar import GatewayComponent
from .host import AuditUnavailable, Host, HostError, ServiceSpec


def _component(pack: str, cid: str, *, connectors=("mail",), namespaces=None,
               credentials=("mailbox_",)) -> GatewayComponent:
    return GatewayComponent(
        pack=pack, id=cid, repo="r-clodia/clodia-logic",
        path=f"catalogs/packs/{pack}/gateway", ref="main", entry="x",
        connectors=tuple(connectors), credentials=tuple(credentials),
        namespaces=namespaces or {"mail": "email"})


COMMS = _component("comms-pack", "mail")
GOOGLE = _component("google-pack", "google", connectors=("google",),
                    namespaces={"google": "gdrive"},
                    credentials=("google_", "gmail_"))


def _host(component: GatewayComponent) -> Host:
    return Host(component, native_names=lambda: [], reserved_namespaces=lambda: [],
                taken=lambda n: None)


class _Profile:
    """`profile.yaml` written for real in a temp datadir."""

    def setUp(self) -> None:  # noqa: D401
        super().setUp()
        self.addCleanup(self._reload)
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)
        for p in (patch.dict(os.environ, {"CLODIA_DATA": str(self.dir)}),
                  patch.object(resolved, "_DATA", self.dir)):
            p.start()
            self.addCleanup(p.stop)

    def _reload(self) -> None:
        instance_profile.load(force=True)
        resolved.invalidate()

    def position(self, **modes: str) -> None:
        lines = ["edition: full", "connectors:"] + [f"  {k}: {v}" for k, v in modes.items()]
        (self.dir / "profile.yaml").write_text("\n".join(lines) + "\n", encoding="utf-8")
        self._reload()


class ServiceLookupTests(_Profile, unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.position(mail="pack", google="pack")
        self.addCleanup(loader.reset)
        loader.reset()
        services = {n: ServiceSpec(component=GOOGLE.key, pack="google-pack", name=n,
                                   handler=lambda *a, _n=n: (_n, a))
                    for n in ("mail_accounts", "mail_exec", "accounts")}
        loader._STATES[GOOGLE.key] = loader.State(component=GOOGLE, status="loaded",
                                                  services=services)

    def test_the_granted_pairs_are_found(self) -> None:
        h = _host(COMMS)
        self.assertEqual(h.service("google-pack", "mail_accounts")(), ("mail_accounts", ()))
        self.assertEqual(h.service("google-pack", "mail_exec")({"x": 1}),
                         ("mail_exec", ({"x": 1},)))

    def test_anything_else_is_refused(self) -> None:
        h = _host(COMMS)
        for pack, name in (("google-pack", "accounts"), ("google-pack", "mail_run"),
                           ("comms-pack", "diagnostics"), ("it-pack", "mail_exec")):
            with self.subTest(pair=(pack, name)), self.assertRaises(HostError):
                h.service(pack, name)
        # Nobody else is granted anything: not even the callee, the other way.
        with self.assertRaises(HostError):
            _host(GOOGLE).service("comms-pack", "diagnostics")

    def test_none_when_the_callee_is_not_serving(self) -> None:
        h = _host(COMMS)
        self.position(mail="pack", google="native")      # google-pack on standby
        self.assertIsNone(h.service("google-pack", "mail_exec"))
        self.position(mail="pack", google="pack")
        loader.reset()
        self.assertIsNone(h.service("google-pack", "mail_exec"))

    def test_the_grant_table_is_code_and_closed(self) -> None:
        self.assertEqual(dict(builtin.COMPONENT_SERVICES), {
            "comms-pack": frozenset({("google-pack", "mail_accounts"),
                                     ("google-pack", "mail_exec")})})


class MailboxScopeTests(_Profile, unittest.TestCase):
    def test_follows_the_mail_switch_for_comms_pack_only(self) -> None:
        self.position(mail="pack")
        self.assertEqual(trust.credential_problem(COMMS, "mailbox_"), "")
        self.position(mail="native")
        self.assertIn("mail", trust.credential_problem(COMMS, "mailbox_"))
        self.position(mail="pack")
        other = _component("google-pack", "google", credentials=("mailbox_",))
        self.assertTrue(trust.credential_problem(other, "mailbox_"))

    def test_comms_pack_cannot_reach_google_credentials(self) -> None:
        self.position(mail="pack", google="pack")
        sneaky = _component("comms-pack", "mail", credentials=("mailbox_", "google_"))
        self.assertTrue(trust.credential_problem(sneaky, "google_"))

    def test_the_scope_is_checked_at_every_access(self) -> None:
        self.position(mail="pack")
        creds = _host(COMMS).credentials("mailbox_")
        with patch("server.vault.has_credential", return_value=True):
            self.assertTrue(creds.has("mailbox_studio"))
            with self.assertRaises(HostError):
                creds.has("google_studio")
            self.position(mail="native")
            with self.assertRaises(HostError):
                creds.has("mailbox_studio")


class PerimeterMailTests(unittest.TestCase):
    SCOPE = "SEAL-1/acme"

    def cfg(self, strict: bool) -> dict:
        return {"egress_allow": ["outbox:studio@x.it"], "scope_egress_allow": {},
                "source_allow": ["inbox:globale@x.it"],
                "scope_source_allow": {self.SCOPE: ["inbox:acme@x.it",
                                                    "mailfrom:ordini@f.it"]},
                "scope_ingress_strict": {self.SCOPE: True} if strict else {},
                "agents": {}}

    def in_room(self):
        class _C:
            def __enter__(s):
                s.t = w.set_current_chat("chan:SEAL-1:acme:clodia")

            def __exit__(s, *a):
                w.reset_current_chat(s.t)
        return _C()

    def test_the_answers_are_the_gateways(self) -> None:
        per = _host(COMMS).perimeter
        for strict in (False, True):
            with self.subTest(strict=strict), patch.object(w, "CONFIG", self.cfg(strict)), \
                    self.in_room():
                for d, a in (("inbox", "acme@x.it"), ("inbox", "globale@x.it"),
                             ("outbox", "studio@x.it"), ("outbox", "acme@x.it")):
                    self.assertEqual(per.mailbox_allowed(d, a), egress.mailbox_allowed(d, a))
                for uri in ("mailfrom:ordini@f.it", "mailfrom:x@y.it"):
                    self.assertEqual(per.source_vetted(uri), egress.is_vetted_source(uri))
                self.assertEqual(per.strict_scope(), self.SCOPE if strict else None)
        self.assertIsNone(per.strict_scope())               # outside a room
        self.assertEqual(per.address_of("Mario <M@X.it>"), egress.address_of("Mario <M@X.it>"))
        self.assertEqual(per.address_of("???"), "")

    def test_legacy_accounts_names_and_addresses_only(self) -> None:
        from ..tools import email as EM
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "email_config.json"
            f.write_text(json.dumps({"accounts": {
                "demo": {"email": "A@B.IT", "password": "SEGRETO"},  # gitleaks:allow
                "vuoto": {"password": "x"}}}), encoding="utf-8")
            with patch.object(EM, "_legacy_config_file", lambda: f):
                out = _host(COMMS).perimeter.legacy_mail_accounts()
        self.assertEqual(out, {"demo": "a@b.it", "vuoto": None})
        self.assertNotIn("SEGRETO", json.dumps(out))


class TopicsCrossingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.notes: list = []
        svc = type("S", (), {"read_file": lambda s, t, n, p: b"bytes"})()
        for p in (patch.object(main, "_topics", lambda: svc),
                  patch.object(main, "_require_topic_member", lambda *a, **k: None),
                  patch.object(main, "_note_crossing",
                               lambda *a, **k: self.notes.append(k))):
            p.start()
            self.addCleanup(p.stop)

    def test_the_kind_is_the_callers(self) -> None:
        topics = _host(COMMS).topics
        self.assertEqual(topics.read_file("SEAL-1", "acme", "files/a.pdf"), b"bytes")
        self.assertEqual(self.notes, [{"data": b"bytes", "kind": "file"}])
        topics.read_file("SEAL-1", "acme", "files/a.pdf", crossing="attachment")
        self.assertEqual(self.notes[-1]["kind"], "attachment")
        self.notes.clear()
        topics.read_file("SEAL-1", "acme", "files/a.pdf", crossing=None)
        self.assertEqual(self.notes, [])


class AuditAndCallFactsTests(unittest.TestCase):
    def test_audit_unavailable_is_its_own_error(self) -> None:
        from .. import audit
        h = _host(COMMS)
        with patch("server.audit.policy.decision",
                   side_effect=audit.AuditWriteError("disk full")):
            with self.assertRaises(AuditUnavailable):
                h.audit_decision("email.list", "ingress", "filter",
                                 reason_class="sender_not_vetted")
        self.assertIs(h.AuditUnavailable, AuditUnavailable)
        seen = []
        with patch("server.audit.policy.decision",
                   lambda *a, **k: seen.append((a, k))):
            h.audit_decision("email.read", "ingress", "deny",
                             reason_class="sender_not_vetted")
        self.assertEqual(seen, [(("email.read", "ingress", "deny"),
                                 {"reason_class": "sender_not_vetted"})])
        with patch("server.audit.policy.decision", side_effect=ValueError("x")):
            with self.assertRaises(ValueError):
                h.audit_decision("email.read", "ingress", "deny")

    def test_tool_allowed_and_current_topic(self) -> None:
        h = _host(COMMS)
        with patch("server.whitelist.tool_allowed",
                   side_effect=PermissionError("no")) as ta:
            with self.assertRaises(PermissionError):
                h.tool_allowed("email.read")
        ta.assert_called_once_with("email.read")
        with patch("server.main.current_chat",
                   return_value="chan:SEAL-1:acme:clodia#2"):
            self.assertEqual(h.current_topic(), ("SEAL-1", "acme"))
        with patch("server.main.current_chat", return_value=None):
            self.assertEqual(h.current_topic(), (None, None))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

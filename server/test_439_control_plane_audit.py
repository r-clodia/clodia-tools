"""clodia-platform#439 — changes to the rules are on the audit trail.

Before: rule changes left no trace except the vault audit log (credentials)
and a provisional `tier_history` in the topic meta. Now every write of the
gateway config reports its delta, and vault, PKI, participants, SEAL
re-classification, topic status, delegations, MCP clients and backup runs emit
their own `control.*` event — attributed, from the verified claims, to whoever
made the request. Credential values never appear.
"""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from . import vault, whitelist as w
from .audit import control
from .claims import ClaimsContext
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicService

ADMIN = {"agent": "clodia", "principal": "davide", "on_behalf": True, "human_role": "admin"}


class _Env(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.root = self.base / "audit"
        env = patch.dict(os.environ, {"CLODIA_AUDIT_DIR": str(self.root),
                                      "CLODIA_AUDIT_KEY_DIR": str(self.base / "k"),
                                      "CLODIA_VAULT_DIR": str(self.base / "vault"),
                                      "CLODIA_DATA": str(self.base / "data")})
        env.start()
        self.addCleanup(env.stop)

    def events(self, prefix: str = "control.") -> list[dict]:
        out = []
        for seg in sorted(self.root.glob("events-*.jsonl")):
            out += [json.loads(x) for x in seg.read_text().splitlines() if x.strip()]
        return [e for e in out if e["event"]["type"].startswith(prefix)]

    def raw(self) -> str:
        return "".join(p.read_text() for p in self.root.glob("events-*.jsonl"))


class DiffTests(unittest.TestCase):
    def test_lists_report_entries_nested_dicts_recurse_scalars_are_hashed(self) -> None:
        before = {"egress_allow": ["mailto:a@x.it"], "agents": {"avvocato": {"allowed_tools": ["t1"]}},
                  "workspace_root": "/a"}
        after = {"egress_allow": ["mailto:a@x.it", "mailto:b@x.it"],
                 "agents": {"avvocato": {"allowed_tools": []}}, "workspace_root": "/b",
                 "scope_egress_allow": {"SEAL-1/acme": ["gdrive:folder/F"]}}
        ch = {c["path"]: c for c in control.config_changes(before, after)}
        self.assertEqual(ch["egress_allow"]["added"], ["mailto:b@x.it"])
        self.assertEqual(ch["agents.avvocato.allowed_tools"]["removed"], ["t1"])
        self.assertEqual(ch["workspace_root"]["op"], "changed")
        self.assertNotIn("/b", json.dumps(ch["workspace_root"]))
        self.assertEqual(ch["scope_egress_allow.SEAL-1/acme"]["added"], ["gdrive:folder/F"])

    def test_no_change_no_entry(self) -> None:
        self.assertEqual(control.config_changes({"a": [1]}, {"a": [1]}), [])


class ConfigWriteTests(_Env):
    def setUp(self) -> None:
        super().setUp()
        self.path = self.base / "config.yaml"
        self.path.write_text(yaml.safe_dump({"workspace_root": ".", "egress_allow": [],
                                             "agents": {"clodia": {"allowed_tools": ["a"]}}}))
        p = patch.object(w, "CONFIG_PATH", self.path)
        p.start()
        # LIFO: stop the patch first, then reload the real config, so that the
        # tiny test config does not leak into the rest of the suite.
        self.addCleanup(w.reload_config)
        self.addCleanup(p.stop)
        w.reload_config()

    def test_a_whitelist_change_is_a_control_event_by_whoever_asked(self) -> None:
        with ClaimsContext(ADMIN, "t"):
            w.CONFIG["egress_allow"] = ["mailto:new@x.it"]
            w.save_config()
        (ev,) = self.events("control.config")
        self.assertEqual(ev["actor"]["id"], "davide")
        self.assertEqual(ev["actor"]["role"], "admin")
        self.assertEqual(ev["result"]["changes"],
                         [{"path": "egress_allow", "op": "list", "added": ["mailto:new@x.it"]}])
        self.assertNotEqual(ev["input"]["before_hash"], ev["input"]["after_hash"])

    def test_a_save_without_changes_is_not_an_event(self) -> None:
        w.save_config()
        self.assertEqual(self.events("control.config"), [])


class VaultTests(_Env):
    def test_deposit_grant_remove_without_the_value(self) -> None:
        with ClaimsContext(ADMIN, "t"):
            vault.deposit("backup_config", {"passphrase": "hunter2-secret"},
                          cred_type="backup_config", grant_agents=[])
            vault.set_grant("backup_config", "sysadmin", True)
            vault.remove("backup_config")
        acts = [(e["event"]["type"], e["event"]["action"]) for e in self.events()]
        self.assertEqual(acts, [("control.vault", "deposit"), ("control.vault", "grant"),
                                ("control.vault", "remove")])
        self.assertNotIn("hunter2", self.raw())
        self.assertEqual(self.events()[1]["result"]["agent"], "sysadmin")


class TopicTests(_Env):
    def setUp(self) -> None:
        super().setUp()
        self.svc = TopicService(LocalFsStorage(self.base / "store"))
        self.svc.new("SEAL-1", "ch", {"title": "ch", "owner": "davide", "participants": ["davide"]})

    def test_participants_and_status(self) -> None:
        with ClaimsContext(ADMIN, "t"):
            self.svc.add_participant("SEAL-1", "ch", "avvocato")
            self.svc.add_participant("SEAL-1", "ch", "avvocato")      # no change, no event
            self.svc.remove_participant("SEAL-1", "ch", "avvocato")
            self.svc.set_status("SEAL-1", "ch", "on-hold")
        acts = [(e["event"]["type"], e["event"]["action"]) for e in self.events()]
        self.assertEqual(acts, [("control.participants", "add"),
                                ("control.participants", "remove"),
                                ("control.topic_status", "change")])
        self.assertEqual(self.events()[0]["result"]["participant"], "avvocato")
        self.assertEqual(self.events()[2]["result"], {"before": "active", "after": "on-hold"})


class PkiTests(_Env):
    def test_only_a_real_issuance_is_recorded(self) -> None:
        from . import pki_mint
        certs = self.base / "certs"
        certs.mkdir()
        calls = []

        def fake(name, force=False):
            calls.append(name)
            p = certs / f"{name}.crt"
            if force or not p.is_file():
                p.write_bytes(f"cert-{len(calls)}".encode())
            return str(p)
        wrapped = pki_mint._audited_issuer(fake)
        with patch.object(pki_mint, "_certs_dir", return_value=certs):
            wrapped("minerva")
            wrapped("minerva")
            wrapped("minerva", force=True)
        acts = [e["event"]["action"] for e in self.events("control.pki")]
        self.assertEqual(acts, ["issue", "reissue"])

    def test_clearing_a_revocation_is_recorded(self) -> None:
        """#466: a revoked.json that loses an entry without `control.pki
        unrevoke` is a revocation undone off the record."""
        from . import pki_mint
        certs = self.base / "certs"
        certs.mkdir()
        rf = self.base / "revoked.json"
        rf.write_text(json.dumps({"revoked": ["minerva", "ophelia"]}))

        def fake(name, pubkey_pem="", force=False):
            (certs / f"{name}.crt").write_bytes(f"cert-{name}".encode())
            data = json.loads(rf.read_text())
            data["revoked"] = [n for n in data["revoked"] if n != name]
            rf.write_text(json.dumps(data))
            return str(certs / f"{name}.crt")
        wrapped = pki_mint._audited_issuer(fake)
        with patch.object(pki_mint, "_certs_dir", return_value=certs), \
                patch.dict(os.environ, {"CLODIA_PKI_REVOKED": str(rf)}):
            wrapped("minerva", force=True)
            wrapped("avvocato", force=True)       # was not revoked: no unrevoke
        acts = [(e["event"]["action"], e["event"]["resource"])
                for e in self.events("control.pki")]
        self.assertEqual(acts, [("issue", "minerva"), ("unrevoke", "minerva"),
                                ("issue", "avvocato")])
        self.assertEqual(json.loads(rf.read_text())["revoked"], ["ophelia"])

    def test_the_real_issuer_clears_and_records(self) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from . import pki_mint
        rf = self.base / "revoked.json"
        rf.write_text(json.dumps({"revoked": ["davide"]}))
        with patch.dict(os.environ, {"CLODIA_SECRETS_DIR": str(self.base / "secrets"),
                                     "CLODIA_PKI_CERTS": str(self.base / "pki" / "certs"),
                                     "CLODIA_PKI_REVOKED": str(rf)}):
            pki_mint.init_ca()
            pub = Ed25519PrivateKey.generate().public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
            pki_mint.issue_cert_for_pubkey("davide", pub.decode(), force=True)
        ev = [e for e in self.events("control.pki") if e["event"]["action"] == "unrevoke"]
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["event"]["resource"], "davide")
        self.assertRegex(ev[0]["result"]["cert_serial"], r"^[0-9a-f]+$")
        self.assertEqual(json.loads(rf.read_text())["revoked"], [])


if __name__ == "__main__":
    unittest.main()

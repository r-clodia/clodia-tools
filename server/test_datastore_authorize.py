from __future__ import annotations

import unittest
from unittest.mock import patch

from . import main


_ENTRY = {
    "pack": "base-pack", "name": "contacts", "path": "data/contacts.db",
    "abs_path": "/datadir/plugins/base-pack/data/contacts.db",
    "purpose": "CRM contatti", "pii": True, "backup": True,
    "clearance": "SEAL-1",
}


class DatastoreAuthorizeTests(unittest.TestCase):
    """An AGENT reaches a datastore only through an import in its scope
    (clodia-platform#669): no seed list, no super-agent bypass."""

    def _patches(self, agent: str, clearance: str, entry=_ENTRY, super_agent=False,
                 scope=None):
        return (
            patch.object(main, "agent_name", return_value=agent),
            patch.object(main, "_is_super", return_value=super_agent),
            patch.object(main, "current_clearance", return_value=clearance),
            patch.object(main.datastores, "find", return_value=entry),
            patch("server.topic_data.scope_of_call", return_value=scope),
        )

    def test_the_scope_decides(self) -> None:
        seen = {}
        p = self._patches("messaggero", "SEAL-2", scope="SEAL-2/crm")
        with p[0], p[1], p[2], p[3], p[4], \
                patch("server.topic_data.authorize",
                      lambda kind, res, **k: seen.update(kind=kind, res=res, **k)):
            entry = main._datastore_authorize("base-pack/contacts", write=True)
        self.assertEqual(entry["name"], "contacts")
        self.assertEqual((seen["kind"], seen["res"], seen["scope"], seen["write"],
                          seen["agent"], seen["clearance"]),
                         ("datastore", "base-pack/contacts", "SEAL-2/crm", True,
                          "messaggero", "SEAL-2"))

    def test_no_scope_no_access_even_with_clearance(self) -> None:
        p = self._patches("messaggero", "SEAL-4")
        with p[0], p[1], p[2], p[3], p[4]:
            with self.assertRaises(PermissionError):
                main._datastore_authorize("base-pack/contacts", write=False)

    def test_a_super_agent_has_no_bypass(self) -> None:
        p = self._patches("qualunque-agente", "SEAL-4", super_agent=True)
        with p[0], p[1], p[2], p[3], p[4]:
            with self.assertRaises(PermissionError):
                main._datastore_authorize("base-pack/contacts", write=False)

    def test_unknown_datastore_is_rejected(self) -> None:
        p = self._patches("messaggero", "SEAL-2", entry=None)
        with p[0], p[1], p[2], p[3], p[4]:
            with self.assertRaises(ValueError):
                main._datastore_authorize("base-pack/nonexistent", write=False)

    def test_bad_key_shape_is_rejected_before_lookup(self) -> None:
        p = self._patches("messaggero", "SEAL-2")
        with p[0], p[1], p[2], p[3], p[4]:
            with self.assertRaises(ValueError):
                main._datastore_authorize("contacts", write=False)


class DatastoreAuthorizeOnBehalfTests(unittest.TestCase):
    """L'asse UMANO (clodia-platform#342): la webui inoltra al PDP
    (`/internal/tool`) con `on_behalf` + ruolo firmato e carrier tecnico
    `clodia`; la persona non eredita mai ciò che il carrier raggiunge.
    """

    def _patches(self, role: str, clearance: str | None, entry=_ENTRY,
                 carrier_super=False, carrier="clodia"):
        return (
            patch.object(main, "agent_name", return_value=carrier),
            patch.object(main, "_is_super", return_value=carrier_super),
            patch.object(main, "is_on_behalf", return_value=True),
            patch.object(main, "current_human_role", return_value=role),
            patch.object(main, "current_principal", return_value="davide"),
            patch.object(main, "current_clearance", return_value=clearance),
            patch.object(main.datastores, "find", return_value=entry),
        )

    def test_admin_with_clearance_reads(self) -> None:
        p = self._patches("admin", "SEAL-2")
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6]:
            got = main._datastore_authorize("base-pack/contacts", write=False)
        self.assertEqual("contacts", got["name"])

    def test_non_admin_human_is_denied(self) -> None:
        p = self._patches("user", "SEAL-4")
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6]:
            with self.assertRaises(PermissionError):
                main._datastore_authorize("base-pack/contacts", write=False)

    def test_admin_without_clearance_is_denied(self) -> None:
        """Il livello resta un asse anche per una persona: admin non è un tier."""
        p = self._patches("admin", "SEAL-0")
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6]:
            with self.assertRaises(PermissionError):
                main._datastore_authorize("base-pack/contacts", write=False)

    def test_missing_clearance_claim_counts_as_seal0(self) -> None:
        """Claim assente = SEAL-0, non «nessun limite». È il caso reale finché
        l'agent-server non conia la clearance dell'umano nel token on-behalf
        (clodia-logic `gateway_pdp._token`)."""
        p = self._patches("admin", None)
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6]:
            with self.assertRaises(PermissionError):
                main._datastore_authorize("base-pack/contacts", write=False)

    def test_write_on_behalf_is_denied_even_to_an_admin(self) -> None:
        """Navigare è leggere: questo monitor non apre scritture a una persona."""
        p = self._patches("admin", "SEAL-4")
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6]:
            with self.assertRaises(PermissionError):
                main._datastore_authorize("base-pack/contacts", write=True)

    def test_super_carrier_does_not_rescue_a_non_admin_human(self) -> None:
        """Il bypass dei super è del CARRIER: se valesse prima del ramo umano,
        una persona qualunque erediterebbe l'autorità dell'agente che la
        trasporta — esattamente ciò che `_human_tool_allowed` esiste per negare."""
        p = self._patches("user", "SEAL-4", carrier_super=True)
        with p[0], p[1], p[2], p[3], p[4], p[5], p[6]:
            with self.assertRaises(PermissionError):
                main._datastore_authorize("base-pack/contacts", write=False)


if __name__ == "__main__":
    unittest.main()

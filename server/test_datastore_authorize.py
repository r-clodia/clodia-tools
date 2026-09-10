from __future__ import annotations

import unittest
from unittest.mock import patch

from . import main


_ENTRY = {
    "pack": "base-pack", "name": "contacts", "path": "data/contacts.db",
    "abs_path": "/datadir/plugins/base-pack/data/contacts.db",
    "purpose": "CRM contatti", "pii": True, "backup": True,
    "clearance": "SEAL-1", "seeds": ["messaggero", "clodia"],
}


class DatastoreAuthorizeTests(unittest.TestCase):
    def _patches(self, agent: str, clearance: str, entry=_ENTRY, super_agent=False):
        return (
            patch.object(main, "agent_name", return_value=agent),
            patch.object(main, "_is_super", return_value=super_agent),
            patch.object(main, "current_clearance", return_value=clearance),
            patch.object(main.datastores, "find", return_value=entry),
        )

    def test_seed_in_allowlist_with_sufficient_clearance_is_authorized(self) -> None:
        p = self._patches("messaggero", "SEAL-2")
        with p[0], p[1], p[2], p[3]:
            entry = main._datastore_authorize("base-pack/contacts", write=False)
        self.assertEqual(entry["name"], "contacts")

    def test_seed_not_in_allowlist_is_denied_even_with_clearance(self) -> None:
        p = self._patches("sysadmin", "SEAL-4")
        with p[0], p[1], p[2], p[3]:
            with self.assertRaises(PermissionError):
                main._datastore_authorize("base-pack/contacts", write=False)

    def test_insufficient_clearance_is_denied_even_if_seed_is_listed(self) -> None:
        p = self._patches("messaggero", "SEAL-0")
        with p[0], p[1], p[2], p[3]:
            with self.assertRaises(PermissionError):
                main._datastore_authorize("base-pack/contacts", write=True)

    def test_unknown_datastore_is_rejected(self) -> None:
        p = self._patches("messaggero", "SEAL-2", entry=None)
        with p[0], p[1], p[2], p[3]:
            with self.assertRaises(ValueError):
                main._datastore_authorize("base-pack/nonexistent", write=False)

    def test_bad_key_shape_is_rejected_before_lookup(self) -> None:
        p = self._patches("messaggero", "SEAL-2")
        with p[0], p[1], p[2], p[3]:
            with self.assertRaises(ValueError):
                main._datastore_authorize("contacts", write=False)

    def test_super_agent_bypasses_the_allowlist_but_not_clearance(self) -> None:
        p = self._patches("qualunque-agente", "SEAL-4", super_agent=True)
        with p[0], p[1], p[2], p[3]:
            main._datastore_authorize("base-pack/contacts", write=False)

        p = self._patches("qualunque-agente", "SEAL-0", super_agent=True)
        with p[0], p[1], p[2], p[3]:
            with self.assertRaises(PermissionError):
                main._datastore_authorize("base-pack/contacts", write=False)

    def test_datastore_without_declared_clearance_or_seeds_denies_everyone(self) -> None:
        """Fail-closed: assenza dei campi non è un default permissivo."""
        bare = {**_ENTRY, "clearance": "SEAL-4", "seeds": []}
        p = self._patches("messaggero", "SEAL-4", entry=bare)
        with p[0], p[1], p[2], p[3]:
            with self.assertRaises(PermissionError):
                main._datastore_authorize("base-pack/contacts", write=False)


if __name__ == "__main__":
    unittest.main()

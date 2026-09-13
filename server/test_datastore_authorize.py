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


class DatastoreAuthorizeOnBehalfTests(unittest.TestCase):
    """L'asse UMANO: una persona non è un seed, e `seeds:` non parla di lei.

    La webui inoltra al PDP (`/internal/tool`) con `on_behalf` + ruolo firmato
    e carrier tecnico `clodia`: chiedere «il carrier è nell'elenco seed?» è la
    domanda sbagliata posta a nome di qualcun altro, e rispondeva no a
    chiunque — motivo per cui un datastore non era navigabile da nessun umano
    (clodia-platform#342).
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

    def test_admin_with_clearance_reads_even_if_carrier_is_not_a_seed(self) -> None:
        """Il carrier NON è in `seeds`: se passasse, passerebbe per la ragione
        sbagliata e il test non direbbe nulla sull'asse umano."""
        entry = {**_ENTRY, "seeds": ["messaggero"]}
        p = self._patches("admin", "SEAL-2", entry=entry)
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
        """Navigare è leggere: la scrittura resta agli agenti dichiarati dal
        pack, che è anche l'unico posto dove qualcuno l'ha autorizzata."""
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

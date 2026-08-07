"""Il proprietario dell'istanza non può essere l'unico escluso dai verbi gated.

Successo il 7 ago 2026. Davide, il cui seed dichiara `role: superadmin`, si è
visto rispondere:

    HTTP 403 — azione 'packs.import_url' riservata agli admin

Il controllo confrontava con la stringa esatta `"admin"`, e `superadmin` non è
`"admin"`. Riprodotto sull'istanza prima di correggere:

    ruolo=superadmin  → consentito: False
    ruolo=admin       → consentito: True
    ruolo=user        → consentito: False

Perché è passato inosservato: ovunque altrove — `human.is_admin`,
`admin._is_admin_yaml`, `origin.principal_may`, `tools_api` — la verifica passa
da `_ADMIN_ROLES = ("superadmin", "admin")`. Un solo punto **duplicava** la regola
invece di usarla. E le duplicazioni di una regola divergono: questa divergeva sul
caso più privilegiato, quindi sbagliava verso il rifiuto — che è la direzione che
non rompe niente e non si nota, finché il proprietario non prova a fare il
proprio mestiere.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import main as M
from .human import _ADMIN_ROLES


class HumanGatedVerbTests(unittest.TestCase):
    def _allowed(self, ruolo, verbo="packs.import_url"):
        with patch.object(M, "current_human_role", lambda: ruolo):
            return M._human_tool_allowed(verbo)

    def test_superadmin_may_invoke_a_gated_verb(self):
        """Il caso di Davide."""
        self.assertTrue(self._allowed("superadmin"))

    def test_admin_may_too(self):
        self.assertTrue(self._allowed("admin"))

    def test_a_plain_user_may_not(self):
        """La regola che il difetto NON doveva allentare: un membro non
        amministra."""
        self.assertFalse(self._allowed("user"))

    def test_an_absent_role_is_treated_as_user(self):
        """Direzione d'errore: un ruolo che non si legge non è un admin."""
        self.assertFalse(self._allowed(None))

    def test_an_unknown_role_is_not_an_admin(self):
        for ruolo in ("member", "owner", "root", "Admin ", "SUPERADMIN"):
            with self.subTest(ruolo=ruolo):
                self.assertFalse(self._allowed(ruolo))

    def test_a_non_gated_verb_is_open_to_any_authenticated_human(self):
        self.assertTrue(self._allowed("user", "topic.open"))


class NoDuplicatedRuleTests(unittest.TestCase):
    """La causa, non il sintomo. Se il confronto torna a essere letterale il
    difetto si ripresenta identico, e su un altro verbo."""

    def test_the_check_uses_the_shared_set_rather_than_a_literal(self):
        """Guarda il CODICE, non i commenti — il primo tentativo di questo test
        falliva sulla spiegazione della correzione, che cita la forma sbagliata
        per dire di non usarla."""
        import inspect
        righe = inspect.getsource(M._human_tool_allowed).splitlines()
        codice = "\n".join(r for r in righe
                           if not r.strip().startswith("#") and '"""' not in r)
        self.assertIn("_ADMIN_ROLES", codice)
        self.assertNotIn('== "admin"', codice,
                         "confronto letterale: escluderebbe di nuovo superadmin")

    def test_the_shared_set_contains_both(self):
        self.assertIn("admin", _ADMIN_ROLES)
        self.assertIn("superadmin", _ADMIN_ROLES)


if __name__ == "__main__":
    unittest.main()

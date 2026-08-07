"""La credenziale Google unificata deve essere VISIBILE dove si concedono i grant.

Difetto trovato il 7 ago 2026, e il modo in cui è emerso conta più del difetto:
messaggero, su venere, ha risposto a Davide che serviva un grant per spedire. Io
ho concluso che si sbagliasse — misurando con `vault.email_connectors()`, che
elenca SOLO le credenziali `gmail_*`. Aveva ragione lui: `google_devnullboxx`
esisteva, ed è concesso a `clodia` soltanto.

Il difetto sotto: `_grant_covers` (main.py) riconosce `google_*` come abilitante
per `email.*` da tempo, ma questa vista — quella che alimenta Integrations nella
webui — enumerava solo le due forme legacy. Su un'istanza con la sola credenziale
unificata la sezione risultava VUOTA: un admin non poteva concedere un accesso
che il gateway avrebbe accettato. Non un permesso mancante, un permesso
concedibile e invisibile.

I test qui sotto legano le due metà, così che non possano più divergere in
silenzio.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import connectors_api as ca


NOMI = ["app_google_oauth", "google_devnullboxx", "mailbox_studio",
        "provider_scaleway", "telegram_bot_token"]


def _env(grants=None):
    grants = grants or {}
    return (patch.object(ca.vault, "store_names", lambda: list(NOMI)),
            patch.object(ca.vault, "email_connectors", lambda: []),
            patch.object(ca.vault, "has_credential", lambda n: n in NOMI),
            patch.object(ca.vault, "agents_with_grant", lambda c: grants.get(c, [])))


class Base(unittest.TestCase):
    def run_with(self, ctx, fn):
        for c in ctx:
            c.start()
        try:
            return fn()
        finally:
            [c.stop() for c in ctx]


class VisibilityTests(Base):
    def test_a_unified_google_credential_is_listed(self):
        """Il caso concreto di venere: l'unica credenziale che abilita l'email
        c'è, e la vista la ignorava — quindi Integrations era vuota."""
        def go():
            ids = [c["id"] for c in ca._connectors(None)]
            self.assertIn("devnullboxx", ids)
        self.run_with(_env(), go)

    def test_it_is_not_typed_as_email(self):
        """Chiamarla «email» farebbe credere a chi concede di aprire un canale
        solo, mentre la credenziale unificata ne apre cinque. Chi autorizza deve
        vedere cosa sta autorizzando."""
        def go():
            row = next(c for c in ca._connectors(None) if c["id"] == "devnullboxx")
            self.assertEqual(row["type"], "google")
            self.assertIn("gdrive", row["enables"])
            self.assertIn("email", row["enables"])
        self.run_with(_env(), go)

    def test_the_grant_state_is_reported_per_agent(self):
        def go():
            rows = {c["id"]: c for c in ca._connectors("messaggero")}
            self.assertFalse(rows["devnullboxx"]["granted"])
            rows2 = {c["id"]: c for c in ca._connectors("clodia")}
            self.assertTrue(rows2["devnullboxx"]["granted"])
        self.run_with(_env({"google_devnullboxx": ["clodia"]}), go)

    def test_legacy_forms_keep_working(self):
        """La correzione aggiunge, non sostituisce: chi ha ancora `mailbox_*`
        non deve perdere la propria riga."""
        def go():
            ids = [c["id"] for c in ca._connectors(None)]
            self.assertIn("studio", ids)
        self.run_with(_env(), go)

    def test_the_credential_resolves_back_from_its_id(self):
        """Senza questo, la riga si vedrebbe ma il pulsante «concedi» non
        troverebbe la credenziale da concedere."""
        def go():
            self.assertEqual(ca._cred_for("devnullboxx"), "google_devnullboxx")
        self.run_with(_env(), go)


class AgreementWithThePermissionCheckTests(unittest.TestCase):
    """Il test che impedisce alla divergenza di tornare: ciò che il controllo
    dei permessi accetta deve essere ciò che la vista mostra."""

    def test_every_credential_prefix_that_enables_email_is_listed_somewhere(self):
        import inspect
        from . import main as M
        src = inspect.getsource(M._grant_covers)
        # i prefissi che main.py riconosce per email.*
        for prefisso in ("google_", "gmail_", "mailbox_"):
            with self.subTest(prefisso=prefisso):
                self.assertIn(prefisso, src,
                              f"{prefisso} non è più riconosciuto da _grant_covers: "
                              "aggiorna anche connectors_api, o le due metà divergono")
        vista = inspect.getsource(ca)
        for prefisso in ("google_", "gmail_", "mailbox_"):
            with self.subTest(vista=prefisso):
                self.assertIn(prefisso, vista,
                              f"{prefisso} abilita email.* ma la vista dei connettori "
                              "non lo enumera: sarebbe un grant concedibile e invisibile")


if __name__ == "__main__":
    unittest.main()

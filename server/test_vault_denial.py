"""Il rifiuto del vault deve distinguere «non hai il verbo» da «non hai la
credenziale», perché la confusione ha prodotto un guasto osservato.

messaggero, su venere, ha letto «non ha grant 'fetch'» e ha riferito in canale
«Non ho il capability email.send, devo coinvolgere l'agente del canale che
possiede quel tool». Il verbo lo aveva — la whitelist era già passata, misurato:
38 tool nella sessione, `email.send` incluso — e quello che gli mancava era la
credenziale.

Le conseguenze di quella confusione sono due, e la seconda è grave: l'agente
riferisce a un umano una diagnosi sbagliata (che non porta alla soluzione), e
tenta una **delega** per aggirare l'ostacolo. Delegare intorno a una credenziale
mancante è un confused deputy: l'altro agente userebbe la propria credenziale,
cioè un'uscita che nessuno ha autorizzato per quella richiesta.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import vault


class DenialMessageTests(unittest.TestCase):
    def _msg(self):
        with patch.object(vault, "grants_for", lambda _a: {}), \
                patch.object(vault, "_audit", lambda *a, **k: None):
            try:
                vault.get_secret("messaggero", "google_devnullboxx")
            except vault.VaultDenied as e:
                return str(e)
        self.fail("get_secret non ha rifiutato")

    def test_it_names_the_agent_and_the_credential(self):
        m = self._msg()
        self.assertIn("messaggero", m)
        self.assertIn("google_devnullboxx", m)

    def test_it_says_the_verb_was_allowed(self):
        """La distinzione che mancava. Senza, «non ha grant» si legge come «non
        hai il permesso per questo tool»."""
        m = self._msg()
        self.assertIn("VERBO", m)
        self.assertIn("whitelist", m)

    def test_it_forbids_the_delegation_instinct_explicitly(self):
        """L'istinto dell'agente è chiedere a un altro. Va contraddetto dove
        nasce, non solo bloccato a valle dall'intersezione della catena."""
        m = self._msg()
        self.assertIn("altro agente", m)
        self.assertIn("propria credenziale", m)

    def test_it_names_the_remedy(self):
        m = self._msg()
        self.assertIn("admin", m)
        self.assertIn("conceda", m)

    def test_it_does_not_name_who_holds_the_grant(self):
        """Elencare chi ha la credenziale sarebbe indicare l'agente a cui
        delegare: suggerirebbe la mossa che il messaggio esiste per impedire."""
        with patch.object(vault, "grants_for",
                          lambda a: {} if a == "messaggero" else {"google_devnullboxx": {}}), \
                patch.object(vault, "_audit", lambda *a, **k: None), \
                patch.object(vault, "agents_with_grant", lambda _c: ["clodia", "ophelia"]):
            try:
                vault.get_secret("messaggero", "google_devnullboxx")
            except vault.VaultDenied as e:
                m = str(e)
        self.assertNotIn("clodia", m)
        self.assertNotIn("ophelia", m)


if __name__ == "__main__":
    unittest.main()

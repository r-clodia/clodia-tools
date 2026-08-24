"""La card Google di /integrations deve poter essere PROVATA (clodia-platform#284).

Il bottone «Test» esiste nella webui da tempo e vale per ogni card connessa, ma
per Google cadeva nel ramo finale di `_test_connector` — «test non disponibile
per questa integrazione». Dal punto di vista di chi guarda la pagina non c'era
alcuna azione di verifica: il solo segnale sulla card era la parola «Connesso»,
che dice *la credenziale ha i campi giusti*, non *il consenso è ancora valido*.

È esattamente la classe di difetto già pagata sulle mailbox (#176): una parola
che promette più di quanto verifica manda a cercare il guasto dalla parte
sbagliata. Un refresh token Google si revoca da solo — app in Testing (7 giorni),
password cambiata, consenso ritirato dall'account — e finché nessuno chiama
Google la card resta verde su un collegamento morto.

I test qui sotto legano la card alla prova vera: rinnovo dell'access token dal
refresh token + una chiamata leggera (`userinfo`), per account.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import tools_api as ta


BUNDLE = {
    "client_id": "cid",
    "client_secret": "csec",
    "refresh_token": "RT-SEGRETO-NON-DEVE-USCIRE",
    "email": "owner@example.com",
    "scope": ("https://mail.google.com/ https://www.googleapis.com/auth/drive "
              "https://www.googleapis.com/auth/userinfo.email"),
}


def _vault(bundles: dict):
    """Vault finto: `bundles` è {nome_credenziale: bundle}."""
    return (
        patch.object(ta.vault, "store_names", lambda: sorted(bundles)),
        patch.object(ta.vault, "has_credential", lambda n: n in bundles),
        patch.object(ta.vault, "read_internal", lambda n: bundles[n]),
    )


class Base(unittest.TestCase):
    def run_with(self, ctx, fn):
        for c in ctx:
            c.start()
        try:
            return fn()
        finally:
            for c in ctx:
                c.stop()


class TheGoogleCardIsTestableTests(Base):
    def test_a_connected_google_account_reports_a_real_verdict(self):
        """Il difetto di #284: la card non aveva alcuna verifica e rispondeva
        «test non disponibile». Ora la risposta è un esito, non un'assenza."""
        def go():
            with patch.object(ta.go, "refresh_access_token",
                              return_value={"access_token": "AT", "scope": BUNDLE["scope"]}), \
                 patch.object(ta.go, "get_userinfo_email", return_value="owner@example.com"):
                r = ta._test_connector("google")
            self.assertIs(r["ok"], True, r["detail"])
            self.assertIn("owner@example.com", r["detail"])
        self.run_with(_vault({"google_owner": dict(BUNDLE)}), go)

    def test_the_test_actually_calls_google(self):
        """Un esito costruito senza chiamare il provider sarebbe la stessa
        bugia della parola «Connesso»: quello che si verifica è il consenso."""
        chiamate = []

        def finto_refresh(client_id, client_secret, refresh_token):
            chiamate.append((client_id, refresh_token))
            return {"access_token": "AT", "scope": BUNDLE["scope"]}

        def go():
            with patch.object(ta.go, "refresh_access_token", finto_refresh), \
                 patch.object(ta.go, "get_userinfo_email", return_value="owner@example.com"):
                ta._test_connector("google")
            self.assertEqual(chiamate, [("cid", BUNDLE["refresh_token"])])
        self.run_with(_vault({"google_owner": dict(BUNDLE)}), go)

    def test_a_revoked_consent_is_reported_as_broken(self):
        """Il caso che la card non sapeva vedere: campi tutti presenti, consenso
        morto. Deve diventare rosso, e dire cosa fare."""
        def go():
            with patch.object(ta.go, "refresh_access_token",
                              side_effect=RuntimeError(
                                  "consenso revocato o scaduto (invalid_grant): riconnetti l'account")):
                r = ta._test_connector("google")
            self.assertIs(r["ok"], False)
            self.assertIn("riconnetti", r["detail"])
        self.run_with(_vault({"google_owner": dict(BUNDLE)}), go)

    def test_the_refresh_token_never_appears_in_the_detail(self):
        """Il dettaglio finisce in un toast della webui e nei log: il segreto
        non ci passa, nemmeno dentro il messaggio d'errore del provider."""
        def go():
            with patch.object(ta.go, "refresh_access_token",
                              side_effect=RuntimeError(
                                  f"Google 400: token {BUNDLE['refresh_token']} rifiutato")):
                r = ta._test_connector("google")
            self.assertNotIn(BUNDLE["refresh_token"], r["detail"])
        self.run_with(_vault({"google_owner": dict(BUNDLE)}), go)

    def test_missing_fields_are_named_without_calling_the_network(self):
        """Una credenziale monca è già diagnosticata: chiamare Google per
        scoprirlo darebbe un errore di protocollo al posto della causa."""
        rotta = {k: v for k, v in BUNDLE.items() if k != "refresh_token"}

        def esplodi(*a, **k):  # pragma: no cover - deve restare non chiamata
            raise AssertionError("nessuna chiamata a Google senza refresh_token")

        def go():
            with patch.object(ta.go, "refresh_access_token", esplodi):
                r = ta._test_connector("google")
            self.assertIs(r["ok"], False)
            self.assertIn("refresh_token", r["detail"])
        self.run_with(_vault({"google_owner": rotta}), go)

    def test_one_broken_account_out_of_two_makes_the_card_red_and_names_both(self):
        """Come per le mailbox: l'esito è per account, e il verde complessivo
        richiede che stiano bene tutti."""
        def refresh(client_id, client_secret, refresh_token):
            if refresh_token == "RT-KO":
                raise RuntimeError("consenso revocato: riconnetti l'account")
            return {"access_token": "AT", "scope": BUNDLE["scope"]}

        def go():
            with patch.object(ta.go, "refresh_access_token", refresh), \
                 patch.object(ta.go, "get_userinfo_email", return_value="uno@example.com"):
                r = ta._test_connector("google")
            self.assertIs(r["ok"], False)
            self.assertIn("uno", r["detail"])
            self.assertIn("due", r["detail"])
        self.run_with(_vault({
            "google_uno": dict(BUNDLE),
            "google_due": dict(BUNDLE, refresh_token="RT-KO"),
        }), go)

    def test_no_google_account_is_not_a_failure(self):
        """«Non connesso» non è «rotto»: colorare di rosso una card mai
        connessa manda a cercare un guasto che non esiste."""
        def go():
            r = ta._test_connector("google")
            self.assertIsNone(r["ok"])
        self.run_with(_vault({"mailbox_studio": {}}), go)

    def test_a_narrowed_consent_is_reported_while_staying_green(self):
        """Il consenso può essere valido ma più stretto di quello chiesto (l'utente
        toglie una spunta): Drive fallirebbe dopo, sulla prima chiamata vera.
        La connessione funziona — verde — ma la card lo dice."""
        def go():
            with patch.object(ta.go, "refresh_access_token", return_value={
                "access_token": "AT",
                "scope": "https://www.googleapis.com/auth/userinfo.email",
            }), patch.object(ta.go, "get_userinfo_email", return_value="owner@example.com"):
                r = ta._test_connector("google")
            self.assertIs(r["ok"], True)
            # Il servizio si nomina come lo chiama l'owner. «drive» ricavato
            # dalla coda dell'URI sarebbe leggibile per caso; «mail.google.com»
            # (coda dello scope Gmail) non lo sarebbe affatto.
            self.assertIn("Drive", r["detail"])
            self.assertIn("Gmail", r["detail"])
            self.assertIn("riconnetti", r["detail"])
        self.run_with(_vault({"google_owner": dict(BUNDLE)}), go)

    def test_the_scaffolding_scopes_are_not_named_as_missing_services(self):
        """`openid`/`userinfo.email` non sono servizi che l'owner riconosce:
        nominarli sarebbe rumore su una card verde e sana."""
        def go():
            with patch.object(ta.go, "refresh_access_token", return_value={
                "access_token": "AT",
                "scope": ("https://mail.google.com/ "
                          "https://www.googleapis.com/auth/drive "
                          "https://www.googleapis.com/auth/documents "
                          "https://www.googleapis.com/auth/calendar"),
            }), patch.object(ta.go, "get_userinfo_email", return_value="owner@example.com"):
                r = ta._test_connector("google")
            self.assertIs(r["ok"], True)
            # Nessuna riserva di nessuna forma: il consenso è completo.
            self.assertEqual(r["detail"], "owner: ok (owner@example.com)")
        self.run_with(_vault({"google_owner": dict(BUNDLE)}), go)

    def test_a_silent_scope_field_is_not_an_alarm(self):
        """Se Google non riporta gli scope non si deduce nulla: dichiarare
        «fuori dal consenso» tutto ciò che non si è visto sarebbe un allarme
        inventato su un collegamento sano."""
        def go():
            with patch.object(ta.go, "refresh_access_token",
                              return_value={"access_token": "AT"}), \
                 patch.object(ta.go, "get_userinfo_email", return_value="owner@example.com"):
                r = ta._test_connector("google")
            self.assertIs(r["ok"], True)
            self.assertEqual(r["detail"], "owner: ok (owner@example.com)")
        self.run_with(_vault({"google_owner": dict(BUNDLE)}), go)

    def test_other_credentials_are_not_dragged_into_the_google_card(self):
        """La card `google` mostra gli account `google_*` (list_tools): provare
        anche i legacy dichiarerebbe rotta una card per un account che non
        elenca, e il rimedio non sarebbe da nessuna parte nella pagina."""
        def esplodi(*a, **k):  # pragma: no cover
            raise AssertionError("nessun account google_*: niente da provare")

        def go():
            with patch.object(ta.go, "refresh_access_token", esplodi):
                r = ta._test_connector("google")
            self.assertIsNone(r["ok"])
        self.run_with(_vault({"gmail_vecchio": dict(BUNDLE),
                              "mailbox_studio": {}}), go)

    def test_a_legacy_card_tests_its_own_credentials(self):
        """Le card storiche (Gmail, Google Workspace connessi separatamente) non
        sono più in `BASE`, ma un'istanza non aggiornata le mostra ancora.
        Puntarle sul prefisso unificato direbbe «nessun account connesso» a chi
        ne ha uno — sotto un altro nome: la prova cercherebbe dove non è."""
        provati = []

        def refresh(client_id, client_secret, refresh_token):
            provati.append(refresh_token)
            return {"access_token": "AT"}

        def go():
            with patch.object(ta.go, "refresh_access_token", refresh), \
                 patch.object(ta.go, "get_userinfo_email", return_value="vecchio@example.com"):
                r = ta._test_connector("gworkspace")
            self.assertIs(r["ok"], True, r["detail"])
            self.assertIn("vecchio", r["detail"])
            self.assertEqual(provati, ["RT-LEGACY"])
        self.run_with(_vault({"google_owner": dict(BUNDLE),
                              "gworkspace_vecchio": dict(BUNDLE, refresh_token="RT-LEGACY")}), go)

    def test_a_legacy_card_is_measured_against_its_own_consent(self):
        """Il consenso Workspace non contiene Gmail: misurarlo su quello
        unificato accuserebbe «fuori dal consenso: Gmail» una card che Gmail
        non l'ha mai promesso."""
        def go():
            with patch.object(ta.go, "refresh_access_token", return_value={
                "access_token": "AT", "scope": ta.go.WORKSPACE_SCOPE,
            }), patch.object(ta.go, "get_userinfo_email", return_value="vecchio@example.com"):
                r = ta._test_connector("gworkspace")
            self.assertIs(r["ok"], True)
            self.assertNotIn("Gmail", r["detail"])
        self.run_with(_vault({"gworkspace_vecchio": dict(BUNDLE)}), go)


class TheRefreshHelperTests(unittest.TestCase):
    """Il rinnovo dal refresh token è l'unico pezzo mancante lato helper: Drive
    e Docs lo ottengono dalla libreria Google, che qui non si può usare (la
    credenziale è dell'owner, non di un agente, e non passa da `get_secret`)."""

    def test_invalid_grant_becomes_an_instruction_not_a_stack_trace(self):
        import io
        import json
        import urllib.error
        from . import google_oauth as go

        errore = urllib.error.HTTPError(
            go.TOKEN_URL, 400, "Bad Request", {},
            io.BytesIO(json.dumps({"error": "invalid_grant",
                                   "error_description": "Token has been expired or revoked."}).encode()))
        with patch.object(go, "urlopen", side_effect=errore):
            with self.assertRaises(RuntimeError) as ctx:
                go.refresh_access_token("cid", "csec", "RT")
        self.assertIn("riconnetti", str(ctx.exception).lower())

    def test_the_secret_is_not_echoed_in_the_error(self):
        import io
        import urllib.error
        from . import google_oauth as go

        errore = urllib.error.HTTPError(go.TOKEN_URL, 401, "Unauthorized", {}, io.BytesIO(b"nope"))
        with patch.object(go, "urlopen", side_effect=errore):
            with self.assertRaises(RuntimeError) as ctx:
                go.refresh_access_token("cid", "csec", "RT-SEGRETO")
        self.assertNotIn("RT-SEGRETO", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

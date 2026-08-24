"""La card Google di /integrations deve poter PROVARE la connessione.

clodia-platform#284. La card è connessa, il bottone «Test» c'è nella webui
(`clodia-web` src/routes/tools/+page.svelte), l'endpoint c'è
(`POST /tools/{id}/test`) — ma `_test_connector` non conosceva l'id `google` e
cadeva nel ramo finale «test non disponibile per questa integrazione». Sulla
card questo si vede come il badge «—»: l'unica integrazione che apre CINQUE
servizi era anche la sola, insieme alle mailbox (già chiuse in #176), a non
avere una prova reale.

Cosa dice «connesso» oggi, senza questa prova: che i campi della credenziale ci
sono (`credential_diagnostics`). Non che il refresh token sia ancora valido —
ed è proprio quello che scade, viene revocato dal proprietario dell'account o
invalidato da un secondo consenso sugli stessi scope. Quel guasto, senza prova,
si manifesta ore dopo dentro un tool (`email.send`, `gdrive.list`) e non nella
pagina che dovrebbe dirlo.

I test qui sotto fissano le tre distinzioni che contano: «non funziona» (refresh
rifiutato → rosso), «non c'è» (nessun account → non testabile), «non fa quella
cosa» (consenso incompleto → verde che nomina il servizio mancante, come «solo
invio» per le caselle).
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import tools_api


class _Risposta:
    """Risposta HTTP finta: solo ciò che il codice sotto test legge."""

    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}

    def json(self):
        return self._payload


BUNDLE = {
    "client_id": "1234.apps.googleusercontent.com",
    "client_secret": "il-segreto-dell-app",
    "refresh_token": "il-refresh-token",
    "email": "owner@example.com",
    "scope": tools_api.go.UNIFIED_SCOPE,
}

TOKEN_OK = {"access_token": "at-1", "scope": tools_api.go.UNIFIED_SCOPE}
USERINFO_OK = {"email": "owner@example.com"}


def _vault(creds: dict):
    """Vault finto: solo i nomi e la lettura interna, come fa il codice reale."""
    return (
        patch.object(tools_api.vault, "store_names", lambda: sorted(creds)),
        patch.object(tools_api.vault, "read_internal", lambda n: creds[n]),
        patch.object(tools_api.vault, "has_credential", lambda n: n in creds),
    )


class Base(unittest.TestCase):
    def _prova(self, creds: dict, cid: str = "google", post=None, get=None):
        ctx = list(_vault(creds))
        if post is not None:
            ctx.append(patch("requests.post", post))
        if get is not None:
            ctx.append(patch("requests.get", get))
        for c in ctx:
            c.start()
        try:
            return tools_api._test_connector(cid)
        finally:
            for c in reversed(ctx):
                c.stop()


class GoogleTestConnectionTests(Base):
    def test_the_google_card_is_testable_at_all(self):
        """Il difetto della issue: `google` cadeva nel ramo «non disponibile»,
        cioè il badge «—» su una card che dice «Connesso»."""
        r = self._prova(
            {"google_owner": BUNDLE},
            post=lambda *a, **k: _Risposta(200, TOKEN_OK),
            get=lambda *a, **k: _Risposta(200, USERINFO_OK),
        )
        self.assertIsNot(r["ok"], None, r["detail"])
        self.assertNotIn("non disponibile", r["detail"])

    def test_a_working_credential_names_the_account_it_reached(self):
        """«ok» da solo non si distingue da «ok» di un altro account: l'esito
        nomina l'indirizzo che l'API ha risposto, non quello nel bundle."""
        r = self._prova(
            {"google_owner": BUNDLE},
            post=lambda *a, **k: _Risposta(200, TOKEN_OK),
            get=lambda *a, **k: _Risposta(200, {"email": "vero@example.com"}),
        )
        self.assertTrue(r["ok"])
        self.assertIn("vero@example.com", r["detail"])

    def test_a_revoked_consent_is_red_and_says_what_to_do(self):
        """`invalid_grant` è IL guasto di questa integrazione: consenso revocato
        o refresh token scalzato. Il rimedio (riconnettere) va nell'esito."""
        r = self._prova(
            {"google_owner": BUNDLE},
            post=lambda *a, **k: _Risposta(400, {"error": "invalid_grant"}),
            get=lambda *a, **k: _Risposta(200, USERINFO_OK),
        )
        self.assertIs(r["ok"], False)
        self.assertIn("riconnett", r["detail"].lower())

    def test_an_incomplete_consent_is_not_a_broken_connection(self):
        """La card promette cinque servizi. Se il consenso non copre Drive, la
        connessione FUNZIONA e una parte non c'è: è «non fa quella cosa», la
        stessa distinzione di «solo invio» per le caselle. Verde, con il nome
        del servizio mancante — non rosso, che manderebbe a rigenerare un token
        sano."""
        parziale = " ".join(s for s in tools_api.go.UNIFIED_SCOPE.split()
                            if "drive" not in s)
        r = self._prova(
            {"google_owner": BUNDLE},
            post=lambda *a, **k: _Risposta(200, {"access_token": "at-1",
                                                 "scope": parziale}),
            get=lambda *a, **k: _Risposta(200, USERINFO_OK),
        )
        self.assertTrue(r["ok"])
        self.assertIn("Drive", r["detail"])

    def test_no_google_account_is_not_a_failure(self):
        """Nessun account connesso non è un guasto: è niente da provare. Rosso
        qui manderebbe a cercare una credenziale rotta che non esiste."""
        r = self._prova({"telegram_bot_token": {"value": "t"}})
        self.assertIs(r["ok"], None)
        self.assertIn("nessun", r["detail"].lower())

    def test_a_credential_missing_fields_never_reaches_the_network(self):
        """Un bundle senza refresh token si giudica dal vault: chiamare Google
        con un token vuoto ritornerebbe un errore del provider al posto del
        nome del campo che manca."""
        chiamate = []

        def _post(*a, **k):
            chiamate.append(a)
            return _Risposta(200, TOKEN_OK)

        r = self._prova(
            {"google_owner": {k: v for k, v in BUNDLE.items() if k != "refresh_token"}},
            post=_post,
            get=lambda *a, **k: _Risposta(200, USERINFO_OK),
        )
        self.assertIs(r["ok"], False)
        self.assertIn("refresh_token", r["detail"])
        self.assertEqual(chiamate, [])

    def test_the_secret_never_appears_in_the_result(self):
        """L'esito torna alla webui: il bundle non ci entra, per nessun ramo."""
        esiti = [
            self._prova({"google_owner": BUNDLE},
                        post=lambda *a, **k: _Risposta(200, TOKEN_OK),
                        get=lambda *a, **k: _Risposta(200, USERINFO_OK)),
            self._prova({"google_owner": BUNDLE},
                        post=lambda *a, **k: _Risposta(400, {"error": "invalid_grant"}),
                        get=lambda *a, **k: _Risposta(200, USERINFO_OK)),
        ]
        for r in esiti:
            self.assertNotIn(BUNDLE["client_secret"], r["detail"])
            self.assertNotIn(BUNDLE["refresh_token"], r["detail"])

    def test_one_broken_account_among_many_is_reported_by_name(self):
        """Con più account l'esito complessivo è rosso, e dice QUALE: un rosso
        anonimo su tre account costa tre riconnessioni."""
        def _post(url, data=None, **k):
            if (data or {}).get("refresh_token") == "rotto":
                return _Risposta(400, {"error": "invalid_grant"})
            return _Risposta(200, TOKEN_OK)

        r = self._prova(
            {"google_buono": BUNDLE,
             "google_rotto": {**BUNDLE, "refresh_token": "rotto"}},
            post=_post,
            get=lambda *a, **k: _Risposta(200, USERINFO_OK),
        )
        self.assertIs(r["ok"], False)
        self.assertIn("rotto", r["detail"])
        self.assertIn("buono", r["detail"])

    def test_a_network_failure_is_not_a_bad_token(self):
        """Rete giù ≠ credenziale invalida. Confonderle fa riconnettere un
        account sano (e il consenso nuovo scalza il refresh token vecchio)."""
        import requests

        def _post(*a, **k):
            raise requests.RequestException("connection reset")

        r = self._prova({"google_owner": BUNDLE}, post=_post)
        self.assertIs(r["ok"], False)
        self.assertIn("rete", r["detail"].lower())

    def test_the_legacy_workspace_credential_is_testable_too(self):
        """Le istanze connesse prima del consenso unificato hanno
        `gworkspace_<account>`: la prova vale anche per loro, altrimenti la
        migrazione lascia indietro proprio chi non l'ha ancora fatta."""
        r = self._prova(
            {"gworkspace_owner": {**BUNDLE, "scope": tools_api.go.WORKSPACE_SCOPE}},
            cid="gworkspace",
            post=lambda *a, **k: _Risposta(200, {"access_token": "at-1",
                                                 "scope": tools_api.go.WORKSPACE_SCOPE}),
            get=lambda *a, **k: _Risposta(200, USERINFO_OK),
        )
        self.assertTrue(r["ok"], r["detail"])

    def test_the_unified_card_does_not_test_the_legacy_credentials(self):
        """La card `google` elenca gli account `google_*` (list_tools li prende
        da `credential_diagnostics` con kind=google). Provare anche i legacy
        farebbe apparire rossa una card per un account che non mostra."""
        r = self._prova({"gmail_vecchio": BUNDLE})
        self.assertIs(r["ok"], None)


if __name__ == "__main__":
    unittest.main()

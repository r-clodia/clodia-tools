"""Il consenso atteso è quello che la CARD promette, non quello del connettore
nuovo — e vale anche per le card legacy.

clodia-platform#285. La prova della card Google (#284, PR #231) confronta gli
scope concessi con quelli attesi, ma `atteso` lo calcolava così:

    atteso = go.UNIFIED_SCOPE if cid == "google" else ""

cioè sulle card `gworkspace` e `gmail` il confronto **non girava affatto**: una
stringa vuota non ha scope da cercare, quindi `mancanti` era sempre vuoto. Un
consenso Workspace vivo ma senza Drive rispondeva `ok (owner@…)` e basta. Il
rilevatore era cieco esattamente sulle istanze non ancora migrate al consenso
unificato, che sono le sole a cui quelle card vengono mostrate.

Il rimedio ovvio — misurare tutte le card su `UNIFIED_SCOPE` — è il difetto
opposto, e i test qui sotto lo bloccano: la card Workspace non ha mai promesso
Gmail, e accusarla di non averlo manderebbe a riconnettere un account sano (il
consenso nuovo scalza il refresh token buono). Ogni id di card porta quindi il
proprio prefisso nel vault E il consenso che quella card promette.

Le impalcature del banco di prova (vault finto, risposte HTTP finte) sono quelle
del test della #284: si riusano invece di riscriverle, così una modifica al
banco resta in un posto solo.
"""
from __future__ import annotations

import unittest

from . import tools_api
from .test_284_google_test_connection import BUNDLE, USERINFO_OK, Base, _Risposta


def _senza(scope: str, pezzo: str) -> str:
    """Lo stesso consenso, meno un servizio: un consenso ristretto come lo
    produce l'utente che riautorizza togliendo una spunta."""
    return " ".join(s for s in scope.split() if pezzo not in s)


class ConsensoRistrettoSulleCardLegacy(Base):
    def test_a_narrowed_consent_on_a_legacy_card_is_reported_too(self):
        """Il difetto della issue: `gworkspace` non aveva uno scope atteso, e un
        consenso senza Drive passava per completo. La card promette Drive, Docs
        e Calendar: se Drive non c'è va detto lì, non dentro `gdrive.list` ore
        dopo."""
        r = self._prova(
            {"gworkspace_owner": BUNDLE},
            cid="gworkspace",
            post=lambda *a, **k: _Risposta(200, {
                "access_token": "at-1",
                "scope": _senza(tools_api.go.WORKSPACE_SCOPE, "drive"),
            }),
            get=lambda *a, **k: _Risposta(200, USERINFO_OK),
        )
        self.assertTrue(r["ok"], r["detail"])   # funziona, per meno cose
        self.assertIn("Drive", r["detail"])

    def test_the_legacy_gmail_card_is_measured_on_the_gmail_consent(self):
        """Idem per `gmail`, la cui promessa è un servizio solo: se manca, la
        card non ha più niente da offrire e deve dirlo."""
        r = self._prova(
            {"gmail_owner": BUNDLE},
            cid="gmail",
            post=lambda *a, **k: _Risposta(200, {
                "access_token": "at-1",
                "scope": _senza(tools_api.go.SCOPE, "mail.google.com"),
            }),
            get=lambda *a, **k: _Risposta(200, USERINFO_OK),
        )
        self.assertTrue(r["ok"], r["detail"])
        self.assertIn("Gmail", r["detail"])

    def test_a_legacy_card_is_not_measured_on_the_unified_consent(self):
        """La guardia contro il rimedio sbagliato. Un consenso Workspace INTERO
        è completo per la card Workspace: misurarlo su `UNIFIED_SCOPE` lo
        accuserebbe di non avere Gmail — che quella card non elenca — e la
        riconnessione suggerita rigenererebbe un consenso sano, scalzando il
        refresh token che funziona."""
        r = self._prova(
            {"gworkspace_owner": BUNDLE},
            cid="gworkspace",
            post=lambda *a, **k: _Risposta(200, {
                "access_token": "at-1",
                "scope": tools_api.go.WORKSPACE_SCOPE,
            }),
            get=lambda *a, **k: _Risposta(200, USERINFO_OK),
        )
        self.assertTrue(r["ok"], r["detail"])
        self.assertNotIn("fuori dal consenso", r["detail"])
        self.assertNotIn("Gmail", r["detail"])

    def test_the_scaffolding_scopes_are_not_named_as_missing_services(self):
        """`openid` e `userinfo.email` servono a ricavare l'indirizzo, non sono
        servizi che chi legge la card riconosca. Un consenso che li ha lasciati
        indietro non deve produrre una riserva su una card per il resto sana:
        sarebbe un avviso che si impara a ignorare, cioè il `—` grigio che la
        #284 esisteva per togliere. (Il filtro c'è già: questo test lo blocca,
        non lo introduce.)"""
        completo_meno_impalcatura = _senza(
            _senza(tools_api.go.UNIFIED_SCOPE, "userinfo.email"), "openid")
        r = self._prova(
            {"google_owner": BUNDLE},
            post=lambda *a, **k: _Risposta(200, {
                "access_token": "at-1",
                "scope": completo_meno_impalcatura,
            }),
            get=lambda *a, **k: _Risposta(200, USERINFO_OK),
        )
        self.assertTrue(r["ok"], r["detail"])
        self.assertNotIn("fuori dal consenso", r["detail"])
        for rumore in ("openid", "userinfo", "email"):
            self.assertNotIn(f"fuori dal consenso: {rumore}", r["detail"])

    def test_every_testable_google_card_has_an_expected_consent(self):
        """Il difetto era una mappa con un buco, e un buco si ripresenta al
        prossimo id aggiunto. Il dispatch di `_test_connector` e la tabella del
        consenso atteso devono essere la STESSA tabella: due mappe sulle stesse
        chiavi divergono, e a divergere sarebbe di nuovo lo scope atteso."""
        for cid, (prefisso, atteso) in tools_api._GOOGLE_CARD.items():
            self.assertTrue(prefisso.endswith("_"), cid)
            self.assertTrue(atteso.strip(), f"{cid}: nessun consenso atteso")
            # Ogni card promette almeno un servizio con un nome leggibile:
            # altrimenti la riserva non sarebbe nominabile e tacerebbe.
            self.assertTrue(
                [s for s in atteso.split() if s in tools_api._GOOGLE_SERVIZI],
                f"{cid}: nessuno scope nominabile fra quelli attesi")


if __name__ == "__main__":
    unittest.main()

"""Ingresso STRETTO di un canale: `mailfrom:` diventa un limite d'accesso.

Il difetto (clodia-platform#503). `inbox:<casella>` era un limite vero —
`_secrets_env` rifiuta una casella non in lista — mentre `mailfrom:<mittente>`
non lo era affatto: alimentava solo il taint. In un canale che dichiarava
`inbox:A` + `mailfrom:S` un agente leggeva comunque OGNI messaggio arrivato in
A, da chiunque, e poteva rispondere a chiunque fosse elencato come
destinazione. La dichiarazione prometteva un perimetro che a runtime non
esisteva.

Qui si verifica l'interruttore `ingress_strict` per scope: quando è acceso,
`mailfrom:` governa l'accesso e non solo la fiducia.

Tre cose che questi test tengono ferme, e che sono la sostanza della issue:

1. **lo stretto stringe davvero**: le voci GLOBALI di ingresso non valgono in
   un canale stretto. Senza questa sottrazione una casella dichiarata
   nell'istanza resterebbe leggibile ovunque, e «stretto» sarebbe una parola;
2. **si filtra dopo il CLI, non con una query**: la query IMAP la scrive il
   chiamante, e un filtro che il chiamante può riscrivere non è un filtro. Di
   ciò che si toglie esce solo il NUMERO: un oggetto o un indirizzo sarebbero
   il contenuto rifiutato fatto passare dalla porta di servizio;
3. **fail-closed**: un `From:` che non si parsa non è vagliato. Sbagliare in
   questa direzione è silenzioso — un filtro che non scatta non lo si vede.

E il buco accanto, che la issue chiedeva di chiudere nella stessa passata: gli
account LEGACY di `email_config.json` saltavano del tutto la whitelist
`inbox:`/`outbox:`, perché `_secrets_env` usciva dal ramo «nessuna credenziale
in vault» senza chiedere niente a nessuno.

The filtering of listings, reads, attachments and replies — and the legacy
accounts — were the native mail client's (`tools/email.py`); with it removed
(#523) they are comms-pack's component's and tested there. What stays here is
the gateway's half: the switch and what it subtracts, and the refusal class.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import egress as E
from . import whitelist as w

#: La stanza: Davide owner, clodia partecipante. Il perimetro è già una
#: decisione presa, e in un canale stretto continua a valere (altrimenti lo
#: stretto escluderebbe chi sta dentro).
META = {"tier": "SEAL-1", "owner": "davide",
        "participants": {"clodia": "contributor"}}

SEEDS = {
    "davide": {"type": "human", "role": "superadmin", "email": "davide@example.it"},
    "clodia": {"type": "normal", "email": "clodia@example.it"},
}

SCOPE = "SEAL-1/acme"
FORNITORE = "ordini@fornitore.it"        # il `mailfrom:` dichiarato nel canale
ESTRANEO = "spam@altrove.it"             # nessuno l'ha dichiarato


class _Svc:
    def open(self, tier, name):
        return {"meta": META}


class _Chan:
    def __init__(self, v):
        self.v = v

    def __enter__(self):
        self.t = w.set_current_chat(self.v)
        return self

    def __exit__(self, *a):
        w.reset_current_chat(self.t)
        return False


def cfg(*, globali_ingress=(), scope_ingress=(), stretto=None, egressi=()):
    return {
        "egress_allow": list(egressi),
        "scope_egress_allow": {},
        "source_allow": list(globali_ingress),
        "scope_source_allow": {SCOPE: list(scope_ingress)},
        "scope_ingress_strict": dict(stretto or {}),
        "agents": {},
    }


class Base(unittest.TestCase):
    """Canale stretto con `inbox:casella` + `mailfrom:fornitore` dichiarati."""

    STRETTO = {SCOPE: True}

    def setUp(self):
        from . import human as H
        from . import main as M
        self.config = cfg(
            globali_ingress=["inbox:globale@example.it", f"mailfrom:{ESTRANEO}"],
            scope_ingress=["inbox:acme@example.it", f"mailfrom:{FORNITORE}"],
            stretto=self.STRETTO,
        )
        self.decisioni: list[tuple] = []
        ctx = [
            patch.object(H, "_seed", lambda n: SEEDS.get(n, {})),
            patch.object(M, "_topics", lambda: _Svc()),
            patch.object(w, "CONFIG", self.config),
        ]
        for c in ctx:
            c.start()
        self.addCleanup(lambda: [c.stop() for c in ctx])

    def in_room(self, scope=SCOPE):
        return _Chan(f"chan:{scope.replace('/', ':')}:clodia")


# --------------------------------------------------------------------------
# L'interruttore e ciò che sottrae
# --------------------------------------------------------------------------
class FlagTests(Base):
    def test_default_is_off(self):
        """Un canale che non dichiara niente non cambia comportamento."""
        with patch.object(w, "CONFIG", cfg(scope_ingress=["inbox:acme@example.it"])):
            with self.in_room():
                self.assertFalse(E.ingress_strict())

    def test_on_when_declared_for_this_scope(self):
        with self.in_room():
            self.assertTrue(E.ingress_strict())

    def test_another_room_is_not_strict_because_this_one_is(self):
        with self.in_room("SEAL-1/beta"):
            self.assertFalse(E.ingress_strict())

    def test_a_legacy_tier_alias_is_the_same_room(self):
        """`P1/acme` e `SEAL-1/acme` sono un posto solo: due chiavi
        significherebbero un interruttore che qualcuno ha acceso e nessuno
        legge."""
        self.config["scope_ingress_strict"] = {"P1/ACME": True}
        with self.in_room():
            self.assertTrue(E.ingress_strict())

    def test_outside_a_room_there_is_nothing_to_narrow(self):
        self.assertFalse(E.ingress_strict())

    def test_strict_ignores_the_global_ingress_list(self):
        """Il cuore della decisione: senza questo, una casella dichiarata
        nell'istanza resta leggibile anche nel canale che voleva una sola
        fonte."""
        with self.in_room():
            self.assertEqual(E.ingress_rules(),
                             ["inbox:acme@example.it", f"mailfrom:{FORNITORE}"])
            self.assertFalse(E.is_vetted_source(f"mailfrom:{ESTRANEO}"))
            self.assertFalse(E.mailbox_allowed("inbox", "globale@example.it"))

    def test_without_strict_the_union_holds(self):
        """Regressione: i canali di oggi continuano a vedere la lista globale."""
        self.config["scope_ingress_strict"] = {}
        with self.in_room():
            self.assertTrue(E.is_vetted_source(f"mailfrom:{ESTRANEO}"))
            self.assertTrue(E.mailbox_allowed("inbox", "globale@example.it"))

    def test_strict_does_not_touch_the_way_out(self):
        """Lo stretto è dell'INGRESSO. Stringere anche l'uscita sarebbe una
        seconda decisione, presa di nascosto dentro la prima."""
        self.config["egress_allow"] = ["outbox:globale@example.it"]
        with self.in_room():
            self.assertTrue(E.mailbox_allowed("outbox", "globale@example.it"))

    def test_the_room_still_vouches_for_its_own_people(self):
        with self.in_room():
            self.assertTrue(E.is_vetted_source("mailfrom:davide@example.it"))
            self.assertTrue(E.is_vetted_source("mailfrom:clodia@example.it"))


# --------------------------------------------------------------------------
# Elenchi: si filtra, e si dice quanti
# --------------------------------------------------------------------------
def _msg(n, mittente, oggetto="niente"):
    return {"id": str(n), "from": mittente, "to": "acme@example.it",
            "subject": oggetto, "date": "ieri"}


class DenialClassTests(unittest.TestCase):
    def test_the_refusal_is_classified_not_lumped_into_other(self):
        """`main._denial_class` riconosce questo rifiuto dalla frase marcata:
        se la frase cambia da una parte e non dall'altra, la decisione tornerebbe
        `other` senza che nessuno se ne accorga."""
        from . import main as M
        msg = (f"{M.MITTENTE_NON_VAGLIATO}: questo canale è a INGRESSO STRETTO "
               "e ammette solo…")
        self.assertEqual(M._denial_class(msg), "sender_not_vetted")

    def test_other_refusals_keep_their_class(self):
        from . import main as M
        self.assertEqual(M._denial_class("uscita non consentita"), "egress")
        self.assertEqual(M._denial_class("qualcosa d'altro"), "other")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()


from .connectors import first_party_fixture as _first_party


def setUpModule() -> None:
    # The first-party packs, installed as on every instance: since the switch
    # was retired (#526) the tables pinned here are theirs, not the gateway's.
    _first_party.install()


def tearDownModule() -> None:
    _first_party.uninstall()

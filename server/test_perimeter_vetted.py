"""Chi è nella stanza è una fonte fidata in quanto tale.

Davide, 6 ago 2026: «sono d'accordo a prevedere una whitelist anche dei mittenti
email». Fatta (C1), resta la domanda che la whitelist da sola non risolve: se
Giovanni è partecipante di `proof-of-flex` e scrive al topic, deve essere anche
elencato in `source_allow` perché la sua mail non contamini?

No. L'appartenenza al perimetro **è già** la decisione. Riscriverne i recapiti in
una lista è la stessa regola scritta due volte, e due copie divergono: un
partecipante rimosso dal topic resterebbe fidato finché qualcuno non si ricorda
di togliere anche il suo indirizzo — e nessuno se ne accorgerebbe, perché un
taint che non si accende non si vede. È il difetto più costoso disponibile qui,
perché è silenzioso in entrambi i versi.

Il confine di questa regola è stretto di proposito: vale per la posta, dove «di
chi è questo messaggio» ha una risposta netta. Un URL o una cartella non
appartengono a nessuno allo stesso modo, e spegnere il taint per un motivo che
non si sa spiegare è peggio che non spegnerlo.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import egress as E
from . import whitelist as w


META = {"tier": "SEAL-1", "owner": "davide",
        "participants": {"giovanni": "reader", "clodia": "contributor"}}

SEEDS = {
    "davide": {"type": "human", "role": "superadmin", "email": "davide@example.it"},
    "giovanni": {"type": "human", "role": "member", "email": "Giovanni@Example.IT"},
    "clodia": {"type": "normal", "email": "clodia@example.it"},
    "estraneo": {"type": "human", "role": "member", "email": "estraneo@altrove.it"},
}


class _Svc:
    def open(self, tier, name):
        return {"meta": META}


class Base(unittest.TestCase):
    def setUp(self):
        from . import human as H
        from . import main as M
        self.ctx = [
            patch.object(H, "_seed", lambda n: SEEDS.get(n, {})),
            patch.object(M, "_topics", lambda: _Svc()),
            patch.object(w, "CONFIG", {}),   # nessuna lista dichiarata
        ]
        for c in self.ctx:
            c.start()
        self.addCleanup(lambda: [c.stop() for c in self.ctx])

    def in_room(self, scope="SEAL-1/acme"):
        return _Chan(f"chan:{scope.replace('/', ':')}:clodia")


class _Chan:
    def __init__(self, v):
        self.v = v

    def __enter__(self):
        self.t = w.set_current_chat(self.v)
        return self

    def __exit__(self, *a):
        w.reset_current_chat(self.t)
        return False


class MembershipTests(Base):
    def test_a_participant_is_vetted_without_being_listed(self):
        """Il punto della voce: nessuna lista dichiarata, eppure fidato."""
        with self.in_room():
            self.assertTrue(E.is_vetted_source("mailfrom:giovanni@example.it"))

    def test_the_owner_is_vetted_too(self):
        with self.in_room():
            self.assertTrue(E.is_vetted_source("mailfrom:davide@example.it"))

    def test_an_agent_in_the_room_counts_as_much_as_a_human(self):
        """Distinguerli renderebbe fidato un partecipante e non l'altro senza
        che la differenza sia stata decisa da nessuno."""
        with self.in_room():
            self.assertTrue(E.is_vetted_source("mailfrom:clodia@example.it"))

    def test_someone_outside_the_room_is_not(self):
        with self.in_room():
            self.assertFalse(E.is_vetted_source("mailfrom:estraneo@altrove.it"))

    def test_the_address_comparison_ignores_case(self):
        """Il seed di Giovanni scrive `Giovanni@Example.IT`."""
        with self.in_room():
            self.assertTrue(E.is_vetted_source("mailfrom:GIOVANNI@example.it"))

    def test_a_display_name_around_the_address_still_matches(self):
        with self.in_room():
            self.assertTrue(
                E.is_vetted_source("mailfrom:Giovanni Rossi <giovanni@example.it>"))


class BoundaryTests(Base):
    def test_outside_a_room_there_is_no_perimeter(self):
        """Un job non ha partecipanti: lì vale solo ciò che è dichiarato."""
        self.assertFalse(E.is_vetted_source("mailfrom:giovanni@example.it"))
        self.assertEqual(E.perimeter_addresses(), set())

    def test_membership_does_not_vouch_for_urls(self):
        """Un URL non appartiene a nessuno come una mail: allargare qui
        spegnerebbe il taint per un motivo che non si può spiegare."""
        with self.in_room():
            self.assertFalse(E.is_perimeter_source("https://example.it/x"))
            self.assertFalse(E.is_perimeter_source("gdrive:folder/abc"))
            self.assertFalse(E.is_perimeter_source("mcp:normattiva.search"))

    def test_an_unreadable_topic_vouches_for_nobody(self):
        """Fail-closed: un guasto non deve diventare un permesso."""
        from . import main as M

        class _Rotto:
            def open(self, t, n):
                raise RuntimeError("giù")

        with patch.object(M, "_topics", lambda: _Rotto()), self.in_room():
            self.assertEqual(E.perimeter_addresses(), set())
            self.assertFalse(E.is_vetted_source("mailfrom:giovanni@example.it"))

    def test_a_member_with_no_declared_address_vouches_for_nothing(self):
        """Nessun recapito, nessuna corrispondenza: e soprattutto una stringa
        vuota non deve combaciare con una stringa vuota."""
        with patch.dict(SEEDS, {"giovanni": {"type": "human", "role": "member"}}), \
             self.in_room():
            self.assertFalse(E.is_vetted_source("mailfrom:"))
            self.assertNotIn("", E.perimeter_addresses())


class LegacyTests(Base):
    def test_a_legacy_participant_list_still_forms_a_perimeter(self):
        """I topic non ancora convertiti alla mappa non devono perdere il
        perimetro: sarebbe una rottura silenziosa travestita da irrigidimento."""
        class _S:
            def open(self, t, n):
                return {"meta": {"tier": "SEAL-1", "owner": "davide",
                                 "participants": ["giovanni"]}}

        from . import main as M
        with patch.object(M, "_topics", lambda: _S()), self.in_room():
            self.assertTrue(E.is_vetted_source("mailfrom:giovanni@example.it"))


class CoexistenceTests(Base):
    def test_a_declared_source_still_works(self):
        """La regola è additiva: aggiunge il perimetro, non sostituisce le
        liste."""
        with patch.object(w, "CONFIG",
                          {"source_allow": ["mailfrom:fornitore@terzi.it"]}), \
             self.in_room():
            self.assertTrue(E.is_vetted_source("mailfrom:fornitore@terzi.it"))
            self.assertTrue(E.is_vetted_source("mailfrom:giovanni@example.it"))


if __name__ == "__main__":
    unittest.main()

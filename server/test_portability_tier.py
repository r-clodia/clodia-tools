"""La portabilità avviene solo se la stanza regge il tier del topic portato.

Punto aperto 6, chiuso da Davide il 7 ago 2026: «se il topic portabile TP ha
SEAL-3, allora di sicuro un participant Alice sarà SEAL-3 o superiore. Se Alice
viene convocata in un topic T SEAL-1 semplicemente non avviene la portabilità dei
dati: Alice potrà partecipare in T ma i dati di TP non saranno a sua
disposizione».

È l'anello più debole applicato al trasporto, e la forma è più fine delle due che
avevo proposto — né un cap sull'appartenenza né un confino della portabilità ai
tier bassi. Il vincolo non sta su chi porta, che la clearance ce l'ha già per
essere participant di TP: sta sulla **stanza**, dove i dati sarebbero letti dai
partecipanti di quella.

**Si rifiuta, non si gata.** Un gate lascerebbe a qualcuno la facoltà di
approvare proprio il travaso che questa regola esiste per impedire, e il consenso
di un owner non alza il tier di una stanza.

**E il rifiuto si dice.** Senza, la portabilità degraderebbe in silenzio: in T
Alice non vede i dati e il suo agente conclude che l'archivio sia vuoto, non che
sia fuori portata. Un agente che sa di non poter vedere chiede; uno che crede di
aver visto tutto risponde male.
"""
from __future__ import annotations

import unittest

from . import main as M


TP = {"tier": "SEAL-3"}


class PortabilityTests(unittest.TestCase):
    def test_a_room_at_the_same_tier_carries(self):
        M._require_room_carries(TP, "SEAL-3", "tp", "SEAL-3/alta")

    def test_a_higher_room_carries(self):
        """Il requisito è un minimo: una stanza più riservata regge dati meno
        riservati."""
        M._require_room_carries(TP, "SEAL-3", "tp", "SEAL-4/altissima")

    def test_a_lower_room_does_not(self):
        with self.assertRaises(PermissionError):
            M._require_room_carries(TP, "SEAL-3", "tp", "SEAL-1/bassa")

    def test_the_refusal_names_both_levels(self):
        """Perché il rimedio dipende da quale dei due si può cambiare."""
        with self.assertRaises(PermissionError) as cm:
            M._require_room_carries(TP, "SEAL-3", "tp", "SEAL-1/bassa")
        t = str(cm.exception)
        self.assertIn("SEAL-3", t)
        self.assertIn("SEAL-1", t)

    def test_the_refusal_says_it_is_not_a_missing_permission(self):
        """Un agente che legge «non hai il permesso» chiede a un admin; qui non
        c'è niente da concedere, e mandarlo a chiederlo è mandarlo dalla persona
        sbagliata."""
        with self.assertRaises(PermissionError) as cm:
            M._require_room_carries(TP, "SEAL-3", "tp", "SEAL-1/bassa")
        t = str(cm.exception)
        self.assertIn("livello della stanza", t)
        self.assertIn("SEAL-3/tp", t)      # dove quei dati si leggono davvero


class OutsideARoomTests(unittest.TestCase):
    def test_a_job_that_declares_its_tier_is_treated_as_a_room(self):
        """Dall'8 ago 2026 il tier del job viaggia nel claim firmato, e questa
        era l'ultima riga del modello scritta e non applicata."""
        from . import whitelist as w
        t = w.set_current_scope_tier("SEAL-1")
        try:
            with self.assertRaises(PermissionError) as cm:
                M._require_room_carries(TP, "SEAL-3", "tp", None)
            self.assertIn("job", str(cm.exception))
        finally:
            w.reset_current_scope_tier(t)

    def test_a_job_at_or_above_the_tier_carries(self):
        from . import whitelist as w
        t = w.set_current_scope_tier("SEAL-3")
        try:
            M._require_room_carries(TP, "SEAL-3", "tp", None)
        finally:
            w.reset_current_scope_tier(t)

    def test_the_refusal_points_at_the_job_not_at_an_admin(self):
        """Il rimedio qui è alzare il tier del job, e nessun admin può
        concedere ciò che il livello dichiarato nega."""
        from . import whitelist as w
        t = w.set_current_scope_tier("SEAL-0")
        try:
            with self.assertRaises(PermissionError) as cm:
                M._require_room_carries(TP, "SEAL-3", "tp", None)
            testo = str(cm.exception)
            self.assertIn("Alza il tier del job", testo)
            self.assertIn("non è un permesso che manca", testo.lower())
        finally:
            w.reset_current_scope_tier(t)

    def test_a_job_with_no_declared_tier_still_carries(self):
        """Deviazione deliberata dalla direzione tenuta altrove, e vale la pena
        saperla. Un job ha un tier (voce 33) che però non arriva al gateway.
        Chiudere qui romperebbe un `carries` scritto apposta da qualcuno, per
        far valere una regola che l'infrastruttura non sa ancora valutare — ed è
        così che un controllo viene spento. Si consente e si logga; il pezzo
        mancante (il tier del job nel claim firmato) è un punto aperto.

        Assente significa «nessun requisito», che è lo stato di ogni job
        esistente: trasformare un'assenza in un divieto spegnerebbe lavoro che
        gira."""
        M._require_room_carries(TP, "SEAL-3", "tp", None)

    def test_a_public_topic_travels_anywhere(self):
        """SEAL-0 non ha niente da proteggere, e chiuderlo renderebbe la
        portabilità inutilizzabile proprio nel caso innocuo."""
        M._require_room_carries({"tier": "SEAL-0"}, "SEAL-0", "pub", None)


class WiringTests(unittest.TestCase):
    def test_the_tier_check_guards_the_portable_shortcut(self):
        """Se stesse altrove, la scorciatoia della portabilità continuerebbe a
        consentire tutto e la regola sarebbe scritta e non applicata."""
        import inspect
        src = inspect.getsource(M._cross_topic_gate_key)
        i_port = src.index("_is_portable(meta, agent)")
        i_check = src.index("_require_room_carries")
        self.assertLess(abs(i_check - i_port), 400)

    def test_it_raises_instead_of_returning_a_gate_key(self):
        """Un gate sarebbe la facoltà di approvare il travaso che la regola
        impedisce."""
        import inspect
        self.assertIn("raise PermissionError",
                      inspect.getsource(M._require_room_carries))


if __name__ == "__main__":
    unittest.main()


class DeclaredByTheTopicTests(unittest.TestCase):
    """La portabilità la dichiara il TOPIC, non il seed.

    Rovesciata l'8 ago 2026 (specification §2.4). Prima era `carries` sul seed —
    «i topic che questo agente si porta dietro» — ed era il lato sbagliato: un
    agente che si aggiunge un topic alla propria lista **si dà da solo un canale**
    fra le stanze. Dichiarata dal topic, la portabilità è una decisione di chi
    possiede i contenuti.

    Misurato prima di spostarla: **nessun agente** usava `carries`, su nessuna
    delle due istanze. Lo spostamento non migra nulla e non rompe niente — e
    saperlo prima è la differenza fra una modifica e una scommessa.
    """

    PORT = {"tier": "SEAL-2", "portable": True, "owner": "davide",
            "participants": ["impiegato-tomato"]}

    def test_a_participant_of_a_portable_topic_reaches_it(self):
        self.assertTrue(M._is_portable(self.PORT, "impiegato-tomato"))

    def test_the_owner_reaches_it_too(self):
        self.assertTrue(M._is_portable(self.PORT, "davide"))

    def test_a_stranger_does_not(self):
        """Portabile non vuol dire pubblico: restano DUE condizioni."""
        self.assertFalse(M._is_portable(self.PORT, "estraneo"))

    def test_an_ordinary_topic_is_not_portable_for_its_participants(self):
        """La sola membership non attraversa i muri (voce 29): se bastasse,
        avremmo riaperto il compartimento dalla porta di servizio."""
        normale = dict(self.PORT)
        normale.pop("portable")
        self.assertFalse(M._is_portable(normale, "impiegato-tomato"))

    def test_only_an_explicit_true_makes_it_portable(self):
        """Un valore strano non deve rendere un topic portabile per errore."""
        for v in ("si", 1, "true", [], None):
            with self.subTest(valore=v):
                m = dict(self.PORT, portable=v)
                from .topics.service import normalize_meta_v2
                self.assertFalse(normalize_meta_v2(m, "SEAL-2")["portable"] is not False
                                 and normalize_meta_v2(m, "SEAL-2")["portable"])

    def test_the_seed_can_no_longer_grant_it_to_itself(self):
        """Il difetto che il ribaltamento chiude: `carries` non esiste più."""
        import inspect
        src = inspect.getsource(M)
        self.assertNotIn("def _carries(", src)

    def test_declaring_it_is_an_act_on_the_walls(self):
        """Rende i contenuti raggiungibili da ogni stanza: è un gate `walls`,
        quindi dell'owner e non di un partecipante qualunque."""
        from . import gate
        self.assertEqual(gate.gate_class("topic.set_portable"), gate.GATE_WALLS)

"""Il terzo termine dell'intersezione: il ruolo nella stanza.

Fino a oggi la catena `origin` diceva «ha chiesto Giovanni» e si fermava lì:
contribuiva la matrice GLOBALE di Giovanni, la stessa in ogni stanza. Ma Giovanni
è owner del job che ha creato e reader in `proof-of-flex` — e il modello dice
(voce 29) che l'accesso appartiene allo scope, non al seed né, per gli umani, al
solo profilo.

Autorità effettiva = matrice del profilo ∩ ruolo nello scope ∩ verbi dell'agente.
INTERSEZIONE, mai unione: un ruolo non concede ciò che il profilo nega, e un
profilo non concede ciò che il ruolo nega.

E il rifiuto deve dire QUALE dei due ha bloccato, perché i rimedi sono persone
diverse: «il tuo profilo non ha questo verbo» si risolve con un admin, «qui sei
reader» con l'owner del topic. Un messaggio che non distingue manda a chiedere
alla persona sbagliata — che è il difetto più costoso di oggi, ripetuto tre volte
su altri fronti.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import origin
from . import whitelist as w


CANALE = "chan:SEAL-1:acme:clodia"
META = {"tier": "SEAL-1", "owner": "davide",
        "participants": {"giovanni": "reader", "matteo": "contributor"}}


class _Svc:
    def open(self, tier, name):
        return {"meta": META}


class _Chat:
    def __init__(self, v):
        self.v = v

    def __enter__(self):
        self.t = w.set_current_chat(self.v)
        return self

    def __exit__(self, *a):
        w.reset_current_chat(self.t)
        return False


def _env(profilo_consente=True):
    from . import main as _m
    return (patch.object(_m, "_topics", lambda: _Svc()),
            patch.object(origin, "_human_may", lambda n, v: profilo_consente))


class Base(unittest.TestCase):
    def run_with(self, ctx, fn):
        for c in ctx:
            c.start()
        try:
            return fn()
        finally:
            [c.stop() for c in ctx]


class ReaderTests(Base):
    def test_a_reader_may_not_mutate_even_with_the_profile_allowing_it(self):
        """Il cuore del terzo termine: il profilo dice sì, la stanza dice no."""
        def go():
            with _Chat(CANALE):
                self.assertFalse(origin.principal_may("human", "giovanni", "topic.put"))
        self.run_with(_env(), go)

    def test_a_reader_may_read(self):
        def go():
            with _Chat(CANALE):
                self.assertTrue(origin.principal_may("human", "giovanni", "topic.read_file"))
        self.run_with(_env(), go)

    def test_a_reader_may_speak(self):
        """Parlare non è mutare: è il punto del ruolo."""
        def go():
            with _Chat(CANALE):
                self.assertTrue(origin.principal_may("human", "giovanni", "topic.post_message"))
        self.run_with(_env(), go)

    def test_a_reader_may_not_send_anything_out_of_the_room(self):
        """Fuori dai verbi `topic.*` il criterio è l'uscita."""
        def go():
            with _Chat(CANALE):
                self.assertFalse(origin.principal_may("human", "giovanni", "email.send"))
        self.run_with(_env(), go)


class ContributorTests(Base):
    def test_a_contributor_may_mutate(self):
        def go():
            with _Chat(CANALE):
                self.assertTrue(origin.principal_may("human", "matteo", "topic.put"))
        self.run_with(_env(), go)

    def test_the_owner_may_mutate(self):
        def go():
            with _Chat(CANALE):
                self.assertTrue(origin.principal_may("human", "davide", "topic.put"))
        self.run_with(_env(), go)


class IntersectionTests(Base):
    def test_a_role_does_not_grant_what_the_profile_denies(self):
        """L'altra direzione dell'intersezione. Se un ruolo potesse concedere,
        sarebbe un'unione — e diventare contributor da qualche parte darebbe
        permessi che il profilo non ha."""
        def go():
            with _Chat(CANALE):
                self.assertFalse(origin.principal_may("human", "matteo", "packs.import_url"))
        self.run_with(_env(profilo_consente=False), go)


class OutsideAScopeTests(Base):
    def test_outside_a_room_the_third_term_does_not_pronounce(self):
        """In un job non c'è una stanza: il termine tace invece di rifiutare."""
        def go():
            with _Chat("job:42"):
                self.assertTrue(origin.principal_may("human", "giovanni", "topic.put"))
        self.run_with(_env(), go)

    def test_a_non_participant_is_not_refused_HERE(self):
        """La partecipazione è già verificata altrove. Rifiutare anche qui
        farebbe due controlli in due posti, che è il modo di farli divergere."""
        def go():
            with _Chat(CANALE):
                self.assertTrue(origin.principal_may("human", "estraneo", "topic.put"))
        self.run_with(_env(), go)

    def test_an_unreadable_scope_does_not_grant_a_role(self):
        from . import main as _m

        class _Rotto:
            def open(self, t, n):
                raise RuntimeError("giù")
        ctx = (patch.object(_m, "_topics", lambda: _Rotto()),
               patch.object(origin, "_human_may", lambda n, v: True))

        def go():
            with _Chat(CANALE):
                self.assertIsNone(origin._scope_role_of("giovanni"))
        self.run_with(ctx, go)


class DenialMessageTests(Base):
    def test_the_refusal_says_which_of_the_two_blocked(self):
        """I rimedi sono persone diverse: un admin per il profilo, l'owner del
        topic per il ruolo."""
        def go():
            with _Chat(CANALE):
                v = origin.evaluate([("human", "giovanni"), ("agent", "clodia")],
                                    "topic.put")
                self.assertEqual(v["action"], "deny")
                self.assertEqual(v["reason"], "ruolo-nello-scope")
                msg = origin.denial_message(v)
                self.assertIn("reader", msg)
                self.assertIn("owner del topic", msg)
                self.assertIn("non con un admin", msg)
        self.run_with(_env(), go)

    def test_a_profile_refusal_still_points_at_an_admin(self):
        def go():
            with _Chat(CANALE):
                v = origin.evaluate([("human", "matteo")], "packs.import_url")
                self.assertEqual(v["reason"], "profilo")
                self.assertIn("admin", origin.denial_message(v))
        self.run_with(_env(profilo_consente=False), go)


class SignedSourceTests(unittest.TestCase):
    def test_the_scope_comes_from_the_signed_claim(self):
        """Una regola che leggesse la stanza da un argomento sarebbe la parola di
        chi chiede su dove si trova."""
        import inspect
        src = inspect.getsource(origin._scope_role_of)
        self.assertIn("current_channel()", src)
        self.assertNotIn("arguments", src)


if __name__ == "__main__":
    unittest.main()

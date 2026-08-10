"""Da un client MCP di una persona: chi parla, e chi ha diritto di stare lì.

Due modifiche nel dispatch dei verbi `topic.*`, entrambe nate dalla stessa
osservazione: fino a ieri da lì passavano solo agenti, e il codice lo dava per
scontato in due punti che ora direbbero il falso.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import main as M
from . import whitelist


class _Persona:
    """Una sessione on-behalf legata a una stanza, come la conia `human_mcp`."""

    def __init__(self, chi="giovanni", chat="chan:SEAL-1:acme:giovanni",
                 clearance="SEAL-1"):
        self._v = (chi, chat, clearance)

    def __enter__(self):
        chi, chat, cl = self._v
        self._t = (whitelist.set_current_on_behalf(True),
                   whitelist.set_current_principal(chi),
                   whitelist.set_current_chat(chat),
                   whitelist.set_current_clearance(cl),
                   whitelist.set_current_agent("clodia"))
        return self

    def __exit__(self, *a):
        ob, pr, ch, cl, ag = self._t
        whitelist.reset_current_agent(ag)
        whitelist.reset_current_clearance(cl)
        whitelist.reset_current_chat(ch)
        whitelist.reset_current_principal(pr)
        whitelist.reset_current_on_behalf(ob)
        return False


class _Svc:
    def __init__(self, meta):
        self._meta = meta
        self.posted = None

    def open(self, tier, name):
        return {"meta": self._meta}

    def post_message(self, tier, name, author, text, kind="human", **k):
        self.posted = {"author": author, "kind": kind, "text": text}
        return dict(self.posted, id="m1")


META = {"tier": "SEAL-1", "owner": "davide",
        "participants": {"davide": "owner", "giovanni": "member",
                         "matteo": "reader"}}


class WhoSpokeTests(unittest.TestCase):
    """Firmare sempre col carrier-agent era corretto finché a chiamare c'erano
    solo agenti. Da un client umano la stessa riga farebbe comparire il messaggio
    di Giovanni a nome dell'agente che porta il suo token — la chat direbbe una
    cosa falsa su chi ha parlato.
    """

    def _posta(self, testo="ciao"):
        svc = _Svc(META)
        with patch.object(M, "_topics", lambda: svc), \
             patch.object(M, "runtime", unittest.mock.MagicMock()):
            M._dispatch_topic("topic.post_message",
                              {"tier": "SEAL-1", "name": "acme", "text": testo})
        return svc.posted

    def test_a_person_signs_with_their_own_name(self):
        with _Persona():
            self.assertEqual(self._posta()["author"], "giovanni")

    def test_a_person_posts_a_human_message(self):
        """`kind` non segue l'autore per estetica: è il campo su cui poggiano due
        regole già scritte — «una menzione a una persona non instrada un'AI» e
        «solo i messaggi umani accodano una notifica Telegram». Scriverlo `ai`
        le disattiverebbe entrambe in silenzio."""
        with _Persona():
            self.assertEqual(self._posta()["kind"], "human")

    def test_an_agent_is_unchanged(self):
        svc = _Svc(META)
        tok = whitelist.set_current_agent("ophelia")
        try:
            with patch.object(M, "_topics", lambda: svc), \
                 patch.object(M, "runtime", unittest.mock.MagicMock()), \
                 patch.object(M, "_require_topic_member", lambda *a, **k: None):
                M._dispatch_topic("topic.post_message",
                                  {"tier": "SEAL-1", "name": "acme", "text": "x"})
        finally:
            whitelist.reset_current_agent(tok)
        self.assertEqual(svc.posted["author"], "ophelia")
        self.assertEqual(svc.posted["kind"], "ai")


class WhichRoomTests(unittest.TestCase):
    def test_the_claim_binds_exactly_one_room(self):
        with _Persona():
            self.assertTrue(M._chat_binds_this_topic("SEAL-1", "acme"))
            self.assertFalse(M._chat_binds_this_topic("SEAL-1", "altro"))
            self.assertFalse(M._chat_binds_this_topic("SEAL-2", "acme"))

    def test_a_session_without_a_chat_claim_is_not_bound(self):
        """Le sessioni umane della webui non portano un `chat`: devono continuare
        a passare dal ramo di prima, non da questo."""
        tok = whitelist.set_current_chat(None)
        try:
            self.assertFalse(M._chat_binds_this_topic("SEAL-1", "acme"))
        finally:
            whitelist.reset_current_chat(tok)


class WhoMayBeThereTests(unittest.TestCase):
    """La membership da verificare è quella della PERSONA.

    Chiedere quella del carrier chiuderebbe l'accesso a Giovanni perché l'agente
    che gli firma il token non partecipa — un rifiuto che non riguarda nessuno
    dei due. Non è un bypass: il perimetro non lo dà il principal, lo dà il
    `chat` firmato, che vale per QUESTA stanza e per nessun'altra.
    """

    def _apri(self, chi="giovanni", tier_topic="SEAL-1", clearance="SEAL-1",
              mutating=False):
        svc = _Svc(META)
        with _Persona(chi=chi, chat=f"chan:{tier_topic}:acme:{chi}",
                      clearance=clearance):
            M._require_topic_member(svc, tier_topic, "acme", mutating=mutating)

    def test_a_participant_gets_in(self):
        self._apri("giovanni")            # non solleva

    def test_a_stranger_does_not(self):
        with self.assertRaises(PermissionError) as e:
            self._apri("estraneo")
        self.assertIn("non è partecipante", str(e.exception))

    def test_a_reader_may_read_and_speak_but_not_change(self):
        self._apri("matteo")                                   # leggere: sì
        with self.assertRaises(PermissionError):
            self._apri("matteo", mutating=True)                # cambiare: no

    def test_clearance_still_bounds_the_person(self):
        """Il compartimento non sostituisce il livello: partecipare a una stanza
        più riservata della propria clearance non la alza."""
        with self.assertRaises(PermissionError) as e:
            self._apri("giovanni", tier_topic="SEAL-1", clearance="SEAL-0")
        self.assertIn("clearance", str(e.exception))

    def test_the_agent_rule_is_untouched_without_a_chat_claim(self):
        """La regola generale resta: fuori da un token legato a una stanza, il
        principal umano NON è un bypass del compartimento dell'agente."""
        svc = _Svc(META)
        toks = (whitelist.set_current_on_behalf(True),
                whitelist.set_current_principal("giovanni"),
                whitelist.set_current_chat(None),
                whitelist.set_current_clearance("SEAL-1"),
                whitelist.set_current_agent("impiegato-tomato"))
        try:
            with patch.object(M, "_gate", create=True):
                with self.assertRaises(PermissionError) as e:
                    M._require_topic_member(svc, "SEAL-1", "acme")
            self.assertIn("l'agente", str(e.exception))
        finally:
            for f, t in zip((whitelist.reset_current_agent,
                             whitelist.reset_current_clearance,
                             whitelist.reset_current_chat,
                             whitelist.reset_current_principal,
                             whitelist.reset_current_on_behalf),
                            reversed(toks)):
                f(t)


class OneRoomMeansOneRoomTests(unittest.TestCase):
    """Il difetto che i primi test non hanno visto.

    Chiedevano al ramo giusto se faceva la cosa giusta, e mai all'altro se stava
    zitto. Un token legato a `proof-of-flex-2` chiamato su un ALTRO topic non
    entrava in questo ramo — `_chat_binds_this_topic` diceva False — e cadeva
    tranquillamente su quello del carrier-agent. In esercizio il carrier è
    `clodia`, che partecipa a tutto: il token «legato a una stanza» le apriva
    tutte, rispondendo `200`.

    Il confinamento sembrava esserci perché il caso felice funzionava. È il
    difetto più difficile da vedere leggendo: nessuna riga è sbagliata, manca un
    ramo — e un permesso mancante non fallisce, riesce.

    Trovato usando il token per davvero contro il gateway in esercizio.
    """

    def _prova(self, tier_tok, topic_tok, tier_chiesto, topic_chiesto,
               carrier="clodia"):
        svc = _Svc({**META, "tier": tier_chiesto})
        with _Persona(chi="giovanni",
                      chat=f"chan:{tier_tok}:{topic_tok}:giovanni"):
            tok = whitelist.set_current_agent(carrier)
            try:
                M._require_topic_member(svc, tier_chiesto, topic_chiesto)
            finally:
                whitelist.reset_current_agent(tok)

    def test_the_bound_room_works(self):
        self._prova("SEAL-1", "acme", "SEAL-1", "acme")

    def test_another_room_is_refused_even_if_the_carrier_belongs(self):
        """`clodia` è participant di quasi tutto: se il rifiuto non è esplicito,
        il ripiego sul carrier concede."""
        with self.assertRaises(PermissionError) as e:
            self._prova("SEAL-1", "acme", "SEAL-1", "un-altro-topic")
        self.assertIn("vale per", str(e.exception))

    def test_another_tier_is_refused_too(self):
        with self.assertRaises(PermissionError):
            self._prova("SEAL-1", "acme", "SEAL-2", "acme")

    def test_listing_from_a_bound_token_shows_only_that_room(self):
        """`list`/`search` non passano da `_require_topic_member`: filtrano da sé,
        e lo facevano sul CARRIER. Dal client di Giovanni una ricerca rispondeva
        con i titoli dei topic di clodia — non i contenuti, ma la mappa delle
        stanze che non lo riguardano. Una lista di titoli sembra sempre
        plausibile, che è ciò che rende la perdita difficile da notare."""
        class _L:
            def list(self, tier=None, include_archived=False):
                return [{"tier": "SEAL-1", "name": "acme"},
                        {"tier": "SEAL-1", "name": "segreto-di-clodia"},
                        {"tier": "SEAL-2", "name": "acme"}]

            def search(self, q, mode="lexical"):
                return self.list()

        with _Persona(chi="giovanni", chat="chan:SEAL-1:acme:giovanni"), \
             patch.object(M, "_topics", lambda: _L()):
            for verbo, args in (("topic.list", {}),
                                ("topic.search", {"query": "x"})):
                righe = M._dispatch_topic(verbo, args)
                self.assertEqual(righe, [{"tier": "SEAL-1", "name": "acme"}],
                                 f"{verbo} ha mostrato più di una stanza")


class MentionsAreAlwaysAboutTheCallerTests(unittest.TestCase):
    def test_no_argument_can_name_someone_else(self):
        """Un parametro `principal` renderebbe `my_mentions` un modo per leggere
        la casella di un altro. L'identità viene dal claim firmato, punto."""
        import inspect
        src = inspect.getsource(M._dispatch_topic)
        blocco = src[src.index('if verb in ("my_mentions"'):]
        blocco = blocco[:blocco.index('if verb == "save_summary"')]
        self.assertIn("current_principal()", blocco)
        self.assertNotIn('a.get("principal")', blocco)
        self.assertNotIn('a["principal"]', blocco)


if __name__ == "__main__":
    unittest.main()

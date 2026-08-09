"""Un agente reader legge e parla, non muta.

Domanda di Davide, 7 ago 2026: «cosa succede se metto reader come ruolo ad un
agent ai?». Risposta misurata: **niente**. Il ruolo era applicato solo sul
percorso UMANO — gli endpoint della webui — e un agente non passa da lì: passa
dai verbi del gateway, dove la guardia guardava appartenenza e clearance e non il
ruolo. Un agente messo a reader poteva comunque chiamare `topic.put` e
`save_summary`.

Il ruolo esisteva e nessuno lo consultava dove serviva di più. Un agente reader è
precisamente il caso dell'osservatore invitato a guardare e commentare senza
toccare — più netto del caso umano, non meno.

`post_message` NON è fra i verbi che mutano, di proposito: parlare non è mutare.
Azzittire un reader sarebbe una cosa diversa da quella che il ruolo descrive, e
la sua richiesta deve poter arrivare a chi può eseguirla.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import main as M
from .topics.service import TopicService as T


META = {"tier": "SEAL-1", "owner": "davide",
        "participants": {"clodia": "contributor", "osservatore": "reader"}}


class _Svc:
    def open(self, tier, name):
        return {"meta": META}


def _env(chi, clearance="SEAL-3"):
    return (patch.object(M, "agent_name", lambda: chi),
            patch.object(M, "current_clearance", lambda: clearance),
            patch.object(M, "_topics", lambda: _Svc()))


class Base(unittest.TestCase):
    def run_with(self, ctx, fn):
        for c in ctx:
            c.start()
        try:
            return fn()
        finally:
            [c.stop() for c in ctx]


class ReaderTests(Base):
    def test_a_reader_agent_may_read(self):
        def go():
            M._require_topic_member(_Svc(), "SEAL-1", "acme", mutating=False)
        self.run_with(_env("osservatore"), go)

    def test_a_reader_agent_may_not_mutate(self):
        """Il difetto che questo file esiste per chiudere."""
        def go():
            with self.assertRaises(PermissionError) as cm:
                M._require_topic_member(_Svc(), "SEAL-1", "acme", mutating=True)
            self.assertIn("reader", str(cm.exception))
        self.run_with(_env("osservatore"), go)

    def test_the_refusal_says_who_can_change_it(self):
        """Un rifiuto che non indica la strada insegna solo che il sistema dice
        di no."""
        def go():
            with self.assertRaises(PermissionError) as cm:
                M._require_topic_member(_Svc(), "SEAL-1", "acme", mutating=True)
            self.assertIn("owner", str(cm.exception))
        self.run_with(_env("osservatore"), go)


class ContributorTests(Base):
    def test_a_contributor_agent_may_mutate(self):
        def go():
            M._require_topic_member(_Svc(), "SEAL-1", "acme", mutating=True)
        self.run_with(_env("clodia"), go)

    def test_the_owner_may_mutate(self):
        def go():
            M._require_topic_member(_Svc(), "SEAL-1", "acme", mutating=True)
        self.run_with(_env("davide"), go)


class VerbClassificationTests(unittest.TestCase):
    def test_speaking_is_not_mutating(self):
        """Un reader resta nella stanza per seguirne il lavoro e dire la sua."""
        self.assertNotIn("post_message", M._TOPIC_MUTATING_VERBS)

    def test_reading_verbs_are_not_mutating(self):
        for v in ("open", "files", "read_file", "read_document", "fetch",
                  "remote_status"):
            with self.subTest(verbo=v):
                self.assertNotIn(v, M._TOPIC_MUTATING_VERBS)

    def test_writing_verbs_are_mutating(self):
        for v in ("put", "write_file", "delete_file", "save_summary",
                  "save_agents_md", "remote_push", "migrate_storage"):
            with self.subTest(verbo=v):
                self.assertIn(v, M._TOPIC_MUTATING_VERBS)

    def test_every_mutating_verb_is_a_real_topic_verb(self):
        """Una classificazione su un verbo che non esiste è una regola che non si
        applica mai — e sembra applicarsi."""
        for v in M._TOPIC_MUTATING_VERBS:
            with self.subTest(verbo=v):
                self.assertIn(v, M._TOPIC_SCOPED_VERBS)

    def test_every_classified_verb_is_actually_declared(self):
        """Il confronto che mancava, e il difetto che ha lasciato passare.

        Il test qui sopra confronta DUE LISTE fra loro: un verbo scritto in
        entrambe le supera, anche se non esiste alcun tool che lo esponga.
        `topic.set_portable` era esattamente così — classificato `walls`, gated,
        scoped, mutante, e **non dichiarato né dispatchato** (trovato il 9 ago
        2026, quando Davide ha chiesto come si dichiara portabile un topic: la
        risposta era «modificando meta.json a mano»).

        Il confronto giusto è con la superficie REALE: i tool che il gateway
        annuncia. Due liste coerenti fra loro descrivono un mondo che può non
        esistere.
        """
        dichiarati = {t.name.split(".", 1)[1]
                      for lst in (getattr(M, n) for n in dir(M) if n.endswith("_TOOLS"))
                      for t in lst if t.name.startswith("topic.")}
        for v in sorted(M._TOPIC_SCOPED_VERBS | set(M._TOPIC_MUTATING_VERBS)):
            with self.subTest(verbo=v):
                self.assertIn(v, dichiarati,
                              f"'topic.{v}' è classificato ma nessun tool lo espone")


class LegacyTests(Base):
    def test_a_legacy_list_leaves_everyone_able_to_mutate(self):
        """Nessuno perde qualcosa perché il suo topic non è ancora stato
        convertito: la lista vale tutta contributor."""
        legacy = {"tier": "SEAL-1", "owner": "davide", "participants": ["clodia"]}

        class _S:
            def open(self, t, n):
                return {"meta": legacy}

        ctx = (patch.object(M, "agent_name", lambda: "clodia"),
               patch.object(M, "current_clearance", lambda: "SEAL-3"),
               patch.object(M, "_topics", lambda: _S()))

        def go():
            M._require_topic_member(_S(), "SEAL-1", "acme", mutating=True)
        self.run_with(ctx, go)


if __name__ == "__main__":
    unittest.main()

"""Il compartimento è dello SPAWN, non del seed.

Il difetto, misurato il 7 ago 2026 e non ipotetico. `_topic_is_member`
confrontava il nome del SEED con i partecipanti del topic bersaglio, e nessuno
guardava da quale stanza partisse la chiamata. Su marte:

    topic totali: 157
      clodia   participant di 135

Quindi uno spawn di clodia, stando in una stanza qualunque, poteva leggere i file
degli altri 134 topic senza gate e riversarli lì dentro. Il modello dichiara due
assi — clearance E compartimento — ma il secondo compartimenta solo se valutato
per spawn: per seed è un permesso globale vestito da compartimento.

La regola nuova, con `qui` preso dal claim FIRMATO:

    T == qui                → consentito
    T ∈ carries             → consentito
    agent ∈ participants(T) → GATE      ← il cambiamento
    altrimenti              → GATE
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import main as M


META_A = {"tier": "SEAL-1", "owner": "davide", "participants": ["clodia", "davide"]}
ARGS_A = {"tier": "SEAL-1", "name": "topic-a"}


class _Chat:
    def __init__(self, v):
        self.v = v

    def __enter__(self):
        from . import whitelist as w
        self.t = w.set_current_chat(self.v)
        return self

    def __exit__(self, *a):
        from . import whitelist as w
        w.reset_current_chat(self.t)
        return False


def _env(modo="on", carries=None, meta=None):
    class _Svc:
        def open(self, tier, name):
            return {"meta": meta if meta is not None else META_A}
    return (patch.dict("os.environ", {"CLODIA_SPAWN_COMPARTMENT": modo}),
            patch.object(M, "_topics", lambda: _Svc()),
            patch.object(M, "_carries", lambda a: set(carries or [])))


class Base(unittest.TestCase):
    def run_with(self, ctx, fn):
        for c in ctx:
            c.start()
        try:
            return fn()
        finally:
            [c.stop() for c in ctx]

    def key(self, **kw):
        return M._cross_topic_gate_key("topic.read_file", ARGS_A, "clodia")


class EnforcedTests(Base):
    def test_reading_your_own_room_is_free(self):
        def go():
            with _Chat("chan:SEAL-1:topic-a:clodia"):
                self.assertIsNone(self.key())
        self.run_with(_env(), go)

    def test_membership_alone_no_longer_waives_the_gate(self):
        """Il cuore della correzione. clodia È participant di topic-a, ma sta in
        topic-b: prima passava, ora chiede."""
        def go():
            with _Chat("chan:SEAL-1:topic-b:clodia"):
                self.assertEqual(self.key(), "topic-access:SEAL-1/topic-a")
        self.run_with(_env(), go)

    def test_a_declared_carry_is_allowed_from_anywhere(self):
        """L'eccezione esplicita: lo scope proprio dell'agente."""
        def go():
            with _Chat("chan:SEAL-1:topic-b:clodia"):
                self.assertIsNone(self.key())
        self.run_with(_env(carries=["SEAL-1/topic-a"]), go)

    def test_a_non_member_still_gates(self):
        def go():
            with _Chat("chan:SEAL-1:topic-b:clodia"):
                self.assertEqual(self.key(), "topic-access:SEAL-1/topic-a")
        self.run_with(_env(meta={"tier": "SEAL-1", "owner": "x", "participants": []}), go)

    def test_outside_any_room_only_a_carry_passes(self):
        """In un job non esiste un «qui». Solo ciò che è dichiarato passa, e il
        resto gata — che per una sessione non presidiata significa negare."""
        def go():
            with _Chat("job:42"):
                self.assertEqual(self.key(), "topic-access:SEAL-1/topic-a")
        self.run_with(_env(), go)

    def test_a_job_can_still_reach_what_it_declares(self):
        def go():
            with _Chat("job:42"):
                self.assertIsNone(self.key())
        self.run_with(_env(carries=["SEAL-1/topic-a"]), go)


class TierAliasTests(Base):
    def test_legacy_tier_aliases_compare_equal(self):
        """I due lati arrivano da sorgenti diverse — il claim firmato e il meta
        del topic. Un confronto per stringa grezza aprirebbe un buco al primo
        alias: `P1/topic-a` e `SEAL-1/topic-a` sono lo stesso posto."""
        def go():
            with _Chat("chan:P1:topic-a:clodia"):
                self.assertIsNone(self.key())
        self.run_with(_env(), go)

    def test_carries_accepts_the_legacy_form_too(self):
        def go():
            with _Chat("chan:SEAL-1:topic-b:clodia"):
                self.assertIsNone(self.key())
        self.run_with(_env(carries=["P1/topic-a"]), go)


class ReportModeTests(Base):
    def test_report_does_not_refuse_but_logs_what_it_would_refuse(self):
        """Il rollout osserva prima di rifiutare: questa regola stringe un
        permesso larghissimo, e stringerlo alla cieca romperebbe l'orchestrazione
        senza che nessuno sappia dove."""
        def go():
            with _Chat("chan:SEAL-1:topic-b:clodia"):
                with self.assertLogs("clodia-tools", level="WARNING") as log:
                    self.assertIsNone(self.key())
                self.assertTrue(any("compartimento spawn" in r for r in log.output))
        self.run_with(_env(modo="report"), go)

    def test_off_restores_the_old_behaviour_exactly(self):
        """Una via di ritirata che non richiede un deploy."""
        def go():
            with _Chat("chan:SEAL-1:topic-b:clodia"):
                self.assertIsNone(self.key())
        self.run_with(_env(modo="off"), go)


class SignedSourceTests(unittest.TestCase):
    def test_the_room_comes_from_the_signed_claim_not_from_an_argument(self):
        """Una regola che leggesse la stanza da un argomento sarebbe la parola
        dell'agente su dove si trova, cioè non un controllo."""
        import inspect
        src = inspect.getsource(M._cross_topic_gate_key)
        self.assertIn("current_channel()", src)
        self.assertNotIn('arguments.get("chat"', src)


if __name__ == "__main__":
    unittest.main()

"""`topic.list`/`topic.search` sono compartimentati per SPAWN, non per seed.

Residuo del punto 4 di clodia-platform#382, scorporato in #401. Gli altri verbi
`topic.*` passano da `_cross_topic_gate_key`, che guarda la stanza da cui parte
la chiamata (claim FIRMATO). `list` e `search` no: non hanno un bersaglio
`tier`/`name`, filtrano da sé con `_filter_member_rows`, e quel filtro decide
sulla membership del SEED (`agent_name()`).

Quindi uno spawn che sta nella stanza X riceveva una riga per OGNI topic di cui
il seed è participant — e la riga di `search` porta il `tldr`, cioè la prima
riga del summary: la riga più informativa di un dossier. Su un'istanza dove
clodia è participant di 135 topic su 157, è la mappa delle stanze altrui portata
dentro X.

Il precedente sta nello stesso ramo del dispatch: per i token umani legati a una
stanza (`_token_is_bound_to_a_room`) le righe sono già ristrette a quella
stanza, e per la stessa ragione — «dal client di Giovanni una ricerca rispondeva
con i titoli dei topic di clodia». Mancava l'analogo per gli spawn.

La modalità è dichiarata ESPLICITAMENTE in ogni test: il default di
`CLODIA_SPAWN_COMPARTMENT` è materia di #382, e un test che ci si appoggiasse
cambierebbe significato al merge di quella PR senza che nessuno lo tocchi.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import gate, main


def _row(tier, name, participants=("clodia",), owner="davide"):
    return {"tier": tier, "name": name, "title": name,
            "tldr": f"segreto di {name}", "owner": owner,
            "participants": list(participants)}


#: clodia è participant di entrambi: è esattamente il caso in cui la sola
#: membership del seed lasciava passare tutto.
ROWS = [_row("SEAL-1", "topic-a"), _row("SEAL-1", "topic-b")]


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


class _Svc:
    def list(self, tier=None, include_archived=False):
        return list(ROWS)

    def search(self, query, mode="lexical"):
        return list(ROWS)


class Base(unittest.TestCase):
    def setUp(self):
        for p in (patch.object(main, "_topics", lambda: _Svc()),
                  patch.object(main, "agent_name", lambda: "clodia"),
                  patch.object(main, "current_clearance", lambda: "SEAL-3")):
            p.start()
            self.addCleanup(p.stop)

    def _env(self, modo):
        p = patch.dict("os.environ", {"CLODIA_SPAWN_COMPARTMENT": modo})
        p.start()
        self.addCleanup(p.stop)

    def names(self, verb="search"):
        a = {"query": "x"} if verb == "search" else {}
        return [r["name"] for r in main._dispatch_topic(f"topic.{verb}", a)]


class EnforcedTests(Base):
    def test_search_does_not_reveal_rooms_other_than_this_one(self):
        """Il cuore del difetto: `topic-a` non ha niente a che fare con la
        stanza in cui lo spawn sta lavorando, e ne usciva titolo + tldr."""
        self._env("on")
        with _Chat("chan:SEAL-1:topic-b:clodia"):
            self.assertEqual(self.names("search"), ["topic-b"])

    def test_list_follows_the_same_rule_as_search(self):
        """Stessa regola, o la si aggira con l'altro verbo."""
        self._env("on")
        with _Chat("chan:SEAL-1:topic-b:clodia"):
            self.assertEqual(self.names("list"), ["topic-b"])

    def test_legacy_tier_aliases_do_not_drop_your_own_room(self):
        """I due lati vengono da sorgenti diverse — il claim firmato e la riga
        del topic. Un confronto per stringa grezza cancellerebbe la propria
        stanza al primo alias di tier."""
        self._env("on")
        with _Chat("chan:P1:topic-b:clodia"):
            self.assertEqual(self.names("search"), ["topic-b"])

    def test_the_room_comes_from_the_signed_claim_not_from_an_argument(self):
        import inspect
        src = inspect.getsource(main._scope_rows_to_this_room)
        self.assertIn("current_channel()", src)
        self.assertNotIn("arguments", src)


class CrossTopicGrantTests(Base):
    def test_an_active_crosstopic_grant_restores_the_full_list(self):
        """Il grant esiste per questo: l'orchestratore che deve davvero
        guardare fuori non perde il verbo, lo usa con un consenso esplicito."""
        self._env("on")
        with _Chat("chan:SEAL-1:topic-b:clodia"), \
                patch("server.whitelist.current_spawn", return_value="clodia-1"), \
                patch.object(gate, "active", return_value=True):
            self.assertEqual(self.names("search"), ["topic-a", "topic-b"])

    def test_an_ineligible_agent_is_not_helped_by_an_active_consent(self):
        """Difesa in profondità, come sul dispatch: l'eleggibilità è un asse a
        monte del gate, non una cosa che il gate possa concedere."""
        self._env("on")
        rows = [_row("SEAL-1", "topic-a", participants=("messaggero",)),
                _row("SEAL-1", "topic-b", participants=("messaggero",))]
        with _Chat("chan:SEAL-1:topic-b:messaggero"), \
                patch.object(main, "agent_name", lambda: "messaggero"), \
                patch("server.whitelist.current_spawn", return_value="messaggero-1"), \
                patch.object(gate, "active", return_value=True), \
                patch.object(_Svc, "search", lambda self, q, mode="lexical": list(rows)):
            self.assertEqual(self.names("search"), ["topic-b"])


class RolloutTests(Base):
    def test_report_lets_everything_through_but_says_what_it_would_cut(self):
        """Stessa maniglia di rollout del compartimento per-spawn: si osserva
        prima di rifiutare, e il WARNING dice quanto si taglierebbe."""
        self._env("report")
        with _Chat("chan:SEAL-1:topic-b:clodia"):
            with self.assertLogs("clodia-tools", level="WARNING") as log:
                self.assertEqual(self.names("search"), ["topic-a", "topic-b"])
            self.assertTrue(any("compartimento spawn" in r for r in log.output))

    def test_report_stays_silent_when_there_is_nothing_to_cut(self):
        """Un WARNING per ogni elenco lo renderebbe rumore che nessuno legge."""
        self._env("report")
        rows = [_row("SEAL-1", "topic-b")]
        with _Chat("chan:SEAL-1:topic-b:clodia"), \
                patch.object(_Svc, "search", lambda self, q, mode="lexical": list(rows)):
            with patch("logging.Logger.warning") as w:
                self.assertEqual(self.names("search"), ["topic-b"])
            self.assertFalse(
                [c for c in w.call_args_list if "compartimento spawn" in str(c)])

    def test_off_restores_the_old_behaviour_exactly(self):
        """Una via di ritirata che non richiede un deploy."""
        self._env("off")
        with _Chat("chan:SEAL-1:topic-b:clodia"):
            self.assertEqual(self.names("search"), ["topic-a", "topic-b"])


class NoRoomTests(Base):
    """Fuori da una stanza l'elenco NON si restringe, ed è una scelta.

    Il difetto è «portare dentro la stanza X ciò che appartiene a Y»: senza un
    «qui» non c'è nessun X. Chi è qui è una sessione presidiata della webui — un
    umano che chiede a Clodia quali topic esistono — e svuotargli l'elenco
    toglierebbe una funzione senza chiudere niente. Una sessione NON presidiata
    non arriva fin qui: `topic.list`/`topic.search` le sono già negati a monte
    (`_UNATTENDED_TOPIC_ALLOW` ammette solo `topic.post_message`).
    """

    def test_a_webui_session_still_sees_the_seed_scope(self):
        self._env("on")
        with _Chat("dm:davide"):
            self.assertEqual(self.names("search"), ["topic-a", "topic-b"])

    def test_unattended_sessions_never_reach_this_code(self):
        self.assertNotIn("topic.search", main._UNATTENDED_TOPIC_ALLOW)
        self.assertNotIn("topic.list", main._UNATTENDED_TOPIC_ALLOW)


class RuntimeTopicsTests(Base):
    """`runtime.topics()` è la stessa porta con un'altra maniglia.

    Filtra anch'esso per membership del SEED (`whitelist.agent_name()`) e
    restituisce i METADATI dei topic. Stringere solo `topic.list`/`topic.search`
    lascerebbe il verbo accanto a fare esattamente quello che si è appena
    chiuso — ed è proprio da `runtime.topics()` su `tomato-blogging` che nasce
    la decisione del 23 set sul grant `crosstopic`.
    """

    def _topics(self, **kw):
        with patch.object(main.runtime, "topics",
                          lambda include_restricted=False: {
                              "count": len(ROWS), "topics": list(ROWS)}):
            out = main._dispatch_runtime("runtime.topics", {}, "clodia")
        return [t["name"] for t in out["topics"]], out["count"]

    def test_it_does_not_reveal_rooms_other_than_this_one(self):
        self._env("on")
        with _Chat("chan:SEAL-1:topic-b:clodia"):
            self.assertEqual(self._topics(), (["topic-b"], 1))

    def test_the_count_follows_the_rows_it_returns(self):
        """Un `count` che non corrisponde alle righe racconterebbe comunque
        quante stanze esistono: il numero è già un'informazione."""
        self._env("on")
        with _Chat("chan:SEAL-1:topic-b:clodia"):
            names, count = self._topics()
            self.assertEqual(count, len(names))

    def test_off_restores_the_old_behaviour_exactly(self):
        self._env("off")
        with _Chat("chan:SEAL-1:topic-b:clodia"):
            self.assertEqual(self._topics(), (["topic-a", "topic-b"], 2))


class NeedToKnowStillAppliesTests(Base):
    def test_a_topic_of_another_seed_stays_out_in_every_mode(self):
        """Il filtro per membership non viene sostituito, viene stretto: un
        topic che non è del seed resta fuori anche in `off`."""
        rows = [_row("SEAL-1", "topic-b"),
                _row("SEAL-1", "altrui", participants=("commercialista",))]
        for modo in ("off", "report", "on"):
            with self.subTest(modo=modo):
                with patch.dict("os.environ", {"CLODIA_SPAWN_COMPARTMENT": modo}), \
                        _Chat("chan:SEAL-1:topic-b:clodia"), \
                        patch.object(_Svc, "search",
                                     lambda self, q, mode="lexical": list(rows)):
                    self.assertNotIn("altrui", self.names("search"))


if __name__ == "__main__":
    unittest.main()

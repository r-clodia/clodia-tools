"""`telegram.listen` non aggancia una chat che nessuno ha dichiarato fonte.

clodia-platform#364, epic #359. Il meccanismo A (`topic.telegram_bind`) era
WALLS: collegare un gruppo Telegram a uno scope passava dall'owner. Il
meccanismo B che lo sostituisce scriveva `telegram-bindings.json` senza chiedere
niente a nessuno — cioè il binding era diventato l'atto di autorizzazione senza
esserne mai stato incaricato, ed è il buco più largo dell'epic.

Il rimedio è una precondizione, non un gate nuovo: la chat dev'essere GIÀ
dichiarata ingress del topic bersaglio, e la dichiarazione (`topic.ingress_add`)
è WALLS come tutti gli `ingress_add`. Così l'autorizzazione torna dove si
rilegge — nella lista dello scope — e il file dei binding torna a rispondere
alla sola domanda tecnica: quale istanza ascolta quale chat.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from unittest.mock import patch

from . import egress
from . import main as M


class _Topics:
    """Il servizio topic ridotto a ciò che il verbo tocca: il meta dello scope."""

    def __init__(self, tier="SEAL-1"):
        self._tier = tier

    def open(self, tier, name):
        return {"meta": {"tier": self._tier, "owner": "davide", "participants": {}}}


class TelegramListenIngressTests(unittest.TestCase):

    def setUp(self):
        # I binding stanno in un file del datadir: una dir usa-e-getta per test,
        # così non si tocca quello vero e ogni caso parte pulito.
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.datadir = d.name

        from . import whitelist as wl
        self.cfg = {"agents": {}, "egress_allow": [], "source_allow": [],
                    "scope_egress_allow": {}, "scope_source_allow": {}}
        for pt in (patch.dict(os.environ, {"CLODIA_DATA": self.datadir}),
                   patch.object(wl, "CONFIG", self.cfg),
                   patch.object(wl, "save_config", lambda: None),
                   patch.object(M, "_topics", lambda: _Topics()),
                   patch.object(M, "_require_topic_member", lambda *a, **k: None),
                   patch.object(M, "agent_name", lambda: "messaggero-1"),
                   # Nessuno è nel perimetro: qui si vaglia la LISTA.
                   patch.object(egress, "perimeter_addresses", lambda scope=None: set()),
                   # La chiamata arriva da un canale QUALSIASI, non dal bersaglio:
                   # è precisamente il caso che il vaglio deve saper distinguere.
                   patch.object(egress, "_scope_of_call", lambda: "SEAL-1/altrove")):
            pt.start()
            self.addCleanup(pt.stop)

    def _listen(self, tier="SEAL-1", name="bersaglio", chat="-1001"):
        return M._dispatch_telegram(
            "telegram.listen", {"tier": tier, "name": name, "chat_id": chat})

    def _bindings(self):
        from .tools import telegram_bindings as tb
        return tb.load()

    # ── il gate ──────────────────────────────────────────────────────────────

    def test_an_undeclared_chat_is_refused(self):
        """IL CASO: senza dichiarazione non si aggancia, e non si scrive nulla."""
        with self.assertRaises(ValueError) as e:
            self._listen()
        self.assertEqual(self._bindings(), {},
                         "rifiutata ma scritta: il binding non deve sopravvivere al no")
        msg = str(e.exception)
        self.assertIn("topic.ingress_add", msg,
                      "l'errore deve nominare il rimedio, non solo il divieto")
        self.assertIn("tg:-1001", msg)
        self.assertIn("SEAL-1/bersaglio", msg)

    def test_a_declared_chat_goes_through_as_before(self):
        egress.scope_allow("ingress", "SEAL-1/bersaglio", "tg:-1001")
        r = self._listen()
        self.assertTrue(r["ok"])
        self.assertEqual(r["topic"], "SEAL-1/bersaglio")
        self.assertEqual(self._bindings()["-1001"]["topic"], "bersaglio")

    def test_declared_ELSEWHERE_does_not_open_the_target(self):
        """Il caso che passerebbe se lo scope si deducesse dal chiamante: la chat
        è dichiarata nella stanza da cui parte la chiamata, non in quella che si
        sta agganciando."""
        egress.scope_allow("ingress", "SEAL-1/altrove", "tg:-1001")
        with self.assertRaises(ValueError):
            self._listen(name="bersaglio")
        self.assertEqual(self._bindings(), {})

    def test_a_globally_declared_chat_is_enough(self):
        """L'unione globale + scope vale anche qui: non è una lista a parte."""
        egress.allow("ingress", "tg:-1001")
        self.assertTrue(self._listen()["ok"])

    def test_the_check_runs_before_the_one_chat_one_topic_rule(self):
        """Una chat non dichiarata dev'essere rifiutata per il motivo GIUSTO:
        se l'invariante scattasse prima, il messaggio parlerebbe di `unlisten`
        altrove e nasconderebbe la causa vera."""
        egress.scope_allow("ingress", "SEAL-1/primo", "tg:-1001")
        self._listen(name="primo")
        with self.assertRaises(ValueError) as e:
            self._listen(name="secondo")
        self.assertIn("topic.ingress_add", str(e.exception))

    # ── la revoca ────────────────────────────────────────────────────────────

    def test_removing_the_source_unbinds_the_chat(self):
        """Togliere la fonte scollega: altrimenti la revoca non revoca e il relay
        continuerebbe a riportare da un gruppo de-autorizzato."""
        egress.scope_allow("ingress", "SEAL-1/bersaglio", "tg:-1001")
        self._listen()
        out = M._dispatch_topic("topic.ingress_remove",
                                {"tier": "SEAL-1", "name": "bersaglio",
                                 "uri": "tg:-1001"})
        self.assertTrue(out["removed"])
        self.assertTrue(out["unbound"], "l'effetto collaterale va raccontato")
        self.assertEqual(self._bindings(), {})

    def test_removing_a_source_does_not_touch_another_topics_binding(self):
        """Il binding si tocca solo se è di QUESTO topic: una chat agganciata
        altrove non è affare della revoca di questa stanza."""
        egress.scope_allow("ingress", "SEAL-1/primo", "tg:-1001")
        self._listen(name="primo")
        M._dispatch_topic("topic.ingress_remove",
                          {"tier": "SEAL-1", "name": "secondo", "uri": "tg:-1001"})
        self.assertIn("-1001", self._bindings())

    def test_removing_a_non_telegram_source_is_unaffected(self):
        """La revoca di una fonte qualsiasi non deve andare a cercare binding."""
        egress.scope_allow("ingress", "SEAL-1/bersaglio", "mailfrom:a@b.it")
        out = M._dispatch_topic("topic.ingress_remove",
                                {"tier": "SEAL-1", "name": "bersaglio",
                                 "uri": "mailfrom:a@b.it"})
        self.assertTrue(out["removed"])
        self.assertNotIn("unbound", out)

    def test_unlisten_still_works_without_touching_the_list(self):
        """`unlisten` resta il gesto tecnico opposto a `listen`: stacca l'ascolto
        e lascia la dichiarazione in piedi — chi ha approvato la fonte non l'ha
        disapprovata perché un'istanza ha smesso di ascoltare."""
        egress.scope_allow("ingress", "SEAL-1/bersaglio", "tg:-1001")
        self._listen()
        r = M._dispatch_telegram("telegram.unlisten",
                                 {"tier": "SEAL-1", "name": "bersaglio",
                                  "chat_id": "-1001"})
        self.assertTrue(r["removed"])
        self.assertEqual(egress.scope_uris("ingress", "SEAL-1/bersaglio"),
                         ["tg:-1001"])

    def test_a_legacy_tier_alias_still_unbinds(self):
        """`P1/acme` e `SEAL-1/acme` sono la stessa stanza: confrontare le
        stringhe grezze farebbe fallire lo scollegamento in silenzio — fonte via
        dalla lista, relay che continua a riportare."""
        egress.scope_allow("ingress", "SEAL-1/bersaglio", "tg:-1001")
        self._listen()
        out = M._dispatch_topic("topic.ingress_remove",
                                {"tier": "P1", "name": "bersaglio",
                                 "uri": "tg:-1001"})
        self.assertTrue(out.get("unbound"))
        self.assertEqual(self._bindings(), {})


if __name__ == "__main__":
    unittest.main()

"""Le liste di destinazioni e fonti hanno un secondo asse: lo scope.

Perché servivano. La lista era **globale e sola** (#128, per una buona ragione:
per-agente non converge mai). Ma un asse solo significa che approvare un
indirizzo lo apre per OGNI stanza e per sempre — la issue #150, e il caso
Giovanni: una volta approvato `mailto:cliente@x.it` nel topic A, un partecipante
del topic B può farci spedire senza che nessuno veda più niente.

Con la lista per scope, un'approvazione data in una stanza non autorizza nulla
altrove. La regola (voce 18 del system-notebook):

    destinazione nella lista GLOBALE   → passa
    nella lista dello SCOPE            → passa
    in nessuna delle due               → gate

L'unione, non la sostituzione: la lista globale resta il canale che raggiunge
ogni stanza, e proprio per questo dovrebbe restringersi ai recapiti
d'infrastruttura dell'owner invece di allargarsi.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import egress
from . import whitelist as w


CANALE = "chan:SEAL-1:acme:clodia"
ALTRO = "chan:SEAL-1:beta:clodia"


class _Chat:
    def __init__(self, v):
        self.v = v

    def __enter__(self):
        self.t = w.set_current_chat(self.v)
        return self

    def __exit__(self, *a):
        w.reset_current_chat(self.t)
        return False


def _cfg(globali=None, per_scope=None, fonti=None, fonti_scope=None):
    return {
        "egress_allow": list(globali or []),
        "scope_egress_allow": dict(per_scope or {}),
        "source_allow": list(fonti or []),
        "scope_source_allow": dict(fonti_scope or {}),
        "agents": {},
    }


class Base(unittest.TestCase):
    def env(self, **kw):
        return patch.object(w, "CONFIG", _cfg(**kw))


class EffectiveTests(Base):
    def test_a_scope_entry_counts_only_in_its_own_room(self):
        """Il caso Giovanni, che è la ragione per cui questo asse esiste."""
        with self.env(per_scope={"SEAL-1/acme": ["mailto:cliente@x.it"]}):
            with _Chat(CANALE):
                self.assertIn("mailto:cliente@x.it", egress.effective_uris("egress"))
            with _Chat(ALTRO):
                self.assertNotIn("mailto:cliente@x.it", egress.effective_uris("egress"))

    def test_the_global_list_counts_everywhere(self):
        """Ed è per questo che dovrebbe restare piccola: è l'unico percorso che
        raggiunge ogni stanza."""
        with self.env(globali=["mailto:davide@x.it"]):
            for c in (CANALE, ALTRO):
                with _Chat(c):
                    self.assertIn("mailto:davide@x.it", egress.effective_uris("egress"))

    def test_it_is_a_union_not_a_replacement(self):
        with self.env(globali=["mailto:a@x.it"],
                      per_scope={"SEAL-1/acme": ["mailto:b@x.it"]}):
            with _Chat(CANALE):
                r = egress.effective_uris("egress")
                self.assertIn("mailto:a@x.it", r)
                self.assertIn("mailto:b@x.it", r)

    def test_outside_any_room_only_the_global_list_applies(self):
        """In un job non c'è uno scope: dedurlo da un argomento sarebbe la parola
        dell'agente su dove si trova."""
        with self.env(globali=["mailto:a@x.it"],
                      per_scope={"SEAL-1/acme": ["mailto:b@x.it"]}):
            with _Chat("job:42"):
                r = egress.effective_uris("egress")
                self.assertIn("mailto:a@x.it", r)
                self.assertNotIn("mailto:b@x.it", r)

    def test_legacy_tier_aliases_reach_the_same_list(self):
        """`P1/acme` e `SEAL-1/acme` sono la stessa stanza: due chiavi darebbero
        due liste, e una resterebbe invisibile a chi guarda l'altra."""
        with self.env(per_scope={"P1/acme": ["mailto:c@x.it"]}):
            with _Chat(CANALE):
                self.assertIn("mailto:c@x.it", egress.effective_uris("egress"))


class DecideTests(Base):
    def test_a_destination_approved_in_this_room_passes(self):
        with self.env(per_scope={"SEAL-1/acme": ["mailto:cliente@x.it"]}):
            with _Chat(CANALE):
                v = egress.decide({}, "email.send", {"to": "cliente@x.it"})
                self.assertTrue(v["allowed"])

    def test_the_same_destination_from_another_room_is_refused(self):
        with self.env(per_scope={"SEAL-1/acme": ["mailto:cliente@x.it"]}):
            with _Chat(ALTRO):
                v = egress.decide({}, "email.send", {"to": "cliente@x.it"})
                self.assertFalse(v["allowed"])


class RememberTests(Base):
    def test_approving_inside_a_room_remembers_inside_that_room(self):
        """Il pezzo che chiude la #150: l'approvazione non deborda."""
        cfg = _cfg()
        with patch.object(w, "CONFIG", cfg), patch.object(w, "save_config", lambda: None):
            with _Chat(CANALE):
                egress.remember("clodia", "email", ["mailto:nuovo@x.it"])
        self.assertEqual(cfg["scope_egress_allow"]["SEAL-1/acme"], ["mailto:nuovo@x.it"])
        self.assertEqual(cfg["egress_allow"], [],
                         "un'approvazione in una stanza non deve toccare la lista globale")

    def test_outside_a_room_it_still_remembers_globally(self):
        """Una DM o un job non hanno una stanza in cui ricordare. Resta il
        comportamento di prima, che è l'unico possibile lì."""
        cfg = _cfg()
        with patch.object(w, "CONFIG", cfg), patch.object(w, "save_config", lambda: None):
            with _Chat("job:7"):
                egress.remember("clodia", "email", ["mailto:x@y.it"])
        self.assertEqual(cfg["egress_allow"], ["mailto:x@y.it"])


class IngressTests(Base):
    def test_a_source_vetted_in_a_room_is_vetted_only_there(self):
        """Simmetrico all'uscita: una fonte approvata per un topic non diventa
        fidata per tutti, altrimenti il taint di una stanza si spegnerebbe in
        tutte."""
        with self.env(fonti_scope={"SEAL-1/acme": ["mailfrom:tizio@x.it"]}):
            with _Chat(CANALE):
                self.assertTrue(egress.is_vetted_source("mailfrom:tizio@x.it"))
            with _Chat(ALTRO):
                self.assertFalse(egress.is_vetted_source("mailfrom:tizio@x.it"))

    def test_an_empty_list_still_vets_nothing(self):
        """La direzione d'errore che non cambia: una fonte non dichiarata non è
        fidata, e sbagliare qui è silenzioso."""
        with self.env():
            with _Chat(CANALE):
                self.assertFalse(egress.is_vetted_source("https://qualsiasi.example"))


class RepositoryTests(Base):
    """I repository sono il primo tipo di voce che motiva questo asse (voce 31):
    un repo è una destinazione dello scope, non un remote del topic."""

    def test_a_repository_is_expressible_with_the_existing_vocabulary(self):
        repo = "https://github.com/uncommon-creative/proof-of-flex-backend"
        with self.env(per_scope={"SEAL-1/acme": [repo]}):
            with _Chat(CANALE):
                self.assertIn(repo, egress.effective_uris("egress"))
            with _Chat(ALTRO):
                self.assertNotIn(repo, egress.effective_uris("egress"))


if __name__ == "__main__":
    unittest.main()

"""Una destinazione già ammessa non si fa approvare due volte.

`github.push` verso un repository nella whitelist egress era la stessa decisione
presa due volte: il perimetro ha già detto sì, e il gate la richiedeva a ogni
pubblicazione. Su `SEAL-1/software-house` sono 17 gate per un solo agente, otto
dei quali per `create_branch`. Un agente che pubblica di mestiere accumula
conferme finché non si approva senza leggere.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import egress


class DestinationsAlreadyAllowedTests(unittest.TestCase):
    def _regole(self, *uris):
        return patch.object(egress, "effective_uris", lambda *_a, **_k: list(uris))

    def test_a_push_to_an_allowed_repo_is_already_decided(self):
        with self._regole("https://github.com/r-clodia/"):
            self.assertTrue(egress.destinations_already_allowed(
                "github.push", {"repo": "https://github.com/r-clodia/clodia-logic"}))

    def test_the_native_verbs_are_seen_by_the_pdp_at_all(self):
        """`push` nudo non combaciava con nessun prefisso di `_GITHUB_WRITE`:
        il verbo che pubblica davvero stava fuori dal perimetro, governato dal
        solo gate. Toglierne il gate senza questo lo avrebbe lasciato senza
        alcun controllo."""
        self.assertIsNotNone(egress.spec_for("github.push"))
        self.assertIsNotNone(egress.spec_for("github.pull_request"))
        self.assertIsNone(egress.spec_for("github.clone"),
                          "clone porta DENTRO: nessuna destinazione da approvare")

    def test_a_pull_request_to_an_allowed_repo_is_already_decided(self):
        with self._regole("https://github.com/r-clodia/"):
            self.assertTrue(egress.destinations_already_allowed(
                "github.pull_request",
                {"repo": "https://github.com/r-clodia/clodia-tools.git", "head": "x",
                 "title": "t"}))

    def test_a_push_outside_the_perimeter_is_not(self):
        """Fuori dal perimetro il gate resta: è lì che il confine si sposta."""
        with self._regole("https://github.com/r-clodia/"):
            self.assertFalse(egress.destinations_already_allowed(
                "github.push", {"repo": "https://github.com/altro-owner/segreti"}))

    def test_no_rules_means_no_shortcut(self):
        with self._regole():
            self.assertFalse(egress.destinations_already_allowed(
                "github.push", {"repo": "https://github.com/r-clodia/clodia-logic"}))

    def test_a_verb_without_declared_destinations_still_asks(self):
        with self._regole("*"):
            self.assertFalse(egress.destinations_already_allowed(
                "packs.remove", {"name": "x"}))

    def test_no_destination_extracted_still_asks(self):
        """In dubbio si chiede: il `True` di questa funzione toglie un gate."""
        with self._regole("https://github.com/r-clodia/"):
            self.assertFalse(egress.destinations_already_allowed("github.push", {}))

    def test_every_destination_must_match_not_just_one(self):
        with self._regole("https://github.com/r-clodia/"), \
             patch.object(egress, "spec_for",
                          lambda _v: ("github", lambda _a: [
                              "https://github.com/r-clodia/clodia-logic",
                              "https://github.com/altro/repo"])):
            self.assertFalse(egress.destinations_already_allowed("github.push", {}))


if __name__ == "__main__":
    unittest.main()

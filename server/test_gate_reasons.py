"""Il perimetro risponde a UNA domanda, e la risponde per tutte e tre le ragioni.

Un verbo può chiedere un umano per tre motivi diversi (`main.call_tool`):

    globale      il verbo è pericoloso per chiunque (`gate.is_gated`)
    per-agente   è pericoloso per QUESTO agente (`gated_tools`)
    fuori profilo lo può raggiungere ma non lo dichiara (`profile_tools`)

Sono domande distinte, e restano distinte nel testo della card. Ma una sola di
esse chiede «dove sta andando questa roba», e a quella la whitelist ha già
risposto — regola dell'owner del 17 ago 2026, citata in `main._context_gate_needed`:

    «se la destinazione è censita in whitelist allora va considerata come parte
     del perimetro e non deve essere un segnale che fa scattare il gate»

Applicata al gate di contesto (#217) e al gate GLOBALE (#210), non alle altre
due. Conseguenza misurata in `SEAL-1/risoluzione-issue-clodia` e riportata in
clodia-platform#254: `clodia` non dichiara `github.push` fra i suoi
`profile_tools` (config.yaml), quindi ogni push verso un repository **già in
whitelist** produceva una card nuova — indistinguibile da un push verso una
destinazione mai vista. Lo stesso accade a chiunque abbia ancora `github.*` nei
propri `gated_tools` nella copia del gateway, dopo che il seed li ha rimossi il
17 ago: la deriva fra le due copie riproduceva il sintomo da sola.

`web.post` NON è coperto, di proposito: `egress._http()` riduce la destinazione a
`schema://host/` e scarta il path, quindi «host censito» non promette quello che
promette «repository censito».
"""
from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from . import egress, gate


def _perimetro(verb: str, arguments: dict, *regole: str) -> bool:
    """`destinations_already_allowed` con una whitelist finta: è la stessa
    funzione che usa il dispatch, non una sua imitazione."""
    with patch.object(egress, "effective_uris", lambda *_a, **_k: list(regole)):
        return egress.destinations_already_allowed(verb, arguments)


_PUSH = {"repo": "https://github.com/r-clodia/clodia-logic"}
_R_CLODIA = "https://github.com/r-clodia/"


class PerimeterAnswersTests(unittest.TestCase):
    """A QUALI gate il perimetro può rispondere."""

    def test_outward_verbs_are_the_ones_it_answers(self):
        for v in ("github.push", "github.pull_request"):
            with self.subTest(verbo=v):
                self.assertTrue(gate.perimeter_answers(v))

    def test_system_and_walls_are_not_about_a_destination(self):
        """`agents.grant_tool` non va da nessuna parte: cambia le regole. Nessuna
        whitelist di destinazioni ha qualcosa da dire su di esso."""
        for v in ("agents.grant_tool", "topic.remote_add", "topic.add_participant",
                  "settings.set", "packs.remove"):
            with self.subTest(verbo=v):
                self.assertFalse(gate.perimeter_answers(v))

    def test_web_post_stays_outside_the_shortcut(self):
        """La whitelist HTTP censisce un host, non un path: `_http()` il path lo
        butta. Approvare `https://x.it/` non è approvare `https://x.it/qualunque`,
        e un corpo POST arbitrario è esattamente ciò che cambia fra i due."""
        self.assertEqual(gate.gate_class("web.post"), gate.GATE_OUTWARD)
        self.assertFalse(gate.perimeter_answers("web.post"))

    def test_a_verb_that_is_not_gated_at_all(self):
        self.assertFalse(gate.perimeter_answers("github.clone"))


class NeedsConsentTests(unittest.TestCase):
    """La decisione composta: le tre ragioni più il perimetro."""

    def test_no_reason_no_card(self):
        self.assertFalse(gate.needs_consent(
            "github.clone", globally_gated=False, agent_gated=False,
            off_profile=False, perimeter_ok=False))

    def test_the_global_gate_yields_to_the_perimeter(self):
        """Già vero prima di #254 (#210): resta vero, ed è la riga che dice che
        non l'abbiamo perso per strada."""
        self.assertFalse(gate.needs_consent(
            "github.push", globally_gated=True, agent_gated=False,
            off_profile=False, perimeter_ok=_perimetro("github.push", _PUSH, _R_CLODIA)))

    def test_the_per_agent_gate_yields_too(self):
        """La copia del gateway può ancora elencare `github.*` fra i `gated_tools`
        di un dev: il seed li ha rimossi il 17 ago, la copia autorevole si scrive
        alla registrazione. Con la deriva il sintomo tornava intero."""
        self.assertFalse(gate.needs_consent(
            "github.push", globally_gated=True, agent_gated=True,
            off_profile=False, perimeter_ok=_perimetro("github.push", _PUSH, _R_CLODIA)))

    def test_outside_the_profile_yields_too(self):
        """Il caso di clodia in clodia-platform#254: `github.push` non è nel suo
        `profile_tools`, quindi la card scattava a ogni push verso un repository
        che il perimetro aveva già approvato."""
        self.assertFalse(gate.needs_consent(
            "github.pull_request", globally_gated=True, agent_gated=False,
            off_profile=True,
            perimeter_ok=_perimetro("github.pull_request",
                                    {"repo": "https://github.com/r-clodia/clodia-tools",
                                     "head": "x", "title": "t"}, _R_CLODIA)))

    def test_outside_the_perimeter_every_reason_still_asks(self):
        """Fuori whitelist il gate resta: è lì che il confine si sposta."""
        fuori = _perimetro("github.push",
                           {"repo": "https://github.com/altro-owner/segreti"}, _R_CLODIA)
        for ragione in ("globally_gated", "agent_gated", "off_profile"):
            with self.subTest(ragione=ragione):
                self.assertTrue(gate.needs_consent(
                    "github.push", perimeter_ok=fuori,
                    **{r: r == ragione for r in
                       ("globally_gated", "agent_gated", "off_profile")}))

    def test_a_walls_verb_is_asked_even_with_a_whitelisted_destination(self):
        """`perimeter_ok` non arriva mai True qui (nessuna destinazione), ma la
        regola non deve dipendere da quel dettaglio: se domani un verbo `walls`
        acquistasse una destinazione, il gate sui muri resterebbe."""
        self.assertTrue(gate.needs_consent(
            "topic.remote_add", globally_gated=True, agent_gated=False,
            off_profile=False, perimeter_ok=True))

    def test_widening_the_whitelist_is_never_covered_by_the_whitelist(self):
        """`egress.allow` è `outward` e non ha destinazione: il verbo che ALLARGA
        il perimetro non può essere assolto dal perimetro che allarga."""
        self.assertFalse(_perimetro("egress.allow", {"uri": "mailto:x@y.it"}, "*"))
        self.assertTrue(gate.needs_consent(
            "egress.allow", globally_gated=True, agent_gated=False,
            off_profile=False, perimeter_ok=False))

    def test_web_post_toward_a_whitelisted_host_still_asks(self):
        args = {"url": "https://hooks.example.it/incoming", "body": "x"}
        self.assertTrue(_perimetro("web.post", args, "https://hooks.example.it/"),
                        "l'host È in whitelist: è il perimetro a dirlo")
        self.assertTrue(gate.needs_consent(
            "web.post", globally_gated=True, agent_gated=False,
            off_profile=False, perimeter_ok=True),
            "e nonostante questo la POST si fa approvare")


class TheShortCircuitIsGoneTests(unittest.TestCase):
    """La guardia contro il ritorno del difetto.

    `server.main` non è importabile in ogni ambiente (dipende da `mcp`), e questa
    verifica non deve dipendere da quello: si legge il sorgente come testo, come
    già fa `server/api/test_mention_boundary.py` per le regex ritirate.
    """

    def _src(self) -> str:
        return (Path(__file__).with_name("main.py")).read_text(encoding="utf-8")

    def test_the_two_reasons_no_longer_skip_the_perimeter_check(self):
        """Era: `if _gate.is_gated(name) and not (agent_gates(...) or _off_profile)`
        — cioè il perimetro non veniva nemmeno consultato per due delle tre
        ragioni. È la riga di clodia-platform#254."""
        self.assertNotIn("and not (agent_gates(name, _ag) or _off_profile)",
                         self._src())

    def test_the_dispatch_asks_the_rule_instead_of_rebuilding_it(self):
        """Due copie della stessa condizione divergono: la decisione sta in
        `gate.needs_consent`, e il dispatch la interroga."""
        src = self._src()
        self.assertIn("_gate.needs_consent(", src)
        self.assertIn("_gate.perimeter_answers(", src)


if __name__ == "__main__":
    unittest.main()

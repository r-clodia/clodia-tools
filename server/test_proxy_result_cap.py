"""Il risultato di un backend MCP di terzi rientra con un tetto (platform#328).

`call_proxied` è il punto di rientro comune di OGNI verbo proxato: i 19 verbi
GitHub concessi, e quelli che il backend aggiungerà domani. Senza tetto qui,
`get_file_contents` su un file grosso, `search_code` su una query larga o
`get_commit --detail=full_patch` versano nel contesto tutto quello che il
backend ha voglia di mandare, e ci restano per tutto il turno.

Il tetto sta QUI e non sul singolo verbo: un cap per verbo sarebbe 19 porte da
tenere chiuse a mano, questa è una porta sola che nasce chiusa anche per chi
arriva dopo.

Forma: **taglio dichiarato, non paginazione.** La fetta successiva richiederebbe
di rifare per intero la chiamata a monte, quindi non c'è `next_offset` da
promettere: c'è una nota che dice che il taglio è avvenuto, che i byte tagliati
non tornano, e quale strada costa una chiamata sola (`github.clone` + lettura
locale, o una query più stretta).
"""
from __future__ import annotations

import asyncio
import json
import unittest
from contextlib import asynccontextmanager
from unittest.mock import patch

from . import proxy as P


class _Text:
    type = "text"

    def __init__(self, text: str):
        self.text = text


class _Res:
    def __init__(self, content):
        self.content = content


def _call(payload: str, verb: str = "github.get_file_contents") -> str:
    """Percorre `call_proxied` con un backend finto che risponde `payload`."""

    @asynccontextmanager
    async def fake_session(b):
        class S:
            async def call_tool(self, name, arguments):
                return _Res([_Text(payload)])

        yield S()

    backend = verb.split(".", 1)[0]
    with patch.object(P, "_backends", lambda: {backend: {"name": backend}}), \
            patch.object(P, "_session", fake_session):
        return asyncio.run(P.call_proxied(verb, {}))


class TheCapTests(unittest.TestCase):
    def test_a_small_result_passes_through_untouched(self):
        """Il tetto non deve farsi sentire sul caso normale: nessuna nota,
        nessun byte in più, o ogni risposta breve porterebbe rumore."""
        self.assertEqual(_call("piccolo\n"), "piccolo\n")

    def test_a_result_over_the_cap_is_cut(self):
        out = _call("x" * (P.RESULT_CAP_BYTES * 3))
        self.assertLess(len(out.encode("utf-8")),
                        P.RESULT_CAP_BYTES * 2,
                        "il risultato rientra nel contesto senza tetto")

    def test_the_cut_keeps_the_first_bytes(self):
        """Si tiene la testa, che è la parte che di solito serve."""
        out = _call("INIZIO" + "x" * (P.RESULT_CAP_BYTES * 2))
        self.assertTrue(out.startswith("INIZIO"))

    def test_the_cut_is_declared(self):
        out = _call("x" * (P.RESULT_CAP_BYTES * 2))
        self.assertIn("truncated", out.lower())

    def test_the_note_says_json_is_no_longer_valid(self):
        """Molti risultati proxati sono JSON, e un JSON tagliato NON è JSON: se
        la nota non lo dice, chi riceve l'errore di `json.loads` conclude che il
        backend abbia risposto male e va a cercare il guasto lì."""
        out = _call(json.dumps({"content": "y" * (P.RESULT_CAP_BYTES * 2)}))
        self.assertIn("JSON", out)

    def test_the_note_points_at_the_way_out(self):
        """Il taglio è irreversibile: senza il rimando, l'unica mossa che resta
        a chi legge è richiamare lo stesso verbo e ripagare l'upstream."""
        out = _call("x" * (P.RESULT_CAP_BYTES * 2))
        self.assertIn("github.clone", out)

    def test_the_note_does_not_promise_pagination(self):
        """`next_offset` qui sarebbe una promessa falsa: non c'è nessuna fetta
        già pagata da richiedere."""
        out = _call("x" * (P.RESULT_CAP_BYTES * 2))
        self.assertNotIn("next_offset", out)

    def test_the_cut_result_still_decodes(self):
        """Il taglio è sui BYTE: senza arretrare al confine del carattere, un
        risultato pieno di accenti diventerebbe indecodificabile a seconda di
        dove capita l'ultimo `€`."""
        out = _call("€" * P.RESULT_CAP_BYTES)  # 3 byte per carattere
        self.assertIsInstance(out, str)
        out.encode("utf-8").decode("utf-8")

    def test_the_cap_is_not_only_for_github(self):
        """Il difetto non è di un verbo né di un backend: è del punto di
        rientro. Un backend montato domani deve nascere cappato."""
        out = _call("z" * (P.RESULT_CAP_BYTES * 2), verb="altro.qualcosa")
        self.assertLess(len(out.encode("utf-8")), P.RESULT_CAP_BYTES * 2)


if __name__ == "__main__":
    unittest.main()

"""L'elenco dei verbi di un seed, coi lucchetti (scheda del seed).

Regola di espansione: un wildcard si espande SOLO se contiene almeno un verbo
gated. Si espande dove c'è qualcosa da vedere; altrimenti un `*` produce duecento
righe in cui il lucchetto che conta non si nota.
"""
from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import patch

from . import agents_api


class _Req:
    def __init__(self, name="avvocato", secret="s3cr3t"):
        self.headers = {"authorization": "Bearer tok"} if secret else {}
        self.path_params = {"name": name}


def _call(name="avvocato", cfg=None, catalogue=None, gated_global=()):
    from . import whitelist as wl, gate, main
    with patch.object(agents_api, "_authorize", lambda r: ("clodia", None)), \
            patch.object(wl, "CONFIG", {"agents": cfg or {}}), \
            patch.object(main, "all_native_verb_names", lambda: list(catalogue or [])), \
            patch.object(gate, "is_gated", lambda v: v in gated_global), \
            patch.object(gate, "gated_verbs_spec", lambda: {"exact": sorted(gated_global),
                                                            "prefixes": []}):
        r = asyncio.run(agents_api.verbs(_Req(name)))
    return json.loads(r.body)


CAT = ["topic.open", "topic.read_file", "topic.remote_push", "topic.add_participant",
       "normattiva.articolo", "normattiva.indice", "email.send", "email.list"]


class ExpansionTests(unittest.TestCase):
    def test_a_wildcard_with_a_gated_verb_is_expanded(self):
        b = _call(cfg={"avvocato": {"allowed_tools": ["topic.*"],
                                    "gated_tools": ["topic.remote_push"]}},
                  catalogue=CAT)
        g = b["groups"][0]
        self.assertTrue(g["expanded"])
        self.assertEqual(sorted(v["verb"] for v in g["verbs"]),
                         ["topic.add_participant", "topic.open", "topic.read_file",
                          "topic.remote_push"])
        locked = [v["verb"] for v in g["verbs"] if v["gated"]]
        self.assertEqual(locked, ["topic.remote_push"])

    def test_a_wildcard_without_gated_verbs_stays_compact(self):
        """Ma dice QUANTI verbi copre: «compatto» non deve leggersi come «pochi»."""
        b = _call(cfg={"avvocato": {"allowed_tools": ["normattiva.*"]}}, catalogue=CAT)
        g = b["groups"][0]
        self.assertFalse(g["expanded"])
        self.assertEqual(g["count"], 2)
        self.assertEqual(g["verbs"], [])

    def test_a_globally_gated_verb_also_triggers_expansion(self):
        """Il lucchetto non viene solo dal seed: `topic.add_participant` è gated
        per chiunque, e va visto anche se l'agente non lo dichiara."""
        b = _call(cfg={"avvocato": {"allowed_tools": ["topic.*"]}}, catalogue=CAT,
                  gated_global={"topic.add_participant"})
        g = b["groups"][0]
        self.assertTrue(g["expanded"])
        row = next(v for v in g["verbs"] if v["verb"] == "topic.add_participant")
        self.assertEqual(row["gated_by"], "global")

    def test_denied_verbs_do_not_appear_in_an_expansion(self):
        """Un verbo negato non è un verbo dell'agente: mostrarlo, anche senza
        lucchetto, direbbe che può farlo."""
        b = _call(cfg={"avvocato": {"allowed_tools": ["topic.*"],
                                    "denied_tools": ["topic.read_file"],
                                    "gated_tools": ["topic.remote_push"]}},
                  catalogue=CAT)
        verbs = [v["verb"] for v in b["groups"][0]["verbs"]]
        self.assertNotIn("topic.read_file", verbs)

    def test_a_denied_exact_grant_is_dropped(self):
        b = _call(cfg={"avvocato": {"allowed_tools": ["email.send", "email.list"],
                                    "denied_tools": ["email.send"]}}, catalogue=CAT)
        self.assertEqual([v["verb"] for v in b["verbs"]], ["email.list"])

    def test_a_star_grant_covers_every_namespace(self):
        b = _call(name="clodia",
                  cfg={"clodia": {"allowed_tools": ["*"], "gated_tools": ["email.send"]}},
                  catalogue=CAT)
        g = b["groups"][0]
        self.assertTrue(g["expanded"])
        self.assertEqual(len(g["verbs"]), len(CAT))

    def test_exact_grants_carry_their_own_lock(self):
        b = _call(cfg={"avvocato": {"allowed_tools": ["email.send", "topic.open"],
                                    "gated_tools": ["email.send"]}}, catalogue=CAT)
        rows = {v["verb"]: v for v in b["verbs"]}
        self.assertTrue(rows["email.send"]["gated"])
        self.assertEqual(rows["email.send"]["gated_by"], "agent")
        self.assertFalse(rows["topic.open"]["gated"])

    def test_an_unknown_agent_answers_empty_not_error(self):
        b = _call(name="fantasma", cfg={}, catalogue=CAT)
        self.assertEqual(b["verbs"], [])
        self.assertEqual(b["groups"], [])


if __name__ == "__main__":
    unittest.main()

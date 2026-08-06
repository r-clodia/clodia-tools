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


def _call(name="avvocato", cfg=None, catalogue=None, gated_global=(),
          proxied=(), proxy_ok=True):
    from . import whitelist as wl, gate, main, proxy as pmod
    from types import SimpleNamespace

    async def _list_proxied():
        if not proxy_ok:
            raise RuntimeError("backend MCP non raggiungibile")
        return [SimpleNamespace(name=n) for n in proxied]

    with patch.object(agents_api, "_authorize", lambda r: ("clodia", None)), \
            patch.object(wl, "CONFIG", {"agents": cfg or {}}), \
            patch.object(main, "all_native_verb_names", lambda: list(catalogue or [])), \
            patch.object(pmod, "list_proxied_tools", _list_proxied), \
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

    def test_a_wildcard_without_gated_verbs_still_carries_its_verbs(self):
        """Regola cambiata il 6 ago, e il perché conta più del cosa.

        Prima un wildcard senza lucchetti restava «compatto» — verbi non
        restituiti, solo un conteggio — per non trasformare il `*` di clodia in un
        muro di 145 righe. Il criterio era quello sbagliato: ciò che rende un
        gruppo un muro è la sua DIMENSIONE, non l'assenza di serrature. Misurato
        sulla scheda di `messaggero`: `email.*` e `telegram.*`, 8 verbi ciascuno e
        il suo mestiere, non comparivano affatto mentre `topic` e `jobs` sì.

        Ora i verbi ci sono sempre; è il DEFAULT DI APERTURA a variare (vedi
        `open_by_default`). «Chiuso» significa «un clic», non «assente».
        """
        b = _call(cfg={"avvocato": {"allowed_tools": ["normattiva.*"]}}, catalogue=CAT)
        g = b["groups"][0]
        self.assertTrue(g["expanded"])
        self.assertEqual(g["count"], 2)
        self.assertEqual(len(g["verbs"]), 2)
        self.assertFalse(g["has_gated"])
        # e il nodo dell'albero esiste, chiuso di default perché non c'è nulla da
        # guardare: è lì che la vecchia regola sopravvive, dove appartiene
        node = next(n for n in b["tree"] if n["namespace"] == "normattiva")
        self.assertEqual(node["count"], 2)
        self.assertFalse(node["open_by_default"])

    def test_a_narrow_namespace_that_is_the_agents_trade_is_visible(self):
        """Il caso concreto che ha fatto cambiare la regola: un postino la cui
        posta non compariva nella propria scheda."""
        b = _call(cfg={"messaggero": {"allowed_tools": ["email.*", "topic.open"]}},
                  catalogue=CAT + ["email.send", "email.read", "email.list"],
                  name="messaggero")
        namespaces = {n["namespace"] for n in b["tree"]}
        self.assertIn("email", namespaces, "il mestiere dell'agente deve comparire")
        email_node = next(n for n in b["tree"] if n["namespace"] == "email")
        self.assertEqual(email_node["count"], 3)

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



class McpNamespaceTests(unittest.TestCase):
    """Un namespace MCP montato fa parte del catalogo.

    `normattiva.*` copriva 0 verbi perché il catalogo era solo quello nativo — e
    avvocato ha chiamato `normattiva.articolo` dieci volte. Un pannello che
    dichiara zero su qualcosa di vivo è peggio di un pannello che non dichiara.
    """

    def test_a_proxied_namespace_reports_its_verbs(self):
        b = _call(cfg={"avvocato": {"allowed_tools": ["normattiva.*"]}},
                  catalogue=CAT, proxied=["normattiva.articolo", "normattiva.indice"])
        g = b["groups"][0]
        self.assertEqual(g["count"], 2)
        self.assertTrue(b["catalogue_complete"])

    def test_a_gated_proxied_verb_triggers_expansion(self):
        b = _call(cfg={"avvocato": {"allowed_tools": ["normattiva.*"],
                                    "gated_tools": ["normattiva.articolo"]}},
                  catalogue=CAT, proxied=["normattiva.articolo", "normattiva.indice"])
        g = b["groups"][0]
        self.assertTrue(g["expanded"])
        self.assertEqual([v["verb"] for v in g["verbs"] if v["gated"]],
                         ["normattiva.articolo"])

    def test_an_unreachable_proxy_is_DECLARED_not_hidden(self):
        """Senza il flag, i gruppi MCP mostrerebbero un conteggio che sembra
        completo. Chi legge deve sapere che l'elenco è parziale."""
        b = _call(cfg={"avvocato": {"allowed_tools": ["normattiva.*"]}},
                  catalogue=CAT, proxy_ok=False)
        self.assertFalse(b["catalogue_complete"])


if __name__ == "__main__":
    unittest.main()


class HumanPrincipalTests(unittest.TestCase):
    """La scheda di un umano deve mostrare la sua matrice, non zero verbi.

    Il difetto che questo chiude non è cosmetico. Un umano non sta in
    `config.yaml`, quindi l'endpoint leggeva una spec vuota e rispondeva «nessun
    verbo». Ma lo stato reale di un umano senza matrice è l'opposto — ricade sulla
    regola precedente e può quasi tutto. Un pannello che mostra «bloccato» dove il
    sistema è «aperto» è peggio di nessun pannello: l'owner smette di guardare
    proprio dove dovrebbe.
    """

    def _body(self, name, seed):
        import asyncio, json
        from unittest.mock import patch as _p
        from . import agents_api, human

        class R:
            path_params = {"name": name}
            query_params: dict = {}
            headers: dict = {}

        with _p.object(agents_api, "_authorize", lambda _r: ("admin", None)), \
                _p.object(human, "_seed", lambda n: seed if n == name else {}):
            r = asyncio.run(agents_api.verbs(R()))
        return json.loads(r.body)

    def test_a_declared_matrix_is_returned_as_verbs(self):
        b = self._body("giovanni", {"type": "human", "role": "member",
                                    "clearance": "SEAL-2",
                                    "tool_permissions": ["topic.open", "topic.files"]})
        self.assertEqual(b["principal_kind"], "human")
        self.assertTrue(b["matrix_declared"])
        self.assertEqual(sorted(v["verb"] for v in b["verbs"]),
                         ["topic.files", "topic.open"])
        self.assertEqual(b["role"], "member")
        self.assertEqual(b["clearance"], "SEAL-2")

    def test_an_undeclared_matrix_is_flagged_not_shown_as_zero(self):
        b = self._body("nuovo", {"type": "human", "role": "member"})
        self.assertEqual(b["principal_kind"], "human")
        self.assertFalse(b["matrix_declared"],
                         "senza questo flag la UI mostrerebbe «nessun verbo» "
                         "dove lo stato vero è «ricade sulla regola precedente»")

    def test_an_empty_matrix_is_declared_and_really_empty(self):
        b = self._body("chiuso", {"type": "human", "role": "member",
                                  "tool_permissions": []})
        self.assertTrue(b["matrix_declared"])
        self.assertEqual(b["verbs"], [])

    def test_for_a_human_the_lock_means_admin_not_approval(self):
        from unittest.mock import patch as _p
        with _p("server.gate.is_gated", lambda v: v == "packs.remove"):
            b = self._body("giovanni", {"type": "human", "role": "member",
                                        "tool_permissions": ["packs.remove",
                                                             "topic.open"]})
        by = {v["verb"]: v["gated_by"] for v in b["verbs"]}
        self.assertEqual(by["packs.remove"], "admin")
        self.assertIsNone(by["topic.open"])

    def test_an_agent_is_unaffected(self):
        b = self._body("messaggero", {})       # nessun seed umano
        self.assertEqual(b["principal_kind"], "agent")
        self.assertTrue(b["matrix_declared"])
        self.assertIsNone(b["role"])

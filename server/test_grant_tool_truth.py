"""`agents.grant_tool` non deve rispondere ok senza aver concesso
(clodia-platform#304).

Il difetto: `grant_tool` scrive nei `tool_permissions` della **datadir**
(`PATCH /api/agents/<n>/caps`) e ritorna `{"ok": true}`, ma l'autorizzazione si
legge dalla whitelist del **gateway** (`config.yaml`), che quel verbo non tocca.
Il permesso compare nel file, l'agente lo vede in lista, e ogni chiamata viene
rifiutata — la peggior forma di rifiuto, perché nessuno la cerca.

Costo osservato nella issue: l'`avvocato` ha ripiegato per due giorni su
`sysadmin` per eseguire python sui docx, cioè ha aggirato il least-privilege
passando da un agente più privilegiato, mentre il verbo scritto per evitarlo era
in produzione e inerte.

Il rimedio scelto qui è il secondo dei due che la issue elenca — «risponde
dicendo che da solo non autorizza e indica il percorso corretto» — e non il
primo (scrivere anche nella whitelist del gateway), che aprirebbe una decisione
non dello sviluppatore: cosa succede quando la sincronizzazione dal seed del
pack sovrascrive un grant d'istanza.

Il verso della revoca è peggiore e ha lo stesso rimedio: una revoca che sembra
applicata e non toglie niente.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import whitelist as w
from .tools import agents_admin as adm


SEED_ARCH = {"name": "archseed", "abstract": True,
             "tool_permissions": ["topic.open", "topic.post_message"]}


class _Harness:
    """La datadir e il gateway, tenuti separati come lo sono in produzione.

    `card` è ciò che l'agent-server serve su `/api/agents` (la datadir, che
    `_patch_caps` scrive davvero); `cfg` è la whitelist del gateway, che il verbo
    NON tocca. Il test esiste per la distanza fra le due.
    """

    def __init__(self, cfg: dict, card_tools: list[str] | None = None):
        self.cfg = {"agents": cfg}
        self.card = {"name": "avvocato", "type": "worker",
                     "tool_permissions": list(card_tools or [])}
        self.patched: dict | None = None

    def _patch_caps(self, name: str, body: dict) -> dict:
        self.patched = body
        self.card.update(body)
        return dict(body)

    def __enter__(self):
        from . import human as H
        self._p = [
            patch.object(adm, "_find", lambda n: self.card if n == "avvocato" else None),
            patch.object(adm, "_patch_caps", self._patch_caps),
            patch.object(w, "CONFIG", self.cfg),
            patch.object(H, "_seed", lambda n: SEED_ARCH if n == "archseed" else {}),
        ]
        for p in self._p:
            p.start()
        return self

    def __exit__(self, *exc):
        for p in reversed(self._p):
            p.stop()
        return False


class GrantTellsTheTruth(unittest.TestCase):
    def test_a_grant_that_does_not_authorize_does_not_answer_ok(self):
        """Il caso della issue, riprodotto: il verbo entra nella datadir e resta
        non autorizzato."""
        with _Harness({"avvocato": {"allowed_tools": ["topic.write_file"]}},
                      ["topic.write_file"]) as h:
            res = adm.grant_tool("avvocato", "topic.write_document")
        # la scrittura è avvenuta davvero: `ok: false` non deve far credere
        # che non sia stato toccato niente
        self.assertEqual(h.patched,
                         {"tool_permissions": ["topic.write_file", "topic.write_document"]})
        self.assertTrue(res["written"])
        self.assertFalse(res["effective"])
        self.assertFalse(res["ok"])

    def test_the_refusal_names_where_the_authority_is_and_what_to_do(self):
        """Un «non ha funzionato» senza il percorso corretto costa un'altra
        indagine: la risposta nomina l'autorità e la via per cambiarla."""
        with _Harness({"avvocato": {"allowed_tools": ["topic.write_file"]}}):
            res = adm.grant_tool("avvocato", "topic.write_document")
        detail = res["detail"]
        self.assertIn("whitelist del gateway", detail)
        self.assertIn("seed del pack", detail)
        self.assertIn("topic.write_document", detail)

    def test_a_grant_that_does_authorize_answers_ok(self):
        """Nessun allarme quando il permesso vale davvero — un avviso che c'è
        sempre non è un avviso."""
        with _Harness({"avvocato": {"allowed_tools": ["topic.*"]}}):
            res = adm.grant_tool("avvocato", "topic.write_document")
        self.assertTrue(res["ok"])
        self.assertTrue(res["effective"])
        self.assertNotIn("detail", res)

    def test_a_verb_inherited_from_an_ancestor_counts_as_authorized(self):
        """L'autorità è l'insieme EFFETTIVO, non la riga propria dell'agente:
        un verbo che arriva da un antenato è concesso, e dirlo negato sarebbe la
        stessa bugia al contrario."""
        with _Harness({"avvocato": {"allowed_tools": [], "parents": ["professionista"]},
                       "professionista": {"allowed_tools": ["topic.write_document"]}}):
            res = adm.grant_tool("avvocato", "topic.write_document")
        self.assertTrue(res["ok"])

    def test_a_denied_verb_says_that_the_deny_is_the_obstacle(self):
        """Il deny vince su ogni allow: qui il percorso corretto è un altro, e
        indicare il seed del pack manderebbe a modificare la cosa sbagliata."""
        with _Harness({"avvocato": {"allowed_tools": ["topic.*"],
                                    "denied_tools": ["topic.write_document"]}}):
            res = adm.grant_tool("avvocato", "topic.write_document")
        self.assertFalse(res["ok"])
        self.assertIn("denied_tools", res["detail"])


class RevokeTellsTheTruth(unittest.TestCase):
    def test_a_revoke_that_removes_nothing_does_not_answer_ok(self):
        with _Harness({"avvocato": {"allowed_tools": ["topic.*"]}},
                      ["topic.write_document"]) as h:
            res = adm.revoke_tool("avvocato", "topic.write_document")
        self.assertEqual(h.patched, {"tool_permissions": []})
        self.assertTrue(res["written"])
        self.assertTrue(res["still_authorized"])
        self.assertFalse(res["ok"])

    def test_a_revoke_names_the_origin_that_keeps_the_verb_alive(self):
        """Togliere dall'agente non toglie ciò che eredita: sono due rimedi
        diversi, e sbagliarli significa modificare un file e vedere che non
        cambia niente (`whitelist.tools_with_provenance`)."""
        with _Harness({"avvocato": {"allowed_tools": [], "parents": ["professionista"]},
                       "professionista": {"allowed_tools": ["topic.write_document"]}},
                      ["topic.write_document"]):
            res = adm.revoke_tool("avvocato", "topic.write_document")
        self.assertFalse(res["ok"])
        self.assertIn("professionista", res["detail"])
        self.assertIn("denied_tools", res["detail"])

    def test_a_revoke_that_removes_the_authority_answers_ok(self):
        with _Harness({"avvocato": {"allowed_tools": ["fs.list_dir"]}},
                      ["topic.write_document"]):
            res = adm.revoke_tool("avvocato", "topic.write_document")
        self.assertTrue(res["ok"])
        self.assertFalse(res["still_authorized"])


class WhatMustNotChange(unittest.TestCase):
    def test_skills_and_rules_are_not_verbs_and_keep_their_answer(self):
        """Il difetto è dei `tool_permissions`: skill e rule le consuma
        l'agent-server dalla datadir, dove questo verbo scrive. Allargare
        l'avviso a loro sarebbe un falso allarme."""
        with _Harness({"avvocato": {"allowed_tools": []}}):
            res = adm.grant_skill("avvocato", "docx")
        self.assertTrue(res["ok"])
        self.assertEqual(res["capabilities"], ["docx"])
        self.assertNotIn("effective", res)

    def test_an_immutable_target_is_still_refused_before_writing(self):
        with _Harness({"avvocato": {"allowed_tools": []}}) as h:
            h.card["type"] = "super"
            with self.assertRaises(PermissionError):
                adm.grant_tool("avvocato", "topic.write_document")
            self.assertIsNone(h.patched)

    def test_an_unknown_agent_is_still_refused(self):
        with _Harness({"avvocato": {"allowed_tools": []}}):
            with self.assertRaises(ValueError):
                adm.grant_tool("ignoto", "topic.write_document")

    def test_an_unverifiable_authority_is_not_reported_as_granted(self):
        """Se il controllo non si può fare, la risposta lo dice invece di
        inventare un esito: `effective: null` è un terzo stato, e nasconderlo
        dentro `true` rimetterebbe la bugia dov'era."""
        def _boom(*a, **k):
            raise RuntimeError("whitelist illeggibile")

        with _Harness({"avvocato": {"allowed_tools": []}}):
            with patch.object(adm, "_may", _boom):
                res = adm.grant_tool("avvocato", "topic.write_document")
        self.assertIsNone(res["effective"])
        self.assertIn("non è verificabile", res["detail"])


if __name__ == "__main__":
    unittest.main()

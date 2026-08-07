"""I due seed fondamentali degli umani.

Voce 20: «gli umani sono agenti come gli altri, ma non hanno provider, non
forkano spawn — sono essi stessi spawn di due seed fondamentali: admin e member.
Il loro seed definisce verbi e tier».

Misurato il 6 ago 2026: i due seed **non esistevano**. `grep 'type: human'
catalogs/` non trovava nulla, e ogni umano era un `agent.yaml` individuale che
poteva portarsi la propria `tool_permissions`. La matrice era quindi per persona
e derivava — due member sulla stessa istanza potevano avere verbi diversi senza
che nessuno l'avesse deciso. Il lavoro di questa voce non è aggiungere un campo:
è spostare la matrice da N file individuali a 2 seed.

Un fatto per posto. Il RUOLO è per persona e sta nel suo file; la MATRICE è per
classe e sta nel seed. La persona dice a quale classe appartiene, la classe dice
cosa può fare.

E l'intersezione, come ovunque oggi: una dichiarazione individuale può solo
RESTRINGERE. Se potesse ampliare, il seed non definirebbe più i verbi e saremmo
tornati esattamente al punto di partenza.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import human as H
from . import origin


def _as(seed_dict):
    return patch.object(H, "_seed", lambda n: seed_dict)


ADMIN = {"type": "human", "role": "admin"}
SUPER = {"type": "human", "role": "superadmin"}
MEMBER = {"type": "human", "role": "member"}
IGNOTO = {"type": "human", "role": "capoccia"}
AGENTE = {"type": "normal", "role": "admin"}


class SeedsExistTests(unittest.TestCase):
    """L'affermazione «ci sono due seed» dev'essere vera su ogni istanza."""

    def test_both_seeds_exist(self):
        s = H.seeds()
        self.assertIn(H.SEED_ADMIN, s)
        self.assertIn(H.SEED_MEMBER, s)

    def test_they_do_not_depend_on_a_file(self):
        """Se fossero file, un'istanza potrebbe non averli — e «fondamentali»
        smetterebbe di essere vero ovunque."""
        with patch.object(H, "seeds", H.seeds):
            self.assertTrue(H._BUILTIN_SEEDS[H.SEED_ADMIN]["tool_permissions"])
            self.assertTrue(H._BUILTIN_SEEDS[H.SEED_MEMBER]["tool_permissions"])


class MembershipTests(unittest.TestCase):
    def test_an_admin_is_a_spawn_of_the_admin_seed(self):
        with _as(ADMIN):
            self.assertEqual(H.seed_of("x"), H.SEED_ADMIN)

    def test_the_instance_owner_is_still_an_admin_spawn(self):
        """`superadmin` non è un terzo seed: è un ATTRIBUTO dello spawn admin."""
        with _as(SUPER):
            self.assertEqual(H.seed_of("x"), H.SEED_ADMIN)
            self.assertTrue(H.is_instance_owner("x"))

    def test_an_admin_is_not_the_instance_owner(self):
        with _as(ADMIN):
            self.assertFalse(H.is_instance_owner("x"))

    def test_everyone_else_is_a_member(self):
        for d in (MEMBER, IGNOTO):
            with self.subTest(ruolo=d["role"]), _as(d):
                self.assertEqual(H.seed_of("x"), H.SEED_MEMBER)

    def test_an_agent_is_not_a_spawn_of_a_human_seed(self):
        with _as(AGENTE):
            self.assertIsNone(H.seed_of("x"))
            self.assertIsNone(H.seed_matrix("x"))


class MatrixTests(unittest.TestCase):
    def test_an_admin_may_everything(self):
        with _as(ADMIN):
            self.assertIn("*", H.seed_matrix("x"))

    def test_a_member_may_do_ordinary_work(self):
        with _as(MEMBER):
            m = H.seed_matrix("x")
            for ns in ("topic", "email", "memory", "gdrive"):
                self.assertIn(f"{ns}.*", m)

    def test_a_member_may_not_touch_the_rules_of_the_machine(self):
        """Non duplica i gate: li rinforza dall'altro verso. Un gate chiede un
        consenso quando l'azione parte; questa lista dice che per un member
        certe azioni non partono affatto."""
        with _as(MEMBER):
            m = H.seed_matrix("x")
            for ns in ("agents", "packs", "providers", "mcp", "settings"):
                with self.subTest(namespace=ns):
                    self.assertNotIn(f"{ns}.*", m)


class IntersectionTests(unittest.TestCase):
    """Il pezzo che impedisce il ritorno alla matrice per persona."""

    def test_a_member_cannot_exceed_their_seed_by_declaring_more(self):
        """Se una dichiarazione individuale potesse ampliare, il seed non
        definirebbe più i verbi e saremmo al punto di partenza."""
        d = dict(MEMBER, tool_permissions=["settings.*", "topic.*"])
        with _as(d):
            self.assertFalse(origin._human_may("x", "settings.set"))
            self.assertTrue(origin._human_may("x", "topic.put"))

    def test_an_individual_declaration_can_narrow(self):
        """«Questo member, meno»: è l'unico verso in cui ha senso."""
        d = dict(MEMBER, tool_permissions=["topic.*"])
        with _as(d):
            self.assertTrue(origin._human_may("x", "topic.put"))
            self.assertFalse(origin._human_may("x", "email.send"))

    def test_without_an_individual_declaration_the_seed_decides(self):
        with _as(MEMBER):
            self.assertTrue(origin._human_may("x", "topic.put"))
            self.assertFalse(origin._human_may("x", "settings.set"))

    def test_an_admin_keeps_everything(self):
        with _as(ADMIN):
            for v in ("settings.set", "packs.import_url", "topic.put"):
                with self.subTest(verbo=v):
                    self.assertTrue(origin._human_may("x", v))

    def test_an_empty_individual_list_means_nothing_not_no_opinion(self):
        """`None` e `[]` sono cose diverse: senza la distinzione non si può
        dichiarare un utente di sola lettura."""
        d = dict(MEMBER, tool_permissions=[])
        with _as(d):
            self.assertFalse(origin._human_may("x", "topic.put"))


class NonHumanTests(unittest.TestCase):
    def test_an_agent_falls_back_to_the_rule_of_before(self):
        """Nessun seed umano da applicare: vale la regola in vigore, che è
        quella di ieri. La retrocompatibilità va verso «come prima», non verso
        «tutto chiuso»: il contrario disconnetterebbe tutti al primo deploy."""
        with _as(AGENTE):
            self.assertTrue(origin._human_may("x", "topic.put"))


class ConfigOverrideTests(unittest.TestCase):
    def test_config_may_narrow_a_seed(self):
        with patch("server.whitelist.CONFIG",
                   {"human_seeds": {"member": {"tool_permissions": ["topic.*"]}}}):
            with _as(MEMBER):
                self.assertTrue(origin._human_may("x", "topic.put"))
                self.assertFalse(origin._human_may("x", "email.send"))

    def test_a_broken_override_does_not_erase_the_seeds(self):
        with patch("server.whitelist.CONFIG", {"human_seeds": "spazzatura"}):
            self.assertIn(H.SEED_MEMBER, H.seeds())


if __name__ == "__main__":
    unittest.main()

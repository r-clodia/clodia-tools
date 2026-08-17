"""Le liste si possono modificare a mano, per conto dell'owner.

Richiesta dell'owner, 17 ago 2026: «devo poter inserire un egress o ingress anche
a mano». Fino a oggi le liste si riempivano solo attraverso il dialog del gate —
il posto giusto quando la destinazione arriva da un agente che la chiede, e nessun
posto quando l'owner sa già cosa censire: le cento fonti di un digest non passano
da cento dialog.

Il controllo dei ruoli NON è qui (rotta interna, lo fa l'agent-server che conosce
i ruoli umani) e la validazione NON è nella rotta (la fa `egress.allow`): questi
test fissano che la rotta esista, che rifiuti con un MOTIVO e che non duplichi
regole altrove.
"""
from __future__ import annotations

import unittest


class WhitelistEditRouteTests(unittest.TestCase):
    def test_the_route_exists_for_both_directions(self) -> None:
        from server import egress_api
        paths = {r.path for r in egress_api.routes}
        self.assertIn("/internal/egress/whitelist/{direction}/{action}", paths)

    def test_the_route_is_a_post(self) -> None:
        from server import egress_api
        for r in egress_api.routes:
            if r.path.endswith("{direction}/{action}"):
                self.assertIn("POST", r.methods or [])
                self.assertNotIn("GET", [m for m in (r.methods or []) if m != "HEAD"],
                                 "una modifica non deve stare su una GET: un link "
                                 "o un prefetch la eseguirebbe")


class GrantableValidationTests(unittest.TestCase):
    """La validazione vive in `egress`, e questi casi dicono perché conta.

    Non sono duplicati della rotta: sono le regole che rendono sicura una casella
    di testo. Un campo che accetta qualunque stringa e poi la ignora al
    caricamento è il modo in cui una whitelist smette di significare qualcosa.
    """

    def test_the_wrong_direction_is_refused(self) -> None:
        from server import egress as eg
        with self.assertRaises(ValueError):
            eg.check_grantable("egress", "mailfrom:chiunque@esempio.it")
        with self.assertRaises(ValueError):
            eg.check_grantable("ingress", "mailto:qualcuno@esempio.it")

    def test_a_degenerate_entry_is_refused(self) -> None:
        """`gdrive:folder/` senza id aprirebbe l'intero Drive."""
        from server import egress as eg
        for degenere in ("gdrive:folder/", "https://", "mailto:"):
            with self.subTest(uri=degenere):
                with self.assertRaises(ValueError):
                    eg.check_grantable("egress", degenere)

    def test_a_good_entry_comes_back_normalised(self) -> None:
        from server import egress as eg
        self.assertEqual("mailto:qualcuno@esempio.it",
                         eg.check_grantable("egress", " MAILTO:Qualcuno@Esempio.it "))

    def test_a_source_scheme_is_accepted_in_ingress(self) -> None:
        from server import egress as eg
        self.assertEqual("mcp:normattiva.",
                         eg.check_grantable("ingress", "mcp:normattiva."))


if __name__ == "__main__":
    unittest.main()

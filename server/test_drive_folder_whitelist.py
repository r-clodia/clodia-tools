"""Una cartella Drive è una voce di whitelist, non un sottoalbero.

Correzione di Davide, 7 ago 2026: «non esiste questo concetto di root per
devnullboxx, devnull è un account google al quale condivido file e cartelle in
modo sparso».

Questo invalida un presupposto del confinamento costruito il 5 agosto.
`gdrive_roots` è un TETTO D'ACCOUNT — un sottoalbero dentro cui tutto è
permesso — e presuppone che un account abbia una radice. Un account condiviso
non ce l'ha: le cartelle arrivano da «Condivisi con me», ognuna di un
proprietario diverso, senza antenato comune. Non c'è radice da mettere, e
forzarne una proteggerebbe niente (troppo larga) o bloccherebbe tutto (troppo
stretta).

La forma giusta è quella già costruita per le altre risorse: una voce di lista,
come un repository (voce 31) o un indirizzo email. Il vocabolario esisteva già —
`gdrive:folder/<id>` è un URI di egress ammesso da sempre.

E questo sblocca la seconda metà della voce 24. Il timore era che un owner
autorizzato a spostare i muri del proprio scope potesse puntare un remote a
qualunque cartella raggiunta dalla credenziale condivisa — il caso di Davide del
30 luglio. Con la lista, un owner può puntare solo a cartelle **già approvate**,
e approvarne una nuova resta un atto di chi amministra.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import whitelist as w
from .tools import gdrive_root as G
from .topics.service import TopicService, TopicError


def _cfg(**kw):
    return patch.object(w, "CONFIG", dict(kw))


class ApprovedFoldersTests(unittest.TestCase):
    def test_a_folder_in_the_egress_list_is_approved(self):
        with _cfg(egress_allow=["gdrive:folder/ABC", "mailto:x@y.it"]):
            self.assertEqual(G.approved_folders(), ["ABC"])

    def test_nothing_declared_means_no_confinement(self):
        """Direzione della retrocompatibilità: una lista vuota che chiudesse
        tutto verrebbe spenta il giorno stesso, e allora non proteggerebbe
        niente."""
        with _cfg():
            self.assertEqual(G.approved_folders(), [])

    def test_legacy_account_roots_stay_with_their_account(self):
        """Le vecchie `gdrive_roots` sono per account per costruzione. Portarle
        fra le approvate renderebbe la radice dell'account A un perimetro anche
        per B — cioè confinerebbe un account oggi non confinato, che è la
        compatibilità che marte richiede."""
        with _cfg(gdrive_roots={"conto": ["LEG"]}):
            self.assertNotIn("LEG", G.approved_folders())
            self.assertIn("LEG", G.roots_for("conto"))
            self.assertNotIn("LEG", G.roots_for("altro"))

    def test_the_two_sources_add_up_for_the_account_that_has_both(self):
        with _cfg(egress_allow=["gdrive:folder/ABC"], gdrive_roots={"conto": ["LEG"]}):
            self.assertEqual(sorted(G.roots_for("conto")), ["ABC", "LEG"])

    def test_an_approved_folder_belongs_to_no_account(self):
        """Se restasse fuori da `roots_for`, una cartella approvata sarebbe
        collegabile a un topic ma poi irraggiungibile: una lista che concede a
        metà è peggio di nessuna lista, perché chi la legge conclude che
        funzioni."""
        with _cfg(egress_allow=["gdrive:folder/ABC"]):
            self.assertIn("ABC", G.roots_for("qualunque-account"))

    def test_a_malformed_entry_is_ignored_not_treated_as_a_folder(self):
        with _cfg(egress_allow=["gdrive:folder/", "gdrive:file/XYZ"]):
            self.assertEqual(G.approved_folders(), [])


class RemoteEnableTests(unittest.TestCase):
    """La seconda metà della voce 24: l'owner sposta i muri, ma dentro il
    perimetro già approvato."""

    def test_an_unapproved_folder_is_refused(self):
        with _cfg(egress_allow=["gdrive:folder/APPROVATA"]):
            with self.assertRaises(TopicError) as cm:
                TopicService._require_approved_folder("ALTRA", "SEAL-1", "acme")
            self.assertIn("ALTRA", str(cm.exception))

    def test_the_refusal_says_how_to_approve_it(self):
        """Un rifiuto che non indica la strada insegna solo che il sistema dice
        di no — e qui la strada esiste: è un atto di chi amministra."""
        with _cfg(egress_allow=["gdrive:folder/APPROVATA"]):
            with self.assertRaises(TopicError) as cm:
                TopicService._require_approved_folder("ALTRA", "SEAL-1", "acme")
            testo = str(cm.exception)
            self.assertIn("gdrive:folder/ALTRA", testo)
            self.assertIn("amministra", testo)

    def test_an_approved_folder_passes(self):
        with _cfg(egress_allow=["gdrive:folder/APPROVATA"]):
            TopicService._require_approved_folder("APPROVATA", "SEAL-1", "acme")

    def test_with_no_list_at_all_nothing_is_refused(self):
        """Nessuna cartella dichiarata = nessun perimetro dichiarato. Rifiutare
        qui romperebbe ogni collegamento Drive esistente al primo deploy."""
        with _cfg():
            TopicService._require_approved_folder("QUALUNQUE", "SEAL-1", "acme")

    def test_no_folder_at_all_is_not_a_refusal(self):
        with _cfg(egress_allow=["gdrive:folder/APPROVATA"]):
            TopicService._require_approved_folder(None, "SEAL-1", "acme")
            TopicService._require_approved_folder("", "SEAL-1", "acme")

    def test_the_check_runs_where_the_remote_is_actually_declared(self):
        """Controllarlo altrove lascerebbe la strada aperta a chi passa da
        `remote_enable` diretto — ed è il verbo che l'owner usa."""
        import inspect
        src = inspect.getsource(TopicService.remote_enable)
        self.assertIn("_require_approved_folder", src)


class ScopeTests(unittest.TestCase):
    def test_a_folder_approved_for_one_room_is_not_global(self):
        """Con la sola lista globale, approvare una cartella per un topic la
        aprirebbe per tutti — che è l'asse mancante della voce 30."""
        with _cfg(scope_egress_allow={"SEAL-1/acme": ["gdrive:folder/SOLO_ACME"]}):
            self.assertEqual(G.approved_folders("SEAL-2/altro"), [])
            self.assertEqual(G.approved_folders("SEAL-1/acme"), ["SOLO_ACME"])


if __name__ == "__main__":
    unittest.main()

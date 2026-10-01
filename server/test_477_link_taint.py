"""Taint di un file letto attraverso un topic collegato (clodia-platform#477).

Collegare due topic li dichiara fonti l'uno dell'altra: leggere il lavoro della
stanza accanto non deve contaminare il canale, se no il taint si accende sui
file della colonia e si smette di guardarlo — che è il modo in cui una difesa
muore senza che nessuno la tolga.

Quello che NON deve succedere è il contrario: un allegato arrivato da un terzo e
marcato `untrusted` non si ripulisce attraversando un collegamento. L'etichetta
viaggia col file, non con la stanza da cui lo si guarda — la stessa lezione di
clodia-platform#419, dove a lavare l'etichetta era una copia invece di un path.
"""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from .topics import service as service_mod
from .topics.local_fs import LocalFsStorage
from .topics.service import TopicService


class LinkTaintTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="taint477-"))
        self.svc = TopicService(LocalFsStorage(str(self.root)))
        self.svc.new("SEAL-1", "acme", {"title": "Acme", "owner": "davide"})
        self.svc.new("SEAL-1", "legale", {"title": "Legale", "owner": "davide"})
        # Un documento della colonia: nessuno gli ha mai messo un'etichetta.
        self.svc.s.write("SEAL-1/legale/files/parere.md", b"# parere")
        # Un allegato di un terzo, marcato all'ingresso.
        self.svc.put_file("SEAL-1", "legale", "contratto.pdf", b"%PDF",
                          "untrusted", by="messaggero")
        with patch.object(TopicService, "_link_ingress"):
            self.svc.link_add("SEAL-1", "acme", "SEAL-1", "legale", approver="davide")
        # Who may read through the link is checked elsewhere (review fix B1):
        # here every read is let through, the question is the taint only.
        g = patch.object(service_mod, "_LINK_READER_GUARD", lambda t, n, m: None)
        g.start()
        self.addCleanup(g.stop)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _vetted(self, path, scope_sources=(), other_scope_sources=()):
        from . import main, whitelist as wl
        cfg = {"agents": {},
               "scope_source_allow": {"SEAL-1/acme": list(scope_sources),
                                      "SEAL-1/legale": list(other_scope_sources)}}
        with patch.object(wl, "CONFIG", cfg), \
                patch.object(main, "_topics", lambda: self.svc):
            return main._source_vetted(
                "topic.read_file",
                {"tier": "SEAL-1", "name": "acme", "path": path}, None)

    def test_an_unlabelled_file_of_the_linked_topic_taints(self):
        """Review fix B2: read inside `legale` this file taints, so it taints
        read through the link too — even with `topic:SEAL-1/legale` declared
        as a source of `acme`. Being linked vouches for nothing the other room
        would not vouch for itself."""
        self.assertIs(self._vetted("legale/parere.md",
                                   ["topic:SEAL-1/legale"]), False)
        self.assertIs(self._vetted("legale/parere.md", []), False)

    def test_same_verdict_as_inside_the_linked_topic(self):
        from . import main, whitelist as wl
        cfg = {"agents": {}, "scope_source_allow": {}}
        with patch.object(wl, "CONFIG", cfg), \
                patch.object(main, "_topics", lambda: self.svc):
            for via_link, at_home in (("legale/parere.md", "local/parere.md"),
                                      ("legale/contratto.pdf", "local/contratto.pdf")):
                with self.subTest(path=via_link):
                    self.assertIs(
                        main._source_vetted("topic.read_file", {
                            "tier": "SEAL-1", "name": "acme", "path": via_link}),
                        main._source_vetted("topic.read_file", {
                            "tier": "SEAL-1", "name": "legale", "path": at_home}))

    def test_an_unlabelled_file_in_a_shared_subfolder_taints(self):
        """Files that arrive without a label — the Mac-shared folder, a Drive
        sync into the local tree — are unlabelled at home, and so through the
        link."""
        self.svc.s.write("SEAL-1/legale/files/condivisa/dal-mac.md", b"?")
        self.assertIs(self._vetted("legale/condivisa/dal-mac.md",
                                   ["topic:SEAL-1/legale"]), False)

    def test_a_drive_backed_linked_topic_is_judged_on_its_own_folder(self):
        """`legale` lives on a Drive folder: labels do not exist there, the
        source is the folder, and it is the folder declared for `legale` that
        counts — not `acme`'s list, not the link."""
        p = self.root / "SEAL-1/legale/meta.json"
        import json as _json
        meta = _json.loads(p.read_text())
        meta["remote"] = {"type": "drive", "config": {"folder": "F123"}}
        p.write_text(_json.dumps(meta))
        self.assertIs(self._vetted("legale/parere.md",
                                   ["topic:SEAL-1/legale", "gdrive:folder/F123"]), False)
        self.assertIs(self._vetted("legale/parere.md",
                                   other_scope_sources=["gdrive:folder/F123"]), True)

    def test_a_trusted_file_of_the_linked_topic_does_not_taint(self):
        self.svc.put_file("SEAL-1", "legale", "nota.md", b"n", "trusted", by="giovanni")
        self.assertIs(self._vetted("legale/nota.md"), True)

    def test_un_allegato_untrusted_resta_untrusted_anche_dal_collegamento(self):
        """Il caso che vale: il collegamento dichiara fidata la STANZA, non ciò
        che un terzo ci ha depositato dentro."""
        self.assertIs(self._vetted("legale/contratto.pdf",
                                   ["topic:SEAL-1/legale"]), False)

    def test_un_file_trusted_di_casa_letto_come_local_non_contamina(self):
        """Il sidecar è indicizzato relativo a `files/`, la vista mostra
        `local/x`: chi valutava il taint tagliava solo il prefisso `files/`,
        quindi per la forma che si copia dalla UI l'etichetta risultava assente
        e un file dichiarato `trusted` dall'owner contaminava comunque."""
        self.svc.put_file("SEAL-1", "acme", "nota.md", b"n", "trusted", by="davide")
        for forma in ("nota.md", "files/nota.md", "local/nota.md"):
            with self.subTest(forma=forma):
                self.assertIs(self._vetted(forma), True)

    def test_un_file_senza_etichetta_di_casa_contamina(self):
        """Il controllo negativo del test sopra: la correzione non deve
        trasformare «non so» in «fidato» dentro il topic stesso."""
        self.svc.s.write("SEAL-1/acme/files/ignoto.md", b"?")
        self.assertIs(self._vetted("local/ignoto.md"), False)


class TopicSourceSchemeTests(unittest.TestCase):
    """`topic:` è uno schema di sola INGRESSO, e vuole livello e nome."""

    def test_un_topic_e_una_fonte_concedibile(self):
        from . import egress
        self.assertEqual(egress.check_grantable("ingress", "topic:SEAL-1/acme"),
                         "topic:SEAL-1/acme")

    def test_non_e_una_destinazione(self):
        """Nei file di un altro topic non si scrive: il mount è in sola
        lettura, quindi `topic:` in uscita è un errore di configurazione e va
        rifiutato invece che ignorato."""
        from . import egress
        with self.assertRaises(ValueError):
            egress.check_grantable("egress", "topic:SEAL-1/acme")

    def test_un_livello_intero_non_e_una_fonte(self):
        """`topic` non è uno schema gerarchico: `topic:SEAL-1/` non combacerebbe
        con nessun topic, cioè sarebbe approvata e inefficace — e il sintomo
        («l'ho messa in lista e contamina ancora») non nominerebbe la causa."""
        from . import egress
        for brutta in ("topic:SEAL-1/", "topic:SEAL-1", "topic:*", "topic:acme"):
            with self.subTest(uri=brutta), self.assertRaises(ValueError):
                egress.check_grantable("ingress", brutta)


if __name__ == "__main__":
    unittest.main()

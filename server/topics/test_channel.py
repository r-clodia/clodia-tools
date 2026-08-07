"""Test dei metodi canale del TopicService (Fase 1: partecipanti/messaggi/file)."""
from __future__ import annotations

import tempfile
import unittest
from unittest.mock import patch

from .local_fs import LocalFsStorage
from .service import TopicService


class ChannelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.svc = TopicService(LocalFsStorage(tempfile.mkdtemp()))
        # Il profilo dell'istanza locale non deve alterare le aspettative unit.
        with patch("server.instance_profile.topic_default_participants", return_value=[]):
            self.svc.new("P1", "ch", {"title": "Canale", "owner": "owner"})

    def test_owner_and_default_participant(self) -> None:
        meta = self.svc.open("P1", "ch")["meta"]
        self.assertEqual(meta["owner"], "owner")
        # L'owner non è duplicato fra i partecipanti: lo aggiunge participants_map.
        from .service import TopicService
        self.assertEqual(TopicService.participants_map(meta), {"owner": "owner"})

    def test_participants_add_remove(self) -> None:
        # 7 ago 2026: i partecipanti sono una MAPPA nome→ruolo, e l'owner non vi
        # è più duplicato — sta nel campo `owner`, che è la fonte di verità della
        # proprietà. L'appartenenza EFFETTIVA non cambia: `participants_map` lo
        # riporta dentro col ruolo owner. Si asserisce quella, non la forma.
        from .service import TopicService
        first = self.svc.add_participant("P1", "ch", "clodia")
        again = self.svc.add_participant("P1", "ch", "clodia")  # idempotente
        mappa = TopicService.participants_map(self.svc.open("P1", "ch")["meta"])
        self.assertEqual(mappa, {"owner": "owner", "clodia": "contributor"})
        self.assertTrue(first["added"])
        self.assertFalse(again["added"])
        messages = self.svc.list_messages("P1", "ch")
        self.assertEqual(
            [(m["author"], m["kind"], m["text"]) for m in messages],
            [("system", "system", "clodia è entrato nel topic come contributor")],
        )
        # L'owner NON si rimuove dai partecipanti: uno scope senza owner non
        # avrebbe più nessuno che risponde dei suoi gate (voce 24).
        self.svc.remove_participant("P1", "ch", "owner")
        mappa2 = TopicService.participants_map(self.svc.open("P1", "ch")["meta"])
        self.assertEqual(mappa2.get("owner"), "owner")
        self.assertEqual(mappa2.get("clodia"), "contributor")

    def test_messages_ordered_with_kind_and_attachments(self) -> None:
        self.svc.post_message("P1", "ch", "owner", "ciao", kind="human")
        self.svc.post_message("P1", "ch", "clodia", "ecco il file", kind="ai",
                              attachments=["r.md"])
        msgs = self.svc.list_messages("P1", "ch")
        self.assertEqual([(m["author"], m["kind"]) for m in msgs],
                         [("owner", "human"), ("clodia", "ai")])
        self.assertEqual(msgs[1]["attachments"], ["r.md"])

    def test_files_upload_and_list(self) -> None:
        self.svc.put_file("P1", "ch", "report.md", b"# R\n")
        # list_files starts from the topic ROOT, not from files/ — the navigator
        # shows the real structure and one navigates into it. The test predates
        # that change and used to assert the old files/-relative listing.
        root = self.svc.list_files("P1", "ch")
        self.assertEqual([f["name"] for f in root], # 7 ago 2026: la radice espone i MOUNT, non `files/`. Il contenuto
        # non si è spostato — si raggiunge da `local/`.
        # 7 ago 2026: e la radice e' quella dei DATI — niente control-plane.
        ["local"])
        inside = self.svc.list_files("P1", "ch", "files")
        self.assertEqual([f["name"] for f in inside], ["report.md"])
        self.assertEqual(self.svc.read_file("P1", "ch", "files/report.md"), b"# R\n")

    def test_subfolders_are_navigable_not_links(self) -> None:
        """#117: a subfolder must be a navigable dir, whatever the backend.

        On a Drive remote a folder's mime is `application/vnd.google-apps.folder`,
        which matches the native-Google-document prefix. Classified by mime
        before kind, every subfolder was emitted as a remote FILE carrying a
        webViewLink, so the UI opened the Drive web app instead of navigating.
        """
        self.svc.put_field = None  # noqa: B010 - guard against accidental reuse
        self.svc.put_file("P1", "ch", "archivio/2026/nota.md", b"x")
        entries = self.svc.list_files("P1", "ch", "files")
        arch = [f for f in entries if f["name"] == "archivio"]
        self.assertEqual(len(arch), 1)
        self.assertEqual(arch[0]["kind"], "dir")
        self.assertEqual(arch[0]["path"], "local/archivio")
        # and it is navigable one level deeper
        deeper = self.svc.list_files("P1", "ch", "local/archivio")
        self.assertEqual([f["name"] for f in deeper], ["2026"])
        self.assertEqual(deeper[0]["kind"], "dir")

    def test_put_file_rejects_traversal(self) -> None:
        from .service import TopicError
        with self.assertRaises(TopicError):
            self.svc.put_file("P1", "ch", "../evil", b"x")

    def test_provenance_defaults_to_untrusted_and_shows_in_the_listing(self) -> None:
        """#104 §3: default `untrusted`, and the label follows the file.

        The cost of erring this way must stay low — one extra approval
        downstream — not high, i.e. an unreadable file. So it is a
        CLASSIFICATION, not an authorisation: reading stays free and taints the
        channel instead.
        """
        r = self.svc.put_file("P1", "ch", "contratto.pdf", b"%PDF")
        self.assertEqual(r["provenance"], "untrusted")
        entry = [f for f in self.svc.list_files("P1", "ch", "files")
                 if f["name"] == "contratto.pdf"][0]
        self.assertEqual(entry["provenance"], "untrusted")

    def test_a_declared_trusted_file_keeps_its_label(self) -> None:
        self.svc.put_file("P1", "ch", "mio.md", b"x", "trusted", by="davide")
        entry = [f for f in self.svc.list_files("P1", "ch", "files")
                 if f["name"] == "mio.md"][0]
        self.assertEqual(entry["provenance"], "trusted")

    def test_an_invalid_provenance_falls_back_to_untrusted(self) -> None:
        r = self.svc.put_file("P1", "ch", "x.md", b"x", "fidatissimo")
        self.assertEqual(r["provenance"], "untrusted")

    def test_a_file_with_no_label_reads_as_unknown_not_trusted(self) -> None:
        """Files uploaded before §3 existed. A reassuring default on historical
        data is the wrong direction of error."""
        self.svc.put_file("P1", "ch", "vecchio.md", b"x")
        # simula l'assenza del sidecar (file pre-esistente)
        self.svc.s.write(self.svc._prov_path("P1", "ch"), b"{}")
        entry = [f for f in self.svc.list_files("P1", "ch", "files")
                 if f["name"] == "vecchio.md"][0]
        self.assertEqual(entry["provenance"], "unknown")

    def test_the_provenance_sidecar_is_hidden_from_the_navigator(self) -> None:
        """È un dotfile: comparirebbe fra i file del topic e non è un documento."""
        self.svc.put_file("P1", "ch", "a.md", b"x")
        names = [f["name"] for f in self.svc.list_files("P1", "ch")]
        self.assertNotIn(self.svc._PROV_FILE, names)


if __name__ == "__main__":
    unittest.main()

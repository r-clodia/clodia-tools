"""Collegamento fra due topic: una vista, non una copia (clodia-platform#477).

Due topic dello stesso livello SEAL si collegano, e da quel momento ognuno vede
l'albero dati dell'altro come una cartella accanto a `local/`. I file restano
uno solo, nel topic che li possiede, e con loro l'etichetta di provenienza — che
è il motivo per cui questo non si fa copiando (clodia-platform#419: una copia
rietichetta, e il flag `untrusted` di un allegato di terzi sparisce).

I test che contano, nell'ordine in cui romperebbero qualcosa di vero:

1. il mount è in SOLA LETTURA — scriverci metterebbe un file in una stanza di
   cui chi scrive può non rispondere;
2. la provenienza letta attraverso il collegamento è quella dell'ALTRO topic —
   se no un allegato `untrusted` diventa `unknown` cambiando solo il path;
3. il collegamento vale finché è RECIPROCO e fra pari livello, e le due cose si
   verificano a ogni lettura: `set_tier` sposta un topic di livello dopo, e un
   controllo fatto solo alla creazione lascerebbe un SEAL-2 leggibile da un
   SEAL-1 senza che nulla lo dica.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from .local_fs import LocalFsStorage
from . import service as service_mod
from .service import TopicService, TopicError, topic_links


class Base(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="links-"))
        self.svc = TopicService(LocalFsStorage(str(self.root)))
        self.svc.new("SEAL-1", "acme", {"title": "Acme", "owner": "davide"})
        self.svc.new("SEAL-1", "legale", {"title": "Legale", "owner": "davide"})
        self.svc.put_file("SEAL-1", "legale", "parere.md", b"# parere",
                          "agent", by="avvocato")
        # Un allegato arrivato dalla posta nell'altro topic: resta untrusted
        # anche visto da qui.
        self.svc.put_file("SEAL-1", "legale", "allegati/contratto.pdf", b"%PDF",
                          "untrusted", by="messaggero")
        # L'iscrizione alle liste di ingresso è un effetto REALE su config.yaml:
        # nei test si osserva (vedi IngressTests) e non si esegue.
        self._ing = mock.patch.object(TopicService, "_link_ingress")
        self._ing.start()
        self.addCleanup(self._ing.stop)
        # The read-time access check on the linked topic is the gateway's (it
        # knows the caller): here a guard that lets every read through, and the
        # tests of the check itself replace it.
        self.guard_calls = []
        g = mock.patch.object(service_mod, "_LINK_READER_GUARD",
                              lambda t, n, m: self.guard_calls.append((t, n)))
        g.start()
        self.addCleanup(g.stop)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _link(self, mount=None, approver="davide"):
        # davide owns both topics: his one consent is the consent of both.
        return self.svc.link_add("SEAL-1", "acme", "SEAL-1", "legale", mount,
                                 approver=approver)

    def _names(self, tier="SEAL-1", name="acme", sub=""):
        return [f["name"] for f in self.svc.list_files(tier, name, sub)]


class VistaTests(Base):
    def test_il_topic_collegato_compare_come_cartella_nei_due_sensi(self):
        """L'esempio della issue: T collegato a Y mostra una cartella Y, e Y una
        cartella T. Simmetrico, perché un collegamento a senso unico sarebbe un
        diritto di lettura che la stanza letta non vede dichiarato da nessuna
        parte."""
        self._link()
        self.assertIn("legale", self._names("SEAL-1", "acme"))
        self.assertIn("acme", self._names("SEAL-1", "legale"))
        mount = [f for f in self.svc.list_files("SEAL-1", "acme")
                 if f["name"] == "legale"][0]
        self.assertEqual(mount["mount"], TopicService.MOUNT_KIND_LINK)
        self.assertTrue(mount["readonly"])
        self.assertEqual(mount["topic"], "SEAL-1/legale")

    def test_dentro_la_cartella_ci_sono_i_file_dellaltro_topic(self):
        self._link()
        self.assertEqual(sorted(self._names("SEAL-1", "acme", "legale")),
                         ["allegati", "parere.md"])
        self.assertEqual(self.svc.read_file("SEAL-1", "acme", "legale/parere.md"),
                         b"# parere")
        self.assertEqual(
            self.svc.read_file("SEAL-1", "acme", "legale/allegati/contratto.pdf"),
            b"%PDF")

    def test_senza_collegamento_quel_path_non_apre_niente(self):
        """Il controllo negativo: senza il collegamento lo stesso path è solo un
        file che non c'è — non una scorciatoia verso un altro topic."""
        with self.assertRaises(Exception):
            self.svc.read_file("SEAL-1", "acme", "legale/parere.md")

    def test_open_elenca_i_collegamenti_attivi(self):
        self._link()
        aperto = self.svc.open("SEAL-1", "acme")
        self.assertEqual([(l["name"], l["tier"], l["topic"]) for l in aperto["links"]],
                         [("legale", "SEAL-1", "legale")])


class SolaLetturaTests(Base):
    """La metà che non si vede guardando la vista: un mount di collegamento non
    si scrive. Chi partecipa a questa stanza può non partecipare a quella."""

    def setUp(self):
        super().setUp()
        self._link()

    def test_put_file_rifiuta_il_mount_collegato(self):
        with self.assertRaises(TopicError) as e:
            self.svc.put_file("SEAL-1", "acme", "legale/nuovo.txt", b"x")
        self.assertIn("sola lettura", str(e.exception).lower())
        self.assertNotIn("nuovo.txt", self._names("SEAL-1", "acme", "legale"))

    def test_delete_file_rifiuta_il_mount_collegato(self):
        with self.assertRaises(TopicError):
            self.svc.delete_file("SEAL-1", "acme", "legale/parere.md")
        self.assertEqual(self.svc.read_file("SEAL-1", "legale", "local/parere.md"),
                         b"# parere")

    def test_move_file_rifiuta_sia_la_sorgente_sia_la_destinazione(self):
        self.svc.put_file("SEAL-1", "acme", "mio.txt", b"mio")
        with self.assertRaises(TopicError):      # portare via dall'altro topic
            self.svc.move_file("SEAL-1", "acme", "legale/parere.md", "local/rubato.md")
        with self.assertRaises(TopicError):      # depositare nell'altro topic
            self.svc.move_file("SEAL-1", "acme", "local/mio.txt", "legale/mio.txt")
        self.assertEqual(sorted(self._names("SEAL-1", "acme", "legale")),
                         ["allegati", "parere.md"])

    def test_il_nome_del_collegamento_non_diventa_una_cartella_locale(self):
        """La forma legacy senza prefisso (`<nome>/file`) è quella che gli
        agenti scrivono per abitudine: deve finire nel rifiuto, non creare di
        nascosto una cartella locale omonima che poi il mount nasconde."""
        with self.assertRaises(TopicError):
            self.svc.put_file("SEAL-1", "acme", "legale/furtivo.txt", b"x")
        self.assertFalse((self.root / "SEAL-1/acme/files/legale").exists())


class ProvenienzaTests(Base):
    def test_letichetta_viaggia_col_file_non_con_la_stanza(self):
        """Il cuore del perché questo non si fa copiando: l'allegato di un terzo
        resta `untrusted` anche guardato dall'altro topic. Con una copia (o con
        il sidecar sbagliato) tornerebbe `unknown`, cioè la difesa si
        spegnerebbe cambiando solo il path."""
        self._link()
        voci = {f["name"]: f.get("provenance")
                for f in self.svc.list_files("SEAL-1", "acme", "legale/allegati")}
        self.assertEqual(voci["contratto.pdf"], "untrusted")
        self.assertEqual(
            self.svc.provenance_of("SEAL-1", "acme", "legale/allegati/contratto.pdf"),
            "untrusted")
        self.assertEqual(self.svc.provenance_of("SEAL-1", "acme", "legale/parere.md"),
                         "agent")

    def test_provenance_of_capisce_il_prefisso_del_mount_locale(self):
        """Il sidecar è indicizzato relativo a `files/`, ma la vista mostra
        `local/x`: chi valutava il taint tagliava solo `files/`, quindi per la
        forma che si copia dalla UI l'etichetta risultava assente e un file
        dichiarato `trusted` dall'owner contaminava comunque il canale."""
        self.svc.put_file("SEAL-1", "acme", "nota.md", b"n", "trusted", by="davide")
        for forma in ("nota.md", "files/nota.md", "local/nota.md"):
            self.assertEqual(self.svc.provenance_of("SEAL-1", "acme", forma),
                             "trusted", forma)
        self.assertIsNone(self.svc.provenance_of("SEAL-1", "acme", "summary.md"))


class ValiditaTests(Base):
    def test_livelli_diversi_non_si_collegano(self):
        self.svc.new("SEAL-2", "riservato", {"title": "R", "owner": "davide"})
        with self.assertRaises(TopicError) as e:
            self.svc.link_add("SEAL-1", "acme", "SEAL-2", "riservato", approver="davide")
        self.assertIn("stesso livello", str(e.exception))

    def test_un_topic_non_si_collega_a_se_stesso(self):
        with self.assertRaises(TopicError):
            self.svc.link_add("SEAL-1", "acme", "SEAL-1", "acme", approver="davide")

    def test_due_volte_lo_stesso_collegamento_e_un_errore(self):
        self._link()
        with self.assertRaises(TopicError) as e:
            self._link()
        self.assertIn("già collegato", str(e.exception))

    def test_una_dichiarazione_a_senso_unico_non_da_nessun_accesso(self):
        """Se il meta dell'altro lato perde la sua voce — scollegato di là,
        ripristinato da un backup, scritto a mano — il mount sparisce di qua.
        Un collegamento non reciproco non è un collegamento."""
        self._link()
        p = self.root / "SEAL-1/legale/meta.json"
        meta = json.loads(p.read_text())
        meta["links"] = []
        p.write_text(json.dumps(meta))
        self.assertNotIn("legale", self._names("SEAL-1", "acme"))
        with self.assertRaises(TopicError) as e:
            self.svc.read_file("SEAL-1", "acme", "legale/parere.md")
        self.assertIn("non è attivo", str(e.exception))

    def test_riclassificare_un_topic_spegne_il_collegamento(self):
        """`set_tier` è il caso che un controllo fatto solo alla creazione non
        coglie: dopo, i due topic non sono più pari livello, e il più basso non
        deve continuare a leggere il più alto."""
        self._link()
        self.svc.set_tier("SEAL-1", "legale", "SEAL-2", by="davide",
                          reason="contiene dati di terzi")
        self.assertNotIn("legale", self._names("SEAL-1", "acme"))
        with self.assertRaises(TopicError):
            self.svc.read_file("SEAL-1", "acme", "legale/parere.md")

    def test_il_nome_del_mount_non_copre_una_cartella_che_ce_gia(self):
        """Un collegamento chiamato come una cartella esistente la renderebbe
        irraggiungibile per il suo path legacy: il file sembrerebbe sparito pur
        essendo ancora lì."""
        self.svc.put_file("SEAL-1", "acme", "legale/vecchio.txt", b"v")
        self._link()
        nomi = self._names("SEAL-1", "acme")
        self.assertIn("legale-2", nomi)
        self.assertEqual(self.svc.read_file("SEAL-1", "acme", "local/legale/vecchio.txt"),
                         b"v")


class ScollegamentoTests(Base):
    def test_link_remove_toglie_la_dichiarazione_da_entrambi_i_lati(self):
        """Lasciarla sull'altro lato non darebbe accesso (non sarebbe più
        reciproca) ma direbbe a chi rilegge quel meta che questa stanza lo sta
        leggendo: una cosa falsa, nel posto in cui si va a controllare chi legge
        cosa."""
        self._link()
        self.svc.link_remove("SEAL-1", "acme", "legale")
        self.assertNotIn("legale", self._names("SEAL-1", "acme"))
        self.assertNotIn("acme", self._names("SEAL-1", "legale"))
        meta, _ = self.svc._read_meta("SEAL-1", "legale")
        self.assertEqual(topic_links(meta), [])

    def test_scollegare_non_cancella_niente(self):
        self._link()
        self.svc.link_remove("SEAL-1", "acme", "legale")
        self.assertEqual(self.svc.read_file("SEAL-1", "legale", "local/parere.md"),
                         b"# parere")

    def test_mount_inesistente(self):
        with self.assertRaises(TopicError) as e:
            self.svc.link_remove("SEAL-1", "acme", "fantasma")
        self.assertIn("fantasma", str(e.exception))


class IngressTests(Base):
    def test_il_collegamento_dichiara_le_due_stanze_come_fonti(self):
        """Senza, ogni lettura attraverso il collegamento contaminerebbe il
        canale come un allegato di un estraneo — e il taint si accenderebbe su
        file della colonia, cioè nel punto in cui si smette di guardarlo."""
        self._ing.stop()
        with mock.patch("server.egress.scope_allow") as allow:
            self._link()
        self.assertEqual(
            sorted(c.args for c in allow.call_args_list),
            [("ingress", "SEAL-1/acme", "topic:SEAL-1/legale"),
             ("ingress", "SEAL-1/legale", "topic:SEAL-1/acme")])
        self._ing.start()


class ConsentOfBothOwnersTests(Base):
    """Review fix B1: a link opens a read path into BOTH rooms, so it is
    effective only with the consent of the owner of each — or of an admin.
    Here `legale` belongs to giovanni, `acme` to davide."""

    def setUp(self):
        super().setUp()
        p = self.root / "SEAL-1/legale/meta.json"
        meta = json.loads(p.read_text())
        meta["owner"] = "giovanni"
        p.write_text(json.dumps(meta))

    def test_the_other_owner_not_consulted_leaves_the_link_pending(self):
        res = self._link(approver="davide")
        self.assertEqual(res["state"], "pending")
        self.assertEqual(res["awaiting_owner_of"], ["SEAL-1/legale"])
        self.assertNotIn("legale", self._names("SEAL-1", "acme"))
        self.assertNotIn("acme", self._names("SEAL-1", "legale"))
        with self.assertRaises(TopicError) as e:
            self.svc.read_file("SEAL-1", "acme", "legale/parere.md")
        self.assertIn("non è attivo", str(e.exception))
        self.assertEqual(self.guard_calls, [])
        stato = self.svc.open("SEAL-1", "acme")
        self.assertEqual(stato["links"], [])
        self.assertEqual([(l["name"], l["state"], l["awaiting_owner_of"])
                          for l in stato["links_declared"]],
                         [("legale", "pending", ["SEAL-1/legale"])])

    def test_different_owners_need_both_approvals(self):
        self._link(approver="davide")
        # The same consent again does not speak for the other topic.
        with self.assertRaises(TopicError) as e:
            self._link(approver="davide")
        self.assertIn("attende il consenso", str(e.exception))
        # giovanni consents from his side: now, and only now, it is active.
        res = self.svc.link_add("SEAL-1", "legale", "SEAL-1", "acme",
                                approver="giovanni", approve_only=True)
        self.assertEqual(res["state"], "active")
        self.assertIn("legale", self._names("SEAL-1", "acme"))
        self.assertEqual(self.svc.read_file("SEAL-1", "acme", "legale/parere.md"),
                         b"# parere")

    def test_an_approver_who_owns_neither_topic_creates_nothing(self):
        with self.assertRaises(TopicError) as e:
            self._link(approver="mallory")
        self.assertIn("consenso", str(e.exception))
        with self.assertRaises(TopicError):
            self._link(approver="")
        for name in ("acme", "legale"):
            meta, _ = self.svc._read_meta("SEAL-1", name)
            self.assertEqual(topic_links(meta), [], name)

    def test_approve_only_does_not_create_a_link(self):
        with self.assertRaises(TopicError):
            self.svc.link_add("SEAL-1", "legale", "SEAL-1", "acme",
                              approver="giovanni", approve_only=True)

    def test_one_admin_consent_is_enough(self):
        with mock.patch.object(service_mod, "_is_admin_principal",
                               lambda p: p == "root"):
            res = self.svc.link_add("SEAL-1", "acme", "SEAL-1", "legale",
                                    approver="root", approver_admin=True)
            self.assertEqual(res["state"], "active")
            self.assertIn("legale", self._names("SEAL-1", "acme"))
        # Re-checked at read time: an admin who lost the role no longer counts.
        with mock.patch.object(service_mod, "_is_admin_principal", lambda p: False):
            self.assertNotIn("legale", self._names("SEAL-1", "acme"))

    def test_a_change_of_owner_withdraws_the_consent(self):
        self._link(approver="davide")
        self.svc.link_add("SEAL-1", "legale", "SEAL-1", "acme", approver="giovanni")
        self.assertIn("legale", self._names("SEAL-1", "acme"))
        p = self.root / "SEAL-1/legale/meta.json"
        meta = json.loads(p.read_text())
        meta["owner"] = "terzo"
        p.write_text(json.dumps(meta))
        self.assertNotIn("legale", self._names("SEAL-1", "acme"))
        with self.assertRaises(TopicError):
            self.svc.read_file("SEAL-1", "acme", "legale/parere.md")

    def test_no_ingress_entry_while_pending(self):
        self._ing.stop()
        try:
            with mock.patch("server.egress.scope_allow",
                            return_value={"added": True}) as allow:
                self._link(approver="davide")
                self.assertEqual(allow.call_count, 0)
                self.svc.link_add("SEAL-1", "legale", "SEAL-1", "acme",
                                  approver="giovanni")
                self.assertEqual(allow.call_count, 2)
        finally:
            self._ing.start()


class ReaderEntitlementTests(Base):
    """Review fix B1: an approved link does not lend the reader the
    membership of the room it reads from. The read-time check runs on the
    topic that OWNS the bytes."""

    def test_the_check_runs_on_the_linked_topic(self):
        self._link()
        self.svc.read_file("SEAL-1", "acme", "legale/parere.md")
        self.svc.list_files("SEAL-1", "acme", "legale")
        self.assertEqual(set(self.guard_calls), {("SEAL-1", "legale")})

    def test_a_reader_not_entitled_to_the_other_topic_is_refused(self):
        self._link()

        def nega(t, n, m):
            raise PermissionError(f"non partecipante di {t}/{n}")

        with mock.patch.object(service_mod, "_LINK_READER_GUARD", nega):
            with self.assertRaises(PermissionError):
                self.svc.read_file("SEAL-1", "acme", "legale/parere.md")
            with self.assertRaises(PermissionError):
                self.svc.list_files("SEAL-1", "acme", "legale")
            # The room's own files are not affected.
            self.svc.put_file("SEAL-1", "acme", "mio.txt", b"m")
            self.assertEqual(self.svc.read_file("SEAL-1", "acme", "local/mio.txt"), b"m")

    def test_without_a_registered_guard_link_reads_are_refused(self):
        self._link()
        with mock.patch.object(service_mod, "_LINK_READER_GUARD", None):
            with self.assertRaises(PermissionError):
                self.svc.read_file("SEAL-1", "acme", "legale/parere.md")


class UnlinkIngressProvenanceTests(Base):
    """`link_remove` takes back the ingress entries the link added, and only
    those: an entry an operator had declared on their own stays."""

    def test_only_the_entries_the_link_added_are_revoked(self):
        self._ing.stop()
        try:
            def allow(direction, scope, uri):
                # acme's entry is new; legale's was already declared by hand.
                return {"added": scope == "SEAL-1/acme"}

            with mock.patch("server.egress.scope_allow", side_effect=allow):
                self._link()
            with mock.patch("server.egress.scope_revoke") as revoke:
                self.svc.link_remove("SEAL-1", "acme", "legale")
            self.assertEqual([c.args for c in revoke.call_args_list],
                             [("ingress", "SEAL-1/acme", "topic:SEAL-1/legale")])
        finally:
            self._ing.start()


if __name__ == "__main__":
    unittest.main()

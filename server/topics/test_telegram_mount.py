"""Un gruppo Telegram collegato a uno scope, e le menzioni che ne escono.

Il modello, deciso il 10 ago 2026: il gruppo è **un mount** — una risorsa che
l'owner porta dentro lo scope, come un repository o una cartella Drive. Stessa
forma (`{name, type, config}`), stessa collezione, stesso gate `walls`. Non è un
filesystem, e non serve dirlo: la vista dei file monta già solo i tipi che lo
sono, come fa da agosto col mount `git`.

Cosa questi test tengono fermo, in ordine di quanto costa sbagliarlo.

1. **Una menzione non riconosciuta non notifica nessuno.** Avvisare la persona
   sbagliata è l'unico esito peggiore del silenzio, e con una mappa
   `uid → principal` scritta a mano è l'errore più facile da fare.
2. **Una menzione notifica una volta.** Un messaggio riletto o riscritto non
   deve ripetere l'avviso: sarebbe il modo più rapido per far silenziare il
   gruppo, cioè per rendere inutile la funzione.
3. **`excerpt` porta fuori UNA riga, non il messaggio.** Il gruppo non è
   l'insieme dei partecipanti del topic: senza il taglio, chiunque scriva nella
   stanza può farne uscire il contenuto menzionando qualcuno.
4. **Il link c'è sempre.** Senza, l'avviso dice a qualcuno che è stato chiamato
   e lo lascia a cercare dove.
5. **Il cap SEAL vale al collegamento**, non alla prima notifica.
"""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import telegram_notify as tn
from .local_fs import LocalFsStorage
from .service import TopicError, TopicService


MOUNT = {"name": "telegram", "type": "telegram", "config": {
    "chat_id": "-100999", "mode": "excerpt",
    "people": {"12345": "matteo", "67890": "anna"}}}


def _msg(text, mentions, mid="20260810-120000-abc", author="anna"):
    return {"id": mid, "author": author, "text": text, "mentions": mentions}


class Base(unittest.TestCase):
    def setUp(self):
        self.dati = Path(tempfile.mkdtemp(prefix="tgnotify-"))
        self._env = patch.dict(os.environ, {
            "CLODIA_DATA": str(self.dati),
            "CLODIA_WEBUI_URL": "https://clodia.example.org"})
        self._env.start()
        self.addCleanup(self._env.stop)
        self.addCleanup(shutil.rmtree, self.dati, True)


class QueueTests(Base):
    def test_a_recognised_mention_is_queued_once(self):
        n = tn.enqueue_for_message("SEAL-1", "acme", {"title": "Acme"},
                                   _msg("@matteo guardi il D2.3?", ["matteo"]), [MOUNT])
        self.assertEqual(n, 1)
        di_nuovo = tn.enqueue_for_message("SEAL-1", "acme", {"title": "Acme"},
                                          _msg("@matteo guardi il D2.3?", ["matteo"]), [MOUNT])
        self.assertEqual(di_nuovo, 0, "una menzione avvisa una volta sola")
        self.assertEqual(len(tn.pending()), 1)

    def test_an_unmapped_name_notifies_nobody(self):
        """Il caso più facile da sbagliare e il più caro: un nome che nella
        mappa non c'è deve produrre silenzio, non un destinatario a caso."""
        n = tn.enqueue_for_message("SEAL-1", "acme", {}, _msg("@giovanni ci sei?", ["giovanni"]), [MOUNT])
        self.assertEqual(n, 0)
        self.assertEqual(tn.pending(), [])

    def test_two_mentions_two_notifications(self):
        n = tn.enqueue_for_message("SEAL-1", "acme", {},
                                   _msg("@matteo e @anna, ci siete?", ["matteo", "anna"]), [MOUNT])
        self.assertEqual(n, 2)

    def test_no_mount_no_queue(self):
        self.assertEqual(tn.enqueue_for_message("SEAL-1", "acme", {},
                                                _msg("@matteo", ["matteo"]), []), 0)


class WhatLeavesTheRoomTests(Base):
    def test_excerpt_carries_the_line_not_the_message(self):
        testo = ("Riepilogo della call:\n"
                 "- il budget è 240k e il partner portoghese esce\n"
                 "@matteo puoi rivedere il D2.3?\n"
                 "- il resto lo vediamo lunedì")
        tn.enqueue_for_message("SEAL-1", "acme", {}, _msg(testo, ["matteo"]), [MOUNT])
        fuori = tn.render(tn.pending()[0])
        self.assertIn("D2.3", fuori)
        self.assertNotIn("240k", fuori, "il resto della stanza non esce")
        self.assertNotIn("portoghese", fuori)

    def test_notify_mode_carries_no_content_at_all(self):
        solo_fatto = {**MOUNT, "config": {**MOUNT["config"], "mode": "notify"}}
        tn.enqueue_for_message("SEAL-1", "acme", {}, _msg("@matteo il budget è 240k", ["matteo"]), [solo_fatto])
        fuori = tn.render(tn.pending()[0])
        self.assertNotIn("240k", fuori)
        self.assertIn("matteo", fuori)

    def test_a_long_line_is_truncated(self):
        lungo = "@matteo " + ("dettaglio riservato " * 60)
        tn.enqueue_for_message("SEAL-1", "acme", {}, _msg(lungo, ["matteo"]), [MOUNT])
        self.assertLessEqual(len(tn.pending()[0]["excerpt"]), 280)

    def test_the_link_is_absolute_and_points_at_the_message(self):
        tn.enqueue_for_message("SEAL-1", "acme", {}, _msg("@matteo", ["matteo"], mid="M1"), [MOUNT])
        link = tn.pending()[0]["link"]
        self.assertTrue(link.startswith("https://clodia.example.org/topics/SEAL-1/acme"))
        self.assertTrue(link.endswith("#m-M1"))
        self.assertIn(link, tn.render(tn.pending()[0]))


class DeliveryTests(Base):
    def _uno(self):
        tn.enqueue_for_message("SEAL-1", "acme", {}, _msg("@matteo", ["matteo"], mid="M1"), [MOUNT])
        return tn.pending()[0]

    def test_an_acknowledged_notification_is_not_offered_again(self):
        i = self._uno()
        tn.ack(i["message_id"], i["chat_id"], i["principal"], ok=True)
        self.assertEqual(tn.pending(), [])

    def test_a_failure_keeps_it_and_counts_the_attempt(self):
        """Una rete che torna deve recapitare. Cancellare al primo errore
        perderebbe l'avviso senza dirlo a nessuno."""
        i = self._uno()
        tn.ack(i["message_id"], i["chat_id"], i["principal"], ok=False, error="429")
        ancora = tn.pending()
        self.assertEqual(len(ancora), 1)
        self.assertEqual(ancora[0]["attempts"], 1)
        self.assertIn("429", ancora[0]["last_error"])

    def test_it_stops_being_offered_after_the_last_attempt(self):
        i = self._uno()
        for _ in range(tn.MAX_ATTEMPTS):
            tn.ack(i["message_id"], i["chat_id"], i["principal"], ok=False, error="giù")
        self.assertEqual(tn.pending(), [])

    def test_a_failed_notification_stays_readable(self):
        """Non viene cancellata: una notifica sparita in silenzio non dice a
        nessuno che quella persona non è stata avvisata."""
        i = self._uno()
        for _ in range(tn.MAX_ATTEMPTS):
            tn.ack(i["message_id"], i["chat_id"], i["principal"], ok=False)
        self.assertEqual(len(tn._load()), 1)


class BindTests(Base):
    def setUp(self):
        super().setUp()
        self.root = Path(tempfile.mkdtemp(prefix="tgbind-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        self.svc = TopicService(LocalFsStorage(str(self.root)))
        self.svc.new("SEAL-1", "acme", {"title": "Acme", "owner": "davide"})
        self.svc.new("SEAL-3", "riservato", {"title": "R", "owner": "davide"})
        self._ok = (patch.object(TopicService, "_require_bot_in_group",
                                 staticmethod(lambda c: None)),
                    patch.object(TopicService, "_require_known_principals",
                                 staticmethod(lambda n: None)),
                    patch.object(TopicService, "_declare_egress",
                                 lambda *a, **k: None))
        for c in self._ok:
            c.start()
            self.addCleanup(c.stop)

    def test_binding_creates_a_mount_like_any_other_resource(self):
        out = self.svc.telegram_bind("SEAL-1", "acme", "-100999",
                                     people={"12345": "matteo"})
        self.assertEqual(out["mount"]["type"], "telegram")
        meta, _ = self.svc._read_meta("SEAL-1", "acme")
        self.assertEqual([m["type"] for m in self.svc.telegram_mounts(meta)], ["telegram"])

    def test_a_topic_above_the_cap_cannot_bind(self):
        """Telegram è SEAL-1: server non-UE, gruppi non-E2E. Il rifiuto arriva
        al collegamento, non alla prima notifica."""
        with self.assertRaises(TopicError) as ctx:
            self.svc.telegram_bind("SEAL-3", "riservato", "-100999",
                                   people={"12345": "matteo"})
        self.assertIn("cap SEAL-1", str(ctx.exception))

    def test_binding_without_people_is_refused(self):
        """Un collegamento che non avvisa nessuno sembra funzionare."""
        with self.assertRaises(TopicError) as ctx:
            self.svc.telegram_bind("SEAL-1", "acme", "-100999", people={})
        self.assertIn("nessuna persona mappata", str(ctx.exception))

    def test_binding_without_a_public_url_is_refused(self):
        """Ogni notifica porta un link: senza indirizzo pubblico sarebbe
        relativo, cioè un vicolo cieco dentro Telegram."""
        with patch.dict(os.environ, {"CLODIA_WEBUI_URL": ""}):
            with self.assertRaises(TopicError) as ctx:
                self.svc.telegram_bind("SEAL-1", "acme", "-100999",
                                       people={"12345": "matteo"})
        self.assertIn("CLODIA_WEBUI_URL", str(ctx.exception))

    def test_a_half_written_person_is_dropped_not_guessed(self):
        self.assertEqual(
            TopicService._clean_people({"12345": "matteo", "": "anna", "999": ""}),
            {"12345": "matteo"})

    def test_unbinding_removes_only_the_telegram_mount(self):
        self.svc.telegram_bind("SEAL-1", "acme", "-100999", people={"1": "matteo"})
        meta, ver = self.svc._read_meta("SEAL-1", "acme")
        meta["mounts"] = list(meta.get("mounts") or []) + [
            {"name": "drive", "type": "drive", "config": {"folder": "X"}}]
        self.svc._write_meta("SEAL-1", "acme", meta, base_version=ver)
        self.svc.telegram_unbind("SEAL-1", "acme")
        meta, _ = self.svc._read_meta("SEAL-1", "acme")
        self.assertEqual([m["type"] for m in meta["mounts"]], ["drive"])

    def test_an_unknown_mode_is_refused(self):
        with self.assertRaises(TopicError):
            self.svc.telegram_bind("SEAL-1", "acme", "-100999",
                                   mode="tutto", people={"1": "matteo"})


class ItIsNotAFilesystemTests(Base):
    def test_a_telegram_mount_is_not_mounted_in_the_file_view(self):
        """Non serve una regola nuova: la vista monta solo i tipi che sono
        davvero un altro filesystem, ed è la stessa ragione per cui un mount
        `git` ne è fuori dal 7 agosto."""
        from .service import TopicService as T
        svc = T.__new__(T)
        self.assertIsNone(T._remote_mount_name(svc, {"mounts": [MOUNT]}))


if __name__ == "__main__":
    unittest.main()


class ApiContractTests(Base):
    """Il contratto di `api_call`, che avevo dato per scontato.

    `tools/telegram.api_call` **spacchetta già `result`** e solleva sugli
    errori. Il primo tentativo qui leggeva `.get("result")` sulla sua risposta:
    dà `None` sempre, anche quando la chiamata è andata benissimo. Risultato
    misurato il 10 ago 2026 su un gruppo che esiste, con il bot dentro e
    leggibile: collegamento rifiutato con «RuntimeError».

    Due test, per i due difetti che quel giorno hanno lavorato insieme: la
    forma sbagliata, e un messaggio d'errore che diceva il TIPO dell'eccezione
    invece del motivo — «RuntimeError» non distingue un gruppo inesistente da
    un bot fuori o da un token di un altro bot, e sono tre rimedi diversi.
    """

    #: Esattamente ciò che ritorna `api_call`: il contenuto di `result`.
    RISPOSTE = {
        "getMe": {"id": 8713470720, "is_bot": True, "username": "clodia_topics_bot"},
        "getChatMember": {"status": "member",
                          "user": {"id": 8713470720, "is_bot": True}},
    }

    def test_the_check_passes_against_the_shape_api_call_really_returns(self):
        from ..tools import telegram as tg
        with patch.object(tg, "_token_internal", lambda: "T"), \
             patch.object(tg, "api_call", lambda tok, m, p=None: self.RISPOSTE[m]):
            TopicService._require_bot_in_group("-5279916551")   # non solleva

    def test_a_bot_outside_the_group_is_named_as_such(self):
        from ..tools import telegram as tg
        fuori = {**self.RISPOSTE, "getChatMember": {"status": "left"}}
        with patch.object(tg, "_token_internal", lambda: "T"), \
             patch.object(tg, "api_call", lambda tok, m, p=None: fuori[m]):
            with self.assertRaises(TopicError) as ctx:
                TopicService._require_bot_in_group("-5279916551")
        self.assertIn("non è membro", str(ctx.exception))

    def test_the_failure_carries_the_reason_not_the_exception_class(self):
        """Ciò che ha reso il difetto difficile: l'errore diceva
        «RuntimeError» e nascondeva la frase di Telegram."""
        from ..tools import telegram as tg

        def rotto(tok, m, p=None):
            raise RuntimeError("telegram getChatMember: chat not found")

        with patch.object(tg, "_token_internal", lambda: "T"), \
             patch.object(tg, "api_call", rotto):
            with self.assertRaises(TopicError) as ctx:
                TopicService._require_bot_in_group("-1")
        detto = str(ctx.exception)
        self.assertIn("chat not found", detto)
        self.assertNotIn("RuntimeError", detto)


class OnlyAPersonCallsAPersonTests(Base):
    """Il nome che compare non è sempre una chiamata.

    Misurato in coda su venere il 10 ago 2026, con la funzione appena
    consegnata: Giovanni sarebbe stato avvisato **otto** volte per una
    conversazione sola — cinque da Davide, e tre da agenti che quella menzione
    l'avevano soltanto ripetuta. Il segretario che verbalizza cita il messaggio;
    il guardiano che indaga un turno fallito lo discute. Nessuno dei due sta
    chiamando Giovanni: Giovanni era già stato chiamato.

    Moltiplicato per gli agenti di una stanza, è il modo più rapido per far
    silenziare il gruppo — cioè per rendere inutile la funzione.
    """

    def test_a_person_calling_a_person_notifies(self):
        n = tn.enqueue_for_message("SEAL-1", "acme", {},
                                   {**_msg("@matteo ci sei?", ["matteo"]), "kind": "human"},
                                   [MOUNT])
        self.assertEqual(n, 1)

    def test_an_agent_repeating_the_mention_does_not(self):
        n = tn.enqueue_for_message(
            "SEAL-1", "acme", {},
            {**_msg("Riporto: «@matteo ci sei?»", ["matteo"], mid="M2"), "kind": "ai"},
            [MOUNT])
        self.assertEqual(n, 0)

    def test_a_system_message_does_not_either(self):
        n = tn.enqueue_for_message(
            "SEAL-1", "acme", {},
            {**_msg("@matteo è stato aggiunto", ["matteo"], mid="M3"), "kind": "system"},
            [MOUNT])
        self.assertEqual(n, 0)

    def test_a_message_without_a_kind_is_treated_as_human(self):
        """La direzione della retrocompatibilità: un messaggio senza `kind` è
        della forma vecchia, e la forma vecchia erano i messaggi delle persone.
        Trattarlo come agente perderebbe notifiche in silenzio."""
        n = tn.enqueue_for_message("SEAL-1", "acme", {},
                                   _msg("@matteo ci sei?", ["matteo"], mid="M4"), [MOUNT])
        self.assertEqual(n, 1)


class FlushTests(Base):
    """Il drenaggio meccanico, per un job logico.

    Il piano di un job logico è una lista STATICA di verbi: non può iterare su
    una coda di lunghezza variabile. L'alternativa era un turno LLM ogni cinque
    minuti per sempre, per un lavoro che non richiede alcun giudizio — il testo
    è già composto dal gateway, e la skill dice all'agente di inviarlo verbatim
    proprio perché quel giudizio non deve esserci.
    """

    def _accoda(self, n=3):
        for i in range(n):
            tn.enqueue_for_message("SEAL-1", "acme", {},
                                   _msg("@matteo ci sei?", ["matteo"], mid=f"M{i}"),
                                   [MOUNT])

    def test_it_delivers_and_acknowledges(self):
        inviati = []
        from ..tools import telegram as tg
        self._accoda(3)
        with patch.object(tg, "send_internal",
                          lambda chat, text: inviati.append((chat, text))):
            out = tn.flush()
        self.assertEqual(out["delivered"], 3)
        self.assertEqual(len(inviati), 3)
        self.assertEqual(tn.pending(), [], "recapitate = non più proposte")

    def test_one_bad_chat_does_not_stop_the_others(self):
        """Una chat irraggiungibile non deve impedire a un'altra persona di
        essere avvisata."""
        from ..tools import telegram as tg
        self._accoda(3)
        chiamate = {"n": 0}

        def a_volte(chat, text):
            chiamate["n"] += 1
            if chiamate["n"] == 2:
                raise RuntimeError("telegram sendMessage HTTP 400: chat not found")

        with patch.object(tg, "send_internal", a_volte):
            out = tn.flush()
        self.assertEqual(out["delivered"], 2)
        self.assertEqual(out["failed"], 1)
        self.assertEqual(len(tn.pending()), 1, "la fallita resta, con un tentativo")
        self.assertEqual(tn.pending()[0]["attempts"], 1)

    def test_the_reason_of_a_failure_is_reported(self):
        from ..tools import telegram as tg
        self._accoda(1)

        def rotto(chat, text):
            raise RuntimeError("chat not found")

        with patch.object(tg, "send_internal", rotto):
            out = tn.flush()
        self.assertIn("chat not found", " ".join(out["errors"]))

    def test_an_empty_queue_is_a_quiet_no_op(self):
        """Il job gira ogni pochi minuti: a coda vuota non deve fare rumore né
        lavoro."""
        inviati = []
        from ..tools import telegram as tg
        with patch.object(tg, "send_internal", lambda c, t: inviati.append(c)):
            out = tn.flush()
        self.assertEqual((out["delivered"], out["failed"]), (0, 0))
        self.assertEqual(inviati, [])

"""Tests for per-channel taint (clodia-platform#104 §4, step 7).

The flag is what makes the context gate usable at all: #77's condition 1 says the
gate fires only if the channel is ALSO tainted, because 150 of 156 channels are at
3/3 capability and a gate on capability alone would fire almost always — and a
gate approved by reflex is worse than no gate.

So the tests that matter here are about the flag being ARMED and CLEARED at the
right moments, and about the channel being the unit rather than the spawn.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import taint


class ChannelKeyTests(unittest.TestCase):
    def test_a_session_key_normalises_to_the_channel(self):
        """The taint belongs to the CHANNEL, not the spawn: if one spawn of clodia
        reads a hostile page, the contamination concerns the room. With
        multi-spawn this is concrete — four spawns share the channel."""
        for chat, want in (
            ("chan:SEAL-2:contract:clodia", "SEAL-2/contract"),
            ("chan:SEAL-2:contract:clodia#3", "SEAL-2/contract"),
            ("chan:SEAL-1:hedge-iot-new:fullstack-dev#2", "SEAL-1/hedge-iot-new"),
        ):
            with self.subTest(chat=chat):
                self.assertEqual(taint.channel_of(chat), want)

    def test_a_direct_chat_gets_its_own_flag_rather_than_none(self):
        """A DM is not different from a channel (decision of 2 Aug 2026), so it
        must have a flag instead of having none."""
        self.assertEqual(taint.channel_of("dm:davide:clodia"), "dm:davide:clodia")

    def test_no_chat_means_no_channel(self):
        for empty in ("", None, "   "):
            self.assertIsNone(taint.channel_of(empty))


class TaintingVerbTests(unittest.TestCase):
    def test_verbs_that_return_third_party_content_taint(self):
        for verb in ("web.fetch", "email.read", "github.get_file_contents",
                     "github.list_issues", "topic.read_file", "gdrive.download",
                     "normattiva.search", "trello.cards"):
            with self.subTest(verb=verb):
                self.assertTrue(taint.taints(verb))

    def test_send_only_and_control_verbs_do_not_taint(self):
        """A verb that only pushes data out brings nothing INTO the context, and
        acquiring a lease is access control, not reading."""
        for verb in ("email.send", "telegram.send", "web.post",
                     "telegram.lease_acquire", "topic.save_summary",
                     "gsheets.write_range", "github.create_pull_request"):
            with self.subTest(verb=verb):
                self.assertFalse(taint.taints(verb))


class StateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        p = patch.object(taint, "_path",
                         side_effect=lambda: Path(self.tmp.name) / "taint.json")
        p.start()
        self.addCleanup(p.stop)

    def test_an_unknown_channel_is_clean_not_unknown(self):
        """Nothing has entered yet, so there is nothing to be cautious about."""
        st = taint.status("chan:SEAL-1:nuovo:clodia")
        self.assertFalse(st["tainted"])
        self.assertEqual(st["sources"], [])

    def test_marking_arms_the_flag_and_records_where_it_came_from(self):
        """«The channel is tainted» is not actionable; «an untrusted PDF came in»
        is. A boolean cannot carry that, and without it the human declassifies
        blind (#104 §4)."""
        taint.mark("chan:SEAL-1:x:clodia", "file", "contratto.pdf", "davide")
        st = taint.status("chan:SEAL-1:x:clodia")
        self.assertTrue(st["tainted"])
        self.assertEqual(st["sources"][-1]["detail"], "contratto.pdf")
        self.assertEqual(st["sources"][-1]["kind"], "file")

    def test_the_same_source_twice_does_not_pile_up(self):
        for _ in range(3):
            taint.mark("chan:SEAL-1:x:clodia", "verb", "web.fetch", "clodia")
        self.assertEqual(len(taint.status("chan:SEAL-1:x:clodia")["sources"]), 1)

    def test_only_the_last_sources_are_kept(self):
        for i in range(10):
            taint.mark("chan:SEAL-1:x:clodia", "verb", f"web.fetch/{i}")
        self.assertEqual(len(taint.status("chan:SEAL-1:x:clodia")["sources"]),
                         taint._MAX_SOURCES)

    def test_clear_disarms_the_flag_but_keeps_the_history(self):
        """After an unlock one must still be able to say what had come in, or the
        audit loses the reason that unlock was asked for."""
        taint.mark("chan:SEAL-1:x:clodia", "verb", "web.fetch")
        taint.clear("chan:SEAL-1:x:clodia", by="davide")
        st = taint.status("chan:SEAL-1:x:clodia")
        self.assertFalse(st["tainted"])
        self.assertEqual(st["sources"], [])
        raw = taint._load()["SEAL-1/x"]
        self.assertEqual(raw["cleared_by"], "davide")
        self.assertEqual(len(raw["archived_sources"]), 1)

    def test_taint_re_arms_after_a_clear(self):
        """This is the definition from #77 — «entered AFTER the last unlock» — and
        the reason the open question «close the window or ask again?» needed no
        decision: the flag re-arms and the next outbound action gates again,
        without interrupting the turn."""
        taint.mark("chan:SEAL-1:x:clodia", "verb", "web.fetch")
        taint.clear("chan:SEAL-1:x:clodia", by="davide")
        taint.mark("chan:SEAL-1:x:clodia", "verb", "email.read")
        self.assertTrue(taint.status("chan:SEAL-1:x:clodia")["tainted"])

    def test_taint_does_not_cross_channels(self):
        """Sessions are already per-channel, so it does not spill by itself. The
        case of an agent that REPORTS the content across is still open (#104 §4)."""
        taint.mark("chan:SEAL-1:a:clodia", "verb", "web.fetch")
        self.assertFalse(taint.status("chan:SEAL-1:b:clodia")["tainted"])

    def test_note_verb_marks_only_for_tainting_verbs(self):
        with patch("server.whitelist.current_chat", return_value="chan:SEAL-1:x:clodia"):
            taint.note_verb("email.send", "messaggero")
            self.assertFalse(taint.status("chan:SEAL-1:x:clodia")["tainted"])
            taint.note_verb("web.fetch", "clodia")
            self.assertTrue(taint.status("chan:SEAL-1:x:clodia")["tainted"])

    def test_note_verb_never_raises(self):
        """A measurement that breaks the turn it is measuring is worse than a
        missing measurement."""
        with patch.object(taint, "mark", side_effect=RuntimeError("boom")):
            taint.note_verb("web.fetch", "clodia")   # must not raise


if __name__ == "__main__":
    unittest.main()


class CompositionEpochTests(unittest.TestCase):
    """La composizione entra nella chiave del gate di contesto.

    È IL meccanismo con cui «il cambio di composizione invalida gli unlock
    attivi» (#77): con la composizione dentro la chiave, aggiungere un
    partecipante produce una chiave diversa e l'unlock precedente non combacia
    più. Nessuna revoca da spazzare — che è l'unico modo per cui non può essere
    dimenticata.
    """

    def test_the_key_changes_when_a_participant_is_added(self):
        a = taint.context_gate_key("chan:SEAL-1:x:clodia", ["clodia", "davide"])
        b = taint.context_gate_key("chan:SEAL-1:x:clodia",
                                   ["clodia", "davide", "messaggero"])
        self.assertNotEqual(a, b)

    def test_the_key_does_not_depend_on_the_order(self):
        """Altrimenti si invaliderebbe a ogni riordino del meta, e i gate
        arriverebbero senza che nulla sia cambiato."""
        a = taint.context_gate_key("chan:SEAL-1:x:clodia", ["clodia", "davide"])
        b = taint.context_gate_key("chan:SEAL-1:x:clodia", ["davide", "clodia"])
        self.assertEqual(a, b)

    def test_the_key_names_the_channel_and_is_not_per_spawn(self):
        k = taint.context_gate_key("chan:SEAL-1:x:clodia#4", ["clodia"])
        self.assertTrue(k.startswith("egress-context:SEAL-1/x:"))

    def test_no_channel_means_no_key(self):
        self.assertIsNone(taint.context_gate_key("", ["clodia"]))


class VettedSourceTests(unittest.TestCase):
    """Il taint segue la PROVENIENZA, non il solo nome del verbo (#128).

    Prima `topic.read_file` contaminava sempre: anche su un PDF che l'owner aveva
    caricato marcandolo `trusted`. Un flag che si accende su tutto smette di
    discriminare, che è esattamente la condizione posta in #77 per non produrre
    consent fatigue — e rende il gate di contesto onnipresente, cioè inutile.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        p = patch.object(taint, "_path",
                         side_effect=lambda: Path(self.tmp.name) / "t.json")
        p.start()
        self.addCleanup(p.stop)
        self.CH = "chan:SEAL-1:x:clodia"

    def _tainted(self, vetted):
        taint._save({})
        with patch("server.whitelist.current_chat", return_value=self.CH):
            taint.note_verb("topic.read_file", "clodia", vetted=vetted)
        return taint.status(self.CH)["tainted"]

    def test_a_vetted_source_does_not_taint(self):
        self.assertFalse(self._tainted(True))

    def test_an_unvetted_source_taints(self):
        self.assertTrue(self._tainted(False))

    def test_an_undeterminable_source_taints(self):
        """Direzione prudente: una lettura di cui non sappiamo la provenienza non
        è una lettura fidata, e sbagliare qui è silenzioso."""
        self.assertTrue(self._tainted(None))

    def test_a_non_tainting_verb_is_unaffected_by_the_verdict(self):
        """`vetted=False` non deve trasformare un invio in una contaminazione: la
        tabella dei verbi resta il primo filtro."""
        taint._save({})
        with patch("server.whitelist.current_chat", return_value=self.CH):
            taint.note_verb("email.send", "messaggero", vetted=False)
        self.assertFalse(taint.status(self.CH)["tainted"])


class SourceResolutionTests(unittest.TestCase):
    """La regola è «verbo + fonte», e va applicata a OGNI verbo che ha una fonte.

    Formulata da @ddbit il 4 ago 2026: «quello che conta non è né il verbo né la
    fonte, ma l'evento in cui l'agente legge da una fonte non fidata. Prima della
    lettura non c'è taint.» Applicandola ho trovato che era implementata a metà:
    sei verbi con una fonte identificabile contaminavano comunque sempre.
    """

    def test_every_tainting_verb_with_one_source_resolves_it(self):
        from . import main
        resolved = set(main._TOPIC_READ_VERBS) | set(main._RESOURCE_READ_VERBS) \
            | {"email.read"}
        # Chi resta mescola più fonti in una risposta: non c'è UNA fonte da
        # vagliare, e dichiararne una sarebbe peggio che ammettere di non poterlo
        # fare. Se un giorno uno di questi diventa a fonte singola, va spostato.
        mixed = {"email.list", "email.search", "email.get_attachment",
                 "telegram.inbox", "telegram.receive", "telegram.pull",
                 "trello.cards", "trello.comments", "trello.show_card",
                 "gcalendar.list_events"}
        unaccounted = {v for v in taint._TAINTING_EXACT
                       if v not in resolved and v not in mixed}
        self.assertEqual(unaccounted, set(),
                         f"verbi che contaminano senza fonte né motivo: {unaccounted}")

    def test_a_read_from_a_vetted_folder_does_not_taint_on_pull_either(self):
        """`remote_pull` è una lettura da quella fonte come le altre: trattarla a
        parte contaminerebbe anche il pull da una cartella vagliata."""
        from . import main
        self.assertIn("topic.remote_pull", main._TOPIC_READ_VERBS)

"""La regola dei gate, resa visibile — e tenuta tale.

Un gate non è una proprietà del verbo: è ciò che accade quando un'azione
ATTRAVERSA un confine, o quando chi la chiede non ne ha titolo (voce 23,
emendata dalla 26).

Fino al 7 ago 2026 era una lista piatta di nomi. Funzionava, ma la regola non si
vedeva: ogni verbo nuovo obbligava un umano a indovinare in quale secchio andasse,
ed è così che i meccanismi di gating sono diventati quattro invece di uno.

Il test che conta è l'ULTIMO: ogni verbo gated deve avere una classe. Senza,
aggiungerne uno alla lista senza classificarlo lo rimetterebbe nella condizione da
cui usciamo — gated per convenzione invece che per una ragione leggibile — e
nessun test se ne accorgerebbe.

E la quarta classe non deve esistere. Quando ho misurato i 28 verbi il 6 agosto,
la riga «usa una risorsa del tuo scope» era VUOTA: non c'è, e non c'è mai stato,
un gate sul lavoro dentro la propria stanza. Se un verbo finisse lì sarebbe
esattamente la cosa che la voce 23 dice di non fare.
"""
from __future__ import annotations

import unittest

from . import gate


class ClassificationTests(unittest.TestCase):
    def test_changing_the_rules_is_system(self):
        for v in ("agents.grant_tool", "packs.install_pip", "providers.pause",
                  "mcp.add"):
            with self.subTest(verbo=v):
                self.assertEqual(gate.gate_class(v), gate.GATE_SYSTEM)

    def test_the_prefixes_are_system(self):
        for v in ("settings.set", "pki.issue", "ca.rotate"):
            with self.subTest(verbo=v):
                self.assertEqual(gate.gate_class(v), gate.GATE_SYSTEM)

    def test_moving_the_walls_is_its_own_class(self):
        """Il gate va all'OWNER dello scope, non a un admin qualunque (voce 24):
        è per questo che non stanno con i verbi di sistema."""
        for v in ("topic.add_participant", "topic.remote_add",
                  "topic.remote_disable", "topic.save_agents_md"):
            with self.subTest(verbo=v):
                self.assertEqual(gate.gate_class(v), gate.GATE_WALLS)

    def test_crossing_outward_is_its_own_class(self):
        for v in ("web.post", "egress.allow", "ingress.allow"):
            with self.subTest(verbo=v):
                self.assertEqual(gate.gate_class(v), gate.GATE_OUTWARD)

    def test_a_verb_that_is_not_gated_has_no_class(self):
        for v in ("topic.open", "topic.read_file", "email.list", "agents.list"):
            with self.subTest(verbo=v):
                self.assertIsNone(gate.gate_class(v))


class CompletenessTests(unittest.TestCase):
    """Il test che impedisce alla lista di tornare piatta."""

    def test_every_gated_verb_has_a_class(self):
        senza = sorted(v for v in gate._DEFAULT_GATED_EXACT
                       if gate.gate_class(v) is None)
        self.assertEqual(
            senza, [],
            "verbi gated senza classe: sono gated per convenzione invece che per "
            "una ragione leggibile, ed è la condizione da cui questa modifica "
            "esce. Classificali in `_GATE_CLASS`.")

    def test_every_classified_verb_is_actually_gated(self):
        """L'altra direzione: una classificazione su un verbo non gated è una
        regola che non si applica mai — e sembra applicarsi. Stesso difetto
        trovato oggi su `add_participant` fra i verbi mutanti."""
        fantasmi = sorted(v for v in gate._GATE_CLASS
                          if not gate.is_gated(v))
        self.assertEqual(fantasmi, [])

    def test_the_prefixes_are_classified_too(self):
        for pref in gate._DEFAULT_GATED_PREFIXES:
            with self.subTest(prefisso=pref):
                self.assertIsNotNone(gate.gate_class(pref + "qualcosa"))


class NoFourthClassTests(unittest.TestCase):
    """La riga vuota della tabella, tenuta vuota.

    Misurati i 28 verbi il 6 ago 2026: nessuno significa «usa una risorsa del tuo
    scope». Non c'è mai stato un gate sul lavoro dentro la propria stanza, ed è
    la proprietà che rende il modello vivibile — se ce ne fosse uno, ogni turno
    di lavoro normale chiederebbe il permesso.
    """

    def test_no_gated_verb_is_ordinary_work_inside_a_scope(self):
        lavoro_dentro = {"topic.open", "topic.files", "topic.read_file",
                         "topic.read_document", "topic.fetch", "topic.put",
                         "topic.write_file", "topic.post_message",
                         "topic.save_summary", "topic.search", "topic.list",
                         "topic.delete_file", "topic.remote_status",
                         "topic.remote_pull", "topic.remote_commit",
                         "topic.remote_push"}
        gated = {v for v in lavoro_dentro if gate.is_gated(v)}
        self.assertEqual(
            gated, set(),
            "un gate sul lavoro dentro la stanza: la voce 23 dice che non deve "
            "esistere, e un gate che scatta su ogni turno normale smette di "
            "essere letto")


if __name__ == "__main__":
    unittest.main()


class ClassTravelsWithTheRequestTests(unittest.TestCase):
    """La classe deve arrivare a chi decide, che sta in un altro servizio.

    Se sparisse da `list_requests()`, `clodia-logic` non riderivarebbe nulla:
    tornerebbe IN SILENZIO ad «admin per tutto», e l'owner perderebbe l'autorità
    sui gate della propria stanza senza che niente fallisca. È lo stesso modo in
    cui `gated_in_channel` era dichiarato e non portato da nessuno.
    """

    def setUp(self):
        import tempfile
        from unittest.mock import patch
        from pathlib import Path
        self.d = tempfile.mkdtemp(prefix="gate-req-")
        self.p = patch.object(gate, "_req_path",
                              lambda: Path(self.d) / "req.json")
        self.p.start()
        self.addCleanup(self.p.stop)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.d, ignore_errors=True)

    def test_a_pending_request_carries_its_class(self):
        gate.request("clodia", "-", "topic.add_participant",
                     chat="chan:SEAL-1:acme:clodia")
        r = gate.list_requests()
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0]["class"], gate.GATE_WALLS)

    def test_a_system_request_carries_its_class(self):
        gate.request("clodia", "-", "agents.grant_tool")
        self.assertEqual(gate.list_requests()[0]["class"], gate.GATE_SYSTEM)

    def test_the_room_comes_from_the_request_not_from_the_approver(self):
        gate.request("clodia", "-", "web.post", chat="chan:SEAL-2:proof:clodia")
        self.assertEqual(gate.list_requests()[0]["chat"], "chan:SEAL-2:proof:clodia")


class EgressKeysAreOutwardTests(unittest.TestCase):
    """Una destinazione nuova è un'uscita, e va detto.

    `egress.gate_key(tipo, destinazione)` produce chiavi come
    `egress:github:https://github.com/…`: un gate per DESTINAZIONE, non per
    verbo. Non erano classificate, e il 10 ago 2026 la card della webui l'ha
    detto in faccia — «attraversa un confine che il gateway non ha
    classificato». Il messaggio era giusto e la lacuna vera: chiedere a
    qualcuno di approvare un'uscita senza dirgli che **è** un'uscita è
    precisamente ciò che la classificazione serve a evitare.
    """

    def test_every_egress_key_is_outward(self):
        from . import egress, gate
        for dtype, dest in (("github", "https://github.com/acme/tool"),
                            ("email", "mario@example.org"),
                            ("tg", "-1001234567890"),
                            ("web", "https://example.org/hook")):
            with self.subTest(dtype):
                self.assertEqual(gate.gate_class(egress.gate_key(dtype, dest)),
                                 gate.GATE_OUTWARD)

    def test_a_destination_containing_a_verb_like_string_is_still_outward(self):
        """Le destinazioni contengono URL, che contengono punti: la
        classificazione non deve dipendere da come è fatta la destinazione."""
        from . import gate
        self.assertEqual(
            gate.gate_class("egress:web:https://x.org/settings.php"),
            gate.GATE_OUTWARD)

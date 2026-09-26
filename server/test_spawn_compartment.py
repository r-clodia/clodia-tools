"""Il compartimento è dello SPAWN, non del seed.

Il difetto, misurato il 7 ago 2026 e non ipotetico. `_topic_is_member`
confrontava il nome del SEED con i partecipanti del topic bersaglio, e nessuno
guardava da quale stanza partisse la chiamata. Su marte:

    topic totali: 157
      clodia   participant di 135

Quindi uno spawn di clodia, stando in una stanza qualunque, poteva leggere i file
degli altri 134 topic senza gate e riversarli lì dentro. Il modello dichiara due
assi — clearance E compartimento — ma il secondo compartimenta solo se valutato
per spawn: per seed è un permesso globale vestito da compartimento.

La regola, con `qui` preso dal claim FIRMATO:

    T == qui                → consentito
    agent ∈ participants(T) → GATE      ← il cambiamento
    altrimenti              → GATE

*Aggiornato il 6 set 2026*: esisteva un'eccezione, «T dichiarato portabile
dal TOPIC → consentito» (decision-record #28/#29). Abrogata (decision-record
#39, clodia-platform#313): nessun topic bypassa più il gate dichiarandosi
tale, non resta nessuna terza via oltre "sei nella tua stanza" o "gate".

*Aggiornato il 23 set 2026*: la chiave di gate non è più per-target
(`topic-access:<tier>/<name>`), è il grant unico `crosstopic` — vedi
`test_topic_access.py` per l'eleggibilità (solo clodia/sysadmin) e lo scoping
per spawn del consenso stesso.
"""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from . import main as M


META_A = {"tier": "SEAL-1", "owner": "davide", "participants": ["clodia", "davide"]}
ARGS_A = {"tier": "SEAL-1", "name": "topic-a"}


class _Chat:
    def __init__(self, v):
        self.v = v

    def __enter__(self):
        from . import whitelist as w
        self.t = w.set_current_chat(self.v)
        return self

    def __exit__(self, *a):
        from . import whitelist as w
        w.reset_current_chat(self.t)
        return False


class _NonPresidiata:
    """Sessione di job: il claim `unattended` è firmato, l'agente non lo sceglie."""

    def __enter__(self):
        from . import whitelist as w
        self.t = w.set_current_unattended(True)
        return self

    def __exit__(self, *a):
        from . import whitelist as w
        w.reset_current_unattended(self.t)
        return False


class _SenzaVariabile:
    """L'ambiente del deploy che NON dichiara `CLODIA_SPAWN_COMPARTMENT`.

    È il caso che conta davvero: la modalità la sceglie il default del codice, e
    per settimane quel default è stato `report` — cioè «osserva e lascia
    passare» (clodia-platform#382)."""

    def start(self):
        self._p = patch.dict("os.environ", {})
        self._p.start()
        os.environ.pop("CLODIA_SPAWN_COMPARTMENT", None)

    def stop(self):
        self._p.stop()


def _svc_patch(meta=None):
    base = meta if meta is not None else META_A

    class _Svc:
        def open(self, tier, name):
            return {"meta": base}
    return patch.object(M, "_topics", lambda: _Svc())


def _env(modo="on", meta=None):
    return (patch.dict("os.environ", {"CLODIA_SPAWN_COMPARTMENT": modo}),
            _svc_patch(meta))


def _env_default(meta=None):
    """Nessuna variabile: decide il default del codice."""
    return (_SenzaVariabile(), _svc_patch(meta))


class Base(unittest.TestCase):
    def run_with(self, ctx, fn):
        for c in ctx:
            c.start()
        try:
            return fn()
        finally:
            [c.stop() for c in ctx]

    def key(self, verbo="topic.read_file", agente="clodia", **kw):
        return M._cross_topic_gate_key(verbo, ARGS_A, agente)


class EnforcedTests(Base):
    def test_reading_your_own_room_is_free(self):
        def go():
            with _Chat("chan:SEAL-1:topic-a:clodia"):
                self.assertIsNone(self.key())
        self.run_with(_env(), go)

    def test_membership_alone_no_longer_waives_the_gate(self):
        """Il cuore della correzione. clodia È participant di topic-a, ma sta in
        topic-b: prima passava, ora chiede."""
        def go():
            with _Chat("chan:SEAL-1:topic-b:clodia"):
                self.assertEqual(self.key(), "crosstopic")
        self.run_with(_env(), go)

    def test_a_non_member_still_gates(self):
        def go():
            with _Chat("chan:SEAL-1:topic-b:clodia"):
                self.assertEqual(self.key(), "crosstopic")
        self.run_with(_env(meta={"tier": "SEAL-1", "owner": "x", "participants": []}), go)

    def test_outside_any_room_a_non_member_still_gates(self):
        """Fuori da una stanza non esiste un «qui», e non c'è più nessuna
        eccezione dichiarata dal topic (decision-record #39): chi non è
        partecipante passa dal gate come ovunque.

        *Rivisto il 26 set 2026 (clodia-platform#382)*: qui prima si asseriva
        che fuori da una stanza gatasse TUTTO, membership compresa. Quella
        regola non è mai stata in esercizio — il default era `report` — e
        accenderla così com'era avrebbe gatato ogni verbo `topic.*` di ogni
        chat normale della webui, che non ha un `chan:` (il suo `chat_id` è un
        timestamp). Avrebbe rotto l'esercizio senza chiudere il leak, che vive
        nelle stanze: vedi `RoomlessSessionTests`."""
        def go():
            with _Chat("job:42"):
                self.assertEqual(self.key(), "crosstopic")
        self.run_with(_env(meta={"tier": "SEAL-1", "owner": "x",
                                 "participants": []}), go)

    def test_ineligible_agent_is_denied_not_gated(self):
        """23 set 2026: solo clodia/sysadmin possono chiedere 'crosstopic'.
        Un agente diverso non riceve una card, riceve un rifiuto subito."""
        def go():
            with _Chat("chan:SEAL-1:topic-b:esperto-bandi"):
                with self.assertRaises(PermissionError):
                    M._cross_topic_gate_key("topic.read_file", ARGS_A, "esperto-bandi")
        self.run_with(_env(), go)


class TierAliasTests(Base):
    def test_legacy_tier_aliases_compare_equal(self):
        """I due lati arrivano da sorgenti diverse — il claim firmato e il meta
        del topic. Un confronto per stringa grezza aprirebbe un buco al primo
        alias: `P1/topic-a` e `SEAL-1/topic-a` sono lo stesso posto."""
        def go():
            with _Chat("chan:P1:topic-a:clodia"):
                self.assertIsNone(self.key())
        self.run_with(_env(), go)


class ReportModeTests(Base):
    def test_report_does_not_refuse_but_logs_what_it_would_refuse(self):
        """Il rollout osserva prima di rifiutare: questa regola stringe un
        permesso larghissimo, e stringerlo alla cieca romperebbe l'orchestrazione
        senza che nessuno sappia dove."""
        def go():
            with _Chat("chan:SEAL-1:topic-b:clodia"):
                with self.assertLogs("clodia-tools", level="WARNING") as log:
                    self.assertIsNone(self.key())
                self.assertTrue(any("compartimento spawn" in r for r in log.output))
        self.run_with(_env(modo="report"), go)

    def test_off_restores_the_old_behaviour_exactly(self):
        """Una via di ritirata che non richiede un deploy."""
        def go():
            with _Chat("chan:SEAL-1:topic-b:clodia"):
                self.assertIsNone(self.key())
        self.run_with(_env(modo="off"), go)


class DefaultModeTests(Base):
    """clodia-platform#382. Il leak osservato da Davide il 21/09 non è passato
    da un buco della regola: la regola c'era e **non era accesa**. Il default di
    `_spawn_compartment_mode()` era `report`, e in `report` un agente che è
    participant del bersaglio legge senza card — che è precisamente il caso di
    clodia, participant di quasi tutto.

    Finché il default è insicuro, «questa istanza è configurata bene?» è una
    domanda che va posta a ogni deploy, e la risposta non è verificabile da
    dentro. Un default sicuro la rende una domanda inutile."""

    def test_senza_variabile_il_default_e_on(self):
        def go():
            self.assertEqual(M._spawn_compartment_mode(), "on")
        self.run_with(_env_default(), go)

    def test_senza_variabile_la_membership_non_grazia_piu(self):
        """Lo scenario dell'issue, con l'ambiente del deploy reale: clodia è
        participant di `topic-a` ma sta in `topic-b`."""
        def go():
            with _Chat("chan:SEAL-1:topic-b:clodia"):
                self.assertEqual(self.key("topic.messages"), "crosstopic")
        self.run_with(_env_default(), go)

    def test_cio_che_si_e_stretto_lascia_una_riga_leggibile(self):
        """Dopo il flip serve sapere COSA si è stretto, o la decisione non si
        può né confermare né ritirare su evidenza. Si registra solo il caso che
        la modalità cambia — l'agente è participant del bersaglio — perché chi
        non lo è era gatato anche prima e non dice niente di nuovo.
        Si rilegge con `logs.tail(source="gateway")`."""
        def go():
            with _Chat("chan:SEAL-1:topic-b:clodia"):
                with self.assertLogs("clodia-tools", level="WARNING") as log:
                    self.key("topic.messages")
                self.assertTrue(any("GATE" in r for r in log.output), log.output)
        self.run_with(_env_default(), go)

    def test_chi_non_e_partecipante_non_fa_rumore(self):
        def go():
            with _Chat("chan:SEAL-1:topic-b:clodia"):
                with self.assertNoLogs("clodia-tools", level="WARNING"):
                    self.key("topic.messages")
        self.run_with(_env_default(meta={"tier": "SEAL-1", "owner": "x",
                                         "participants": []}), go)

    def test_una_variabile_vuota_non_e_una_ritirata(self):
        """`CLODIA_SPAWN_COMPARTMENT=` (vuota) è una variabile dimenticata, non
        una decisione: cade sul default, che ora enforce."""
        def go():
            with _Chat("chan:SEAL-1:topic-b:clodia"):
                self.assertEqual(self.key(), "crosstopic")
        self.run_with(_env(modo=""), go)

    def test_la_ritirata_esplicita_resta(self):
        """`off`/`report` restano raggiungibili senza un deploy: cambia chi deve
        dichiararsi, non quante vie ci sono."""
        def go():
            self.assertEqual(M._spawn_compartment_mode(), "off")
        self.run_with(_env(modo="off"), go)


class RoomlessSessionTests(Base):
    """Una sessione senza `chan:` non è una stanza in cui riversare.

    Il compartimento che questa regola difende È la stanza: il danno di #382 è
    portare in una stanza contenuti che la sua platea non ha titolo di vedere.
    Una chat 1:1 della webui non ha platea — e non ha nemmeno un `chan:`, perché
    il suo `chat_id` è un timestamp (`_new_chat_id()` in clodia-logic). Gatarla
    significherebbe chiedere una card per ogni verbo `topic.*` di ogni
    conversazione normale: si romperebbe l'esercizio senza chiudere il leak.

    Quello che resta in piedi non è niente: `_require_topic_member` esige
    comunque la membership (o il grant `crosstopic`) e la clearance ≥ tier.
    Cambia solo che qui non si aggiunge un gate."""

    def test_una_chat_della_webui_lavora_sui_suoi_topic(self):
        def go():
            with _Chat("20260926-201500-ab12cd"):
                self.assertIsNone(self.key("topic.read_file"))
        self.run_with(_env_default(), go)

    def test_e_lo_dice_in_un_log_che_qualcuno_puo_leggere(self):
        """L'osservazione non è decorativa: è l'unico modo di sapere quanto
        questa via è usata davvero, e ora si rilegge con
        `logs.tail(source="gateway")`."""
        def go():
            with _Chat("20260926-201500-ab12cd"):
                with self.assertLogs("clodia-tools", level="WARNING") as log:
                    self.key("topic.read_file")
                self.assertTrue(any("compartimento spawn" in r for r in log.output))
        self.run_with(_env_default(), go)

    def test_una_chat_della_webui_non_apre_i_topic_altrui(self):
        def go():
            with _Chat("20260926-201500-ab12cd"):
                self.assertEqual(self.key("topic.read_file"), "crosstopic")
        self.run_with(_env_default(meta={"tier": "SEAL-1", "owner": "x",
                                         "participants": []}), go)

    def test_dentro_una_stanza_la_regola_resta_stretta(self):
        """Il contrasto che rende la distinzione una regola e non uno sconto."""
        def go():
            with _Chat("chan:SEAL-1:topic-b:clodia"):
                self.assertEqual(self.key("topic.read_file"), "crosstopic")
        self.run_with(_env_default(), go)


class UnattendedDepositTests(Base):
    """Il deposito di un job non presidiato sopravvive all'enforcement.

    Un job nasce con `run_id="job:<id>"` (clodia-logic, `scheduler.py`): niente
    `chan:`, quindi `current_channel()` è `None` e la regola «T == qui» non può
    mai essere soddisfatta. Con l'enforcement acceso e nessuna eccezione, ogni
    job che deposita in un topic — la mail in arrivo del messaggero, un handoff
    — verrebbe gatato, e gatare una sessione non presidiata significa negarla.

    L'eccezione è la più stretta che copre quel caso: **solo** `post_message`,
    **solo** senza stanza, **solo** verso un topic di cui l'agente è già
    partecipante. È la direzione che deposita, non quella che porta fuori: non
    apre nessuna lettura, ed è l'unico verbo che una sessione non presidiata
    può comunque chiamare (`_UNATTENDED_TOPIC_ALLOW`)."""

    def test_un_job_deposita_ancora_nel_suo_topic(self):
        def go():
            with _Chat("job:42"), _NonPresidiata():
                self.assertIsNone(self.key("topic.post_message"))
        self.run_with(_env_default(), go)

    def test_lo_stesso_job_non_puo_leggere_quel_topic(self):
        """L'eccezione è per verbo, non per sessione: depositare sì, leggere no."""
        def go():
            with _Chat("job:42"), _NonPresidiata():
                self.assertEqual(self.key("topic.read_file"), "crosstopic")
                self.assertEqual(self.key("topic.messages"), "crosstopic")
        self.run_with(_env_default(), go)

    def test_un_job_non_deposita_dove_non_e_partecipante(self):
        def go():
            with _Chat("job:42"), _NonPresidiata():
                self.assertEqual(self.key("topic.post_message"), "crosstopic")
        self.run_with(_env_default(meta={"tier": "SEAL-1", "owner": "x",
                                         "participants": []}), go)

    def test_un_agente_non_eleggibile_e_comunque_negato_fuori_dai_suoi_topic(self):
        def go():
            with _Chat("job:42"), _NonPresidiata():
                with self.assertRaises(PermissionError):
                    self.key("topic.post_message", agente="messaggero")
        self.run_with(_env_default(meta={"tier": "SEAL-1", "owner": "x",
                                         "participants": []}), go)

    def test_il_messaggero_deposita_nei_topic_di_cui_fa_parte(self):
        """Il caso d'esercizio: la mail in arrivo finisce nel topic giusto anche
        se chi la consegna non è eleggibile al grant cross-topic."""
        def go():
            with _Chat("job:42"), _NonPresidiata():
                self.assertIsNone(self.key("topic.post_message",
                                           agente="messaggero"))
        self.run_with(_env_default(meta={"tier": "SEAL-1", "owner": "davide",
                                         "participants": ["messaggero"]}), go)

    def test_non_presidiata_e_piu_stretta_di_presidiata(self):
        """Il claim `unattended` è FIRMATO e stringe, non allarga: senza umano
        che legga il risultato resta solo il deposito. La stessa lettura, in una
        sessione presidiata senza stanza, passa (`RoomlessSessionTests`)."""
        def leggi():
            return self.key("topic.read_file")

        def go():
            with _Chat("20260926-201500-ab12cd"):
                self.assertIsNone(leggi())
                with _NonPresidiata():
                    self.assertEqual(leggi(), "crosstopic")
        self.run_with(_env_default(), go)

    def test_un_job_legato_a_una_stanza_non_ha_l_eccezione(self):
        """Un trigger di topic gira in `chan:`: ha una stanza, quindi scrivere
        in un'ALTRA è cross-topic pieno, e passa dal gate come tutto il resto."""
        def go():
            with _Chat("chan:SEAL-1:topic-b:clodia"), _NonPresidiata():
                self.assertEqual(self.key("topic.post_message"), "crosstopic")
        self.run_with(_env_default(), go)

    def test_nella_propria_stanza_un_job_non_chiede_niente(self):
        def go():
            with _Chat("chan:SEAL-1:topic-a:clodia"), _NonPresidiata():
                self.assertIsNone(self.key("topic.post_message"))
        self.run_with(_env_default(), go)


class SignedSourceTests(unittest.TestCase):
    def test_the_room_comes_from_the_signed_claim_not_from_an_argument(self):
        """Una regola che leggesse la stanza da un argomento sarebbe la parola
        dell'agente su dove si trova, cioè non un controllo."""
        import inspect
        src = inspect.getsource(M._cross_topic_gate_key)
        self.assertIn("current_channel()", src)
        self.assertNotIn('arguments.get("chat"', src)


if __name__ == "__main__":
    unittest.main()

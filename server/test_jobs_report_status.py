"""Il verbo con cui un run dichiara com'è andata, e perché non passa dal gate.

Metà gateway di clodia-platform#206. L'agent-server registra lo stato; qui si
verifica che il verbo esista con la forma giusta, che l'identità del run non sia
auto-dichiarata, e che una conferma umana non si metta di mezzo — un run
schedulato gira di notte, e una card che nessuno approva lo lascerebbe senza
esito proprio nel caso per cui il verbo è stato scritto.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import gate
from .tools import runtime


class IlVerboNonPassaDalGateTests(unittest.TestCase):
    """`jobs.report_status` racconta, non agisce."""

    def test_nessuna_delle_tre_ragioni_lo_fa_chiedere(self):
        for ragione in ("globally_gated", "agent_gated", "off_profile"):
            with self.subTest(ragione=ragione):
                self.assertFalse(
                    gate.needs_consent(
                        "jobs.report_status", perimeter_ok=False,
                        **{r: r == ragione for r in
                           ("globally_gated", "agent_gated", "off_profile")}),
                    "un run notturno non può attendere un'approvazione per dire com'è andata")

    def test_e_nemmeno_tutte_e_tre_insieme(self):
        self.assertFalse(gate.needs_consent(
            "jobs.report_status", globally_gated=True, agent_gated=True,
            off_profile=True, perimeter_ok=False))

    def test_l_esenzione_non_si_estende_ai_vicini(self):
        """`jobs.propose` CREA lavoro ricorrente e resta gated: se l'esenzione
        prendesse il prefisso `jobs.` invece del verbo, un agente potrebbe
        proporre job senza che l'owner veda nulla."""
        self.assertTrue(gate.needs_consent(
            "jobs.propose", globally_gated=False, agent_gated=False,
            off_profile=True, perimeter_ok=False))

    def test_l_insieme_delle_esenzioni_resta_di_un_verbo(self):
        """Non è pedanteria: questo insieme è un bypass del consenso umano, e la
        pressione a infilarci «solo un altro verbo» arriverà. Se il numero
        cambia, che cambi con un test rosso e una discussione davanti."""
        self.assertEqual(gate.SELF_REPORTING, frozenset({"jobs.report_status"}))

    def test_nessun_verbo_esente_e_anche_gated(self):
        """Un verbo che sta in entrambi gli insiemi è una contraddizione
        dichiarata: qualcuno lo ha ritenuto pericoloso e qualcun altro innocuo."""
        for v in gate.SELF_REPORTING:
            with self.subTest(verbo=v):
                self.assertFalse(gate.is_gated(v))
                self.assertIsNone(gate.gate_class(v))


class LaFormaDelloStatoTests(unittest.TestCase):
    """Validazione lato gateway: rifiutare senza un giro di rete."""

    def test_i_tre_stati_ammessi_arrivano_all_agent_server(self):
        for s in ("success", "error", "fatal"):
            with self.subTest(stato=s):
                with patch.object(runtime, "_post", return_value={"ok": True}) as p:
                    runtime.report_run_status(chat_id="c1", status=s, agent="clodia")
                self.assertEqual(p.call_args[0][1]["status"], s)

    def test_lo_stato_e_normalizzato(self):
        with patch.object(runtime, "_post", return_value={"ok": True}) as p:
            runtime.report_run_status(chat_id="c1", status="  SUCCESS  ")
        self.assertEqual(p.call_args[0][1]["status"], "success")

    def test_failed_non_e_dichiarabile_e_l_errore_lo_spiega(self):
        """Un agente che è morto non dichiara nulla: `failed` lo constata
        l'infrastruttura. L'errore deve dirlo, altrimenti l'agente ritenta."""
        with patch.object(runtime, "_post") as p:
            with self.assertRaises(ValueError) as ctx:
                runtime.report_run_status(chat_id="c1", status="failed")
            p.assert_not_called()
        msg = str(ctx.exception)
        self.assertIn("failed", msg)
        for s in ("success", "error", "fatal"):
            self.assertIn(s, msg, "l'errore deve elencare i valori ammessi")

    def test_uno_stato_inventato_non_arriva_alla_rete(self):
        with patch.object(runtime, "_post") as p:
            with self.assertRaises(ValueError):
                runtime.report_run_status(chat_id="c1", status="quasi")
            p.assert_not_called()

    def test_il_detail_vuoto_diventa_none(self):
        """`""` e «non l'ho scritto» sono la stessa cosa, e lo storico non deve
        mostrare un dettaglio vuoto come se fosse una spiegazione."""
        for vuoto in ("", "   ", None):
            with self.subTest(detail=repr(vuoto)):
                with patch.object(runtime, "_post", return_value={"ok": True}) as p:
                    runtime.report_run_status(chat_id="c1", status="error", detail=vuoto)
                self.assertIsNone(p.call_args[0][1]["detail"])

    def test_il_detail_arriva_intero(self):
        with patch.object(runtime, "_post", return_value={"ok": True}) as p:
            runtime.report_run_status(chat_id="c1", status="error",
                                      detail="3 fonti su 5 in 403")
        self.assertEqual(p.call_args[0][1]["detail"], "3 fonti su 5 in 403")

    def test_la_rotta_e_quella_interna_dell_agent_server(self):
        with patch.object(runtime, "_post", return_value={"ok": True}) as p:
            runtime.report_run_status(chat_id="c1", status="success")
        self.assertEqual(p.call_args[0][0], "/clodia/jobs/report-status/internal")

    def test_gli_stati_dichiarabili_non_includono_failed(self):
        self.assertEqual(set(runtime._REPORTABLE), {"success", "error", "fatal"})
        self.assertNotIn("failed", runtime._REPORTABLE)


class IlChatIdNonEAutoDichiaratoTests(unittest.TestCase):
    """L'identità del run viene dal claim firmato, non dagli argomenti."""

    def test_il_verbo_non_accetta_chat_id_fra_gli_argomenti(self):
        """Se lo accettasse, dichiarare l'esito del run di qualcun altro sarebbe
        questione di cambiare un campo — e per un modello quel campo è testo come
        tutto il resto."""
        from . import main
        tool = next(t for t in main._JOBS_TOOLS if t.name == "jobs.report_status")
        props = set((tool.inputSchema.get("properties") or {}).keys())
        self.assertEqual(props, {"status", "detail"})
        self.assertNotIn("chat_id", props)
        self.assertNotIn("job_id", props)
        self.assertNotIn("run_id", props)

    def test_lo_schema_dichiara_i_tre_stati(self):
        from . import main
        tool = next(t for t in main._JOBS_TOOLS if t.name == "jobs.report_status")
        enum = (tool.inputSchema["properties"]["status"] or {}).get("enum")
        self.assertEqual(set(enum or []), {"success", "error", "fatal"},
                         "l'enum nello schema è ciò che il modello legge per primo")
        self.assertEqual(tool.inputSchema.get("required"), ["status"])


if __name__ == "__main__":
    unittest.main()

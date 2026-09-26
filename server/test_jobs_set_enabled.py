"""Il freno su un job schedulato — e perché passa da un umano.

clodia-platform#399. Il 26/09/2026 un trigger di topic ha riemesso per 77 volte
un ordine su un'epic chiusa. La superficie `jobs.*` copriva osservazione
(`jobs.list`) e creazione (`jobs.propose`): nessun verbo fermava un job già
schedulato, e l'unica via d'uscita — scalare all'owner — è morta quel giorno su
entrambi i canali. In più `jobs.list` non elencava affatto i job
`mode: topic_trigger`, quindi chi cercava il job 6 concludeva che non esistesse.

Qui si verifica la metà gateway: il verbo esiste, è gated in entrambe le
direzioni, non si può invocare a metà, e la lista non nasconde più una categoria
di job.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import gate
from .tools import runtime

try:
    from . import main as _main
    _MAIN_IMPORT_ERROR: Exception | None = None
except Exception as _e:  # noqa: BLE001 — `server.main` dipende da `mcp`, non
    # installato in ogni ambiente (stesso guardrail di `test_gate_reasons`)
    _main = None
    _MAIN_IMPORT_ERROR = _e


def _tool(nome: str):
    return next(t for t in _main._JOBS_TOOLS if t.name == nome)


class FermareUnJobPassaDaUnUmanoTests(unittest.TestCase):
    def test_il_verbo_e_gated(self):
        self.assertTrue(gate.is_gated("jobs.set_enabled"))

    def test_e_gated_anche_riaccendere(self):
        """Un solo verbo per le due direzioni, quindi il gate le copre entrambe:
        riaccendere un job che qualcuno aveva fermato apposta è l'atto più
        privilegiato dei due, non il meno."""
        self.assertTrue(gate.needs_consent(
            "jobs.set_enabled", globally_gated=gate.is_gated("jobs.set_enabled"),
            agent_gated=False, off_profile=False, perimeter_ok=False))

    def test_ha_una_classe_e_quella_giusta(self):
        """`system`: cambia cosa la macchina fa da sola quando nessuno guarda —
        stessa classe di `providers.pause`, non una risorsa dentro uno scope."""
        self.assertEqual(gate.gate_class("jobs.set_enabled"), gate.GATE_SYSTEM)

    def test_il_perimetro_non_risponde_per_lui(self):
        """La whitelist delle destinazioni non ha nulla da dire su «questo job
        deve continuare a partire?»: se rispondesse, il gate sparirebbe verso
        ogni destinazione già censita."""
        self.assertFalse(gate.perimeter_answers("jobs.set_enabled"))

    def test_leggere_e_raccontare_restano_liberi(self):
        for v in ("jobs.list", "jobs.report_status"):
            with self.subTest(verbo=v):
                self.assertFalse(gate.is_gated(v))


class LaFormaDellaChiamataTests(unittest.TestCase):
    def test_la_rotta_e_quella_interna_dell_agent_server(self):
        with patch.object(runtime, "_post", return_value={"ok": True}) as p:
            runtime.set_job_enabled(6, False, by="sysadmin", reason="epic chiusa")
        self.assertEqual(p.call_args[0][0], "/clodia/jobs/6/set-enabled/internal")
        self.assertEqual(p.call_args[0][1],
                         {"enabled": False, "by": "sysadmin", "reason": "epic chiusa"})

    @unittest.skipIf(_main is None, f"server.main non importabile: {_MAIN_IMPORT_ERROR}")
    def test_chi_chiede_lo_mette_il_gateway_non_il_modello(self):
        with patch.object(_main.runtime, "set_job_enabled",
                          return_value={"ok": True}) as p:
            _main._dispatch_jobs("jobs.set_enabled",
                                 {"job_id": 6, "enabled": False, "by": "davide"},
                                 "sysadmin")
        self.assertEqual(p.call_args.kwargs["by"], "sysadmin",
                         "`by` viene dall'identità del chiamante, non dagli argomenti")

    @unittest.skipIf(_main is None, f"server.main non importabile: {_MAIN_IMPORT_ERROR}")
    def test_senza_enabled_non_si_indovina(self):
        """«spegni» e «riaccendi» sono l'opposto l'uno dell'altro: un default
        riaccenderebbe da solo un job che qualcuno aveva fermato."""
        with patch.object(_main.runtime, "set_job_enabled") as p:
            with self.assertRaises(ValueError) as ctx:
                _main._dispatch_jobs("jobs.set_enabled", {"job_id": 6}, "sysadmin")
            p.assert_not_called()
        self.assertIn("enabled", str(ctx.exception))

    @unittest.skipIf(_main is None, f"server.main non importabile: {_MAIN_IMPORT_ERROR}")
    def test_senza_job_id_non_parte_una_chiamata(self):
        with patch.object(_main.runtime, "set_job_enabled") as p:
            with self.assertRaises(ValueError):
                _main._dispatch_jobs("jobs.set_enabled", {"enabled": False},
                                     "sysadmin")
            p.assert_not_called()

    @unittest.skipIf(_main is None, f"server.main non importabile: {_MAIN_IMPORT_ERROR}")
    def test_lo_schema_chiede_id_e_direzione(self):
        schema = _tool("jobs.set_enabled").inputSchema
        self.assertEqual(sorted(schema.get("required") or []),
                         ["enabled", "job_id"])
        self.assertIn("reason", schema["properties"])

    @unittest.skipIf(_main is None, f"server.main non importabile: {_MAIN_IMPORT_ERROR}")
    def test_la_card_dice_cosa_succede_e_in_quale_direzione(self):
        """Il testo che l'owner legge deve distinguere i due versi: approvare
        «ferma» e approvare «riaccendi» non sono la stessa decisione."""
        ferma = _main._gate_effect_reason(
            "jobs.set_enabled", {"job_id": 6, "enabled": False,
                                 "reason": "epic chiusa"})
        riaccendi = _main._gate_effect_reason(
            "jobs.set_enabled", {"job_id": 6, "enabled": True})
        self.assertIn("FERMA", ferma)
        self.assertIn("epic chiusa", ferma)
        self.assertIn("RIACCENDE", riaccendi)
        self.assertNotIn("FERMA", riaccendi)


class LaListaNonNascondeUnaCategoriaTests(unittest.TestCase):
    """Una read che omette in silenzio un tipo di oggetto produce diagnosi
    sbagliate, non risposte incomplete: il job 6 c'era, e `jobs.list` ha fatto
    concludere che non esistesse."""

    def test_chiede_anche_i_trigger_di_topic(self):
        with patch.object(runtime, "_get", return_value=[]) as g:
            runtime.jobs()
        self.assertIn("include_topic_triggers=true", g.call_args[0][0])

    def test_il_risultato_dice_che_cos_e_e_di_quale_stanza(self):
        riga = {"id": 6, "name": "topic-trigger:SEAL-1/software-house",
                "mode": "topic_trigger", "topic_tier": "SEAL-1",
                "topic_name": "software-house", "interval_minutes": 15,
                "fired_count": 77, "enabled": True, "prompt": "segreto"}
        with patch.object(runtime, "_get", return_value=[riga]):
            out = runtime.jobs()
        job = out["jobs"][0]
        self.assertEqual(out["count"], 1)
        for campo in ("mode", "topic_tier", "topic_name", "interval_minutes",
                      "fired_count"):
            self.assertIn(campo, job, f"senza `{campo}` un trigger si legge "
                                      f"come un job cron qualunque")
        self.assertNotIn("prompt", job, "la lista resta metadati, non contenuto")


if __name__ == "__main__":
    unittest.main()

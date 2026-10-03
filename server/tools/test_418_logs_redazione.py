"""Il log del reference monitor non nomina stanze che chi legge non può aprire.

clodia-platform#418, punti 5 e 6. `logs.tail` rende leggibile il file del
gateway a chi ha il verbo, **indipendentemente dalla sua clearance**: è la
scelta che ha chiuso il buco cieco di #382, dove una modalità di rollout
scriveva su un logger che nessuno dentro la colonia poteva leggere. Ma le righe
del reference monitor dicono quale stanza un agente ha toccato, e fra quelle
stanze ci sono SEAL-2 e SEAL-3. Il contenuto non entra mai nel log; il NOME sì,
e il nome di un dossier è già informazione — dice che esiste e come si chiama.

La redazione si fa a LETTURA, non a scrittura: il file resta completo per chi
ha la clearance (e per l'analisi offline), e ogni lettore riceve ciò che gli
compete. Il tier resta visibile — «SEAL-3/•••» dice a sysadmin che è successo,
a che livello e a chi, e toglie solo la parte che non lo riguarda.
"""
from __future__ import annotations

import logging
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from .. import main as M
from .. import whitelist
from . import logs


class _Clearance:
    def __init__(self, v):
        self.v = v

    def __enter__(self):
        self.t = whitelist.set_current_clearance(self.v)
        return self

    def __exit__(self, *a):
        whitelist.reset_current_clearance(self.t)
        return False


class _Datadir:
    """Un datadir temporaneo, così `tail` legge un file scritto da noi."""

    def __enter__(self):
        self.d = tempfile.TemporaryDirectory()
        self.p = patch.dict(os.environ, {"CLODIA_DATA": self.d.name})
        self.p.start()
        (Path(self.d.name) / "logs").mkdir(parents=True, exist_ok=True)
        return self

    def __exit__(self, *a):
        self.p.stop()
        self.d.cleanup()
        return False

    def scrivi(self, *righe: str) -> None:
        f = Path(self.d.name) / "logs" / "clodia-tools.log"
        f.write_text("\n".join(righe) + "\n", encoding="utf-8")


def _leggi(righe, clearance):
    with _Datadir() as d, _Clearance(clearance), \
            patch.object(logs, "tool_allowed", lambda *_a, **_k: True):
        d.scrivi(*righe)
        return logs.tail(50, source="gateway")["lines"]


RIGA = ("2026-10-03 00:10:00 WARNING clodia-tools.refmon: compartimento spawn · "
        "clodia tocca SEAL-3/dossier-tizio (topic.read_file) da "
        "chan:SEAL-2:istruttoria-caio:clodia, participant del seed: GATE")


class RedazioneTests(unittest.TestCase):
    def test_un_lettore_SEAL_1_non_legge_il_nome_di_un_SEAL_3(self):
        out = _leggi([RIGA], "SEAL-1")[0]
        self.assertNotIn("dossier-tizio", out)
        self.assertIn("SEAL-3/•••", out)

    def test_la_stanza_di_partenza_e_un_nome_come_gli_altri(self):
        """La riga nomina DUE topic: il bersaglio e la stanza da cui si parte,
        nella forma del claim `chan:<tier>:<nome>:<seed>`. Redigere solo il
        primo avrebbe lasciato il secondo in chiaro — ed è lo stesso dato."""
        out = _leggi([RIGA], "SEAL-1")[0]
        self.assertNotIn("istruttoria-caio", out)
        self.assertIn("chan:SEAL-2:•••", out)

    def test_chi_ha_la_clearance_legge_tutto(self):
        out = _leggi([RIGA], "SEAL-3")[0]
        self.assertIn("dossier-tizio", out)
        self.assertIn("istruttoria-caio", out)

    def test_il_proprio_livello_non_si_redige(self):
        """`<=`, non `<`: un lettore SEAL-2 legge i SEAL-2."""
        out = _leggi([RIGA], "SEAL-2")[0]
        self.assertIn("istruttoria-caio", out)
        self.assertNotIn("dossier-tizio", out)

    def test_senza_clearance_dichiarata_si_redige(self):
        """Fail closed: un token che non dice fin dove arriva non arriva."""
        out = _leggi([RIGA], None)[0]
        self.assertNotIn("dossier-tizio", out)
        self.assertNotIn("istruttoria-caio", out)

    def test_il_tier_resta_visibile(self):
        """Oscurare la riga intera renderebbe il log inutile proprio a chi lo
        legge per mestiere: resta il livello, sparisce il nome."""
        out = _leggi([RIGA], "SEAL-1")[0]
        self.assertIn("SEAL-3", out)
        self.assertIn("compartimento spawn", out)
        self.assertIn("clodia tocca", out)

    def test_il_filtro_di_livello_continua_a_funzionare(self):
        """La redazione non tocca il formato: `tail` filtra il livello cercando
        ' WARNING ' nella riga, e un sostituto goloso lo mangerebbe."""
        info = RIGA.replace(" WARNING ", " INFO ")
        with _Datadir() as d, _Clearance("SEAL-1"), \
                patch.object(logs, "tool_allowed", lambda *_a, **_k: True):
            d.scrivi(info, RIGA)
            out = logs.tail(50, level="WARNING", source="gateway")["lines"]
        self.assertEqual(len(out), 1, out)

    def test_i_segreti_restano_redatti(self):
        """Non-regressione: la redazione dei nomi si aggiunge, non sostituisce."""
        riga = "2026-10-03 00:10:00 WARNING clodia-tools.refmon: token=abc123"
        out = _leggi([riga], "SEAL-4")[0]
        self.assertNotIn("abc123", out)

    def test_la_scala_dei_tier_e_la_stessa_del_dispatch(self):
        """La copia di `_rank` in `logs` non può divergere da quella di `main`:
        due scale diverse significano redigere con un metro e autorizzare con
        un altro."""
        for t in ("SEAL-0", "SEAL-1", "SEAL-2", "SEAL-3", "SEAL-4",
                  "", None, "sconosciuto"):
            with self.subTest(tier=t):
                self.assertEqual(logs._rank(t), M._rank(t))
        # L'alias storico `P<n>`: qui lo capiamo, perché nel log ci può finire
        # una riga vecchia. Non è un disaccordo sulla scala, è un ingresso in più.
        self.assertEqual(logs._rank("P2"), 2)


class RigaDelRefmonTests(unittest.TestCase):
    """La riga che il reference monitor emette DAVVERO deve essere redigibile.

    È il test che clodia ha chiesto a difesa dello SHORTCUT: la redazione è
    testuale e funziona perché l'emettitore scrive il tier attaccato al nome. Se
    un giorno loggasse un nome nudo, la redazione non avrebbe appiglio e nessuno
    se ne accorgerebbe leggendo `logs.py` — qui invece si rompe.
    """

    META = {"tier": "SEAL-3", "owner": "davide", "participants": ["clodia"]}

    def _riga_emessa(self) -> str:
        class _Svc:
            def open(_s, tier, name):
                return {"meta": dict(RigaDelRefmonTests.META)}

        with patch.dict(os.environ, {"CLODIA_SPAWN_COMPARTMENT": "on"}), \
                patch.object(M, "_topics", lambda: _Svc()):
            t = whitelist.set_current_chat("chan:SEAL-2:istruttoria-caio:clodia")
            try:
                with self.assertLogs(logs.REFMON_LOGGER, level="WARNING") as cm:
                    M._cross_topic_gate_key(
                        "topic.read_file",
                        {"tier": "SEAL-3", "name": "dossier-tizio"}, "clodia")
            finally:
                whitelist.reset_current_chat(t)
        return cm.output[0]

    def test_il_nome_del_bersaglio_e_redigibile(self):
        riga = self._riga_emessa()
        self.assertIn("dossier-tizio", riga)  # l'emettitore lo nomina davvero
        self.assertNotIn("dossier-tizio", logs._redact_topics(riga, "SEAL-1"))

    def test_e_anche_quello_della_stanza_di_partenza(self):
        riga = self._riga_emessa()
        self.assertIn("istruttoria-caio", riga)
        self.assertNotIn("istruttoria-caio", logs._redact_topics(riga, "SEAL-1"))


class SorgenteSconosciutaTests(unittest.TestCase):
    """Punto 6. `_log_file` documenta un `ValueError` per la sorgente
    sconosciuta; su un `source` non stringa sollevava `AttributeError` dal
    `.strip()`, cioè un guasto al posto di una risposta."""

    def test_una_sorgente_non_stringa_e_una_sorgente_sconosciuta(self):
        for v in (123, True, ["gateway"], {"source": "gateway"}, object()):
            with self.subTest(source=v):
                with self.assertRaises(ValueError):
                    logs._log_file(v)  # type: ignore[arg-type]

    def test_il_messaggio_elenca_ancora_le_sorgenti_buone(self):
        with self.assertRaises(ValueError) as e:
            logs._log_file(123)  # type: ignore[arg-type]
        self.assertIn("gateway", str(e.exception))
        self.assertIn("agent-server", str(e.exception))

    def test_none_resta_il_default_non_un_errore(self):
        """`None` significa «non ho scelto», e il default c'è: l'unico caso in
        cui il ripiego è corretto."""
        self.assertEqual(logs._log_file(None).name, "agent-server.log")


if __name__ == "__main__":  # pragma: no cover
    logging.disable(logging.CRITICAL)
    unittest.main()

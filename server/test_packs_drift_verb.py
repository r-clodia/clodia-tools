"""`packs.drift` esiste come verbo suo, e non è gated (clodia-platform#266).

La rotta che risponde «il seed installato non è più quello del pack» è una
LETTURA. Poteva farsi autorizzare da `packs.import_url`, come le altre rotte
read-only dell'agent-server, e sarebbe stato il prestito che `clodia-tools#242` e
`clodia-logic#365` hanno appena corretto per la #297: un verbo che non dice cosa
autorizza, e un rifiuto che nomina la scusa sbagliata («non puoi importare
pack») a chi voleva solo guardare.

Due proprietà, e sono in tensione — per questo stanno insieme in un file:

1. il verbo **esiste** nel catalogo, quindi `sysadmin` (che ha `packs.*`) lo
   riceve senza che nessuno aggiunga una riga al suo seed, e un rifiuto lo
   nomina;
2. il verbo **non è gated**: un drift non muta niente e non esegue codice di
   terzi — è la classe di `packs.list`/`show`/`check_command`. Metterlo fra i
   gated farebbe alzare una richiesta di consenso all'owner per una diagnostica
   in sola lettura, che è consent fatigue costruita apposta.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch

from . import gate
from . import main as M
from . import whitelist


class IlVerboEsisteTests(unittest.TestCase):
    def test_it_is_in_the_catalogue(self):
        self.assertIn("packs.drift", M.all_native_verb_names())

    def test_a_packs_wildcard_grant_reaches_it(self):
        """`sysadmin` ha `packs.*`: il verbo nuovo deve cadere sotto quel grant,
        altrimenti l'unico agente che fa manutenzione ai pack resta fuori."""
        self.assertTrue(whitelist._listed("packs.drift", {"packs.*"}))


class NonEGatedTests(unittest.TestCase):
    def test_reading_does_not_cost_a_consent(self):
        self.assertFalse(gate.is_gated("packs.drift"))

    def test_the_mutating_siblings_still_are(self):
        """Il controllo di sopra vale solo se il gate esiste ancora per chi muta."""
        self.assertTrue(gate.is_gated("packs.import_url"))
        self.assertTrue(gate.is_gated("packs.remove"))


class ArrivaAllaRottaTests(unittest.TestCase):
    def test_the_dispatch_calls_the_read_only_route(self):
        """Un verbo dichiarato e non instradato è un 'unknown packs tool' che si
        scopre al primo uso."""
        visti: dict = {}

        def finto(method, path, payload=None):
            visti.update(method=method, path=path)
            return {"name": "base-pack", "drifted": 0}

        from .tools import platform_ops as ops
        with patch.object(ops, "_req", finto):
            res = M._dispatch_packs("packs.drift", {"name": "base-pack"})
        self.assertEqual(visti["method"], "POST")
        self.assertEqual(visti["path"], "/clodia/packs/base-pack/drift")
        self.assertEqual(res["drifted"], 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

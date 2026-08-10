"""`LOG` esiste, in ogni modulo che lo usa.

In `main.py` `LOG` compariva in cinque punti ed era definito in nessuno. Tutti e
cinque stanno dentro un `except`: si percorrono solo quando qualcosa è **già**
andato storto, e allora il `NameError` sostituisce l'errore vero con uno che non
c'entra — mandando a cercare il guasto nel posto sbagliato.

Trovato usando davvero un token MCP umano contro il gateway in esercizio: due
verbi nuovi non erano nella tabella della provenienza, il ramo di ripiego ha
provato a scriverlo nel log, e `topic.my_mentions` ha risposto «NameError» a chi
chiedeva se qualcuno l'aveva chiamato.

Nessun test lo vedeva perché nessun test entrava in quei rami. Questo non li
percorre: guarda il **testo**, che è l'unico modo per cui una riga mai eseguita
può comunque essere verificata.
"""
from __future__ import annotations

import ast
import pathlib
import unittest


class NameIsBoundTests(unittest.TestCase):
    def _moduli(self):
        base = pathlib.Path(__file__).parent
        for p in sorted(base.rglob("*.py")):
            if p.name.startswith("test_") or "__pycache__" in str(p):
                continue
            yield p

    def test_every_module_that_logs_has_a_logger(self):
        senza = []
        for p in self._moduli():
            src = p.read_text()
            albero = ast.parse(src)
            usa = any(isinstance(n, ast.Name) and n.id == "LOG" and
                      isinstance(n.ctx, ast.Load)
                      for n in ast.walk(albero))
            if not usa:
                continue
            definisce = any(
                isinstance(n, ast.Name) and n.id == "LOG" and isinstance(n.ctx, ast.Store)
                for n in ast.walk(albero))
            # anche `from .x import LOG` conta come legame
            importa = any(
                isinstance(n, ast.ImportFrom) and
                any(a.name == "LOG" or a.asname == "LOG" for a in n.names)
                for n in ast.walk(albero))
            if not (definisce or importa):
                senza.append(p.name)
        self.assertEqual(senza, [],
                         f"usano LOG senza definirlo: {senza}")


if __name__ == "__main__":
    unittest.main()
